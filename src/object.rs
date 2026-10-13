//! The vault Durable Object: one per vault, the one writer, and the one
//! place requests are authenticated. It serves:
//!
//! - `/v1/*` ([`crate::route`]) over [`cce_sync::core::Vault`] on
//!   [`SqlStore`], with the shared `SYNC_TOKEN` (the laptop daemon);
//! - `/mcp`, Claude's connector ([`cce_sync::mcp`]), with an OAuth access
//!   token bound to it (or the shared token, for Claude Code by header);
//! - `/oauth/*` and the two `/.well-known` documents ([`crate::auth`]);
//! - the Google bridge ([`crate::google`]): `/v1/agenda`, the agenda in
//!   Claude's `daily_note`, and the `#gtask` pass, which runs on the
//!   object's alarm: soon after a commit, then every 5 minutes while any
//!   task is promoted (Google Tasks has no push notifications).
//!
//! It tells every live socket the new seq after each commit, Claude's
//! included. Requests interleave at awaits (an R2 read, a blob write), so
//! the vault sits behind an async lock: one batch at a time, and no read
//! between a batch's staging and its commit.

use async_lock::Mutex;
use std::collections::{BTreeMap, HashMap};

use cce_sync::core::{ApplyError, Operation, Store, Vault};
use cce_sync::gtask::{self, Act, Fields, Find, LineEdit};
use cce_sync::mcp::Mcp;
use cce_sync::proto::{
    pre_from_headers, BatchRequest, Kind, LiveNotice, Pre, Refusal, Status, H_DEVICE, H_HASH, H_REV,
};
use worker::*;

use crate::auth::Auth;
use crate::google::{AgendaFrom, Google, TASKS_SCOPE};
use crate::oauth;
use crate::route::{device, route, token_matches, Route};
use crate::sql::SqlStore;

#[durable_object]
pub struct VaultObject {
    state: State,
    env: Env,
    vault: Mutex<Vault<SqlStore>>,
    /// Locked after `vault`, never alone.
    mcp: Mutex<Mcp>,
    auth: Auth,
    google: Google,
}

/// The device the bridge's note edits are recorded as.
const BRIDGE_DEVICE: &str = "google";
/// How soon after a commit the bridge looks (a burst of edits, one pass).
const BRIDGE_SOON_MS: i64 = 10_000;
/// How often it polls Google while tasks are promoted.
const BRIDGE_POLL_MS: i64 = 5 * 60_000;

fn json<T: serde::Serialize>(value: &T, status: u16) -> Result<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}

fn refused(r: &Refusal) -> Result<Response> {
    json(r, r.status())
}

fn store_failed(e: impl std::fmt::Display) -> Result<Response> {
    console_error!("store: {e}");
    Response::error(format!("store: {e}"), 500)
}

fn now() -> i64 {
    Date::now().as_millis() as i64
}

impl DurableObject for VaultObject {
    fn new(state: State, env: Env) -> Self {
        let store = SqlStore::open(state.storage().sql(), env.clone()).expect("vault schema");
        let auth = Auth::open(state.storage().sql(), env.clone()).expect("oauth schema");
        let google = Google::open(state.storage().sql(), env.clone()).expect("google schema");
        VaultObject { state, env, vault: Mutex::new(Vault::new(store)), mcp: Mutex::new(Mcp::new()), auth, google }
    }

    /// The bridge's pass; again in 5 minutes while tasks are promoted, or
    /// after a failure.
    async fn alarm(&self) -> Result<Response> {
        let again = match self.bridge().await {
            Ok(polling) => polling,
            Err(e) => {
                console_error!("google bridge: {e}");
                true
            }
        };
        if again {
            self.state.storage().set_alarm(BRIDGE_POLL_MS).await?;
        }
        Response::ok("")
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let origin = url.origin().ascii_serialization();
        match url.path() {
            p if p.starts_with("/.well-known/oauth-protected-resource") => {
                return json(&oauth::protected_resource_metadata(&origin), 200)
            }
            "/.well-known/oauth-authorization-server" => return json(&oauth::authorization_server_metadata(&origin), 200),
            p if p.starts_with("/oauth/") => {
                let signed_in = p == "/oauth/google/callback";
                let resp = self.auth.handle(req, &origin, &self.google).await;
                if signed_in {
                    self.bridge_soon(5_000).await;
                }
                return resp;
            }
            "/mcp" => return self.mcp(req, &origin).await,
            p if p.starts_with("/v1/") => {}
            _ => return Response::error("not found", 404),
        }
        if !self.v1_allowed(&req, &url, &origin)? {
            let _ = req.bytes().await; // drained, or the runtime logs an error
            return Response::error("unauthorized", 401);
        }
        let method = req.method().to_string();
        let r = route(&method, url.path(), url.query().unwrap_or(""));
        let dev = device(req.headers().get(H_DEVICE)?.as_deref());
        match r {
            Route::Live => self.live(),
            Route::Changes { since, limit } => match self.vault.lock().await.changes(since, limit) {
                Ok(page) => json(&page, 200),
                Err(e) => store_failed(e),
            },
            Route::Listing => match self.vault.lock().await.listing() {
                Ok(l) => json(&l, 200),
                Err(e) => store_failed(e),
            },
            Route::Status => {
                let vault = self.vault.lock().await;
                match vault.listing() {
                    Ok(l) => json(&Status::of(&l, vault.store.database_size() as u64), 200),
                    Err(e) => store_failed(e),
                }
            }
            Route::History(path) => match self.vault.lock().await.history(&path) {
                Ok(h) => json(&h, 200),
                Err(e) => store_failed(e),
            },
            Route::Get(path) => match self.vault.lock().await.read(&path).await {
                Ok(Some((meta, bytes))) => {
                    let headers = Headers::new();
                    headers.set(H_REV, &meta.rev.to_string())?;
                    headers.set(H_HASH, &meta.hash)?;
                    headers.set("etag", &format!("\"{}\"", meta.rev))?;
                    headers.set("content-type", "application/octet-stream")?;
                    Ok(Response::from_bytes(bytes)?.with_headers(headers))
                }
                Ok(None) => Response::error("not found", 404),
                Err(e) => store_failed(e),
            },
            Route::Blob(hash) => {
                match self.vault.lock().await.store.blob_get(&hash).await {
                    Ok(Some(bytes)) => Response::from_bytes(bytes),
                    Ok(None) => Response::error("not found", 404),
                    Err(e) => store_failed(e),
                }
            }
            Route::Put(path) => {
                let pre = pre_from_headers(
                    req.headers().get("if-match")?.as_deref(),
                    req.headers().get("if-none-match")?.as_deref(),
                );
                let Some(pre) = pre else {
                    return refused(&Refusal::BadRequest {
                        reason: "a write needs If-Match: <rev> or If-None-Match: *".into(),
                    });
                };
                let bytes = req.bytes().await?;
                self.write(vec![Operation::Put { path, pre, bytes }], &dev).await
            }
            Route::Delete(path) => {
                let pre = match pre_from_headers(req.headers().get("if-match")?.as_deref(), None) {
                    Some(p @ Pre::Rev(_)) => p,
                    _ => {
                        return refused(&Refusal::BadRequest { reason: "a delete needs If-Match: <rev>".into() })
                    }
                };
                self.write(vec![Operation::Delete { path, pre }], &dev).await
            }
            Route::Batch => {
                let batch: BatchRequest = match req.json().await {
                    Ok(b) => b,
                    Err(e) => return refused(&Refusal::BadRequest { reason: format!("batch: {e}") }),
                };
                let mut ops = Vec::with_capacity(batch.ops.len());
                for op in batch.ops {
                    match Operation::from_wire(op) {
                        // Devices must say what they wrote from.
                        Ok(Operation::Put { pre: Pre::Any, .. })
                        | Ok(Operation::Delete { pre: Pre::Any, .. })
                        | Ok(Operation::Move { pre: Pre::Any, .. }) => {
                            return refused(&Refusal::BadRequest { reason: "batch ops need a precondition".into() })
                        }
                        Ok(op) => ops.push(op),
                        Err(r) => return refused(&r),
                    }
                }
                self.write(ops, &dev).await
            }
            Route::Agenda(Some(date)) => json(&self.google.agenda(&date).await, 200),
            Route::Agenda(None) => refused(&Refusal::BadRequest { reason: "agenda needs ?date=YYYY-MM-DD".into() }),
            Route::LiveTicket => json(&serde_json::json!({ "ticket": self.auth.ticket()?, "expires_in": 60 }), 200),
            Route::Grants => json(&self.auth.grants()?, 200),
            Route::RevokeGrant(id) => match self.auth.revoke(&id)? {
                true => json(&serde_json::json!({ "revoked": id }), 200),
                false => Response::error("no such grant", 404),
            },
            Route::BadPath(p) => refused(&Refusal::BadPath { index: 0, path: p, reason: "not a vault path".into() }),
            Route::MethodNotAllowed => Response::error("method not allowed", 405),
            Route::NotFound => Response::error("not found", 404),
        }
    }

    async fn websocket_message(&self, ws: WebSocket, message: WebSocketIncomingMessage) -> Result<()> {
        // The only message a client sends is a keep-alive.
        if let WebSocketIncomingMessage::String(s) = message {
            if s == "ping" {
                ws.send_with_str("pong")?;
            }
        }
        Ok(())
    }

    async fn websocket_close(&self, ws: WebSocket, code: usize, reason: String, _clean: bool) -> Result<()> {
        // Echo the close so the socket finishes closing on both sides.
        let code = if (1000..5000).contains(&code) && code != 1005 && code != 1006 { code as u16 } else { 1000 };
        let _ = ws.close(Some(code), Some(reason));
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        let _ = ws.close(Some(1011), Some("error"));
        Ok(())
    }
}

impl VaultObject {
    /// `/v1`: the shared token (the laptop), an access token issued to the
    /// phone app for the sync API, or, for the live socket only, a
    /// single-use ticket in the URL (browsers can't set headers on a
    /// WebSocket).
    fn v1_allowed(&self, req: &Request, url: &Url, origin: &str) -> Result<bool> {
        let authz = req.headers().get("authorization")?;
        if token_matches(authz.as_deref(), &self.shared_token()) {
            return Ok(true);
        }
        if let Some(bearer) = authz.as_deref().and_then(|a| a.strip_prefix("Bearer ")).filter(|b| !b.is_empty()) {
            return Ok(self.auth.access(bearer, &oauth::sync_resource(origin)).is_some());
        }
        if url.path() == "/v1/live" {
            if let Some((_, t)) = url.query_pairs().find(|(k, _)| k == "ticket") {
                return Ok(self.auth.take_ticket(&t));
            }
        }
        Ok(false)
    }

    fn shared_token(&self) -> String {
        self.env.secret("SYNC_TOKEN").map(|s| s.to_string()).unwrap_or_default()
    }

    /// Claude's connector. A missing or invalid token gets the `401` whose
    /// `WWW-Authenticate` points at the resource metadata: that is what
    /// starts sign-in in Claude.
    async fn mcp(&self, mut req: Request, origin: &str) -> Result<Response> {
        if req.method() != Method::Post {
            let headers = Headers::new();
            headers.set("allow", "POST")?;
            return Ok(Response::error("this MCP server answers POST only (no event stream)", 405)?.with_headers(headers));
        }
        let authz = req.headers().get("authorization")?;
        let bearer = authz.as_deref().and_then(|a| a.strip_prefix("Bearer ")).unwrap_or_default();
        let allowed = token_matches(authz.as_deref(), &self.shared_token())
            || (!bearer.is_empty() && self.auth.access(bearer, &oauth::resource(origin)).is_some());
        if !allowed {
            let _ = req.bytes().await; // drained, or the runtime logs an error
            let headers = Headers::new();
            headers.set("www-authenticate", &oauth::challenge(origin))?;
            return Ok(Response::from_json(&serde_json::json!({ "error": "invalid_token" }))?.with_status(401).with_headers(headers));
        }
        let body = req.bytes().await?;
        let mut vault = self.vault.lock().await;
        let mut mcp = self.mcp.lock().await;
        let before = vault.store.seq().unwrap_or(0);
        let reply = mcp.handle_with(&mut vault, &body, now(), &AgendaFrom(&self.google)).await;
        let after = vault.store.seq().unwrap_or(0);
        drop(mcp);
        drop(vault);
        if after != before {
            self.notify(after);
            self.bridge_soon(BRIDGE_SOON_MS).await;
        }
        match reply.body {
            Some(b) => {
                let headers = Headers::new();
                headers.set("content-type", "application/json")?;
                Ok(Response::ok(b)?.with_headers(headers).with_status(reply.status))
            }
            None => Ok(Response::empty()?.with_status(reply.status)),
        }
    }

    async fn write(&self, ops: Vec<Operation>, device: &str) -> Result<Response> {
        let result = self.vault.lock().await.apply(ops, device, now()).await;
        match result {
            Ok(committed) => {
                if committed.applied.iter().any(|a| !a.unchanged) {
                    self.notify(committed.seq);
                    if device != BRIDGE_DEVICE {
                        self.bridge_soon(BRIDGE_SOON_MS).await;
                    }
                }
                json(&committed, 200)
            }
            Err(ApplyError::Refused(r)) => refused(&r),
            Err(ApplyError::Store(e)) => store_failed(e),
        }
    }

    /// Tell every live socket the vault's new seq. Hibernated sockets wake
    /// for this; nothing else is sent, so a notice costs one small frame.
    fn notify(&self, seq: u64) {
        let Ok(notice) = serde_json::to_string(&LiveNotice { seq }) else { return };
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_str(&notice);
        }
    }

    /// Accept a live socket (hibernatable: an idle one costs no duration)
    /// and send it the current seq at once, so a client that connects after
    /// a gap knows whether to pull.
    fn live(&self) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        let seq = self.vault.try_lock().and_then(|v| v.store.seq().ok());
        if let Some(seq) = seq {
            pair.server.send_with_str(serde_json::to_string(&LiveNotice { seq })?)?;
        }
        Response::from_websocket(pair.client)
    }

    /// Run the bridge's pass within `ms`, unless one is due sooner. Only
    /// with Google Tasks connected.
    async fn bridge_soon(&self, ms: i64) {
        if !self.google.has(TASKS_SCOPE) {
            return;
        }
        let storage = self.state.storage();
        match storage.get_alarm().await {
            Ok(Some(at)) if at <= now() + ms => {}
            _ => {
                if let Err(e) = storage.set_alarm(ms).await {
                    console_error!("google bridge: setting the alarm: {e}");
                }
            }
        }
    }

    /// One `#gtask` pass (`cce_sync::gtask`): read the promoted lines,
    /// list Google's tasks, make the Google-side changes, then the note
    /// edits as one batch from the device `google`, each conditional on the
    /// note being as read (re-read under the lock). Whether to keep polling.
    async fn bridge(&self) -> std::result::Result<bool, String> {
        if !self.google.has(TASKS_SCOPE) {
            return Ok(false);
        }
        let s = |e: cce_sync::core::StoreError| e.to_string();
        let mut lines = Vec::new();
        let mut times: HashMap<String, i64> = HashMap::new();
        {
            let vault = self.vault.lock().await;
            for row in vault.store.live_files().map_err(s)? {
                let Some(hash) = row.hash.as_deref() else { continue };
                if Kind::of(&row.path) != Kind::Note {
                    continue;
                }
                let bytes = vault.store.blob_get(hash).await.map_err(s)?.unwrap_or_default();
                let text = String::from_utf8_lossy(&bytes);
                if text.contains(gtask::TAG) || text.contains("[gtask::") {
                    lines.extend(gtask::scan(&row.path, &text));
                    times.insert(row.path.clone(), row.at);
                }
            }
        }
        let (bases, pending) = (self.google.bases(), self.google.pending());
        if lines.is_empty() && bases.is_empty() {
            return Ok(false);
        }
        let remote = self.google.tasks().await?;
        let acts = gtask::plan(&lines, &|p| times.get(p).copied().unwrap_or(0), &remote, &bases, &pending);

        // Google first. A base waits for its line edit when there is one.
        let pulled: Vec<&str> = acts.iter().filter_map(|a| if let Act::Pull { id, .. } = a { Some(id.as_str()) } else { None }).collect();
        let origin = self.google.origin();
        let mut edits: BTreeMap<String, Vec<Edit>> = BTreeMap::new();
        for act in &acts {
            match act {
                Act::Create { path, raw, fields } => {
                    let mut notes = format!("From the vault: {path}");
                    if !origin.is_empty() {
                        notes.push_str(&format!("\n{origin}/?note={}", crate::oauth::escape(path)));
                    }
                    let id = self.google.create(fields, &notes).await?;
                    self.google.add_pending(path, raw, &id);
                    edits.entry(path.clone()).or_default().push(Edit::Attach { raw: raw.clone(), id, fields: fields.clone() });
                }
                Act::Attach { path, raw, id, fields } => {
                    edits.entry(path.clone()).or_default().push(Edit::Attach { raw: raw.clone(), id: id.clone(), fields: fields.clone() });
                }
                Act::Push { id, fields } => self.google.patch(id, fields).await?,
                Act::Pull { path, id, fields } => {
                    edits.entry(path.clone()).or_default().push(Edit::Pull { id: id.clone(), fields: fields.clone() });
                }
                Act::Untag { path, id } => edits.entry(path.clone()).or_default().push(Edit::Untag { id: id.clone() }),
                Act::Unlink { path, raw, .. } => edits.entry(path.clone()).or_default().push(Edit::Unlink { raw: raw.clone() }),
                Act::Delete { id } => self.google.delete(id).await?,
                Act::SetBase { id, fields } if !pulled.contains(&id.as_str()) => self.google.set_base(id, fields),
                Act::SetBase { .. } => {}
                Act::Forget { id } => self.google.forget(id),
            }
        }

        // Then the notes, as read now.
        if !edits.is_empty() {
            let mut vault = self.vault.lock().await;
            let mut ops = Vec::new();
            let mut landed: Vec<(String, Edit)> = Vec::new();
            for (path, list) in edits {
                let Some((meta, bytes)) = vault.read(&path).await.map_err(s)? else { continue };
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let (new, done) = gtask::edit_note(&text, &list.iter().map(Edit::line_edit).collect::<Vec<_>>());
                landed.extend(list.into_iter().zip(done).filter(|(_, ok)| *ok).map(|(e, _)| (path.clone(), e)));
                if new != text {
                    ops.push(Operation::Put { path, pre: Pre::Rev(meta.rev), bytes: new.into_bytes() });
                }
            }
            if !ops.is_empty() {
                match vault.apply(ops, BRIDGE_DEVICE, now()).await {
                    Ok(c) => self.notify(c.seq),
                    Err(e) => return Err(format!("writing the notes: {e:?}")),
                }
            }
            drop(vault);
            for (path, e) in landed {
                match e {
                    Edit::Attach { raw, id, fields } => {
                        self.google.set_base(&id, &fields);
                        self.google.drop_pending(&path, &raw);
                    }
                    Edit::Pull { id, fields } => self.google.set_base(&id, &fields),
                    Edit::Untag { .. } | Edit::Unlink { .. } => {}
                }
            }
        }
        Ok(!self.google.bases().is_empty() || !self.google.pending().is_empty())
    }
}

/// A line edit the bridge makes, and what it means once it lands.
enum Edit {
    Attach { raw: String, id: String, fields: Fields },
    Pull { id: String, fields: Fields },
    Untag { id: String },
    Unlink { raw: String },
}

impl Edit {
    fn line_edit(&self) -> LineEdit {
        match self {
            Edit::Attach { raw, id, .. } => {
                let id = id.clone();
                LineEdit { find: Find::Exact(raw.clone()), with: Box::new(move |l| gtask::attach(l, &id)) }
            }
            Edit::Pull { id, fields } => {
                let fields = fields.clone();
                LineEdit { find: Find::Id(id.clone()), with: Box::new(move |l| gtask::rewrite(l, &fields)) }
            }
            Edit::Untag { id } => LineEdit { find: Find::Id(id.clone()), with: Box::new(gtask::untag) },
            Edit::Unlink { raw } => LineEdit { find: Find::Exact(raw.clone()), with: Box::new(gtask::unlink) },
        }
    }
}
