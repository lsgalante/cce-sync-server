//! The vault Durable Object: one per vault, the one writer, and the one
//! place requests are authenticated. It serves:
//!
//! - `/v1/*` ([`crate::route`]) over [`cce_sync::core::Vault`] on
//!   [`SqlStore`], with the shared `SYNC_TOKEN` (the laptop daemon);
//! - `/mcp`, Claude's connector ([`cce_sync::mcp`]), with an OAuth access
//!   token bound to it (or the shared token, for Claude Code by header);
//! - `/oauth/*` and the two `/.well-known` documents ([`crate::auth`]).
//!
//! It tells every live socket the new seq after each commit, Claude's
//! included. Requests interleave at awaits (an R2 read, a blob write), so
//! the vault sits behind an async lock: one batch at a time, and no read
//! between a batch's staging and its commit.

use async_lock::Mutex;
use cce_sync::core::{ApplyError, Operation, Store, Vault};
use cce_sync::mcp::Mcp;
use cce_sync::proto::{
    pre_from_headers, BatchRequest, LiveNotice, Pre, Refusal, Status, H_DEVICE, H_HASH, H_REV,
};
use worker::*;

use crate::auth::Auth;
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
}

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
        VaultObject { state, env, vault: Mutex::new(Vault::new(store)), mcp: Mutex::new(Mcp::new()), auth }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let origin = url.origin().ascii_serialization();
        match url.path() {
            p if p.starts_with("/.well-known/oauth-protected-resource") => {
                return json(&oauth::protected_resource_metadata(&origin), 200)
            }
            "/.well-known/oauth-authorization-server" => return json(&oauth::authorization_server_metadata(&origin), 200),
            p if p.starts_with("/oauth/") => return self.auth.handle(req, &origin).await,
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
        let reply = mcp.handle(&mut vault, &body, now()).await;
        let after = vault.store.seq().unwrap_or(0);
        drop(mcp);
        drop(vault);
        if after != before {
            self.notify(after);
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
}
