//! The OAuth 2.1 authorization server, on the Durable Object's SQLite.
//! The rules (metadata, allowed redirects, PKCE, Google's ID token, the
//! consent page) are `oauth.rs`'s; this is storage and HTTP.
//!
//! The flow, for Claude:
//!
//! 1. `POST /oauth/register` (Dynamic Client Registration), or a Client ID
//!    Metadata Document URL as `client_id`, fetched on first use.
//! 2. `GET /oauth/authorize` checks the client and its redirect, keeps the
//!    request, and shows the consent page (who, where the code goes).
//! 3. `POST /oauth/authorize` sends the browser to Google, with PKCE and a
//!    nonce of its own.
//! 4. `GET /oauth/google/callback` exchanges Google's code, checks the ID
//!    token is the one allowed account, and redirects to the client with
//!    a code (single use, 10 minutes, bound to the PKCE challenge).
//! 5. `POST /oauth/token` swaps the code for an access token (1 hour,
//!    bound to the `/mcp` resource) and a refresh token (90 days). Refresh
//!    tokens rotate; presenting a used one revokes the whole grant.
//!
//! Tokens and codes are stored only as SHA-256 digests.

use serde::Serialize;
use serde_json::{json, Value};
use worker::{
    console_error, Date, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result, SqlStorage,
    SqlStorageValue as V,
};

use crate::oauth::{self, Client};
use crate::sql::{int, opt_int, opt_text, text};

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oauth_requests (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT,
        challenge TEXT NOT NULL, resource TEXT NOT NULL, verifier TEXT, nonce TEXT, created INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oauth_codes (
        hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL,
        resource TEXT NOT NULL, email TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL,
        grant_id TEXT)",
    "CREATE TABLE IF NOT EXISTS oauth_grants (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, client_name TEXT NOT NULL, email TEXT NOT NULL,
        resource TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER NOT NULL, revoked INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS oauth_tokens (
        hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL,
        used INTEGER NOT NULL)",
];

pub struct Auth {
    sql: SqlStorage,
    env: Env,
}

/// A grant as `GET /v1/grants` lists it.
#[derive(Debug, Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub client: String,
    pub email: String,
    pub created: i64,
    pub last_used: i64,
    pub revoked: bool,
}

fn now_s() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

/// A random URL-safe token of `n` bytes.
fn random(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("crypto.getRandomValues");
    oauth::b64url(&b)
}

fn err(e: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(e.to_string())
}

fn html(status: u16, body: String) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "text/html; charset=utf-8")?;
    headers.set("cache-control", "no-store")?;
    // The consent page must not be framed (clickjacking).
    headers.set("x-frame-options", "DENY")?;
    headers.set("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")?;
    Ok(Response::ok(body)?.with_headers(headers).with_status(status))
}

fn redirect(to: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("location", to)?;
    headers.set("cache-control", "no-store")?;
    Ok(Response::empty()?.with_headers(headers).with_status(302))
}

/// A token-endpoint error (RFC 6749 section 5.2).
fn token_error(code: &str, description: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("cache-control", "no-store")?;
    Ok(Response::from_json(&json!({ "error": code, "error_description": description }))?.with_headers(headers).with_status(400))
}

impl Auth {
    pub fn open(sql: SqlStorage, env: Env) -> Result<Auth> {
        for stmt in SCHEMA {
            sql.exec(stmt, None)?;
        }
        Ok(Auth { sql, env })
    }

    fn rows(&self, q: &str, bind: Vec<V>) -> Result<Vec<Vec<V>>> {
        self.sql.exec(q, bind)?.raw().collect()
    }

    fn exec(&self, q: &str, bind: Vec<V>) -> Result<()> {
        self.sql.exec(q, bind).map(|_| ())
    }

    /// A setting from a var or a secret; empty when unset.
    fn setting(&self, name: &str) -> String {
        self.env
            .var(name)
            .map(|v| v.to_string())
            .or_else(|_| self.env.secret(name).map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// Route `/oauth/*`.
    pub async fn handle(&self, mut req: Request, origin: &str) -> Result<Response> {
        let url = req.url()?;
        let q = oauth::form(url.query().unwrap_or(""));
        match (req.method(), url.path()) {
            (Method::Post, "/oauth/register") => {
                let body = req.bytes().await?;
                self.register(&body)
            }
            (Method::Get, "/oauth/authorize") => self.authorize(&q, origin).await,
            (Method::Post, "/oauth/authorize") => {
                let f = oauth::form(&req.text().await?);
                self.to_google(f.get("request").map(String::as_str).unwrap_or_default(), origin)
            }
            (Method::Get, "/oauth/google/callback") => self.google_callback(&q, origin).await,
            (Method::Post, "/oauth/token") => {
                let f = oauth::form(&req.text().await?);
                self.token(&f)
            }
            _ => Response::error("not found", 404),
        }
    }

    fn register(&self, body: &[u8]) -> Result<Response> {
        let client = match oauth::register(body, format!("c_{}", random(18))) {
            Ok(c) => c,
            Err(e) => {
                let code = if e.contains("redirect_uri") { "invalid_redirect_uri" } else { "invalid_client_metadata" };
                return Ok(Response::from_json(&json!({ "error": code, "error_description": e }))?.with_status(400));
            }
        };
        let now = now_s();
        self.save_client(&client, now)?;
        Ok(Response::from_json(&oauth::registration_response(&client, now))?.with_status(201))
    }

    fn save_client(&self, c: &Client, now: i64) -> Result<()> {
        self.exec(
            "INSERT INTO oauth_clients (client_id, name, redirect_uris, created) VALUES (?, ?, ?, ?)
             ON CONFLICT(client_id) DO UPDATE SET name = excluded.name, redirect_uris = excluded.redirect_uris,
             created = excluded.created",
            vec![c.client_id.as_str().into(), c.name.as_str().into(), json!(c.redirect_uris).to_string().into(), V::Integer(now)],
        )
    }

    /// A known client, or a Client ID Metadata Document fetched (and kept
    /// for a day).
    async fn client(&self, client_id: &str) -> std::result::Result<Client, String> {
        let rows = self
            .rows("SELECT name, redirect_uris, created FROM oauth_clients WHERE client_id = ?", vec![client_id.into()])
            .map_err(|e| e.to_string())?;
        let is_cimd = oauth::cimd_url_allowed(client_id);
        if let Some(r) = rows.first() {
            let fresh = int(&r[2]).is_ok_and(|t| now_s() - t < 86_400);
            if !is_cimd || fresh {
                let uris: Vec<String> = serde_json::from_str(&text(&r[1]).map_err(|e| e.to_string())?).unwrap_or_default();
                return Ok(Client { client_id: client_id.into(), name: text(&r[0]).map_err(|e| e.to_string())?, redirect_uris: uris });
            }
        }
        if !is_cimd {
            return Err("unknown client: register it first".into());
        }
        let mut resp = Fetch::Url(client_id.parse().map_err(|_| "bad client_id URL")?).send().await.map_err(|e| e.to_string())?;
        if resp.status_code() != 200 {
            return Err(format!("client metadata document: HTTP {}", resp.status_code()));
        }
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        if body.len() > 64 * 1024 {
            return Err("client metadata document too large".into());
        }
        let client = oauth::cimd_client(client_id, &body)?;
        self.save_client(&client, now_s()).map_err(|e| e.to_string())?;
        Ok(client)
    }

    async fn authorize(&self, q: &std::collections::HashMap<String, String>, origin: &str) -> Result<Response> {
        let get = |k: &str| q.get(k).map(String::as_str).unwrap_or_default();
        // Until the client and redirect check out, errors are shown here:
        // never redirect anywhere unverified.
        let client = match self.client(get("client_id")).await {
            Ok(c) => c,
            Err(e) => return html(400, oauth::error_page(&e)),
        };
        let redirect_uri = get("redirect_uri");
        if !oauth::redirect_allowed(redirect_uri) || !oauth::redirect_matches(&client.redirect_uris, redirect_uri) {
            return html(400, oauth::error_page("That redirect address isn't registered for this client."));
        }
        let state = q.get("state").cloned();
        let back = |error: &str, description: &str| {
            let mut p = vec![("error", error), ("error_description", description), ("iss", origin)];
            if let Some(s) = &state {
                p.push(("state", s));
            }
            redirect(&oauth::with_query(redirect_uri, &p))
        };
        if get("response_type") != "code" {
            return back("unsupported_response_type", "only the authorization code flow is supported");
        }
        if get("code_challenge").is_empty() || get("code_challenge_method") != "S256" {
            return back("invalid_request", "PKCE with S256 is required");
        }
        let resource = oauth::resource(origin);
        if !get("resource").is_empty() && get("resource") != resource {
            return back("invalid_target", "this server's resource is its /mcp endpoint");
        }
        let id = random(24);
        let now = now_s();
        self.exec("DELETE FROM oauth_requests WHERE created < ?", vec![V::Integer(now - oauth::REQUEST_TTL_SECS)])?;
        self.exec(
            "INSERT INTO oauth_requests (id, client_id, redirect_uri, state, challenge, resource, created)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                id.as_str().into(),
                client.client_id.as_str().into(),
                redirect_uri.into(),
                state.into(),
                get("code_challenge").into(),
                resource.into(),
                V::Integer(now),
            ],
        )?;
        html(200, oauth::consent_page(&client.name, redirect_uri, &id))
    }

    fn to_google(&self, request: &str, origin: &str) -> Result<Response> {
        let rows = self.rows("SELECT created FROM oauth_requests WHERE id = ?", vec![request.into()])?;
        let fresh = rows.first().and_then(|r| int(&r[0]).ok()).is_some_and(|t| now_s() - t < oauth::REQUEST_TTL_SECS);
        if !fresh {
            return html(400, oauth::error_page("This sign-in has expired. Start connecting again from Claude."));
        }
        let google_id = self.setting("GOOGLE_CLIENT_ID");
        if google_id.is_empty() {
            return html(500, oauth::error_page("Google sign-in isn't set up on this server (GOOGLE_CLIENT_ID)."));
        }
        let (verifier, nonce) = (random(48), random(24));
        self.exec("UPDATE oauth_requests SET verifier = ?, nonce = ? WHERE id = ?", vec![verifier.as_str().into(), nonce.as_str().into(), request.into()])?;
        let auth_url = Some(self.setting("GOOGLE_AUTH_URL")).filter(|s| !s.is_empty()).unwrap_or_else(|| oauth::GOOGLE_AUTH_URL.into());
        let callback = format!("{origin}/oauth/google/callback");
        let challenge = oauth::s256(&verifier);
        let hint = self.setting("ALLOWED_EMAIL");
        redirect(&oauth::with_query(
            &auth_url,
            &[
                ("client_id", &google_id),
                ("redirect_uri", &callback),
                ("response_type", "code"),
                ("scope", "openid email"),
                ("state", request),
                ("nonce", &nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "select_account"),
                ("login_hint", &hint),
            ],
        ))
    }

    async fn google_callback(&self, q: &std::collections::HashMap<String, String>, origin: &str) -> Result<Response> {
        let id = q.get("state").cloned().unwrap_or_default();
        let rows = self.rows(
            "SELECT client_id, redirect_uri, state, challenge, resource, verifier, nonce, created FROM oauth_requests WHERE id = ?",
            vec![id.as_str().into()],
        )?;
        // Single use, whatever happens next.
        self.exec("DELETE FROM oauth_requests WHERE id = ?", vec![id.as_str().into()])?;
        let Some(r) = rows.first() else {
            return html(400, oauth::error_page("This sign-in has expired or was already used. Start again from Claude."));
        };
        let (client_id, redirect_uri, state) = (text(&r[0]).map_err(err)?, text(&r[1]).map_err(err)?, opt_text(&r[2]).map_err(err)?);
        let (challenge, resource) = (text(&r[3]).map_err(err)?, text(&r[4]).map_err(err)?);
        let (verifier, nonce) = (opt_text(&r[5]).map_err(err)?.unwrap_or_default(), opt_text(&r[6]).map_err(err)?.unwrap_or_default());
        let back = |params: Vec<(&str, &str)>| {
            let mut p = params;
            p.push(("iss", origin));
            if let Some(s) = &state {
                p.push(("state", s));
            }
            redirect(&oauth::with_query(&redirect_uri, &p))
        };
        if now_s() - int(&r[7]).map_err(err)? > oauth::REQUEST_TTL_SECS {
            return back(vec![("error", "access_denied"), ("error_description", "the sign-in took too long")]);
        }
        let Some(code) = q.get("code") else {
            return back(vec![("error", "access_denied"), ("error_description", "Google sign-in was cancelled")]);
        };
        let email = match self.google_exchange(code, &verifier, &nonce, origin).await {
            Ok(e) => e,
            Err(e) => {
                console_error!("google sign-in: {e}");
                return back(vec![("error", "access_denied"), ("error_description", &e)]);
            }
        };
        let code = random(32);
        let now = now_s();
        self.exec("DELETE FROM oauth_codes WHERE expires < ?", vec![V::Integer(now - 86_400)])?;
        self.exec(
            "INSERT INTO oauth_codes (hash, client_id, redirect_uri, challenge, resource, email, expires, used)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            vec![
                oauth::digest(&code).into(),
                client_id.into(),
                redirect_uri.as_str().into(),
                challenge.into(),
                resource.into(),
                email.into(),
                V::Integer(now + oauth::CODE_TTL_SECS),
            ],
        )?;
        back(vec![("code", &code)])
    }

    /// Swap Google's code for its ID token and check who signed in.
    async fn google_exchange(&self, code: &str, verifier: &str, nonce: &str, origin: &str) -> std::result::Result<String, String> {
        let (id, secret) = (self.setting("GOOGLE_CLIENT_ID"), self.setting("GOOGLE_CLIENT_SECRET"));
        let token_url = Some(self.setting("GOOGLE_TOKEN_URL")).filter(|s| !s.is_empty()).unwrap_or_else(|| oauth::GOOGLE_TOKEN_URL.into());
        let body = format!(
            "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
            oauth::escape(code),
            oauth::escape(&id),
            oauth::escape(&secret),
            oauth::escape(&format!("{origin}/oauth/google/callback")),
            oauth::escape(verifier),
        );
        let headers = Headers::new();
        headers.set("content-type", "application/x-www-form-urlencoded").map_err(|e| e.to_string())?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(headers).with_body(Some(body.into()));
        let req = Request::new_with_init(&token_url, &init).map_err(|e| e.to_string())?;
        let mut resp = Fetch::Request(req).send().await.map_err(|e| e.to_string())?;
        let v: Value = resp.json().await.map_err(|e| format!("Google's answer: {e}"))?;
        let Some(id_token) = v.get("id_token").and_then(Value::as_str) else {
            return Err(format!("Google refused the sign-in: {}", v.get("error").and_then(Value::as_str).unwrap_or("no ID token")));
        };
        oauth::check_id_token(id_token, &id, nonce, &self.setting("ALLOWED_EMAIL"), now_s())
    }

    fn token(&self, f: &std::collections::HashMap<String, String>) -> Result<Response> {
        let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
        let now = now_s();
        match get("grant_type") {
            "authorization_code" => {
                let rows = self.rows(
                    "SELECT client_id, redirect_uri, challenge, resource, email, expires, used, grant_id FROM oauth_codes WHERE hash = ?",
                    vec![oauth::digest(get("code")).into()],
                )?;
                let Some(r) = rows.first() else { return token_error("invalid_grant", "unknown code") };
                if int(&r[6]).map_err(err)? != 0 {
                    // A code presented twice: whatever it bought is revoked.
                    if let Some(g) = opt_text(&r[7]).map_err(err)? {
                        self.exec("UPDATE oauth_grants SET revoked = 1 WHERE id = ?", vec![g.into()])?;
                    }
                    return token_error("invalid_grant", "code already used");
                }
                let (client_id, redirect_uri, challenge, resource, email) =
                    (text(&r[0]).map_err(err)?, text(&r[1]).map_err(err)?, text(&r[2]).map_err(err)?, text(&r[3]).map_err(err)?, text(&r[4]).map_err(err)?);
                if int(&r[5]).map_err(err)? < now {
                    return token_error("invalid_grant", "code expired");
                }
                if get("client_id") != client_id || get("redirect_uri") != redirect_uri {
                    return token_error("invalid_grant", "client_id or redirect_uri does not match the code");
                }
                if !oauth::pkce_ok(get("code_verifier"), &challenge) {
                    return token_error("invalid_grant", "PKCE verification failed");
                }
                if !get("resource").is_empty() && get("resource") != resource {
                    return token_error("invalid_target", "this server's resource is its /mcp endpoint");
                }
                let name = self
                    .rows("SELECT name FROM oauth_clients WHERE client_id = ?", vec![client_id.as_str().into()])?
                    .first()
                    .and_then(|r| text(&r[0]).ok())
                    .unwrap_or_else(|| client_id.clone());
                let grant = format!("g_{}", random(12));
                self.exec(
                    "INSERT INTO oauth_grants (id, client_id, client_name, email, resource, created, last_used, revoked)
                     VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                    vec![grant.as_str().into(), client_id.into(), name.into(), email.into(), resource.into(), V::Integer(now), V::Integer(now)],
                )?;
                self.exec("UPDATE oauth_codes SET used = 1, grant_id = ? WHERE hash = ?", vec![grant.as_str().into(), oauth::digest(get("code")).into()])?;
                self.issue(&grant, now)
            }
            "refresh_token" => {
                let hash = oauth::digest(get("refresh_token"));
                let rows = self.rows(
                    "SELECT t.grant_id, t.expires, t.used, g.revoked, g.client_id, g.resource FROM oauth_tokens t
                     JOIN oauth_grants g ON g.id = t.grant_id WHERE t.hash = ? AND t.kind = 'refresh'",
                    vec![hash.as_str().into()],
                )?;
                let Some(r) = rows.first() else { return token_error("invalid_grant", "unknown refresh token") };
                let grant = text(&r[0]).map_err(err)?;
                if int(&r[2]).map_err(err)? != 0 {
                    // Rotation broken: someone holds an old refresh token.
                    self.exec("UPDATE oauth_grants SET revoked = 1 WHERE id = ?", vec![grant.as_str().into()])?;
                    return token_error("invalid_grant", "refresh token already used; the grant is revoked");
                }
                if int(&r[1]).map_err(err)? < now || int(&r[3]).map_err(err)? != 0 {
                    return token_error("invalid_grant", "refresh token expired or revoked");
                }
                if !get("client_id").is_empty() && get("client_id") != text(&r[4]).map_err(err)? {
                    return token_error("invalid_grant", "refresh token belongs to another client");
                }
                if !get("resource").is_empty() && get("resource") != text(&r[5]).map_err(err)? {
                    return token_error("invalid_target", "this server's resource is its /mcp endpoint");
                }
                self.exec("UPDATE oauth_tokens SET used = 1 WHERE hash = ?", vec![hash.into()])?;
                self.issue(&grant, now)
            }
            other => token_error("unsupported_grant_type", &format!("grant_type {other} is not supported")),
        }
    }

    fn issue(&self, grant: &str, now: i64) -> Result<Response> {
        self.exec("DELETE FROM oauth_tokens WHERE expires < ?", vec![V::Integer(now)])?;
        let (access, refresh) = (random(32), random(32));
        for (t, kind, ttl) in [(&access, "access", oauth::ACCESS_TTL_SECS), (&refresh, "refresh", oauth::REFRESH_TTL_SECS)] {
            self.exec(
                "INSERT INTO oauth_tokens (hash, grant_id, kind, expires, used) VALUES (?, ?, ?, ?, 0)",
                vec![oauth::digest(t).into(), grant.into(), kind.into(), V::Integer(now + ttl)],
            )?;
        }
        let headers = Headers::new();
        headers.set("cache-control", "no-store")?;
        Ok(Response::from_json(&json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": oauth::ACCESS_TTL_SECS,
            "refresh_token": refresh,
            "scope": oauth::SCOPE,
        }))?
        .with_headers(headers))
    }

    /// The grant behind a valid access token for `resource`, if any.
    pub fn access(&self, token: &str, resource: &str) -> Option<String> {
        let rows = self
            .rows(
                "SELECT t.grant_id, t.expires, g.revoked, g.resource FROM oauth_tokens t
                 JOIN oauth_grants g ON g.id = t.grant_id WHERE t.hash = ? AND t.kind = 'access'",
                vec![oauth::digest(token).into()],
            )
            .ok()?;
        let r = rows.first()?;
        let now = now_s();
        let ok = int(&r[1]).ok()? > now && int(&r[2]).ok()? == 0 && text(&r[3]).ok()? == resource;
        if !ok {
            return None;
        }
        let grant = text(&r[0]).ok()?;
        let _ = self.exec("UPDATE oauth_grants SET last_used = ? WHERE id = ?", vec![V::Integer(now), grant.as_str().into()]);
        Some(grant)
    }

    pub fn grants(&self) -> Result<Vec<GrantInfo>> {
        let rows = self.rows("SELECT id, client_name, email, created, last_used, revoked FROM oauth_grants ORDER BY created DESC", vec![])?;
        rows.iter()
            .map(|r| {
                Ok(GrantInfo {
                    id: text(&r[0]).map_err(err)?,
                    client: text(&r[1]).map_err(err)?,
                    email: text(&r[2]).map_err(err)?,
                    created: int(&r[3]).map_err(err)?,
                    last_used: int(&r[4]).map_err(err)?,
                    revoked: opt_int(&r[5]).map_err(err)?.unwrap_or(0) != 0,
                })
            })
            .collect()
    }

    /// Revoke a grant: its tokens stop working at once.
    pub fn revoke(&self, id: &str) -> Result<bool> {
        let found = !self.rows("SELECT 1 FROM oauth_grants WHERE id = ?", vec![id.into()])?.is_empty();
        self.exec("UPDATE oauth_grants SET revoked = 1 WHERE id = ?", vec![id.into()])?;
        self.exec("DELETE FROM oauth_tokens WHERE grant_id = ?", vec![id.into()])?;
        Ok(found)
    }
}
