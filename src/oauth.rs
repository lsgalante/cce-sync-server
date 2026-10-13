//! The OAuth 2.1 authorization server's rules, with no Workers types so
//! they are tested natively: discovery documents, which clients and
//! redirects are allowed, PKCE, Google's ID token, the consent page.
//! `auth.rs` (wasm32) does the storage, the HTTP and the Google calls.
//!
//! What it implements, from the MCP authorization spec and Claude's
//! connector docs:
//!
//! - Protected Resource Metadata (RFC 9728) naming this origin as the one
//!   authorization server, and a `401` whose `WWW-Authenticate` points at
//!   it: that is what starts sign-in in Claude.
//! - Authorization Server Metadata (RFC 8414) with S256 PKCE, public
//!   clients (`none`), and both Client ID Metadata Documents and Dynamic
//!   Client Registration (RFC 7591).
//! - Redirects only to Claude: `https://claude.ai/api/mcp/auth_callback`
//!   (and the claude.com one it may move to), and loopback `/callback` on
//!   any port for Claude Code. This server has one user; nothing else may
//!   register.
//! - The user is whoever signs in with Google as the one allowed email.

use std::collections::HashMap;

use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The one scope: full read-write access to the vault.
pub const SCOPE: &str = "vault";
pub const ACCESS_TTL_SECS: i64 = 3600;
pub const REFRESH_TTL_SECS: i64 = 90 * 24 * 3600;
pub const CODE_TTL_SECS: i64 = 600;
/// How long a consent page stays good for.
pub const REQUEST_TTL_SECS: i64 = 900;

pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The redirect URIs Claude's hosted apps use.
const CLAUDE_CALLBACKS: &[&str] = &["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"];
/// Hosts whose Client ID Metadata Documents are fetched.
const CIMD_HOSTS: &[&str] = &["claude.ai", "claude.com", "anthropic.com"];

/// The MCP endpoint, which is also the resource Claude's tokens are bound
/// to.
pub fn resource(origin: &str) -> String {
    format!("{origin}/mcp")
}

/// The sync API, the resource the phone app's tokens are bound to.
pub fn sync_resource(origin: &str) -> String {
    format!("{origin}/v1")
}

/// The phone app (cce-vault-web), served by this Worker: a built-in public
/// client that may only send the user back to this origin, and the only
/// client that may ask for the sync API.
pub const FIRST_PARTY: &str = "cce-vault-web";

pub fn first_party(origin: &str) -> Client {
    Client { client_id: FIRST_PARTY.into(), name: "cce vault (the phone app)".into(), redirect_uris: vec![format!("{origin}/")] }
}

/// The resource a sign-in is for: `/mcp` unless the phone app asks for
/// `/v1`. Anything else is `invalid_target`.
pub fn resource_for(origin: &str, requested: &str, client_id: &str) -> Result<String, &'static str> {
    let mcp = resource(origin);
    if requested.is_empty() || requested == mcp {
        return Ok(mcp);
    }
    if requested == sync_resource(origin) {
        return if client_id == FIRST_PARTY { Ok(requested.to_string()) } else { Err("only the vault's own app may use the sync API") };
    }
    Err("this server's resources are its /mcp and /v1 endpoints")
}

/// Whether a client may send a code to `redirect_uri`: one it registered,
/// and either Claude's or loopback, or the phone app back to this origin.
pub fn redirect_ok(client: &Client, redirect_uri: &str) -> bool {
    redirect_matches(&client.redirect_uris, redirect_uri) && (client.client_id == FIRST_PARTY || redirect_allowed(redirect_uri))
}

pub fn resource_metadata_url(origin: &str) -> String {
    format!("{origin}/.well-known/oauth-protected-resource/mcp")
}

pub fn protected_resource_metadata(origin: &str) -> Value {
    json!({
        "resource": resource(origin),
        "authorization_servers": [origin],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "cce vault",
    })
}

pub fn authorization_server_metadata(origin: &str) -> Value {
    json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/oauth/authorize"),
        "token_endpoint": format!("{origin}/oauth/token"),
        "registration_endpoint": format!("{origin}/oauth/register"),
        "scopes_supported": [SCOPE, "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    })
}

/// The `WWW-Authenticate` value of a `401` from `/mcp`.
pub fn challenge(origin: &str) -> String {
    format!("Bearer resource_metadata=\"{}\", scope=\"{SCOPE}\"", resource_metadata_url(origin))
}

/// `(scheme, host, port, path)` of an absolute http(s) URL, lowercased
/// scheme and host. No query or fragment allowed.
fn split_url(url: &str) -> Option<(String, String, Option<u16>, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if rest.contains('#') || rest.contains('?') {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, Some(p.parse().ok()?)),
        _ => (authority, None),
    };
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase(), port, path))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

/// Whether a redirect URI may be used at all: Claude's callback, or an
/// http loopback address (Claude Code; any port).
pub fn redirect_allowed(uri: &str) -> bool {
    if CLAUDE_CALLBACKS.contains(&uri) {
        return true;
    }
    matches!(split_url(uri), Some((s, h, _, _)) if s == "http" && is_loopback(&h))
}

/// Whether `given` matches one of a client's registered redirect URIs:
/// exactly, or for loopback, with the port ignored (RFC 8252 section 7.3).
pub fn redirect_matches(registered: &[String], given: &str) -> bool {
    registered.iter().any(|r| {
        if r == given {
            return true;
        }
        match (split_url(r), split_url(given)) {
            (Some((s1, h1, _, p1)), Some((s2, h2, _, p2))) => s1 == "http" && s1 == s2 && is_loopback(&h1) && h1 == h2 && p1 == p2,
            _ => false,
        }
    })
}

/// Whether a `client_id` is a Client ID Metadata Document URL this server
/// fetches: https, a path, on a Claude host.
pub fn cimd_url_allowed(client_id: &str) -> bool {
    matches!(split_url(client_id), Some((s, h, None, p)) if s == "https" && p.len() > 1 && CIMD_HOSTS.contains(&h.as_str()))
}

/// A registered (or fetched) client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Deserialize)]
struct ClientMetadata {
    client_id: Option<String>,
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
}

/// Validate a Dynamic Client Registration request. Every redirect URI must
/// be allowed; the client is public.
pub fn register(body: &[u8], client_id: String) -> Result<Client, String> {
    let m: ClientMetadata = serde_json::from_slice(body).map_err(|e| format!("invalid client metadata: {e}"))?;
    if m.redirect_uris.is_empty() {
        return Err("redirect_uris is required".into());
    }
    if let Some(bad) = m.redirect_uris.iter().find(|u| !redirect_allowed(u)) {
        return Err(format!("redirect_uri not allowed on this server: {bad}"));
    }
    if m.token_endpoint_auth_method.as_deref().is_some_and(|t| t != "none") {
        return Err("only public clients (token_endpoint_auth_method \"none\") are supported".into());
    }
    Ok(Client { client_id, name: m.client_name.unwrap_or_else(|| "MCP client".into()), redirect_uris: m.redirect_uris })
}

/// The registration response (RFC 7591 section 3.2.1).
pub fn registration_response(c: &Client, issued_at: i64) -> Value {
    json!({
        "client_id": c.client_id,
        "client_id_issued_at": issued_at,
        "client_name": c.name,
        "redirect_uris": c.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })
}

/// Validate a fetched Client ID Metadata Document.
pub fn cimd_client(url: &str, body: &[u8]) -> Result<Client, String> {
    let m: ClientMetadata = serde_json::from_slice(body).map_err(|e| format!("client metadata document: {e}"))?;
    if m.client_id.as_deref() != Some(url) {
        return Err("client metadata document: client_id does not match its URL".into());
    }
    let redirect_uris: Vec<String> = m.redirect_uris.into_iter().filter(|u| redirect_allowed(u)).collect();
    if redirect_uris.is_empty() {
        return Err("client metadata document: no redirect_uri this server allows".into());
    }
    Ok(Client { client_id: url.to_string(), name: m.client_name.unwrap_or_else(|| url.to_string()), redirect_uris })
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256, lowercase hex: tokens and codes are stored only as this.
pub fn digest(s: &str) -> String {
    cce_sync::proto::hash(s.as_bytes())
}

/// The S256 code challenge of a verifier.
pub fn s256(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

/// PKCE (RFC 7636): a verifier of 43-128 unreserved characters whose S256
/// matches the challenge.
pub fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        && s256(verifier) == challenge
}

/// The claims of Google's ID token this server checks.
#[derive(Debug, Deserialize)]
pub struct IdClaims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Read and check the ID token from Google's token endpoint. The token
/// came straight from Google over TLS, so its signature is not checked
/// (OpenID Connect Core 3.1.3.7, step 6); its issuer, audience, expiry and
/// nonce are, and the email must be the one allowed, and verified.
pub fn check_id_token(id_token: &str, client_id: &str, nonce: &str, allowed_email: &str, now: i64) -> Result<String, String> {
    let payload = id_token.split('.').nth(1).ok_or("malformed ID token")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "malformed ID token")?;
    let c: IdClaims = serde_json::from_slice(&bytes).map_err(|e| format!("ID token: {e}"))?;
    if c.iss != "https://accounts.google.com" && c.iss != "accounts.google.com" {
        return Err("ID token from the wrong issuer".into());
    }
    if c.aud != client_id {
        return Err("ID token for another client".into());
    }
    if c.exp <= now {
        return Err("ID token expired".into());
    }
    if c.nonce.as_deref() != Some(nonce) {
        return Err("ID token nonce does not match".into());
    }
    let email = c.email.ok_or("Google did not say which account signed in")?;
    if c.email_verified != Some(true) {
        return Err("that Google account's email is not verified".into());
    }
    if allowed_email.trim().is_empty() || !email.eq_ignore_ascii_case(allowed_email.trim()) {
        return Err(format!("{email} may not use this vault"));
    }
    Ok(email.to_ascii_lowercase())
}

/// Decode an `application/x-www-form-urlencoded` body or query string.
pub fn form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((unescape(k)?, unescape(v)?))
        })
        .collect()
}

fn unescape(s: &str) -> Option<String> {
    cce_sync::proto::decode_path(&s.replace('+', " "))
}

/// Encode for a query string or form.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `base?k=v&…`, or `&…` when `base` already has a query.
pub fn with_query(base: &str, params: &[(&str, &str)]) -> String {
    let q: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", escape(k), escape(v))).collect();
    format!("{base}{}{}", if base.contains('?') { "&" } else { "?" }, q.join("&"))
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// The host a redirect URI sends the code to, as the consent page shows it.
pub fn redirect_host(uri: &str) -> String {
    split_url(uri).map_or_else(|| uri.to_string(), |(_, h, p, _)| p.map_or(h.clone(), |p| format!("{h}:{p}")))
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
<title>{t}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#222;background:#fafafa}}\
@media(prefers-color-scheme:dark){{body{{color:#eee;background:#161616}}}}h1{{font-size:1.3rem}}.warn{{color:#b45309}}\
button{{font:inherit;padding:.6rem 1.2rem;border-radius:.5rem;border:1px solid #888;background:#2563eb;color:#fff;cursor:pointer}}\
code{{font-size:.9em}}</style><h1>{t}</h1>{body}</html>",
        t = html_escape(title)
    )
}

/// The consent page: who is asking, where the code goes, what it grants.
pub fn consent_page(client_name: &str, redirect_uri: &str, request_id: &str) -> String {
    let host = redirect_host(redirect_uri);
    let loopback = split_url(redirect_uri).is_some_and(|(_, h, _, _)| is_loopback(&h));
    let warn = if loopback {
        "<p class=warn>This sends the sign-in to a program on this computer (a loopback address). \
Continue only if you just started connecting Claude Code or another local client yourself.</p>"
    } else {
        ""
    };
    page(
        "Connect to your vault",
        &format!(
            "<p><strong>{name}</strong> is asking for full read and write access to your notes.</p>\
<p>The sign-in goes back to <code>{host}</code>.</p>{warn}\
<p>Every change it makes is kept in the vault's history and can be undone.</p>\
<form method=post action=\"/oauth/authorize\"><input type=hidden name=request value=\"{id}\">\
<button type=submit>Continue with Google</button></form>",
            name = html_escape(client_name),
            host = html_escape(&host),
            id = html_escape(request_id),
        ),
    )
}

pub fn error_page(message: &str) -> String {
    page("Can't connect", &format!("<p>{}</p>", html_escape(message)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects() {
        assert!(redirect_allowed("https://claude.ai/api/mcp/auth_callback"));
        assert!(redirect_allowed("https://claude.com/api/mcp/auth_callback"));
        assert!(redirect_allowed("http://localhost:3118/callback"));
        assert!(redirect_allowed("http://127.0.0.1/callback"));
        assert!(!redirect_allowed("https://claude.ai/api/mcp/other"));
        assert!(!redirect_allowed("https://evil.example/api/mcp/auth_callback"));
        assert!(!redirect_allowed("https://localhost/callback"), "loopback is http only");
        assert!(!redirect_allowed("http://localhost.evil.example/callback"));
        assert!(!redirect_allowed("http://user@localhost/callback"));
        let reg = vec!["http://localhost/callback".to_string(), "https://claude.ai/api/mcp/auth_callback".to_string()];
        assert!(redirect_matches(&reg, "http://localhost:51234/callback"), "port-agnostic loopback");
        assert!(!redirect_matches(&reg, "http://127.0.0.1:51234/callback"), "host must match");
        assert!(!redirect_matches(&reg, "http://localhost:51234/other"));
        assert!(redirect_matches(&reg, "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_matches(&reg, "https://claude.ai:443/api/mcp/auth_callback"));
    }

    #[test]
    fn clients() {
        let c = register(br#"{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}"#, "id1".into()).unwrap();
        assert_eq!(c.name, "Claude");
        assert!(register(br#"{"redirect_uris":["https://evil.example/cb"]}"#, "x".into()).is_err());
        assert!(register(br#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"client_secret_basic"}"#, "x".into()).is_err());
        assert!(register(br#"{}"#, "x".into()).is_err());
        let url = "https://claude.ai/oauth/claude-code-client-metadata";
        assert!(cimd_url_allowed(url));
        assert!(!cimd_url_allowed("https://evil.example/meta.json"));
        assert!(!cimd_url_allowed("http://claude.ai/meta"));
        assert!(!cimd_url_allowed("https://claude.ai/"));
        let doc = format!(r#"{{"client_id":"{url}","client_name":"Claude Code","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"]}}"#);
        let c = cimd_client(url, doc.as_bytes()).unwrap();
        assert_eq!(c.redirect_uris.len(), 2);
        assert!(cimd_client("https://claude.ai/other", doc.as_bytes()).is_err(), "client_id must equal the URL");
    }

    #[test]
    fn the_phone_app() {
        let o = "https://v.example";
        let app = first_party(o);
        assert!(redirect_ok(&app, "https://v.example/"));
        assert!(!redirect_ok(&app, "https://evil.example/"));
        assert!(!redirect_ok(&app, "https://claude.ai/api/mcp/auth_callback"), "only back to its own page");
        assert_eq!(resource_for(o, "https://v.example/v1", FIRST_PARTY).unwrap(), "https://v.example/v1");
        assert!(resource_for(o, "https://v.example/v1", "c_claude").is_err(), "Claude gets /mcp only");
        assert_eq!(resource_for(o, "", "c_claude").unwrap(), "https://v.example/mcp");
        assert!(resource_for(o, "https://other.example/mcp", FIRST_PARTY).is_err());
        let claude = Client { client_id: "c1".into(), name: "Claude".into(), redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".into()] };
        assert!(redirect_ok(&claude, "https://claude.ai/api/mcp/auth_callback"));
    }

    #[test]
    fn pkce() {
        // RFC 7636 appendix B.
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(s256(v), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(pkce_ok(v, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_ok(v, "wrong"));
        assert!(!pkce_ok("short", &s256("short")));
    }

    fn id_token(claims: Value) -> String {
        format!("e30.{}.sig", b64url(claims.to_string().as_bytes()))
    }

    #[test]
    fn google_id_tokens() {
        let good = json!({ "iss": "https://accounts.google.com", "aud": "cid", "exp": 2000, "nonce": "n1",
                           "email": "Me@Example.com", "email_verified": true });
        assert_eq!(check_id_token(&id_token(good.clone()), "cid", "n1", "me@example.com", 1000).unwrap(), "me@example.com");
        let with = |k: &str, v: Value| {
            let mut c = good.clone();
            c[k] = v;
            check_id_token(&id_token(c), "cid", "n1", "me@example.com", 1000)
        };
        assert!(with("iss", json!("https://evil.example")).is_err());
        assert!(with("aud", json!("other")).is_err());
        assert!(with("exp", json!(999)).is_err());
        assert!(with("nonce", json!("n2")).is_err());
        assert!(with("email", json!("someone@else.com")).unwrap_err().contains("may not use"));
        assert!(with("email_verified", json!(false)).is_err());
        assert!(check_id_token(&id_token(good), "cid", "n1", "", 1000).is_err(), "no allowed email: nobody");
        assert!(check_id_token("garbage", "cid", "n1", "me@example.com", 1000).is_err());
    }

    #[test]
    fn forms_and_queries() {
        let f = form("grant_type=authorization_code&code=a%2Bb&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcallback&x=a+b");
        assert_eq!(f["code"], "a+b");
        assert_eq!(f["redirect_uri"], "http://localhost:1/callback");
        assert_eq!(f["x"], "a b");
        assert_eq!(with_query("https://c/cb", &[("code", "a b"), ("state", "x&y")]), "https://c/cb?code=a%20b&state=x%26y");
        assert_eq!(with_query("https://c/cb?k=1", &[("code", "z")]), "https://c/cb?k=1&code=z");
    }

    #[test]
    fn pages_escape_what_they_show() {
        let p = consent_page("<script>", "http://localhost:4000/callback", "r\"1");
        assert!(p.contains("&lt;script&gt;") && !p.contains("<script>"));
        assert!(p.contains("localhost:4000") && p.contains("loopback"));
        assert!(!consent_page("Claude", "https://claude.ai/api/mcp/auth_callback", "r").contains("loopback"));
        assert!(authorization_server_metadata("https://v.example")["token_endpoint_auth_methods_supported"][0] == "none");
        assert_eq!(protected_resource_metadata("https://v.example")["resource"], "https://v.example/mcp");
    }
}
