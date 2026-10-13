//! The request side with no Workers types, so it is tested natively: which
//! endpoint a method and URL name, and the bearer-token check.

use cce_sync::proto::{check_path, decode_path, is_hash, Seq};

/// The changes page size when the client names none, and the most it may.
pub const DEFAULT_LIMIT: usize = 1000;
pub const MAX_LIMIT: usize = 5000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Changes { since: Seq, limit: usize },
    Listing,
    Get(String),
    Put(String),
    Delete(String),
    Batch,
    History(String),
    Blob(String),
    Live,
    /// A single-use ticket for the live socket (browsers).
    LiveTicket,
    Status,
    /// The OAuth grants (what Claude has been allowed), and revoking one.
    Grants,
    RevokeGrant(String),
    /// The local day's events from Google Calendar (`?date=YYYY-MM-DD`);
    /// `None` when the date is missing or malformed.
    Agenda(Option<String>),
    /// A file path that is not a valid vault path.
    BadPath(String),
    NotFound,
    MethodNotAllowed,
}

/// Route a request under `/v1/`. `path` is the URL path as received
/// (percent-encoded); `query` the part after `?`, without it.
pub fn route(method: &str, path: &str, query: &str) -> Route {
    let Some(rest) = path.strip_prefix("/v1/") else { return Route::NotFound };
    let (head, tail) = match rest.split_once('/') {
        Some((h, t)) => (h, Some(t)),
        None => (rest, None),
    };
    let file = |t: &str| match decode_path(t) {
        Some(p) if check_path(&p).is_ok() => Ok(p),
        Some(p) => Err(Route::BadPath(p)),
        None => Err(Route::BadPath(t.to_string())),
    };
    match (method, head, tail) {
        ("GET", "changes", None) => {
            let mut since = 0;
            let mut limit = DEFAULT_LIMIT;
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("since", v)) => since = v.parse().unwrap_or(0),
                    Some(("limit", v)) => limit = v.parse().unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
                    _ => {}
                }
            }
            Route::Changes { since, limit }
        }
        ("GET", "files", None) => Route::Listing,
        (m, "files", Some(t)) if !t.is_empty() => match file(t) {
            Ok(p) => match m {
                "GET" => Route::Get(p),
                "PUT" => Route::Put(p),
                "DELETE" => Route::Delete(p),
                _ => Route::MethodNotAllowed,
            },
            Err(r) => r,
        },
        ("POST", "batch", None) => Route::Batch,
        ("GET", "history", Some(t)) if !t.is_empty() => match file(t) {
            Ok(p) => Route::History(p),
            Err(r) => r,
        },
        ("GET", "blobs", Some(h)) if is_hash(h) => Route::Blob(h.to_string()),
        ("GET", "live", None) => Route::Live,
        ("POST", "live-ticket", None) => Route::LiveTicket,
        ("GET", "status", None) => Route::Status,
        ("GET", "agenda", None) => Route::Agenda(
            query
                .split('&')
                .find_map(|p| p.strip_prefix("date="))
                .filter(|d| cce_sync::agenda::parse_date_ok(d))
                .map(str::to_string),
        ),
        ("GET", "grants", None) => Route::Grants,
        ("DELETE", "grants", Some(id)) if !id.is_empty() && !id.contains('/') => Route::RevokeGrant(id.to_string()),
        (_, "changes" | "files" | "batch" | "history" | "blobs" | "live" | "live-ticket" | "status" | "grants" | "agenda", _) => Route::MethodNotAllowed,
        _ => Route::NotFound,
    }
}

/// Whether `Authorization: Bearer <token>` carries `secret`. Compared in
/// constant time; an empty secret matches nothing.
pub fn token_matches(authorization: Option<&str>, secret: &str) -> bool {
    let Some(token) = authorization.and_then(|a| a.strip_prefix("Bearer ")) else { return false };
    if secret.is_empty() || token.len() != secret.len() {
        return false;
    }
    token.bytes().zip(secret.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The device name a request claims, cleaned for the change feed: at most
/// 32 characters of `[A-Za-z0-9._-]`, else `unknown`.
pub fn device(header: Option<&str>) -> String {
    match header.map(str::trim) {
        Some(d)
            if !d.is_empty()
                && d.len() <= 32
                && d.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
        {
            d.to_string()
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(route("GET", "/v1/changes", "since=12&limit=50"), Route::Changes { since: 12, limit: 50 });
        assert_eq!(route("GET", "/v1/changes", ""), Route::Changes { since: 0, limit: DEFAULT_LIMIT });
        assert_eq!(route("GET", "/v1/changes", "limit=999999"), Route::Changes { since: 0, limit: MAX_LIMIT });
        assert_eq!(route("GET", "/v1/files", ""), Route::Listing);
        assert_eq!(route("GET", "/v1/files/Tasks/To%20Do.md", ""), Route::Get("Tasks/To Do.md".into()));
        assert_eq!(route("PUT", "/v1/files/.cce/vault.kdl", ""), Route::Put(".cce/vault.kdl".into()));
        assert_eq!(route("DELETE", "/v1/files/a.md", ""), Route::Delete("a.md".into()));
        assert_eq!(route("POST", "/v1/batch", ""), Route::Batch);
        assert_eq!(route("GET", "/v1/history/a.md", ""), Route::History("a.md".into()));
        let h = cce_sync::proto::hash(b"x");
        assert_eq!(route("GET", &format!("/v1/blobs/{h}"), ""), Route::Blob(h));
        assert_eq!(route("GET", "/v1/live", ""), Route::Live);
        assert_eq!(route("GET", "/v1/live", "ticket=abc"), Route::Live);
        assert_eq!(route("POST", "/v1/live-ticket", ""), Route::LiveTicket);
        assert_eq!(route("GET", "/v1/status", ""), Route::Status);
        assert_eq!(route("GET", "/v1/agenda", "date=2026-10-13"), Route::Agenda(Some("2026-10-13".into())));
        assert_eq!(route("GET", "/v1/agenda", "date=13.10.2026"), Route::Agenda(None));
        assert_eq!(route("POST", "/v1/agenda", ""), Route::MethodNotAllowed);
        assert_eq!(route("GET", "/v1/grants", ""), Route::Grants);
        assert_eq!(route("DELETE", "/v1/grants/g_abc", ""), Route::RevokeGrant("g_abc".into()));
    }

    #[test]
    fn refusals() {
        assert_eq!(route("GET", "/v1/files/.obsidian/app.json", ""), Route::BadPath(".obsidian/app.json".into()));
        assert_eq!(route("GET", "/v1/files/a/%2E%2E/b.md", ""), Route::BadPath("a/../b.md".into()));
        assert_eq!(route("GET", "/v1/files/%zz", ""), Route::BadPath("%zz".into()));
        assert_eq!(route("POST", "/v1/files/a.md", ""), Route::MethodNotAllowed);
        assert_eq!(route("PUT", "/v1/changes", ""), Route::MethodNotAllowed);
        assert_eq!(route("GET", "/v1/blobs/not-a-hash", ""), Route::MethodNotAllowed);
        assert_eq!(route("GET", "/v2/files", ""), Route::NotFound);
        assert_eq!(route("GET", "/v1/nope", ""), Route::NotFound);
    }

    #[test]
    fn tokens() {
        assert!(token_matches(Some("Bearer s3cret"), "s3cret"));
        assert!(!token_matches(Some("Bearer s3cres"), "s3cret"));
        assert!(!token_matches(Some("s3cret"), "s3cret"));
        assert!(!token_matches(None, "s3cret"));
        assert!(!token_matches(Some("Bearer "), ""));
    }

    #[test]
    fn devices() {
        assert_eq!(device(Some("laptop")), "laptop");
        assert_eq!(device(Some("claude.ios")), "claude.ios");
        assert_eq!(device(Some("bad name")), "unknown");
        assert_eq!(device(None), "unknown");
    }
}
