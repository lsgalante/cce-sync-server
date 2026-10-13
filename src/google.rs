//! The Google bridge's host (phase 6): the Google refresh token, the
//! day's agenda from Google Calendar, and Google Tasks for `#gtask` lines.
//! The rules are `cce_sync::agenda` and `cce_sync::gtask`; this is storage
//! and HTTP.
//!
//! - **The token** comes from the same Google sign-in that proves who the
//!   user is (`auth.rs` asks for Calendar (read-only) and Tasks too, with
//!   offline access). It is kept sealed (`crate::seal`, key
//!   `GOOGLE_TOKEN_KEY`) in `google_token`, and never leaves the server:
//!   no token received from a client is passed to Google, nor the reverse.
//!   Google refusing it (`invalid_grant`) disconnects the bridge until the
//!   next sign-in.
//! - **The agenda** of a day is cached for five minutes.
//! - **Tasks**: the bases (`gtask_base`) and the tasks created whose id has
//!   not reached their line yet (`gtask_pending`, by path and line text).

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use cce_sync::agenda::{self, Agenda};
use cce_sync::gtask::{self, Fields, Remote};
use cce_sync::mcp::AgendaSource;
use serde_json::{json, Value};
use worker::{
    console_error, Date, Env, Fetch, Headers, Method, Request, RequestInit, Result, SqlStorage, SqlStorageValue as V,
};

use crate::oauth;
use crate::sql::text;

pub const CALENDAR_SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";
pub const TASKS_SCOPE: &str = "https://www.googleapis.com/auth/tasks";
const API: &str = "https://www.googleapis.com";
const AGENDA_TTL_MS: i64 = 5 * 60_000;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS google_token (
        id INTEGER PRIMARY KEY CHECK (id = 1), sealed TEXT NOT NULL, scopes TEXT NOT NULL,
        origin TEXT NOT NULL, updated INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gtask_base (id TEXT PRIMARY KEY, fields TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gtask_pending (
        path TEXT NOT NULL, raw TEXT NOT NULL, id TEXT NOT NULL, created INTEGER NOT NULL,
        PRIMARY KEY (path, raw))",
];

type Res<T> = std::result::Result<T, String>;

fn now_ms() -> i64 {
    Date::now().as_millis() as i64
}

pub struct Google {
    sql: SqlStorage,
    env: Env,
    /// The access token and when it goes stale (ms).
    access: RefCell<Option<(String, i64)>>,
    agendas: RefCell<HashMap<String, (i64, Agenda)>>,
}

impl Google {
    pub fn open(sql: SqlStorage, env: Env) -> Result<Google> {
        for stmt in SCHEMA {
            sql.exec(stmt, None)?;
        }
        Ok(Google { sql, env, access: RefCell::new(None), agendas: RefCell::new(HashMap::new()) })
    }

    fn rows(&self, q: &str, bind: Vec<V>) -> Res<Vec<Vec<V>>> {
        self.sql.exec(q, bind).and_then(|c| c.raw().collect()).map_err(|e| e.to_string())
    }

    fn exec(&self, q: &str, bind: Vec<V>) -> Res<()> {
        self.sql.exec(q, bind).map(|_| ()).map_err(|e| e.to_string())
    }

    fn setting(&self, name: &str) -> String {
        self.env
            .var(name)
            .map(|v| v.to_string())
            .or_else(|_| self.env.secret(name).map(|s| s.to_string()))
            .unwrap_or_default()
    }

    fn api(&self) -> String {
        Some(self.setting("GOOGLE_API_URL")).filter(|s| !s.is_empty()).unwrap_or_else(|| API.into())
    }

    // ---- the token --------------------------------------------------------

    fn row(&self) -> Option<(String, String, String)> {
        let rows = self.rows("SELECT sealed, scopes, origin FROM google_token WHERE id = 1", vec![]).ok()?;
        let r = rows.first()?;
        Some((text(&r[0]).ok()?, text(&r[1]).ok()?, text(&r[2]).ok()?))
    }

    /// Whether a token is held with `scope`.
    pub fn has(&self, scope: &str) -> bool {
        self.row().is_some_and(|(_, scopes, _)| scopes.split_whitespace().any(|s| s == scope))
    }

    pub fn connected(&self) -> bool {
        self.row().is_some()
    }

    /// The server's address as the user signed in through it, for links in
    /// Google tasks back to the phone app.
    pub fn origin(&self) -> String {
        self.row().map(|(_, _, o)| o).unwrap_or_default()
    }

    /// Keep the refresh token a sign-in brought (sealed), with its scopes.
    pub fn save(&self, refresh: &str, scopes: &str, origin: &str) -> Res<()> {
        let key = crate::seal::key(&self.setting("GOOGLE_TOKEN_KEY"))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let sealed = crate::seal::seal(&key, nonce, refresh)?;
        self.exec(
            "INSERT INTO google_token (id, sealed, scopes, origin, updated) VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET sealed = excluded.sealed, scopes = excluded.scopes,
             origin = excluded.origin, updated = excluded.updated",
            vec![sealed.into(), scopes.into(), origin.into(), V::Integer(now_ms())],
        )?;
        *self.access.borrow_mut() = None;
        self.agendas.borrow_mut().clear();
        Ok(())
    }

    /// Forget the token (Google refused it).
    fn disconnect(&self) {
        let _ = self.exec("DELETE FROM google_token", vec![]);
        *self.access.borrow_mut() = None;
        self.agendas.borrow_mut().clear();
    }

    async fn access_token(&self) -> Res<String> {
        if let Some((t, exp)) = self.access.borrow().clone() {
            if now_ms() < exp {
                return Ok(t);
            }
        }
        let (sealed, _, _) = self.row().ok_or("Google is not connected")?;
        let key = crate::seal::key(&self.setting("GOOGLE_TOKEN_KEY"))?;
        let refresh = crate::seal::open(&key, &sealed)?;
        let token_url = Some(self.setting("GOOGLE_TOKEN_URL")).filter(|s| !s.is_empty()).unwrap_or_else(|| oauth::GOOGLE_TOKEN_URL.into());
        let body = format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
            oauth::escape(&refresh),
            oauth::escape(&self.setting("GOOGLE_CLIENT_ID")),
            oauth::escape(&self.setting("GOOGLE_CLIENT_SECRET")),
        );
        let (status, v) = send(Method::Post, &token_url, None, Some(Body::Form(body))).await?;
        if v.get("error").and_then(Value::as_str) == Some("invalid_grant") {
            console_error!("google: the refresh token was refused; the bridge is off until the next sign-in");
            self.disconnect();
            return Err("Google refused the stored sign-in; sign in again".into());
        }
        let token = v.get("access_token").and_then(Value::as_str).ok_or_else(|| format!("Google token refresh: {status} {v}"))?;
        let ttl = v.get("expires_in").and_then(Value::as_i64).unwrap_or(3600);
        *self.access.borrow_mut() = Some((token.to_string(), now_ms() + (ttl - 60).max(0) * 1000));
        Ok(token.to_string())
    }

    /// A Google API call. `401` once drops the cached access token and
    /// tries again.
    async fn call(&self, method: Method, url: &str, body: Option<Value>) -> Res<(u16, Value)> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            let (status, v) = send(method.clone(), url, Some(&token), body.clone().map(Body::Json)).await?;
            if status == 401 && attempt == 0 {
                *self.access.borrow_mut() = None;
                continue;
            }
            return Ok((status, v));
        }
        unreachable!()
    }

    // ---- the agenda -------------------------------------------------------

    /// The local day's events, from the cache when it is under five minutes
    /// old. Not connected, or Google failing: an agenda saying so.
    pub async fn agenda(&self, date: &str) -> Agenda {
        if !self.has(CALENDAR_SCOPE) {
            return Agenda { date: date.into(), ..Agenda::default() };
        }
        if let Some((at, a)) = self.agendas.borrow().get(date) {
            if now_ms() - at < AGENDA_TTL_MS {
                return a.clone();
            }
        }
        match self.fetch_agenda(date).await {
            Ok(a) => {
                let mut cache = self.agendas.borrow_mut();
                cache.retain(|_, (at, _)| now_ms() - *at < AGENDA_TTL_MS);
                cache.insert(date.into(), (now_ms(), a.clone()));
                a
            }
            Err(e) => {
                console_error!("agenda {date}: {e}");
                Agenda { date: date.into(), ..Agenda::default() }
            }
        }
    }

    async fn fetch_agenda(&self, date: &str) -> Res<Agenda> {
        let cal = format!("{}/calendar/v3", self.api());
        let (status, list) = self.call(Method::Get, &format!("{cal}/users/me/calendarList?minAccessRole=reader"), None).await?;
        if status != 200 {
            return Err(format!("calendarList: {status} {list}"));
        }
        let items = list.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let b = |v: &Value, k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let tz = items.iter().find(|c| b(c, "primary")).map(|c| s(c, "timeZone")).unwrap_or_default();
        let (min, max) = agenda::window(date).ok_or("bad date")?;
        let mut a = Agenda { date: date.into(), connected: true, time_zone: tz.clone(), events: Vec::new() };
        for c in items.iter().filter(|c| (b(c, "selected") || b(c, "primary")) && !b(c, "hidden")) {
            let id = s(c, "id");
            let name = if b(c, "primary") { String::new() } else { Some(s(c, "summaryOverride")).filter(|n| !n.is_empty()).unwrap_or_else(|| s(c, "summary")) };
            let mut url = format!(
                "{cal}/calendars/{}/events?singleEvents=true&orderBy=startTime&maxResults=250&timeMin={}&timeMax={}",
                oauth::escape(&id),
                oauth::escape(&min),
                oauth::escape(&max)
            );
            if !tz.is_empty() {
                url.push_str(&format!("&timeZone={}", oauth::escape(&tz)));
            }
            let (status, ev) = self.call(Method::Get, &url, None).await?;
            if status != 200 {
                console_error!("events of {id}: {status}");
                continue;
            }
            let items = ev.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
            a.events.extend(agenda::events_on(date, &id, &name, &items));
        }
        a.sort();
        Ok(a)
    }

    // ---- tasks ------------------------------------------------------------

    fn tasks_url(&self) -> String {
        format!("{}/tasks/v1/lists/@default/tasks", self.api())
    }

    /// Every task in the default list, deleted and completed ones too.
    pub async fn tasks(&self) -> Res<BTreeMap<String, Remote>> {
        let mut out = BTreeMap::new();
        let mut page: Option<String> = None;
        loop {
            let mut url = format!("{}?showCompleted=true&showHidden=true&showDeleted=true&maxResults=100", self.tasks_url());
            if let Some(p) = &page {
                url.push_str(&format!("&pageToken={}", oauth::escape(p)));
            }
            let (status, v) = self.call(Method::Get, &url, None).await?;
            if status != 200 {
                return Err(format!("tasks: {status} {v}"));
            }
            for t in v.get("items").and_then(Value::as_array).into_iter().flatten() {
                if let Some((id, r)) = gtask::remote_from_json(t) {
                    out.insert(id, r);
                }
            }
            page = v.get("nextPageToken").and_then(Value::as_str).map(str::to_string);
            if page.is_none() {
                return Ok(out);
            }
        }
    }

    pub async fn create(&self, fields: &Fields, notes: &str) -> Res<String> {
        let (status, v) = self.call(Method::Post, &self.tasks_url(), Some(gtask::google_body(fields, Some(notes)))).await?;
        match v.get("id").and_then(Value::as_str) {
            Some(id) if status == 200 => Ok(id.to_string()),
            _ => Err(format!("creating a task: {status} {v}")),
        }
    }

    /// Set a task's fields. Gone meanwhile is not an error: the next pass
    /// sees it deleted.
    pub async fn patch(&self, id: &str, fields: &Fields) -> Res<()> {
        let url = format!("{}/{}", self.tasks_url(), oauth::escape(id));
        let (status, v) = self.call(Method::Patch, &url, Some(gtask::google_body(fields, None))).await?;
        match status {
            200 | 404 => Ok(()),
            _ => Err(format!("updating task {id}: {status} {v}")),
        }
    }

    pub async fn delete(&self, id: &str) -> Res<()> {
        let url = format!("{}/{}", self.tasks_url(), oauth::escape(id));
        let (status, v) = self.call(Method::Delete, &url, None).await?;
        match status {
            200 | 204 | 404 | 410 => Ok(()),
            _ => Err(format!("deleting task {id}: {status} {v}")),
        }
    }

    pub fn bases(&self) -> BTreeMap<String, Fields> {
        self.rows("SELECT id, fields FROM gtask_base", vec![])
            .unwrap_or_default()
            .iter()
            .filter_map(|r| Some((text(&r[0]).ok()?, serde_json::from_str(&text(&r[1]).ok()?).ok()?)))
            .collect()
    }

    pub fn set_base(&self, id: &str, fields: &Fields) {
        let json = serde_json::to_string(fields).unwrap_or_default();
        let _ = self.exec(
            "INSERT INTO gtask_base (id, fields) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET fields = excluded.fields",
            vec![id.into(), json.into()],
        );
    }

    pub fn forget(&self, id: &str) {
        let _ = self.exec("DELETE FROM gtask_base WHERE id = ?", vec![id.into()]);
    }

    pub fn pending(&self) -> BTreeMap<(String, String), String> {
        // A week is long enough for a note that was busy to settle.
        let _ = self.exec("DELETE FROM gtask_pending WHERE created < ?", vec![V::Integer(now_ms() - 7 * 86_400_000)]);
        self.rows("SELECT path, raw, id FROM gtask_pending", vec![])
            .unwrap_or_default()
            .iter()
            .filter_map(|r| Some(((text(&r[0]).ok()?, text(&r[1]).ok()?), text(&r[2]).ok()?)))
            .collect()
    }

    pub fn add_pending(&self, path: &str, raw: &str, id: &str) {
        let _ = self.exec(
            "INSERT OR REPLACE INTO gtask_pending (path, raw, id, created) VALUES (?, ?, ?, ?)",
            vec![path.into(), raw.into(), id.into(), V::Integer(now_ms())],
        );
    }

    pub fn drop_pending(&self, path: &str, raw: &str) {
        let _ = self.exec("DELETE FROM gtask_pending WHERE path = ? AND raw = ?", vec![path.into(), raw.into()]);
    }
}

/// The agenda for Claude's `daily_note`.
pub struct AgendaFrom<'a>(pub &'a Google);

impl AgendaSource for AgendaFrom<'_> {
    async fn agenda(&self, date: &str) -> Option<Agenda> {
        Some(self.0.agenda(date).await)
    }
}

enum Body {
    Json(Value),
    Form(String),
}

/// One HTTP call: the status and the JSON answer (`null` when empty).
async fn send(method: Method, url: &str, bearer: Option<&str>, body: Option<Body>) -> Res<(u16, Value)> {
    let headers = Headers::new();
    if let Some(t) = bearer {
        headers.set("authorization", &format!("Bearer {t}")).map_err(|e| e.to_string())?;
    }
    let mut init = RequestInit::new();
    init.with_method(method);
    match body {
        Some(Body::Json(v)) => {
            headers.set("content-type", "application/json").map_err(|e| e.to_string())?;
            init.with_body(Some(v.to_string().into()));
        }
        Some(Body::Form(f)) => {
            headers.set("content-type", "application/x-www-form-urlencoded").map_err(|e| e.to_string())?;
            init.with_body(Some(f.into()));
        }
        None => {}
    }
    init.with_headers(headers);
    let req = Request::new_with_init(url, &init).map_err(|e| e.to_string())?;
    let mut resp = Fetch::Request(req).send().await.map_err(|e| e.to_string())?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    let v = if text.trim().is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or_else(|_| json!({ "text": text })) };
    Ok((status, v))
}
