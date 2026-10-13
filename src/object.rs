//! The vault Durable Object: one per vault, the one writer. It serves the
//! `/v1` API ([`crate::route`]) over [`cce_sync::core::Vault`] on
//! [`SqlStore`], and tells every live socket the new seq after each commit.
//!
//! Requests interleave at awaits (an R2 read, a blob write), so the vault
//! sits behind an async lock: one batch at a time, and no read between a
//! batch's staging and its commit.

use async_lock::Mutex;
use cce_sync::core::{ApplyError, Operation, Vault};
use cce_sync::proto::{
    pre_from_headers, BatchRequest, LiveNotice, Pre, Refusal, Status, H_DEVICE, H_HASH, H_REV,
};
use worker::*;

use crate::route::{device, route, Route};
use crate::sql::SqlStore;

#[durable_object]
pub struct VaultObject {
    state: State,
    vault: Mutex<Vault<SqlStore>>,
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
        let store = SqlStore::open(state.storage().sql(), env).expect("vault schema");
        VaultObject { state, vault: Mutex::new(Vault::new(store)) }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
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
                use cce_sync::core::Store;
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
        let seq = self.vault.try_lock().and_then(|v| cce_sync::core::Store::seq(&v.store).ok());
        if let Some(seq) = seq {
            pair.server.send_with_str(serde_json::to_string(&LiveNotice { seq })?)?;
        }
        Response::from_websocket(pair.client)
    }
}
