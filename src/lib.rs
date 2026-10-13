//! cce-sync-server: the vault's always-on home, a Cloudflare Worker.
//!
//! - The Worker ([`fetch`]) checks the bearer token and hands every `/v1`
//!   request to the one vault Durable Object.
//! - [`object::VaultObject`] serves the API over `cce_sync::core::Vault`.
//! - [`sql::SqlStore`] keeps the vault in the object's SQLite, blobs over
//!   1 MB in R2.
//! - [`route`] is the request side with no Workers types, tested natively.
//!
//! Auth is a single shared token (the `SYNC_TOKEN` secret) until phase 3
//! brings the OAuth server; see the design doc "cce-sync: design".

pub mod route;

#[cfg(target_arch = "wasm32")]
mod object;
#[cfg(target_arch = "wasm32")]
mod sql;

#[cfg(target_arch = "wasm32")]
pub use object::VaultObject;

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use crate::route::token_matches;
    use worker::*;

    /// The vault's Durable Object name. One vault per deployment.
    const VAULT_NAME: &str = "vault";

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let path = req.path();
        if path == "/health" {
            return Response::ok("ok");
        }
        if !path.starts_with("/v1/") {
            return Response::error("not found", 404);
        }
        let secret = env.secret("SYNC_TOKEN").map(|s| s.to_string()).unwrap_or_default();
        if !token_matches(req.headers().get("authorization")?.as_deref(), &secret) {
            return Response::error("unauthorized", 401);
        }
        let stub = env.durable_object("VAULT")?.id_from_name(VAULT_NAME)?.get_stub()?;
        stub.fetch_with_request(req).await
    }
}
