//! cce-sync-server: the vault's always-on home, a Cloudflare Worker.
//!
//! - The Worker ([`fetch`]) answers `/health` and hands everything else to
//!   the one vault Durable Object, which authenticates.
//! - [`object::VaultObject`] serves `/v1` over `cce_sync::core::Vault`,
//!   `/mcp` (Claude's connector, `cce_sync::mcp`) and the OAuth server.
//! - [`oauth`] is the OAuth server's rules, tested natively; `auth` its
//!   storage and endpoints.
//! - [`sql::SqlStore`] keeps the vault in the object's SQLite, blobs over
//!   1 MB in R2.
//! - [`route`] is the request side with no Workers types, tested natively.
//!
//! `/v1` takes the shared `SYNC_TOKEN` (the laptop daemon); `/mcp` takes an
//! OAuth access token issued here after a Google sign-in as the one allowed
//! account. See the design doc "cce-sync: design".

pub mod oauth;
pub mod route;

#[cfg(target_arch = "wasm32")]
mod auth;
#[cfg(target_arch = "wasm32")]
mod object;
#[cfg(target_arch = "wasm32")]
mod sql;

#[cfg(target_arch = "wasm32")]
pub use object::VaultObject;

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use worker::*;

    /// The vault's Durable Object name. One vault per deployment.
    const VAULT_NAME: &str = "vault";

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let path = req.path();
        if path == "/health" {
            return Response::ok("ok");
        }
        // Everything else is the object's: it holds the vault and the OAuth
        // tables, and authenticates each request against them.
        let stub = env.durable_object("VAULT")?.id_from_name(VAULT_NAME)?.get_stub()?;
        stub.fetch_with_request(req).await
    }
}
