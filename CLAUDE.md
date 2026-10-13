# cce-sync-server

cce-sync on Cloudflare: a Worker in front of one SQLite-backed Durable
Object that holds the vault, with blobs over 1 MB in R2, the MCP server
Claude's connector calls, and the OAuth server that signs Claude in. The
sync and tool rules live in `cce-sync` (`core`, `mcp`); this crate is the
host. The plan is the doc "cce-sync: design" (phases 1 and 3).

Read `../cce-sync/CLAUDE.md` first: the write rules, the protocol and their
invariants are there.

## Layout

| File | What it owns |
| --- | --- |
| `lib.rs` | The Worker's `fetch`: `/health`, everything else to the `VAULT` object named `vault` |
| `route.rs` | `/v1`: method + URL → `Route`, the token compare, the device name. No Workers types: tested natively |
| `object.rs` | `VaultObject`: authenticates and serves `/v1` over `Vault<SqlStore>`, `/mcp` over `cce_sync::mcp::Mcp`, `/oauth/*` and the `/.well-known` documents; the live sockets (hibernatable) and the seq notice after each commit, Claude's included |
| `oauth.rs` | The OAuth server's rules: metadata, the 401 challenge, allowed redirects and clients (DCR, CIMD), PKCE, Google's ID token, the consent page. No Workers types: tested natively |
| `auth.rs` | The OAuth server's storage (`oauth_*` tables) and endpoints: register, authorize (consent), Google sign-in, token (codes, rotating refresh tokens), access checks, grants |
| `sql.rs` | `SqlStore`: the schema, `Store` over `ctx.storage.sql` and R2 |
| `wrangler.toml` | The bindings: `VAULT` (Durable Object, SQLite migration `v1`), `BLOBS` (R2 bucket `cce-sync-blobs`); the `vault.lucas.co` route, commented out until lucas.co's DNS is on Cloudflare |

## Invariants

- **`SqlStore::commit` must not await.** A Durable Object commits the writes
  of one synchronous run together; an await inside would split a batch.
- **The vault is behind an async lock.** Requests interleave at awaits (R2
  reads, blob writes); without the lock two batches could stage against
  the same state.
- **Blobs up to `INLINE_MAX` (1 MB) stay in SQLite**, bigger ones go to R2
  under `blobs/<sha256>`. A SQLite row holds at most 2 MB.
- **Every write from a device needs a precondition**; `Pre::Any` in a batch
  is refused here. `Pre::Any` is for the server's own writers (Claude's
  tools), which run inside the object under the vault lock.
- **The object authenticates every request**, since it holds the OAuth
  tables: `/v1` takes the shared `SYNC_TOKEN` (the laptop daemon); `/mcp`
  takes an OAuth access token whose grant is live and bound to
  `<origin>/mcp`, or the shared token (Claude Code by header). Never expose
  the object another way.
- **`/mcp` answers a bad token with `401` and `WWW-Authenticate: Bearer
  resource_metadata="…"`.** Claude needs exactly that to start sign-in;
  a `200` with the header is ignored.
- **One user.** Redirects are allowed only to Claude's callback
  (`https://claude.ai/api/mcp/auth_callback`, and the claude.com one) and
  to loopback `/callback` on any port (Claude Code); Client ID Metadata
  Documents are fetched only from claude.ai, claude.com and anthropic.com
  (advertising them means Claude will not fall back to DCR); and only a
  Google sign-in as `ALLOWED_EMAIL` gets a code. An unset `ALLOWED_EMAIL`
  lets nobody in.
- **Tokens and codes are stored as SHA-256 digests only.** Codes are single
  use (a reused code revokes what it bought); refresh tokens rotate (a
  reused one revokes the grant); errors are `invalid_grant`, as Claude
  expects. The consent page shows the redirect's host and warns on
  loopback.
- **Google's ID token is not signature-checked**: it comes straight from
  Google's token endpoint over TLS (OIDC Core 3.1.3.7); issuer, audience,
  expiry, nonce, verified email are.
- The live socket takes the shared token in the `Authorization` header,
  which browsers can't set on a WebSocket; the phone (phase 4) needs a
  ticket scheme first.

## Build, test, run

The root workspace **excludes** this crate (Cargo will not build a Worker
from inside the tree as a non-member), so build and test it from its own
directory, against its own `Cargo.lock` and its git pin of cce-sync:

```sh
cd cce-sync-server
cargo test                                                  # route.rs, oauth.rs, natively
cargo build --target wasm32-unknown-unknown
dev/e2e.sh                                                  # the /v1 API: wrangler dev + the CLI + curl
dev/e2e-mcp.sh                                              # Claude's connector: OAuth + MCP + the laptop
```

To try an unpushed cce-sync change here, point the pin at the sibling for
the run (`cce-sync = { path = "../cce-sync", default-features = false, features = ["mcp"] }`)
and put the git pin back before committing; `../bump-revs.sh` repins after
cce-sync is pushed.

`dev/e2e.sh` runs the Worker under `wrangler dev` (local workerd, local
SQLite and R2 under `.wrangler/`), imports a sample vault with the
`cce-sync` CLI, and checks writes, conflicts, merges, the feed and the live
socket. It needs `worker-build` (`cargo install worker-build`) and Node, and
finds the `cce-sync` binary in the workspace's `target/` or a standalone
build (or `$CCE_SYNC_CLI`). It expects an **empty** vault: never point it at
the deployed server.

`dev/e2e-mcp.sh` plays Claude against a fresh `wrangler dev` whose Google
endpoints point at a mock it serves on :8790 (the `.dev.vars` it needs are
in its header): the 401 challenge, discovery, registration (and a refused
foreign redirect), consent, Google, PKCE (and a wrong verifier), a reused
code, MCP calls, refresh rotation and reuse, grants and revocation, then a
laptop `cce-sync sync` that must bring Claude's notes into a folder.

## Settings

| Name | Kind | What |
| --- | --- | --- |
| `SYNC_TOKEN` | secret | The shared token: the laptop daemon on `/v1`, and Claude Code on `/mcp` by header |
| `GOOGLE_CLIENT_ID` | secret | A Google OAuth client of type **Web application** |
| `GOOGLE_CLIENT_SECRET` | secret | Its secret |
| `ALLOWED_EMAIL` | secret | The one Google account that may sign in (kept out of the public repo) |
| `GOOGLE_AUTH_URL`, `GOOGLE_TOKEN_URL` | `.dev.vars` only | The mock Google, for `dev/e2e-mcp.sh` |

## Deploy

Live at `https://cce-sync.lsgalante12.workers.dev` (phase 1 deployed from
688f887 on 2026-10-13; the user's vault was imported the same day).
`vault.lucas.co` waits on lucas.co's DNS moving to Cloudflare.

```sh
npx wrangler login                     # once
npx wrangler r2 bucket create cce-sync-blobs
npx wrangler secret put SYNC_TOKEN     # a long random string
./deploy.sh
```

Phase 3 adds Google sign-in, set up once:

1. Google Cloud console, the project of the existing "cce" OAuth app →
   APIs & Services → Credentials → Create credentials → OAuth client ID →
   **Web application**. Authorized redirect URI:
   `https://cce-sync.lsgalante12.workers.dev/oauth/google/callback` (add
   the `vault.lucas.co` one when that domain is live). The consent screen
   needs only `openid` and `email`.
2. `npx wrangler secret put GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
   `ALLOWED_EMAIL`; then `./deploy.sh`.
3. claude.ai → Settings → Connectors → Add custom connector → URL
   `https://cce-sync.lsgalante12.workers.dev/mcp`, no client ID. Connect,
   approve on the consent page, sign in with Google. It then works in the
   iOS app too. Claude Code: `claude mcp add --transport http vault
   https://cce-sync.lsgalante12.workers.dev/mcp` (OAuth in the browser).
4. `cce-sync grants` lists what is connected; `cce-sync revoke <id>` ends it.

Workers Paid ($5/month) is assumed: the Free plan's 10 ms CPU per request
is too little for a merge or a big batch.
