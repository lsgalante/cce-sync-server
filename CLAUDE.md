# cce-sync-server

cce-sync on Cloudflare: a Worker in front of one SQLite-backed Durable
Object that holds the vault, with blobs over 1 MB in R2. All the rules
live in `cce-sync` (`core`); this crate is the host. The plan is the doc
"cce-sync: design" (phase 1).

Read `../cce-sync/CLAUDE.md` first: the write rules, the protocol and their
invariants are there.

## Layout

| File | What it owns |
| --- | --- |
| `lib.rs` | The Worker's `fetch`: `/health`, the bearer-token check, hands `/v1/*` to the `VAULT` object named `vault` |
| `route.rs` | Method + URL → `Route`, the token compare, the device name. No Workers types: tested natively |
| `object.rs` | `VaultObject`: serves each `Route` over `Vault<SqlStore>` behind an async lock; the live sockets (hibernatable) and the seq notice after each commit |
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
  is refused here. `Pre::Any` is for the server's own writers (phase 3's
  Claude tools), which run inside the object.
- **The Worker authenticates; the object trusts what reaches it.** Never
  expose the object another way.
- **Auth is one shared token (`SYNC_TOKEN`) until phase 3**, when the OAuth
  server replaces it. The live socket takes the token in the
  `Authorization` header, which browsers can't set on a WebSocket; the
  phone (phase 4) needs a ticket scheme first.

## Build, test, run

The root workspace **excludes** this crate (Cargo will not build a Worker
from inside the tree as a non-member), so build and test it from its own
directory, against its own `Cargo.lock` and its git pin of cce-sync:

```sh
cd cce-sync-server
cargo test                                                  # route.rs, natively
cargo build --target wasm32-unknown-unknown
dev/e2e.sh                                                  # wrangler dev + the CLI + curl, locally
```

To try an unpushed cce-sync change here, point the pin at the sibling for
the run (`cce-sync = { path = "../cce-sync", default-features = false }`)
and put the git pin back before committing; `../bump-revs.sh` repins after
cce-sync is pushed.

`dev/e2e.sh` runs the Worker under `wrangler dev` (local workerd, local
SQLite and R2 under `.wrangler/`), imports a sample vault with the
`cce-sync` CLI, and checks writes, conflicts, merges, the feed and the live
socket. It needs `worker-build` (`cargo install worker-build`) and Node, and
finds the `cce-sync` binary in the workspace's `target/` or a standalone
build (or `$CCE_SYNC_CLI`). It expects an **empty** vault: never point it at
the deployed server.

## Deploy

Live at `https://cce-sync.lsgalante12.workers.dev` (deployed from 688f887
on 2026-10-13; the user's vault was imported the same day). `vault.lucas.co`
waits on lucas.co's DNS moving to Cloudflare.

```sh
npx wrangler login                     # once
npx wrangler r2 bucket create cce-sync-blobs
npx wrangler secret put SYNC_TOKEN     # a long random string
./deploy.sh
```

Workers Paid ($5/month) is assumed: the Free plan's 10 ms CPU per request
is too little for a merge or a big batch.
