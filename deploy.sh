#!/bin/sh
# Build and deploy cce-sync to Cloudflare: the Worker, and the phone app
# (cce-vault-web's PWA, built by its web/build.sh from the sibling checkout)
# as its static assets. Needs `npx wrangler login` once, and the secrets
# CLAUDE.md lists (SYNC_TOKEN, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
# ALLOWED_EMAIL). Set NO_APP=1 to deploy the Worker with whatever site/
# already holds.
set -eu
cd "$(dirname "$0")"
# worker-build installs into cargo's bin dir, which a non-login shell may
# not have on PATH; wrangler's custom build runs it from PATH.
PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export PATH
command -v worker-build >/dev/null || cargo install worker-build
if [ -z "${NO_APP:-}" ]; then
    app=../cce-vault-web
    [ -x "$app/web/build.sh" ] || { echo "deploy.sh: no $app (clone cce-vault-web beside this crate, or NO_APP=1)" >&2; exit 2; }
    "$app/web/build.sh" "$PWD/site"
fi
mkdir -p site
npx --yes wrangler@4 deploy "$@"
