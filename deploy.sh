#!/bin/sh
# Build and deploy cce-sync to Cloudflare. Needs `npx wrangler login` once,
# and the token secret: `npx wrangler secret put SYNC_TOKEN` (a long random
# string; the same one goes in ~/.config/cce/cce-sync.token on the laptop).
set -eu
cd "$(dirname "$0")"
command -v worker-build >/dev/null || cargo install worker-build
npx --yes wrangler@4 deploy "$@"
