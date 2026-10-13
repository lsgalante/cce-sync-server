#!/usr/bin/env bash
# Claude's connector end to end: the OAuth flow and the MCP tools
# (dev/e2e-mcp.mjs, which also serves a mock Google on :8790), then the
# laptop side picking up what Claude wrote.
#
# Start a FRESH local server whose Google endpoints are the mock's:
#   rm -rf .wrangler
#   cat > .dev.vars <<V
#   SYNC_TOKEN=dev-token-123
#   GOOGLE_CLIENT_ID=test-client
#   GOOGLE_CLIENT_SECRET=test-secret
#   ALLOWED_EMAIL=me@example.com
#   GOOGLE_AUTH_URL=http://127.0.0.1:8790/auth
#   GOOGLE_TOKEN_URL=http://127.0.0.1:8790/token
#   V
#   wrangler dev --port 8787
#   dev/e2e-mcp.sh
#
# Never against the deployed server.
set -euo pipefail
SERVER=${1:-http://127.0.0.1:8787}
TOKEN=${2:-dev-token-123}
HERE=$(cd "$(dirname "$0")" && pwd)

node "$HERE/e2e-mcp.mjs" "$SERVER" "$TOKEN"

# The cce-sync binary: $CCE_SYNC_CLI, else the workspace's shared target,
# else a standalone build.
CLI=${CCE_SYNC_CLI:-}
if [ -z "$CLI" ]; then
    for c in "$HERE/../../target/debug/cce-sync" "$HERE/../../cce-sync/target/debug/cce-sync"; do
        [ -x "$c" ] && { CLI=$c; break; }
    done
fi
[ -x "${CLI:-}" ] || { echo "no cce-sync binary: build it (cargo build -p cce-sync) or set CCE_SYNC_CLI" >&2; exit 1; }

echo "== the laptop gets what Claude wrote"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/vault" "$WORK/run"
XDG_STATE_HOME=$WORK/state XDG_RUNTIME_DIR=$WORK/run XDG_CONFIG_HOME=$WORK/cfg \
    CCE_SYNC_SERVER=$SERVER CCE_SYNC_TOKEN=$TOKEN "$CLI" --vault "$WORK/vault" sync | head -1
if grep -q 'edited line' "$WORK/vault/Archive/From Claude.md" && grep -q 'talked to Claude' "$WORK/vault/2026-10-13.md"; then
    echo "  ok    Claude's notes are in the folder"
else
    echo "  FAIL  Claude's notes are not in the folder"; find "$WORK/vault" -type f; exit 1
fi
