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
#   wrangler dev --port 8787 --local-upstream 127.0.0.1:8787
#   dev/e2e-mcp.sh
#
# Never against the deployed server.
set -euo pipefail
SERVER=${1:-http://127.0.0.1:8787}
TOKEN=${2:-dev-token-123}
HERE=$(cd "$(dirname "$0")" && pwd)

node "$HERE/e2e-mcp.mjs" "$SERVER" "$TOKEN"

# The CLI's debug build, wherever cargo puts cce-sync's target: the cce
# workspace's target/ (cce-sync is a member there), its own in a standalone
# clone, or $CARGO_TARGET_DIR.
if [ -z "${CCE_SYNC_CLI:-}" ]; then
    target=$(cargo metadata --no-deps --format-version 1 \
        --manifest-path "$HERE/../../cce-sync/Cargo.toml" | jq -r .target_directory)
    CCE_SYNC_CLI=$target/debug/cce-sync
fi
CLI=$CCE_SYNC_CLI
[ -x "$CLI" ] || { echo "no cce-sync CLI at $CLI: cargo build -p cce-sync, or set CCE_SYNC_CLI" >&2; exit 1; }

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
if grep -q 'Shop, Inc' "$WORK/vault/Finance/Ledger.csv" && [ "$(head -c 2 "$WORK/vault/Finance/Budget.xlsx")" = PK ]; then
    echo "  ok    and Claude's table and workbook"
else
    echo "  FAIL  Claude's table or workbook is not in the folder"; find "$WORK/vault" -type f; exit 1
fi
