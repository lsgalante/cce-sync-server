#!/usr/bin/env bash
# The Google bridge end to end (dev/e2e-google.mjs, which serves a mock
# Google on :8790: sign-in, Calendar, Tasks). Start a FRESH local server
# with the .dev.vars of dev/e2e-mcp.sh plus the bridge's two:
#
#   rm -rf .wrangler
#   cat >> .dev.vars <<V
#   GOOGLE_API_URL=http://127.0.0.1:8790
#   GOOGLE_TOKEN_KEY=$(openssl rand -base64 32)
#   V
#   wrangler dev --port 8787
#   dev/e2e-google.sh
#
# It takes about two minutes: the bridge runs 10 s after a commit. Never
# against the deployed server.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
node "$HERE/e2e-google.mjs" "${1:-http://127.0.0.1:8787}" "${2:-dev-token-123}"
