#!/usr/bin/env bash
# The phone app's server side end to end (dev/e2e-phone.mjs): the site
# served from the Worker, the first-party sign-in, the sync API and the
# live socket with the phone's tokens. Start a FRESH local server with the
# .dev.vars of dev/e2e-mcp.sh (the mock Google) and a site/ to serve:
#
#   rm -rf .wrangler
#   ../cce-vault-web/web/build.sh "$PWD/site"     # or any site/ with an index.html
#   wrangler dev --port 8787
#   dev/e2e-phone.sh
#
# Never against the deployed server.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
node "$HERE/e2e-phone.mjs" "${1:-http://127.0.0.1:8787}"
