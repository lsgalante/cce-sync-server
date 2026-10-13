#!/usr/bin/env bash
# End-to-end check of cce-sync against a running server: the cce-sync CLI
# imports a generated sample vault, then curl and a WebSocket client drive
# writes, conflicts, merges, the feed, history, R2 blobs and the live socket.
#
#   (cd .. && wrangler dev --port 8787)      # with .dev.vars: SYNC_TOKEN=dev-token-123
#   dev/e2e.sh [http://127.0.0.1:8787] [token]
#
# Run it against a FRESH local server (rm -rf .wrangler first): it expects
# an empty vault. Never point it at the deployed one.
set -euo pipefail

SERVER=${1:-http://127.0.0.1:8787}
TOKEN=${2:-dev-token-123}
HERE=$(cd "$(dirname "$0")" && pwd)
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
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
AUTH=(-H "authorization: Bearer $TOKEN")
fails=0

ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
status_of() { curl -s -o "$WORK/body" -w '%{http_code}' "$@"; }
sha() { sha256sum | cut -d' ' -f1; }

echo "== auth"
check "no token is 401" "$(status_of "$SERVER/v1/files")" 401
check "wrong token is 401" "$(status_of -H 'authorization: Bearer nope' "$SERVER/v1/files")" 401
check "health needs none" "$(status_of "$SERVER/health")" 200

echo "== import a sample vault with the CLI"
V="$WORK/vault"
mkdir -p "$V/Tasks" "$V/.obsidian" "$V/.git" "$V/Daily"
printf -- '- [ ] Call the studio\n- [x] Book flights\n' > "$V/Tasks/To Do.md"
printf '# 2026-10-13\n\nMorning notes.\n' > "$V/Daily/2026-10-13.md"
printf '{"nodes":[],"edges":[]}' > "$V/Desktop.canvas"
printf '{"attachmentFolderPath":"Attachments"}' > "$V/.obsidian/app.json"
printf '{"folder":"Daily","format":"YYYY-MM-DD"}' > "$V/.obsidian/daily-notes.json"
printf 'ref: refs/heads/main\n' > "$V/.git/HEAD"
head -c 1500000 /dev/urandom > "$V/photo.jpg"   # over 1 MB: goes to R2
export CCE_SYNC_SERVER=$SERVER CCE_SYNC_TOKEN=$TOKEN
"$CLI" import "$V" --dry-run | tail -1
"$CLI" import "$V" | tail -1
again=$("$CLI" import "$V" | grep -o '^[0-9]* to upload ([0-9]* bytes), [0-9]* already there' || true)
check "a second import uploads nothing" "$again" "0 to upload (0 bytes), 5 already there"
files=$(curl -s "${AUTH[@]}" "$SERVER/v1/files" | jq -r '[.files[].path] | join(",")')
check "listing" "$files" ".cce/vault.kdl,Daily/2026-10-13.md,Desktop.canvas,Tasks/To Do.md,photo.jpg"
kdl=$(curl -s "${AUTH[@]}" "$SERVER/v1/files/.cce/vault.kdl")
case "$kdl" in *'folder "Daily"'*'attachments { folder "Attachments"; }'*) ok "vault.kdl from .obsidian" ;; *) bad "vault.kdl: $kdl" ;; esac
"$CLI" status

echo "== bytes and big blobs"
got=$(curl -s "${AUTH[@]}" "$SERVER/v1/files/photo.jpg" | sha)
check "the 1.5 MB photo round-trips through R2" "$got" "$(sha < "$V/photo.jpg")"
hdr=$(curl -s -D - -o /dev/null "${AUTH[@]}" "$SERVER/v1/files/Tasks/To%20Do.md" | tr -d '\r' | grep -i '^x-cce-hash:' | cut -d' ' -f2)
check "x-cce-hash header" "$hdr" "$(sha < "$V/Tasks/To Do.md")"
blob=$(curl -s "${AUTH[@]}" "$SERVER/v1/blobs/$hdr" | sha)
check "blob by hash" "$blob" "$hdr"

echo "== writes, merges and conflicts"
N="$SERVER/v1/files/Daily/2026-10-13.md"
put() { status_of -X PUT "${AUTH[@]}" -H "x-cce-device: $1" "${@:2}"; }
printf 'a\nb\nc\nd\ne\n' > "$WORK/v1"
check "write from rev 1" "$(put laptop -H 'if-match: 1' --data-binary @"$WORK/v1" "$N")" 200
printf 'A\nb\nc\nd\ne\n' > "$WORK/v2"
check "laptop edits the top (rev 3)" "$(put laptop -H 'if-match: 2' --data-binary @"$WORK/v2" "$N")" 200
printf 'a\nb\nc\nd\nE\n' > "$WORK/v3"
check "phone edits the bottom from rev 2" "$(put phone -H 'if-match: 2' --data-binary @"$WORK/v3" "$N")" 200
check "  ... and it merged" "$(jq -r '.applied[0].merged' "$WORK/body")" true
check "  merged text" "$(curl -s "${AUTH[@]}" "$N")" "$(printf 'A\nb\nc\nd\nE\n')"
printf 'A\nb\nc\nd\nE\nlaptop\n' > "$WORK/v5"
put laptop -H 'if-match: 4' --data-binary @"$WORK/v5" "$N" >/dev/null
printf 'A\nb\nc\nd\nE\nphone\n' > "$WORK/v6"
check "two appends from rev 4 conflict" "$(put phone -H 'if-match: 4' --data-binary @"$WORK/v6" "$N")" 409
check "  refusal names the current rev" "$(jq -r '.error + " " + (.current.rev|tostring)' "$WORK/body")" "conflict 5"
check "a write needs a precondition" "$(put phone --data-binary x "$SERVER/v1/files/x.md")" 400
check "create over an existing file" "$(put phone -H 'if-none-match: *' --data-binary x "$N")" 409
check "case collision" "$(put phone -H 'if-none-match: *' --data-binary x "$SERVER/v1/files/tasks/to%20do.md")" 409
check "  names the existing file" "$(jq -r .existing "$WORK/body")" "Tasks/To Do.md"
check "hidden path refused" "$(put phone -H 'if-none-match: *' --data-binary x "$SERVER/v1/files/.obsidian/x.json")" 400

echo "== batch: a rename with a link rewrite"
cat > "$WORK/batch.json" <<EOF
{"ops":[
 {"op":"move","from":"Desktop.canvas","to":"Boards/Desktop.canvas","pre":{"kind":"rev","rev":1}},
 {"op":"put","path":"Tasks/To Do.md","pre":{"kind":"rev","rev":1},"b64":"$(printf -- '- [ ] Call the studio\nsee [[Boards/Desktop.canvas]]\n' | base64 -w0)"}
]}
EOF
check "batch" "$(status_of -X POST "${AUTH[@]}" -H 'x-cce-device: claude' --data-binary @"$WORK/batch.json" "$SERVER/v1/batch")" 200
bad_batch='{"ops":[{"op":"put","path":"new.md","pre":{"kind":"absent"},"b64":"eA=="},{"op":"delete","path":"Tasks/To Do.md","pre":{"kind":"rev","rev":1}}]}'
check "a batch with a stale op is refused whole" "$(status_of -X POST "${AUTH[@]}" --data-binary "$bad_batch" "$SERVER/v1/batch")" 409
check "  its first op did not land" "$(status_of "${AUTH[@]}" "$SERVER/v1/files/new.md")" 404

echo "== delete, feed, history"
check "stale delete" "$(status_of -X DELETE "${AUTH[@]}" -H 'if-match: 1' "$SERVER/v1/files/Tasks/To%20Do.md")" 409
check "delete" "$(status_of -X DELETE "${AUTH[@]}" -H 'if-match: 2' "$SERVER/v1/files/Tasks/To%20Do.md")" 200
feed=$(curl -s "${AUTH[@]}" "$SERVER/v1/changes?since=0" | jq -r '[.changes[] | .op + ":" + .device] | join(" ")')
check "feed" "$feed" "put:laptop put:laptop put:laptop put:laptop put:laptop put:laptop put:laptop put:phone put:laptop move:claude put:claude delete:unknown"
page=$(curl -s "${AUTH[@]}" "$SERVER/v1/changes?since=10&limit=1" | jq -c '[.seq, .more]')
check "feed pages" "$page" "[11,true]"
hist=$(curl -s "${AUTH[@]}" "$SERVER/v1/history/Daily/2026-10-13.md" | jq -r '[.versions[] | (.rev|tostring) + ":" + .device] | join(" ")')
check "history" "$hist" "5:laptop 4:phone 3:laptop 2:laptop 1:laptop"

echo "== live socket"
cat > "$WORK/live.mjs" <<'EOF'
const [url, token, server] = process.argv.slice(2);
const ws = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
const got = [];
const done = (code) => { console.log(JSON.stringify(got)); process.exit(code); };
setTimeout(() => done(1), 8000);
ws.onmessage = async (m) => {
  got.push(JSON.parse(m.data).seq);
  if (got.length === 1) {
    await fetch(`${server}/v1/files/live.md`, { method: "PUT", body: "hi\n",
      headers: { authorization: `Bearer ${token}`, "if-none-match": "*", "x-cce-device": "laptop" } });
  } else done(0);
};
ws.onerror = (e) => { console.log("error", e.message); done(1); };
EOF
live=$(node "$WORK/live.mjs" "${SERVER/http/ws}/v1/live" "$TOKEN" "$SERVER" || true)
check "connect gets the seq, a write sends the next" "$live" "[12,13]"

echo
if [ "$fails" -eq 0 ]; then echo "all passed"; else echo "$fails failed"; exit 1; fi
