// End-to-end check of what the phone app (cce-vault-web) needs from the
// server, against a local `wrangler dev` with a mock Google on :8790 that
// this script serves itself: the site served from the Worker's origin,
// the first-party sign-in (client cce-vault-web, back to <origin>/, tokens
// for <origin>/v1), the sync API with those tokens, the live socket by
// ticket, and the walls between the phone's tokens and Claude's. Run
// through dev/e2e-phone.sh. Never against the deployed server.
import http from "node:http";
import crypto from "node:crypto";

const SERVER = process.argv[2] ?? "http://127.0.0.1:8787";
const EMAIL = "me@example.com";
let fails = 0;
const ok = (what) => console.log(`  ok    ${what}`);
const bad = (what) => { console.log(`  FAIL  ${what}`); fails++; };
const check = (what, got, want) => (got === want ? ok(what) : bad(`${what} (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`));
const b64url = (b) => Buffer.from(b).toString("base64url");

// The mock Google of e2e-mcp.mjs.
const google = http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1:8790");
  if (u.pathname === "/auth") {
    const code = b64url(JSON.stringify({ nonce: u.searchParams.get("nonce"), client: u.searchParams.get("client_id") }));
    const back = new URL(u.searchParams.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", u.searchParams.get("state"));
    res.writeHead(302, { location: back.toString() }).end();
  } else if (u.pathname === "/token") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const f = new URLSearchParams(body);
      const { nonce, client } = JSON.parse(Buffer.from(f.get("code"), "base64url"));
      const claims = { iss: "https://accounts.google.com", aud: client, exp: Math.floor(Date.now() / 1000) + 300,
                       nonce, email: EMAIL, email_verified: true };
      res.writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ id_token: `e30.${b64url(JSON.stringify(claims))}.sig`, access_token: "g" }));
    });
  } else res.writeHead(404).end();
});
await new Promise((r) => google.listen(8790, "127.0.0.1", r));

const form = (o) => new URLSearchParams(o).toString();
const post = (path, body, headers = {}) => fetch(SERVER + path, { method: "POST", body, headers, redirect: "manual" });
const token = (o) => post("/oauth/token", form(o), { "content-type": "application/x-www-form-urlencoded" });

// The phone's sign-in, as login.rs builds it, up to the code.
async function signIn({ clientId = "cce-vault-web", redirectUri = `${SERVER}/`, resource = `${SERVER}/v1` } = {}) {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: "S256", state: "s1", resource });
  let r = await fetch(`${SERVER}/oauth/authorize?${q}`, { redirect: "manual" });
  const page = await r.text();
  if (r.status !== 200) return { status: r.status, page, location: r.headers.get("location") };
  const request = /name=request value="([^"]+)"/.exec(page)[1];
  r = await post("/oauth/authorize", form({ request }), { "content-type": "application/x-www-form-urlencoded" });
  r = await fetch(r.headers.get("location"), { redirect: "manual" }); // Google
  r = await fetch(r.headers.get("location"), { redirect: "manual" }); // our callback
  return { status: 200, page, back: new URL(r.headers.get("location")), verifier, redirectUri };
}

try {
  console.log("== the site, from the Worker's origin");
  let r = await fetch(`${SERVER}/`);
  const html = await r.text();
  check("/ serves the app's page", r.status === 200 && html.includes("app.js"), true);
  check("  with the site's CSP", (r.headers.get("content-security-policy") ?? "").includes("connect-src 'self'"), true);
  r = await fetch(`${SERVER}/?code=abc&state=s1`);
  check("the sign-in's return gets the page too", r.status === 200 && (await r.text()).includes("app.js"), true);
  r = await fetch(`${SERVER}/_headers`);
  check("_headers itself is not served", r.status === 200 && (await r.text()).includes("Content-Security-Policy"), false);
  r = await fetch(`${SERVER}/v1/files`);
  check("the API is still the Worker's (401)", r.status, 401);
  r = await fetch(`${SERVER}/health`);
  check("  and /health", r.status, 200);

  console.log("== the phone signs in as the first-party client");
  const s = await signIn();
  check("the consent page names the app", s.page.includes("the phone app"), true);
  check("the code comes back to <origin>/", `${s.back.origin}${s.back.pathname}`, `${SERVER}/`);
  check("  with the state", s.back.searchParams.get("state"), "s1");
  r = await token({ grant_type: "authorization_code", code: s.back.searchParams.get("code"), client_id: "cce-vault-web",
    redirect_uri: `${SERVER}/`, code_verifier: s.verifier, resource: `${SERVER}/v1` });
  let tok = await r.json();
  check("the code buys tokens", typeof tok.access_token, "string");
  const bearer = (t) => ({ authorization: `Bearer ${t}`, "x-cce-device": "phone" });

  r = await signIn({ redirectUri: "https://evil.example/" });
  check("the app's client cannot send a code elsewhere", r.status, 400);
  r = await post("/oauth/register", JSON.stringify({ client_name: "Claude Code (test)", redirect_uris: ["http://localhost/callback"], token_endpoint_auth_method: "none" }), { "content-type": "application/json" });
  const other = await r.json();
  r = await signIn({ clientId: other.client_id, redirectUri: "http://localhost:5000/callback" });
  check("another client cannot ask for the sync API", r.status === 302 && new URL(r.location).searchParams.get("error"), "invalid_target");

  console.log("== the sync API with the phone's token");
  r = await fetch(`${SERVER}/v1/files`, { headers: bearer(tok.access_token) });
  check("GET files", r.status, 200);
  r = await fetch(`${SERVER}/v1/files/Phone%20note.md`, { method: "PUT", body: "from the phone\n",
    headers: { ...bearer(tok.access_token), "if-none-match": "*" } });
  check("PUT a note", r.status, 200);
  const put = await r.json();
  r = await fetch(`${SERVER}/v1/changes?since=0`, { headers: bearer(tok.access_token) });
  const feed = await r.json();
  check("the feed records the phone", feed.changes.at(-1)?.device, "phone");
  r = await fetch(`${SERVER}/v1/blobs/${put.applied[0].hash}`, { headers: bearer(tok.access_token) });
  check("a blob by hash", await r.text(), "from the phone\n");
  r = await post("/mcp", JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    { ...bearer(tok.access_token), "content-type": "application/json" });
  check("the phone's token is no good for /mcp", r.status, 401);

  console.log("== refresh rotation");
  r = await token({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: "cce-vault-web" });
  const next = await r.json();
  check("a refresh gives a new pair", typeof next.access_token === "string" && next.refresh_token !== tok.refresh_token, true);
  r = await fetch(`${SERVER}/v1/status`, { headers: bearer(next.access_token) });
  check("  which works on /v1", r.status, 200);
  tok = next;

  console.log("== the live socket by ticket");
  r = await fetch(`${SERVER}/v1/live-ticket`, { method: "POST", headers: bearer(tok.access_token) });
  const { ticket, expires_in } = await r.json();
  check("a ticket for a minute", typeof ticket === "string" && expires_in === 60, true);
  r = await fetch(`${SERVER}/v1/live-ticket`, { method: "POST" });
  check("  only with a token", r.status, 401);
  const live = (url) => new Promise((resolve) => {
    const ws = new WebSocket(url);
    const got = [];
    const done = (v) => { try { ws.close(); } catch {} resolve(v); };
    setTimeout(() => done(got), 5000);
    ws.onmessage = async (m) => {
      got.push(JSON.parse(m.data).seq);
      if (got.length === 1) {
        await fetch(`${SERVER}/v1/files/Live.md`, { method: "PUT", body: "hi\n", headers: { ...bearer(tok.access_token), "if-none-match": "*" } });
      } else done(got);
    };
    ws.onerror = () => done("refused");
  });
  const wsUrl = `${SERVER.replace(/^http/, "ws")}/v1/live?ticket=${encodeURIComponent(ticket)}`;
  const seqs = await live(wsUrl);
  check("connect gets the seq, a write sends the next", Array.isArray(seqs) && seqs.length === 2 && seqs[1] === seqs[0] + 1, true);
  check("a ticket works once", await live(wsUrl), "refused");
  check("no ticket, no socket", await live(`${SERVER.replace(/^http/, "ws")}/v1/live`), "refused");

  console.log("== signing out on the server");
  r = await fetch(`${SERVER}/v1/grants`, { headers: bearer(tok.access_token) });
  const grants = await r.json();
  const mine = grants.find((g) => g.client.includes("phone app") && !g.revoked);
  check("the phone's grant is listed", !!mine, true);
  r = await fetch(`${SERVER}/v1/grants/${mine.id}`, { method: "DELETE", headers: bearer(tok.access_token) });
  check("revoking it", r.status, 200);
  r = await fetch(`${SERVER}/v1/files`, { headers: bearer(tok.access_token) });
  check("  ends its access", r.status, 401);
  r = await token({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: "cce-vault-web" });
  check("  and its refresh", (await r.json()).error, "invalid_grant");
} catch (e) {
  bad(`threw: ${e.stack}`);
} finally {
  google.close();
}
console.log();
if (fails === 0) console.log("all passed");
else { console.log(`${fails} failed`); process.exit(1); }
