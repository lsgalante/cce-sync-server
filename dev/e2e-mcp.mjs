// End-to-end check of Claude's connector: the OAuth flow and the MCP
// tools, against a local `wrangler dev`, with a mock Google on :8790 that
// this script serves itself. Run through dev/e2e-mcp.sh, which starts the
// server with the right .dev.vars. Never against the deployed server.
//
// It plays Claude: the 401 challenge, discovery, Dynamic Client
// Registration, the consent page, Google sign-in, the code exchange with
// PKCE, MCP calls, refresh rotation, and the attacks that must fail (a
// reused code, a wrong verifier, a reused refresh token, a disallowed
// redirect).
import http from "node:http";
import crypto from "node:crypto";

const SERVER = process.argv[2] ?? "http://127.0.0.1:8787";
const SHARED = process.argv[3] ?? "dev-token-123";
const EMAIL = "me@example.com";
let fails = 0;
const ok = (what) => console.log(`  ok    ${what}`);
const bad = (what) => { console.log(`  FAIL  ${what}`); fails++; };
const check = (what, got, want) => (got === want ? ok(what) : bad(`${what} (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`));
const b64url = (b) => Buffer.from(b).toString("base64url");

// --- a mock Google: /auth redirects back with a code that carries the
// nonce; /token answers an (unsigned) ID token for it.
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

try {
  console.log("== the 401 challenge and discovery");
  let r = await post("/mcp", JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }), { "content-type": "application/json" });
  check("an unauthenticated /mcp call is 401", r.status, 401);
  const www = r.headers.get("www-authenticate") ?? "";
  const metaUrl = /resource_metadata="([^"]+)"/.exec(www)?.[1];
  check("  pointing at the resource metadata", metaUrl, `${SERVER}/.well-known/oauth-protected-resource/mcp`);
  const prm = await (await fetch(metaUrl)).json();
  check("resource is the /mcp URL", prm.resource, `${SERVER}/mcp`);
  const as = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
  check("PKCE S256 advertised", as.code_challenge_methods_supported[0], "S256");
  check("CIMD advertised with public clients", as.client_id_metadata_document_supported && as.token_endpoint_auth_methods_supported.includes("none"), true);

  console.log("== registration");
  r = await post("/oauth/register", JSON.stringify({ client_name: "Evil", redirect_uris: ["https://evil.example/cb"] }), { "content-type": "application/json" });
  check("a foreign redirect cannot register", r.status, 400);
  const redirectUri = "http://localhost:53682/callback";
  r = await post("/oauth/register", JSON.stringify({ client_name: "Claude Code (test)", redirect_uris: [redirectUri.replace(":53682", "")], token_endpoint_auth_method: "none" }), { "content-type": "application/json" });
  check("Claude Code registers", r.status, 201);
  const client = await r.json();

  // One sign-in, start to code. `verifier` may be wrong on purpose.
  async function signIn(port = 53682) {
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
    const ru = `http://localhost:${port}/callback`;
    const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: ru, state: "st-1",
      code_challenge: challenge, code_challenge_method: "S256", resource: `${SERVER}/mcp`, scope: "vault" });
    let r = await fetch(`${as.authorization_endpoint}?${q}`, { redirect: "manual" });
    const page = await r.text();
    if (r.status !== 200) throw new Error(`authorize: ${r.status} ${page}`);
    const request = /name=request value="([^"]+)"/.exec(page)[1];
    r = await post("/oauth/authorize", form({ request }), { "content-type": "application/x-www-form-urlencoded" });
    r = await fetch(r.headers.get("location"), { redirect: "manual" }); // Google
    r = await fetch(r.headers.get("location"), { redirect: "manual" }); // our callback
    const back = new URL(r.headers.get("location"));
    return { back, verifier, redirectUri: ru, page };
  }

  console.log("== consent, Google, code");
  const s = await signIn();
  check("the consent page names the redirect host", s.page.includes("localhost:53682"), true);
  check("  and warns about a loopback redirect", s.page.includes("loopback"), true);
  check("the code comes back to the client's port (port-agnostic loopback)", `${s.back.origin}${s.back.pathname}`, s.redirectUri);
  check("  with the state", s.back.searchParams.get("state"), "st-1");
  check("  and the issuer", s.back.searchParams.get("iss"), SERVER);
  const code = s.back.searchParams.get("code");

  const token = (o) => post("/oauth/token", form(o), { "content-type": "application/x-www-form-urlencoded" });
  r = await token({ grant_type: "authorization_code", code, redirect_uri: s.redirectUri, client_id: client.client_id, code_verifier: "x".repeat(43) });
  check("a wrong PKCE verifier is refused", (await r.json()).error, "invalid_grant");
  r = await token({ grant_type: "authorization_code", code, redirect_uri: s.redirectUri, client_id: client.client_id, code_verifier: s.verifier, resource: `${SERVER}/mcp` });
  // The wrong-verifier attempt did not use the code up.
  const first = await r.json();
  check("the code buys tokens", typeof first.access_token, "string");
  r = await token({ grant_type: "authorization_code", code, redirect_uri: s.redirectUri, client_id: client.client_id, code_verifier: s.verifier });
  check("a reused code is refused", (await r.json()).error, "invalid_grant");
  r = await post("/mcp", JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }), { authorization: `Bearer ${first.access_token}`, "content-type": "application/json" });
  check("  and what the code bought is revoked", r.status, 401);
  // Sign in again for the rest.
  const again = await signIn();
  r = await token({ grant_type: "authorization_code", code: again.back.searchParams.get("code"), redirect_uri: again.redirectUri, client_id: client.client_id, code_verifier: again.verifier });
  const tok = await r.json();
  check("a fresh sign-in buys tokens", typeof tok.access_token, "string");

  console.log("== MCP calls with the access token");
  let id = 10;
  const mcp = async (accessToken, method, params) => {
    const r = await post("/mcp", JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
      { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${accessToken}` });
    return { status: r.status, body: r.status === 200 ? await r.json() : null };
  };
  const call = async (name, args, t = tok.access_token) => {
    const r = await mcp(t, "tools/call", { name, arguments: args });
    const res = r.body?.result;
    return { status: r.status, error: res?.isError ?? false, text: res?.content?.[0]?.text ?? "" };
  };
  let m = await mcp(tok.access_token, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  check("initialize", m.body?.result?.protocolVersion, "2025-06-18");
  m = await mcp(tok.access_token, "tools/list", {});
  check("tools/list has the write tools", m.body.result.tools.some((t) => t.name === "rename_note"), true);
  let c = await call("write_note", { path: "Ideas/From Claude.md", content: "# From Claude\nfirst line\n" });
  check("write_note creates a note", c.text.startsWith("created Ideas/From Claude.md"), true);
  c = await call("append_daily", { date: "2026-10-13", text: "- talked to Claude" });
  check("append_daily", c.text.includes("2026-10-13.md"), true);
  c = await call("edit_note", { path: "From Claude", old_text: "first line", new_text: "edited line" });
  check("edit_note", c.error, false);
  c = await call("rename_note", { from: "From Claude", to: "Archive/From Claude.md" });
  check("rename_note", c.text.startsWith("renamed"), true);
  c = await call("read_note", { path: "From Claude" });
  check("read_note finds it by name after the rename", c.text.includes("path: Archive/From Claude.md") && c.text.includes("edited line"), true);
  const hist = await call("history", { path: "Archive/From Claude.md" });
  check("history records claude", hist.text.includes("by claude"), true);
  const shared = await call("search", { query: "edited" }, SHARED);
  check("the shared token also works on /mcp (Claude Code by header)", shared.text.startsWith("Archive/From Claude.md"), true);

  console.log("== tables and workbooks");
  c = await call("write_table", { path: "Finance/Ledger.csv", content: "Date,Payee,Amount\n2026-10-01,Rent,1200\n" });
  check("write_table creates a CSV", c.text, "created Finance/Ledger.csv (1 rows), now rev 1");
  c = await call("append_rows", { path: "Finance/Ledger.csv", rows: '2026-10-03,"Shop, Inc",42' });
  check("append_rows", c.text, "appended 1 row to Finance/Ledger.csv, now rev 2");
  c = await call("append_rows", { path: "Finance/Ledger.csv", rows: "2026-10-04,short" });
  check("  a row of the wrong width is refused", c.error && c.text.includes("the header has 3"), true);
  c = await call("read_table", { path: "Finance/Ledger.csv" });
  check("read_table", c.text.endsWith('2026-10-03,"Shop, Inc",42\n') && c.text.includes("rows: 2"), true);
  c = await call("create_spreadsheet", { path: "Finance/Budget.xlsx", sheets: [{ name: "Budget", rows: [["Item", "Cost"], ["Rent", 1200], ["Food", 300], ["Total", "=SUM(B2:B3)"]] }] });
  check("create_spreadsheet (IronCalc in the Worker)", c.text, "created Finance/Budget.xlsx (1 sheet), rev 1");
  c = await call("append_spreadsheet_rows", { path: "Finance/Budget.xlsx", rows: [["Gas", 40]] });
  check("append_spreadsheet_rows", c.text, "appended rows 5-5 to Finance/Budget.xlsx, now rev 2");
  c = await call("set_cells", { path: "Finance/Budget.xlsx", cells: { B4: "=SUM(B2:B3)+B5" } });
  check("set_cells recalculates", c.text.endsWith("B4 = 1540 (=SUM(B2:B3)+B5)"), true);
  c = await call("read_spreadsheet", { path: "Finance/Budget.xlsx" });
  check("read_spreadsheet", c.text.includes("sheets: Budget (A1:B5)") && c.text.includes("4\tTotal\t1540"), true);

  console.log("== refresh rotation");
  r = await token({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: client.client_id });
  const tok2 = await r.json();
  check("a refresh gives new tokens", typeof tok2.access_token === "string" && tok2.refresh_token !== tok.refresh_token, true);
  check("  and the new access token works", (await call("tags", {}, tok2.access_token)).status, 200);
  r = await token({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: client.client_id });
  check("a reused refresh token is refused", (await r.json()).error, "invalid_grant");
  check("  and the whole grant is revoked", (await call("tags", {}, tok2.access_token)).status, 401);

  console.log("== grants");
  const s2 = await signIn(41000);
  r = await token({ grant_type: "authorization_code", code: s2.back.searchParams.get("code"), redirect_uri: s2.redirectUri, client_id: client.client_id, code_verifier: s2.verifier });
  const tok3 = await r.json();
  const grants = await (await fetch(`${SERVER}/v1/grants`, { headers: { authorization: `Bearer ${SHARED}` } })).json();
  check("every grant is listed (two revoked above, one live)", `${grants.length} ${grants.filter((g) => g.revoked).length}`, "3 2");
  const live = grants.find((g) => !g.revoked);
  check("  with the client and the account", `${live.client} ${live.email}`, `Claude Code (test) ${EMAIL}`);
  r = await fetch(`${SERVER}/v1/grants/${live.id}`, { method: "DELETE", headers: { authorization: `Bearer ${SHARED}` } });
  check("revoking a grant", r.status, 200);
  check("  stops its token at once", (await call("tags", {}, tok3.access_token)).status, 401);
  r = await post("/mcp", "{}", { authorization: "Bearer not-a-token" });
  check("a made-up token is 401", r.status, 401);
} catch (e) {
  bad(`threw: ${e.stack}`);
} finally {
  google.close();
}
console.log(fails === 0 ? "\nall passed" : `\n${fails} failed`);
process.exit(fails === 0 ? 0 : 1);
