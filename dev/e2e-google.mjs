// End-to-end check of the Google bridge (phase 6) against a local
// `wrangler dev`, with a mock Google on :8790 that this script serves:
// sign-in (OIDC + the bridge's Calendar and Tasks scopes, offline), the
// sealed refresh token and its access-token refresh, /v1/agenda, the agenda
// in Claude's daily_note, and #gtask lines kept in step with Google Tasks
// both ways (create, tick, rename, due date, delete on either side). Run
// through dev/e2e-google.sh. Never against the deployed server.
import http from "node:http";
import crypto from "node:crypto";

const SERVER = process.argv[2] ?? "http://127.0.0.1:8787";
const TOKEN = process.argv[3] ?? "dev-token-123";
const EMAIL = "me@example.com";
let fails = 0;
const ok = (what) => console.log(`  ok    ${what}`);
const bad = (what) => { console.log(`  FAIL  ${what}`); fails++; };
const check = (what, got, want) => (JSON.stringify(got) === JSON.stringify(want) ? ok(what) : bad(`${what} (got ${JSON.stringify(got)}, want ${JSON.stringify(want)})`));
const b64url = (b) => Buffer.from(b).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the mock Google ------------------------------------------------------
const google = { authQuery: null, refreshes: 0, access: null, tasks: new Map(), nextId: 1, eventQueries: [], refuseRefresh: false };
const iso = () => new Date().toISOString();
const json = (res, status, v) => res.writeHead(status, { "content-type": "application/json" }).end(v === undefined ? "" : JSON.stringify(v));
const readBody = (req) => new Promise((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });

const mock = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://127.0.0.1:8790");
  const body = await readBody(req);
  if (u.pathname === "/auth") {
    google.authQuery = u.searchParams;
    const code = b64url(JSON.stringify({ nonce: u.searchParams.get("nonce"), client: u.searchParams.get("client_id") }));
    const back = new URL(u.searchParams.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", u.searchParams.get("state"));
    return res.writeHead(302, { location: back.toString() }).end();
  }
  if (u.pathname === "/token") {
    const f = new URLSearchParams(body);
    if (f.get("grant_type") === "refresh_token") {
      if (google.refuseRefresh || f.get("refresh_token") !== "rt-1") return json(res, 400, { error: "invalid_grant" });
      google.refreshes++;
      google.access = `at-${google.refreshes}`;
      return json(res, 200, { access_token: google.access, expires_in: 3600 });
    }
    const { nonce, client } = JSON.parse(Buffer.from(f.get("code"), "base64url"));
    const claims = { iss: "https://accounts.google.com", aud: client, exp: Math.floor(Date.now() / 1000) + 300, nonce, email: EMAIL, email_verified: true };
    return json(res, 200, {
      id_token: `e30.${b64url(JSON.stringify(claims))}.sig`, access_token: "g", refresh_token: "rt-1",
      scope: "openid email https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/tasks",
    });
  }
  // The APIs want the access token the refresh gave.
  if (req.headers.authorization !== `Bearer ${google.access}`) return json(res, 401, { error: "bad token" });
  if (u.pathname === "/calendar/v3/users/me/calendarList") {
    return json(res, 200, { items: [
      { id: EMAIL, summary: EMAIL, primary: true, selected: true, timeZone: "Europe/Berlin" },
      { id: "family@group", summary: "Family", selected: true },
      { id: "hidden@group", summary: "Hidden", selected: true, hidden: true },
      { id: "off@group", summary: "Not shown" },
    ] });
  }
  const ev = u.pathname.match(/^\/calendar\/v3\/calendars\/([^/]+)\/events$/);
  if (ev) {
    const cal = decodeURIComponent(ev[1]);
    google.eventQueries.push(`${cal} ${u.searchParams.get("timeZone")} ${u.searchParams.get("timeMin")}`);
    const items = cal === EMAIL ? [
      { id: "e1", summary: "Standup", start: { dateTime: "2026-10-13T09:00:00+02:00" }, end: { dateTime: "2026-10-13T09:15:00+02:00" } },
      { id: "e2", summary: "Yesterday", start: { dateTime: "2026-10-12T09:00:00+02:00" }, end: { dateTime: "2026-10-12T10:00:00+02:00" } },
    ] : [{ id: "f1", summary: "Dinner", location: "Home", start: { dateTime: "2026-10-13T19:00:00+02:00" }, end: { dateTime: "2026-10-13T21:00:00+02:00" } }];
    return json(res, 200, { items });
  }
  const base = "/tasks/v1/lists/@default/tasks";
  if (u.pathname === base && req.method === "GET") return json(res, 200, { items: [...google.tasks.values()] });
  if (u.pathname === base && req.method === "POST") {
    const t = { id: `t${google.nextId++}`, ...JSON.parse(body), updated: iso() };
    google.tasks.set(t.id, t);
    return json(res, 200, t);
  }
  const one = u.pathname.startsWith(base + "/") && decodeURIComponent(u.pathname.slice(base.length + 1));
  if (one && google.tasks.has(one)) {
    const t = google.tasks.get(one);
    if (req.method === "PATCH") { Object.assign(t, JSON.parse(body), { updated: iso() }); return json(res, 200, t); }
    if (req.method === "DELETE") { t.deleted = true; t.updated = iso(); return json(res, 204); }
  }
  return json(res, 404, { error: "not found" });
});
await new Promise((r) => mock.listen(8790, "127.0.0.1", r));

const v1 = (path, init = {}) => fetch(`${SERVER}/v1/${path}`, { ...init, headers: { authorization: `Bearer ${TOKEN}`, "x-cce-device": "laptop", ...(init.headers ?? {}) } });
const read = async (path) => { const r = await v1(`files/${encodeURIComponent(path)}`); return { rev: Number(r.headers.get("x-cce-rev")), text: await r.text() }; };
const put = async (path, text) => {
  const cur = await v1(`files/${encodeURIComponent(path)}`);
  const pre = cur.status === 200 ? { "if-match": cur.headers.get("x-cce-rev") } : { "if-none-match": "*" };
  await cur.arrayBuffer();
  const r = await v1(`files/${encodeURIComponent(path)}`, { method: "PUT", body: text, headers: pre });
  if (r.status !== 200) throw new Error(`put ${path}: ${r.status} ${await r.text()}`);
};
// The bridge runs ~10 s after a commit. Wait for a condition, up to 40 s.
const until = async (what, cond) => {
  for (let i = 0; i < 40; i++) { if (await cond()) return ok(what); await sleep(1000); }
  bad(`${what} (timed out)`);
};
const poke = () => put("Poke.md", `poke ${Date.now()}\n`); // any commit wakes the bridge

try {
  console.log("== before Google is connected");
  let r = await v1("agenda?date=2026-10-13");
  check("the agenda says so", (await r.json()).connected, false);
  check("a bad date is refused", (await v1("agenda?date=13.10.2026")).status, 400);

  console.log("== the sign-in brings the bridge's token");
  const verifier = b64url(crypto.randomBytes(32));
  const q = new URLSearchParams({ response_type: "code", client_id: "cce-vault-web", redirect_uri: `${SERVER}/`, state: "s",
    code_challenge: b64url(crypto.createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", resource: `${SERVER}/v1` });
  r = await fetch(`${SERVER}/oauth/authorize?${q}`, { redirect: "manual" });
  const request = /name=request value="([^"]+)"/.exec(await r.text())[1];
  r = await fetch(`${SERVER}/oauth/authorize`, { method: "POST", body: new URLSearchParams({ request }).toString(), headers: { "content-type": "application/x-www-form-urlencoded" }, redirect: "manual" });
  r = await fetch(r.headers.get("location"), { redirect: "manual" });
  r = await fetch(r.headers.get("location"), { redirect: "manual" });
  check("signed in", new URL(r.headers.get("location")).searchParams.has("code"), true);
  const scopes = google.authQuery.get("scope").split(" ");
  check("Google was asked for Calendar (read-only) and Tasks", scopes.includes("https://www.googleapis.com/auth/calendar.readonly") && scopes.includes("https://www.googleapis.com/auth/tasks"), true);
  check("  offline, with consent (no token held yet)", [google.authQuery.get("access_type"), google.authQuery.get("prompt")], ["offline", "consent select_account"]);

  console.log("== the agenda");
  r = await v1("agenda?date=2026-10-13");
  const a = await r.json();
  check("connected, in the primary calendar's zone", [a.connected, a.time_zone], [true, "Europe/Berlin"]);
  check("the day's events from the shown calendars", a.events.map((e) => `${e.start}-${e.end} ${e.title}${e.calendar ? " (" + e.calendar + ")" : ""}`), ["09:00-09:15 Standup", "19:00-21:00 Dinner (Family)"]);
  check("asked in local time, around the day", google.eventQueries[0], `${EMAIL} Europe/Berlin 2026-10-12T00:00:00Z`);
  check("the access token came from the stored refresh token", google.refreshes, 1);
  const asked = google.eventQueries.length;
  await v1("agenda?date=2026-10-13");
  check("cached: a second look asks Google nothing", google.eventQueries.length, asked);

  console.log("== Claude's daily_note");
  await put("2026-10-13.md", "# 2026-10-13\n\n```agenda\n```\n");
  r = await fetch(`${SERVER}/mcp`, { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "daily_note", arguments: { date: "2026-10-13" } } }) });
  const dn = (await r.json()).result.content[0].text;
  check("carries the agenda after the note", dn.includes("agenda (Google Calendar, Europe/Berlin; not part of the note):\n09:00–09:15  Standup\n19:00–21:00  Dinner · Home (Family)"), true);

  console.log("== #gtask: a tagged line becomes a Google task");
  await put("Tasks.md", "# Tasks\n- [ ] Call the studio 📅 2026-10-20 #gtask\n- [ ] stays in the vault\n");
  await until("the task is in Google", async () => [...google.tasks.values()].some((t) => t.title === "Call the studio"));
  const task = [...google.tasks.values()].find((t) => t.title === "Call the studio");
  check("  with its due date and a link back", [task.due, task.status, task.notes.split("\n")[0]], ["2026-10-20T00:00:00.000Z", "needsAction", "From the vault: Tasks.md"]);
  await until("the line carries the id", async () => (await read("Tasks.md")).text.includes(`#gtask [gtask:: ${task.id}]`));
  check("only the tagged task went", google.tasks.size, 1);
  r = await v1("changes?since=0");
  check("the edit is the device google's", (await r.json()).changes.at(-1).device, "google");

  console.log("== ticked in Google: the line follows");
  await sleep(1100); // Google's change must be later than the note's
  Object.assign(google.tasks.get(task.id), { status: "completed", updated: iso() });
  await poke();
  await until("the line is ticked", async () => (await read("Tasks.md")).text.includes(`- [x] Call the studio 📅 2026-10-20 #gtask [gtask:: ${task.id}]`));

  console.log("== renamed and re-dated in the vault: Google follows");
  let t = (await read("Tasks.md")).text.replace("- [x] Call the studio 📅 2026-10-20", "- [ ] Call the studio about the mix 📅 2026-10-22");
  await put("Tasks.md", t);
  await until("Google has the new title, date and state", async () => {
    const g = google.tasks.get(task.id);
    return g.title === "Call the studio about the mix" && g.due === "2026-10-22T00:00:00.000Z" && g.status === "needsAction";
  });
  const writes = (await (await v1("changes?since=0")).json()).changes.filter((c) => c.path === "Tasks.md").length;
  await poke();
  await sleep(14000);
  check("in step: the next pass writes nothing", (await (await v1("changes?since=0")).json()).changes.filter((c) => c.path === "Tasks.md").length, writes);

  console.log("== deleted in Google: the line stays, untagged");
  google.tasks.get(task.id).deleted = true;
  await poke();
  await until("untagged", async () => (await read("Tasks.md")).text.includes("- [ ] Call the studio about the mix 📅 2026-10-22\n"));

  console.log("== a line deleted in the vault: the Google task goes");
  await put("Tasks.md", (await read("Tasks.md")).text + "- [ ] Book the room #gtask\n");
  await until("promoted", async () => [...google.tasks.values()].some((t) => t.title === "Book the room" && !t.deleted));
  const room = [...google.tasks.values()].find((t) => t.title === "Book the room");
  await until("its id is on the line", async () => (await read("Tasks.md")).text.includes(`[gtask:: ${room.id}]`));
  await put("Tasks.md", (await read("Tasks.md")).text.split("\n").filter((l) => !l.includes("Book the room")).join("\n"));
  await until("deleted in Google", async () => google.tasks.get(room.id).deleted === true);

  console.log("== Google refusing the stored sign-in turns the bridge off");
  google.refuseRefresh = true;
  google.access = "expired";
  r = await v1("agenda?date=2026-10-14");
  check("the agenda says not connected", (await r.json()).connected, false);
} catch (e) {
  bad(`threw: ${e.stack}`);
} finally {
  mock.close();
}
console.log();
if (fails === 0) console.log("all passed");
else { console.log(`${fails} failed`); process.exit(1); }
