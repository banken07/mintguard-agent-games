// Local HMAC round-trip test for the MintGuard endpoint.
// Usage: AGENT_GAMES_HMAC_SECRET=<test-secret> node test-preflight.mjs [baseUrl]
// Default baseUrl http://127.0.0.1:8080. Uses a TEST secret only — never the real one.
import crypto from "node:crypto";

const BASE = process.argv[2] || "http://127.0.0.1:8080";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "test-secret-do-not-use-in-prod";
const sign = (body) => crypto.createHmac("sha256", Buffer.from(SECRET, "utf8")).update(body).digest("hex");

let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name} ${extra}`);
  ok ? pass++ : fail++;
}

const preflight = { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "test-nonce-1" };
const preBody = Buffer.from(JSON.stringify(preflight));
let r = await fetch(`${BASE}/agent`, {
  method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": sign(preBody) },
  body: preBody,
});
let j = await r.json();
check("preflight status 200", r.status === 200, `(${r.status})`);
check("preflight body {ok:true, protocolVersion:v1}", j.ok === true && j.protocolVersion === "v1", JSON.stringify(j));
const respSig = r.headers.get("x-agent-games-signature");
const respRaw = JSON.stringify(j);
check("response carries x-agent-games-signature", !!respSig);
check("response signature verifies (HMAC-SHA256 hex over raw body)", !!respSig && crypto.timingSafeEqual(Buffer.from(respSig), Buffer.from(sign(Buffer.from(respRaw)))));

// replay: same nonce must return the identical stored response (idempotency)
r = await fetch(`${BASE}/agent`, {
  method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": sign(preBody) },
  body: preBody,
});
j = await r.json();
check("idempotent replay returns same body", j.ok === true && j.protocolVersion === "v1", `(${r.status})`);

// bad signature must be rejected
r = await fetch(`${BASE}/agent`, {
  method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": "00".repeat(32) },
  body: preBody,
});
check("bad signature rejected (401)", r.status === 401, `(${r.status})`);

// gatekeeper task: fail-closed REJECT
const gk = { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_1", mode: "competition", issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input: { registered_vk: "0x00", proof_vk: "0x00", minimum: "1000", public_balance: "1460", recipient: "0xDe42", amount: "500", proof_tx: "0xabc" } };
const gkBody = Buffer.from(JSON.stringify(gk));
r = await fetch(`${BASE}/agent`, {
  method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": sign(gkBody) },
  body: gkBody,
});
j = await r.json();
check("gatekeeper fail-closed REJECT", r.status === 200 && j.decision === "REJECT", JSON.stringify(j));

// steal-the-vfy turn: HOLD, no proof
const stv = { protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition", matchId: "9f4e1b2a-test", turn: 3, issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 60000).toISOString(), state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, strategyCommitment: { hash: "0x00" }, resolverVersion: "v1", nonce: "test-nonce-2" };
const stvBody = Buffer.from(JSON.stringify(stv));
r = await fetch(`${BASE}/agent`, {
  method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": sign(stvBody) },
  body: stvBody,
});
j = await r.json();
check("steal-the-vfy HOLD", r.status === 200 && j.action?.type === "HOLD" && j.matchId === "9f4e1b2a-test", JSON.stringify(j));

// health + root
r = await fetch(`${BASE}/health`);
check("GET /health 200 {ok:true}", r.status === 200 && (await r.json()).ok === true);
r = await fetch(`${BASE}/`);
check("GET / 200 html", r.status === 200 && (r.headers.get("content-type") || "").includes("text/html"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
