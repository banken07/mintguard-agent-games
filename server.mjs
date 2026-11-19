// MintGuard — Agent Games Wildcard agent endpoint (ban7)
// ---------------------------------------------------------------------------
// Protocol: https://agentgames.zkverify.io/build (authoritative spec)
//  - POST /agent accepts signed JSON envelopes.
//  - Inbound: HMAC-SHA256 over the RAW request body, compared against the
//    `x-agent-games-signature` header BEFORE parsing JSON. Reject on mismatch.
//  - Outbound: every 200 response carries `x-agent-games-signature` = hex
//    HMAC-SHA256(secret, raw response body). Response bodies are capped at
//    16 KB; preflight must answer within 10 s; tasks have a 60 s hard deadline.
//  - Preflight envelope: {type:"agent-games.preflight.v1", agent_id, issued_at,
//    nonce}  ->  respond {ok:true, protocolVersion:"v1"} (signed).
//  - Gatekeeper envelope: {type:"agent-games.proof-gatekeeper.v1", task_id,
//    mode, issued_at, deadline_at, input:{...}} -> {decision, reason_code,
//    proof_tx}. This agent has no Groth16 circuit/proof pipeline, so it
//    FAILS CLOSED: always REJECT (never approves a transfer it cannot prove).
//  - Steal the VFY turn envelope: {eventId:"steal-the-vfy", matchId, turn,
//    state, strategyCommitment, nonce, ...} -> {matchId, turn, action, ...}.
//    This agent has no policy circuit / strategy commitment, so it always
//    returns HOLD with no proof (a HOLD turn scores as an invalid-proof HOLD
//    per the spec — honest fail-closed behaviour, NOT arena-competitive).
//  - Unknown envelope types: well-formed signed echo {ok, protocolVersion,
//    taskId, handled:false, reason:"unsupported_task_type"}.
//  - Idempotency: task_id / nonce / matchId:turn is the key; a repeated key
//    returns the stored response without re-executing.
//  - GET /health -> {ok:true} (platform health checks). GET / -> demo page.
//  - POST /check -> public demo: BSC contract safety screen (Sourcify +
//    public BSC RPC, read-only, no signing, no secrets). This is the
//    Wildcard use case reviewers can try: "screen a mint before you sign".
//
// Secrets: the HMAC secret comes ONLY from secret.env (0600, same dir) or
// the AGENT_GAMES_HMAC_SECRET env var. It does not exist yet — it is issued
// once at agent registration (dashboard "Rotate Secret"). Until it is set,
// the server still answers preflight (unsigned) so reachability can be
// tested; the platform preflight will fail its signature check until the
// real secret is in place. Restart the server after dropping the secret in.
//
// HMAC scheme note (verified 2026-11-19): the /build page never states the
// digest algorithm or encoding. HMAC-SHA256 hex is the standard Node
// convention and is used here. Inbound verification also tries the secret
// hex-decoded and base64-decoded as key material (all require the secret),
// and logs WHICH candidate matched, so a real preflight attempt is the
// oracle if the platform uses a different encoding. Outbound signing uses
// the secret string as UTF-8 bytes.
// ---------------------------------------------------------------------------
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "127.0.0.1";
const LOG_FILE = path.join(DIR, "dispatch.log");
const SEEN_FILE = path.join(DIR, "seen.json");
const MAX_SEEN = 500;
const MAX_BODY = 64 * 1024; // inbound cap (platform caps responses at 16 KB)

// ---- secret loading (0600 file or env; never logged, never echoed) ---------
function loadSecret() {
  if (process.env.AGENT_GAMES_HMAC_SECRET) return process.env.AGENT_GAMES_HMAC_SECRET.trim();
  try {
    const raw = fs.readFileSync(path.join(DIR, "secret.env"), "utf8");
    for (const line of raw.split("\n")) {
      const m = line.match(/^\s*AGENT_GAMES_HMAC_SECRET\s*=\s*(.+?)\s*$/);
      if (m) return m[1].replace(/^["']|["']$/g, "").trim();
    }
  } catch { /* file may not exist yet */ }
  return "";
}
let SECRET = loadSecret();
const HAS_SECRET = () => SECRET.length > 0;

// ---- HMAC helpers ----------------------------------------------------------
function hmacHex(keyBytes, data) {
  return crypto.createHmac("sha256", keyBytes).update(data).digest("hex");
}
function keyCandidates() {
  const c = [{ name: "utf8", key: Buffer.from(SECRET, "utf8") }];
  if (/^[0-9a-fA-F]{64}$/.test(SECRET)) c.push({ name: "hex-decoded", key: Buffer.from(SECRET, "hex") });
  if (/^[A-Za-z0-9+/=]{40,}$/.test(SECRET) && SECRET.length % 4 === 0) {
    try { c.push({ name: "base64-decoded", key: Buffer.from(SECRET, "base64") }); } catch { /* ignore */ }
  }
  return c;
}
function signBody(rawBody) {
  if (!HAS_SECRET()) return null;
  return hmacHex(Buffer.from(SECRET, "utf8"), rawBody);
}
function verifySignature(rawBody, header) {
  if (!HAS_SECRET() || !header) return { ok: false, candidate: null };
  const sig = header.trim().toLowerCase();
  for (const c of keyCandidates()) {
    const calc = hmacHex(c.key, rawBody);
    try {
      if (calc.length === sig.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(sig))) {
        return { ok: true, candidate: c.name };
      }
    } catch { /* length mismatch etc. */ }
  }
  return { ok: false, candidate: null };
}

// ---- logging (never log secrets or full bodies) -----------------------------
function log(entry) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...entry }) + "\n";
  fs.appendFile(LOG_FILE, line, () => {});
  console.log(line.trim());
}

// ---- idempotency store (persisted, capped) ---------------------------------
let seen = {};
try { seen = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8")); } catch { seen = {}; }
function saveSeen() {
  const keys = Object.keys(seen);
  if (keys.length > MAX_SEEN) {
    for (const k of keys.slice(0, keys.length - MAX_SEEN)) delete seen[k];
  }
  fs.writeFile(SEEN_FILE, JSON.stringify(seen), () => {});
}
function idemKey(env) {
  if (typeof env?.task_id === "string") return `task:${env.task_id}`;
  if (typeof env?.nonce === "string") return `nonce:${env.nonce}`;
  if (env?.matchId && env?.turn !== undefined) return `match:${env.matchId}:${env.turn}`;
  return `body:${crypto.createHash("sha256").update(JSON.stringify(env)).digest("hex").slice(0, 32)}`;
}

// ---- response helpers -------------------------------------------------------
function sendJson(res, status, obj, { sign = true } = {}) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  if (body.length > 16 * 1024) {
    res.writeHead(413, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "response_too_large" }));
    return body;
  }
  const headers = { "content-type": "application/json", "content-length": body.length };
  if (sign) {
    const sig = signBody(body);
    if (sig) headers["x-agent-games-signature"] = sig;
  }
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

// ---- task handlers ----------------------------------------------------------
function handleEnvelope(env) {
  const type = env?.type || "";
  if (type === "agent-games.preflight.v1") {
    return { status: 200, body: { ok: true, protocolVersion: "v1" }, kind: "preflight" };
  }
  if (type === "agent-games.proof-gatekeeper.v1") {
    // Fail closed: no Groth16 pipeline in this agent, so never APPROVE.
    return {
      status: 200,
      body: {
        decision: "REJECT",
        reason_code: "PROOF_NOT_GENERATED",
        proof_tx: env?.input?.proof_tx ?? null,
      },
      kind: "gatekeeper-reject",
    };
  }
  if (env?.eventId === "steal-the-vfy" || type.includes("steal-the-vfy")) {
    // Fail closed: no policy circuit / strategy commitment, so HOLD, no proof.
    return {
      status: 200,
      body: {
        matchId: env.matchId ?? null,
        turn: env.turn ?? null,
        action: { type: "HOLD" },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: `${env.matchId ?? "?" }:${env.turn ?? "?"}`,
      },
      kind: "steal-hold",
    };
  }
  // Generic / unknown envelope: well-formed signed echo, handled:false.
  return {
    status: 200,
    body: {
      ok: true,
      protocolVersion: "v1",
      taskId: env?.task_id ?? env?.taskId ?? null,
      handled: false,
      reason: "unsupported_task_type",
      type: type || "unknown",
    },
    kind: "generic-echo",
  };
}

// ---- BSC contract safety screen (public demo, read-only) --------------------
const BSC_RPCS = [
  "https://bsc-dataseed.binance.org/",
  "https://bsc-dataseed1.defibit.io/",
  "https://bsc.publicnode.com",
];
async function bscRpc(method, params) {
  // Try public RPCs in order; return null only if ALL fail (distinguish
  // "unreachable" from "0x" = no code). Verified 2026-11-19: these return
  // real chain state (router bytecode, live balances) from this VM.
  for (const url of BSC_RPCS) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 6000);
    try {
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: ctrl.signal,
      });
      const j = await r.json();
      if (j?.error) continue;
      if (typeof j?.result === "string") return j.result;
    } catch { /* try next */ }
    finally { clearTimeout(to); }
  }
  return null;
}
async function sourcifyCheck(address) {
  // Sourcify API v2 (v1 was removed). 200 = verified (runtimeMatch/creationMatch
  // "full"/"perfect"/"match" = exact, "partial" = partial); 404 = not verified.
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`https://sourcify.dev/server/v2/contract/56/${address}`, {
      headers: { "User-Agent": "MintGuard/1.0 (agent-games-wildcard)" },
      signal: ctrl.signal,
    });
    if (r.status === 404) return "none";
    if (!r.ok) return "unknown";
    const j = await r.json();
    const m = j?.runtimeMatch ?? j?.creationMatch ?? null;
    if (m === "partial") return "partial";
    if (m) return "perfect";
    return "partial";
  } catch { return "unknown"; }
  finally { clearTimeout(to); }
}
async function checkContract(address) {
  const addr = address.toLowerCase();
  const [code, sourcify] = await Promise.all([
    bscRpc("eth_getCode", [addr, "latest"]),
    sourcifyCheck(addr),
  ]);
  const rpcFailed = code === null;
  const hasCode = typeof code === "string" && code !== "0x" && code.length > 2;
  const flags = [];
  if (rpcFailed) flags.push("UNKNOWN: could not reach any BSC RPC — code check inconclusive, verify manually");
  else if (!hasCode) flags.push("NO_CODE: address has no contract bytecode (EOA or undeployed)");
  if (sourcify === "perfect") flags.push("OK: source verified on Sourcify (exact match)");
  else if (sourcify === "partial") flags.push("WARN: source only partially verified on Sourcify");
  else if (sourcify === "none") flags.push("WARN: source NOT verified on Sourcify — do not trust the claimed mint logic");
  else flags.push("UNKNOWN: Sourcify check failed — verification status unknown");
  const verdict = rpcFailed ? "UNKNOWN" : !hasCode ? "UNSAFE" : sourcify === "perfect" ? "SAFER" : sourcify === "none" ? "CAUTION" : "CAUTION";
  return { address: addr, chain: "BSC (56)", hasCode: rpcFailed ? null : hasCode, sourcifyStatus: sourcify, verdict, flags, checkedAt: new Date().toISOString() };
}

// ---- HTTP server -------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const started = Date.now();
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      if (url.pathname === "/health") {
        sendJson(res, 200, { ok: true, service: "mintguard-agent-games-wildcard", protocolVersion: "v1", secretConfigured: HAS_SECRET(), time: new Date().toISOString() }, { sign: false });
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(demoPage());
      return;
    }
    if (req.method === "GET" && url.pathname === "/agent") {
      sendJson(res, 200, { ok: true, service: "mintguard-agent-games-wildcard", protocolVersion: "v1", usage: "POST signed JSON envelopes here", secretConfigured: HAS_SECRET() }, { sign: false });
      return;
    }
    if (req.method === "POST" && url.pathname === "/check") {
      const raw = await readBody(req);
      let payload = {};
      try { payload = JSON.parse(raw.toString("utf8")); } catch { return sendJson(res, 400, { ok: false, error: "invalid_json" }, { sign: false }); }
      const address = String(payload.address || "").trim();
      if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
        return sendJson(res, 400, { ok: false, error: "address must be a 0x 40-hex BSC address" }, { sign: false });
      }
      const report = await checkContract(address);
      log({ path: "/check", address: report.address, verdict: report.verdict, ms: Date.now() - started });
      return sendJson(res, 200, { ok: true, ...report }, { sign: false });
    }
    if (req.method === "POST" && url.pathname === "/agent") {
      const raw = await readBody(req);
      const sigHeader = req.headers["x-agent-games-signature"];
      const v = verifySignature(raw, sigHeader);
      if (HAS_SECRET() && !v.ok) {
        log({ path: "/agent", status: 401, reason: "bad_signature", sigPresent: !!sigHeader, ms: Date.now() - started });
        return sendJson(res, 401, { ok: false, error: "bad_signature" }, { sign: false });
      }
      let env;
      try { env = JSON.parse(raw.toString("utf8")); } catch {
        return sendJson(res, 400, { ok: false, error: "invalid_json" }, { sign: false });
      }
      const key = idemKey(env);
      if (seen[key]) {
        const prev = seen[key];
        log({ path: "/agent", kind: prev.kind, key, replay: true, sigCandidate: v.candidate, ms: Date.now() - started });
        return sendJson(res, 200, prev.body);
      }
      const out = handleEnvelope(env);
      seen[key] = { kind: out.kind, body: out.body, at: new Date().toISOString() };
      saveSeen();
      log({ path: "/agent", kind: out.kind, key, type: env?.type || env?.eventId || "?", sigCandidate: v.candidate, secretConfigured: HAS_SECRET(), ms: Date.now() - started });
      return sendJson(res, out.status, out.body);
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "not_found" }));
  } catch (e) {
    log({ path: url.pathname, status: 500, error: String(e?.message || e), ms: Date.now() - started });
    try { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: false, error: "internal" })); } catch {}
  }
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error("body_too_large")); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function demoPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><title>MintGuard — Agent Games Wildcard</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.6;color:#111}code{background:#f0f0f0;padding:2px 6px;border-radius:4px}input{padding:8px;width:340px}button{padding:8px 14px}pre{background:#111;color:#0f0;padding:12px;border-radius:8px;white-space:pre-wrap}</style></head><body>
<h1>MintGuard — Agent Games Wildcard</h1>
<p><b>What it is:</b> a wallet-safety agent for BSC mints. Before you sign a mint, it screens the contract: is the source verified on Sourcify? Does the address even have code? It fails closed — unverified means caution, not a green light.</p>
<p><b>Protocol:</b> this endpoint speaks Agent Games protocol-v1 (<code>POST /agent</code>, HMAC-signed both ways, preflight + fail-closed task handling, idempotent by task id). <code>GET /health</code> for health checks.</p>
<h2>Try it — screen a BSC contract</h2>
<form onsubmit="event.preventDefault();check()"><input id="addr" placeholder="0x… BSC contract address"><button>Check</button></form>
<pre id="out">Result appears here. Read-only demo — no wallet, no signing.</pre>
<script>async function check(){const a=document.getElementById('addr').value.trim();const o=document.getElementById('out');o.textContent='Checking…';try{const r=await fetch('/check',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({address:a})});o.textContent=JSON.stringify(await r.json(),null,2);}catch(e){o.textContent='Error: '+e.message;}}</script>
<p>Built for <a href="https://agentgames.zkverify.io/events/wildcard">Agent Games — Wildcard</a> by @ban7. Source: public GitHub repo linked in the Wildcard submission.</p>
</body></html>`;
}

server.listen(PORT, HOST, () => {
  console.log(`MintGuard listening on http://${HOST}:${PORT} — secret configured: ${HAS_SECRET()}`);
});
