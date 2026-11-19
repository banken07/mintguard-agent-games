# Wildcard submission — copy-paste values for the dashboard form
# Dashboard → Submissions → Wildcard tab → New submission
# Closes 21 Nov 2026, 22:00 UTC. Form action: submitWildcardSubmission.

## Title
MintGuard — a wallet-safety agent for BSC mints

## GitHub repository link (REQUIRED)
https://github.com/banken07/mintguard-agent-games
— REPO DOES NOT EXIST YET. Create public repo `banken07/mintguard-agent-games`
and push the contents of ~/workspace/agentgames/agent/ (server.mjs, README.md,
package.json, start.sh, proxy-command.mjs, test-preflight.mjs, .gitignore,
SUBMISSION.md). NEVER push secret.env / seen.json / dispatch.log / *.pid /
tunnel.* (all gitignored).

## Agent endpoint (optional — but listed as a submission requirement on the event page)
https://705c2ba9698e2d.app.lhr.life/agent
— the protocol-v1 handler (preflight + signed task envelopes). If the tunnel URL
changes (free lhr.life domains rotate), update this field with the current URL
from ~/workspace/agentgames/agent/tunnel.url.

## Additional links (optional, one per line)
https://705c2ba9698e2d.app.lhr.life/
https://github.com/banken07/mintguard-agent-games

## Supporting context (optional, max 1000 chars)
MintGuard screens a BSC contract before you sign a mint: it checks on-chain
bytecode via public BSC RPC and source verification via Sourcify v2, and fails
closed — unverified means caution, never a green light. The endpoint speaks
Agent Games protocol-v1 (HMAC-signed preflight + task handling, idempotent by
task id) and exposes a public demo: paste any BSC contract address on the demo
page and get a safety verdict. Built for the way agent wallets actually mint:
DYOR first, sign second. No zkVerify proof is attached — the agent's claims are
checkable through public Sourcify and BSC RPC reads instead.

## Use case (for the "What it is" / review narrative)
Problem: agent wallets sign mints constantly, and a single unverified or
clone contract can drain funds. Who it helps: any agent (or human) minting on
BSC. What it does: answers "is this contract what it claims to be?" in under
2 seconds, before any signature, and answers platform task envelopes
fail-closed so it can never approve something it cannot prove.

## Build context (for the "How it works" narrative)
Pure Node.js, zero dependencies. One file (server.mjs) implements: HMAC-SHA256
verify/sign over raw bodies, the preflight handshake, deterministic fail-closed
Gatekeeper REJECT and Steal-the-VFY HOLD responses, disk-persisted idempotency,
JSON-lines dispatch logging (no secrets in logs). Deployed on a public HTTPS
endpoint via an SSH tunnel (the VM has no public IP; cloudflared is blocked by
the egress proxy and Tailscale cannot host). A supervisor loop keeps the server
and tunnel alive; recovery is one command (see README.md).
