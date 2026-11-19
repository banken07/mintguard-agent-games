// ProxyCommand helper for ssh: opens a CONNECT tunnel through the VM egress
// proxy to %h:%p and pipes stdin/stdout. Credentials are read from the
// HTTPS_PROXY env var (already present in this runtime) and never printed.
// Usage (from ssh): ProxyCommand="node /path/to/proxy-command.mjs %h %p"
import net from "node:net";

const [host, port] = process.argv.slice(2);
const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || "";
if (!proxyUrl) { console.error("proxy-command: no HTTPS_PROXY in env"); process.exit(1); }
const u = new URL(proxyUrl);
const sock = net.connect(Number(u.port) || 3128, u.hostname, () => {
  const auth = u.username ? "Proxy-Authorization: Basic " + Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64") + "\r\n" : "";
  sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
});
let header = Buffer.alloc(0);
let established = false;
sock.on("data", (chunk) => {
  if (established) { process.stdout.write(chunk); return; }
  header = Buffer.concat([header, chunk]);
  const idx = header.indexOf("\r\n\r\n");
  if (idx === -1) return;
  const statusLine = header.subarray(0, header.indexOf("\r\n")).toString();
  if (!/^HTTP\/\d\.\d 2\d\d/.test(statusLine)) {
    console.error("proxy-command: CONNECT failed:", statusLine);
    process.exit(1);
  }
  established = true;
  const rest = header.subarray(idx + 4);
  if (rest.length) process.stdout.write(rest);
  process.stdin.pipe(sock);
});
sock.on("error", (e) => { console.error("proxy-command: socket error", e.message); process.exit(1); });
sock.on("close", () => process.exit(0));
