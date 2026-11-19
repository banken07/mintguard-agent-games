#!/bin/bash
# MintGuard supervisor: keeps the local agent server + the localhost.run SSH
# tunnel alive. The public URL is written to tunnel.url (changes every time
# the tunnel reconnects — re-register the endpoint in the dashboard if it
# changes). Logs: server.log, tunnel.log.
# Usage: nohup ./start.sh > supervisor.log 2>&1 &
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
export PATH="$PATH:/usr/bin:/bin"

start_server() {
  if ! curl -sf -m 3 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "[$(date -u +%FT%TZ)] starting agent server" >> supervisor.log
    nohup node server.mjs >> server.log 2>&1 &
    echo $! > server.pid
    sleep 2
  fi
}

start_tunnel() {
  if ! pgrep -f "ssh.*localhost.run" >/dev/null 2>&1; then
    echo "[$(date -u +%FT%TZ)] starting localhost.run tunnel" >> supervisor.log
    nohup ssh -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$HOME/.ssh/known_hosts" \
      -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -o ExitOnForwardFailure=yes \
      -o ProxyCommand="node $DIR/proxy-command.mjs %h %p" \
      -R 80:localhost:8080 nokey@localhost.run >> tunnel.log 2>&1 &
    # NOTE: no -N here on purpose: localhost.run prints the public URL into
    # the remote shell session; with -N there is no session channel and the
    # URL is never printed.
    echo $! > tunnel.pid
    sleep 5
    grep -oE 'https://[a-z0-9.-]+\.(localhost\.run|lhr\.life)' tunnel.log | grep -v 'admin' | tail -1 > tunnel.url.tmp || true
    if [ -s tunnel.url.tmp ]; then mv tunnel.url.tmp tunnel.url; fi
  fi
}

# initial start
start_server
start_tunnel

# supervisor loop: restart anything that died
while true; do
  sleep 20
  start_server
  start_tunnel
done
