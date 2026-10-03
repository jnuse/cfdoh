#!/usr/bin/env bash
# End-to-end self test for the cfdoh server (batch 4 acceptance).
#
# Starts the server against real public DoH upstreams (routed through
# $E2E_HTTPS_PROXY when set), exercises /health, /dns-query (POST and GET),
# /explain and /probe, then verifies the graceful-shutdown snapshot and the
# boot-time restore.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/.cache/e2e"
PORT="${E2E_PORT:-18080}"
BASE="http://127.0.0.1:$PORT"
BIN="$WORK/cfdoh"
SNAP="$WORK/cache.json"

rm -rf "$WORK"
mkdir -p "$WORK"
go build -o "$BIN" "$ROOT/cmd/cfdoh"

# Server-side environment: real upstreams, proxy for their HTTPS egress only.
SERVER_ENV=(
  "HOST=127.0.0.1"
  "PORT=$PORT"
  "ADMIN_TOKEN=e2e-admin-token"
  "CACHE_PERSIST_PATH=$SNAP"
)
if [[ -n "${E2E_HTTPS_PROXY:-}" ]]; then
  SERVER_ENV+=("HTTPS_PROXY=$E2E_HTTPS_PROXY")
fi

# curl must never proxy the loopback server itself.
export NO_PROXY="127.0.0.1,localhost"
export no_proxy="$NO_PROXY"

start_server() {
  env "${SERVER_ENV[@]}" "$BIN" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 50); do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "server did not become healthy; log:" >&2
  cat "$WORK/server.log" >&2
  exit 1
}

stop_server() {
  kill -TERM "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}

# dnsmsg <name> <qtype>: base64url wire query on stdout (python3 stdlib).
dnsmsg() {
  python3 - "$1" "$2" <<'PY'
import base64, struct, sys

name, qtype = sys.argv[1], int(sys.argv[2])
out = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
for label in name.rstrip(".").split("."):
    out += bytes([len(label)]) + label.encode()
out += b"\x00"  # root label terminator
out += struct.pack(">HH", qtype, 1)
sys.stdout.write(base64.urlsafe_b64encode(out).decode().rstrip("="))
PY
}

# check_answer <b64-answer>: asserts rcode 0 and the transaction ID echo.
check_answer() {
  python3 - "$1" <<'PY'
import base64, struct, sys

raw = base64.urlsafe_b64decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 4))
tid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", raw[:12])
if tid != 0x1234:
    sys.exit("transaction ID mismatch: %#x" % tid)
if flags & 0x000F != 0:
    sys.exit("non-zero rcode: %d" % (flags & 0x000F))
if an < 1:
    sys.exit("empty answer section")
PY
}

fail() { echo "FAIL: $*" >&2; stop_server; exit 1; }

TYPE_A=1
TYPE_AAAA=28
TYPE_HTTPS=65

echo "== boot =="
start_server

echo "== /health =="
curl -sf "$BASE/health" | grep -q '"ok":true' || fail "health not ok"
echo "   ok"

echo "== /dns-query POST (A www.cloudflare.com) =="
q=$(dnsmsg www.cloudflare.com "$TYPE_A")
a=$(python3 - "$BASE" "$q" <<'PY'
import base64, sys, urllib.request

url, q = sys.argv[1], sys.argv[2]
raw = base64.urlsafe_b64decode(q + "=" * (-len(q) % 4))
req = urllib.request.Request(url + "/dns-query", data=raw, method="POST", headers={
    "Content-Type": "application/dns-message",
    "Accept": "application/dns-message",
})
with urllib.request.urlopen(req, timeout=10) as resp:
    body = resp.read()
    assert resp.headers["Content-Type"] == "application/dns-message", resp.headers["Content-Type"]
    assert resp.headers["Cache-Control"] == "no-store"
print(base64.urlsafe_b64encode(body).decode().rstrip("="))
PY
)
[[ -n "$a" ]] || fail "POST query returned nothing"
check_answer "$a"
echo "   ok (ID echoed, rcode 0)"

echo "== /dns-query GET (AAAA www.cloudflare.com) =="
q=$(dnsmsg www.cloudflare.com "$TYPE_AAAA")
a=$(curl -sf -H "Accept: application/dns-message" "$BASE/dns-query?dns=$q" | base64 -w0 | tr '+/' '-_' | tr -d '=')
[[ -n "$a" ]] || fail "GET query returned nothing"
check_answer "$a"
echo "   ok (ID echoed, rcode 0)"

echo "== /dns-query GET (HTTPS www.cloudflare.com) =="
q=$(dnsmsg www.cloudflare.com "$TYPE_HTTPS")
a=$(curl -sf -H "Accept: application/dns-message" "$BASE/dns-query?dns=$q" | base64 -w0 | tr '+/' '-_' | tr -d '=')
[[ -n "$a" ]] || fail "HTTPS query returned nothing"
check_answer "$a"
echo "   ok (ID echoed, rcode 0)"

echo "== /explain =="
curl -sf "$BASE/explain?name=www.cloudflare.com" >"$WORK/explain.json" || fail "explain failed"
python3 - "$WORK/explain.json" <<'PY' || fail "explain payload incomplete"
import json, sys

doc = json.load(open(sys.argv[1]))
assert "client_ip" in doc and doc["client_ip"], "missing client_ip"
for key in ("A", "AAAA", "HTTPS"):
    assert key in doc.get("answers", {}), "missing answers.%s" % key
assert "chromium_ech" in doc, "missing chromium_ech"
PY
echo "   ok (client_ip, answers A/AAAA/HTTPS, chromium_ech)"

echo "== /probe =="
curl -sf "$BASE/probe" | grep -q '"client_ip"' || fail "probe missing client_ip"
echo "   ok"

echo "== admin auth =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/admin/preferred")
[[ "$code" == "401" ]] || fail "unauthenticated admin should 401, got $code"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer e2e-admin-token" "$BASE/admin/preferred")
[[ "$code" == "200" ]] || fail "admin token should 200, got $code"
echo "   ok (auth matrix)"

echo "== graceful shutdown + snapshot =="
stop_server
[[ -f "$SNAP" ]] || fail "cache snapshot missing after shutdown"
[[ -f "$WORK/pool-state.json" ]] || fail "pool state snapshot missing"
[[ -f "$WORK/h3-state.json" ]] || fail "h3 state snapshot missing"
[[ -f "$WORK/ech-state.json" ]] || fail "ech state snapshot missing"
echo "   ok (cache + 3 probe-state files)"

echo "== reboot restore =="
start_server
q=$(dnsmsg www.cloudflare.com "$TYPE_A")
a=$(curl -sf -H "Accept: application/dns-message" "$BASE/dns-query?dns=$q" | base64 -w0 | tr '+/' '-_' | tr -d '=')
check_answer "$a"
stop_server
echo "   ok (restored and serving)"

echo
echo "ALL E2E CHECKS PASSED"
