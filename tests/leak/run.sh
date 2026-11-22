#!/usr/bin/env bash
# Alizy real-network test suite.
#
# Runs the real alizyd binary against the real kernel (nftables, WireGuard,
# policy routing) inside unprivileged user + network namespaces, so it needs
# no root and cannot disturb the host network:
#
#   client netns  (alizyd, alizy0)  ──veth──  "internet" netns (WireGuard
#   servers wgs/wgs2, UDP sinks, DNS server)
#
# Verdicts are based on where packets actually arrive and with which source
# address — never on daemon-reported state alone.
#
# Usage: tests/leak/run.sh        (builds alizyd first)
set -u

DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)

if [[ "${ALIZY_IN_NS:-}" != 1 ]]; then
  (cd "$ROOT" && cargo build -q -p alizyd) || exit 1
  if ! unshare -rn true 2>/dev/null; then
    echo "SKIP: unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0); run as root instead." >&2
    exit 77
  fi
  exec env ALIZY_IN_NS=1 unshare -rn --kill-child -- bash "$0" "$@"
fi

BIN="$ROOT/target/debug/alizyd"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/alizy-leak.XXXXXX")
H="python3 $DIR/helper.py"
SOCK="$WORK/alizyd.sock"
PASS=0; FAIL=0; FAILED=()
DPID=""

cleanup() {
  [[ -n "$DPID" ]] && kill "$DPID" 2>/dev/null
  kill $(jobs -p) 2>/dev/null
  wait 2>/dev/null
  [[ "${KEEP:-}" == 1 ]] && echo "work dir kept: $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
check(){ local n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }

# ── topology ────────────────────────────────────────────────────────────────
unshare -n sleep infinity & SPID=$!
sleep 0.3
S() { nsenter -t "$SPID" -n -- "$@"; }

ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$SPID"
ip addr add 192.0.2.1/24 dev veth0
ip -6 addr add 2001:db8:1::1/64 dev veth0 nodad
ip link set veth0 up
ip route add default via 192.0.2.2
ip -6 route add default via 2001:db8:1::2
# a pre-existing firewall table owned by "someone else"
nft -f - <<'EOF'
table inet othertool {
  chain out {
    type filter hook output priority 0; policy accept;
    counter
  }
}
EOF

S ip link set lo up
S ip addr add 192.0.2.2/24 dev veth1
S ip -6 addr add 2001:db8:1::2/64 dev veth1 nodad
S ip link set veth1 up
S ip link add dummy0 type dummy
for a in 10 11 20 21 22 53; do S ip addr add 198.51.100.$a/32 dev dummy0; done
for a in 10 11; do S ip -6 addr add 2001:db8:ff::$a/128 dev dummy0 nodad; done
S ip link set dummy0 up

umask 077
CPRIV=$(wg genkey); CPUB=$(echo "$CPRIV" | wg pubkey)
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
S2PRIV=$(wg genkey); S2PUB=$(echo "$S2PRIV" | wg pubkey)
echo "$SPRIV" > "$WORK/s.key"; echo "$S2PRIV" > "$WORK/s2.key"
S ip link add wgs type wireguard
S wg set wgs listen-port 51820 private-key "$WORK/s.key" peer "$CPUB" allowed-ips 10.66.0.2/32,fd66::2/128
S ip addr add 10.66.0.1/24 dev wgs; S ip -6 addr add fd66::1/64 dev wgs nodad; S ip link set wgs up
S ip link add wgs2 type wireguard
S wg set wgs2 listen-port 51821 private-key "$WORK/s2.key" peer "$CPUB" allowed-ips 10.67.0.2/32,fd67::2/128
S ip addr add 10.67.0.1/24 dev wgs2; S ip -6 addr add fd67::1/64 dev wgs2 nodad; S ip link set wgs2 up

cat > "$WORK/records.json" <<'EOF'
{"bank.example.test": {"A": ["198.51.100.20"], "ttl": 2},
 "www.bank.example.test": {"cname": "edge.cdn.example.test", "ttl": 30},
 "edge.cdn.example.test": {"A": ["198.51.100.22"], "ttl": 30}}
EOF
nsenter -t "$SPID" -n -- python3 "$DIR/helper.py" recv 9999 "$WORK/recv.log" &
nsenter -t "$SPID" -n -- python3 "$DIR/helper.py" dns 198.51.100.53 "$WORK/records.json" "$WORK/dns.log" &
echo "nameserver 198.51.100.53" > "$WORK/resolv.conf"
touch "$WORK/recv.log" "$WORK/dns.log"
sleep 0.5

# ── helpers ─────────────────────────────────────────────────────────────────
N=0
send() { N=$((N+1)); PAYLOAD="p$N"; $H send "$1" 9999 "$PAYLOAD" ${2:-} 2>/dev/null; }
arrived_from() { sleep 0.4; grep -q "^$1 $PAYLOAD\$" "$WORK/recv.log"; }
not_arrived()  { sleep 0.6; ! grep -q " $PAYLOAD\$" "$WORK/recv.log"; }
ipc() { $H ipc "$SOCK" "$(tr -d '\n' <<<"$1")"; }
field() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(eval(sys.argv[1]))" "$1"; }
status() { ipc '{"id":1,"cmd":"get_status"}' | field "$1"; }
wait_state() { for _ in $(seq 1 ${2:-50}); do [[ "$(status "d['result']['Ok']['data']['state']")" == "$1" ]] && return 0; sleep 0.2; done; return 1; }
policy() { ipc "{\"id\":2,\"cmd\":\"set_policy\",\"policy\":$1}" ; }
spec() { # name addr4 addr6 port pub
  cat <<EOF
{"profile_id":"$1","profile_name":"$1","config":{"interface":{"private_key":"$CPRIV","addresses":["$2","$3"],"dns":["198.51.100.53"],"dns_search":[],"mtu":null,"listen_port":null},"peers":[{"public_key":"$5","preshared_key":null,"allowed_ips":["0.0.0.0/0","::/0"],"endpoint":{"host":{"kind":"ip","value":"192.0.2.2"},"port":$4},"persistent_keepalive":5}]},"cached_endpoints":[]}
EOF
}
connect() { ipc "{\"id\":3,\"cmd\":\"connect\",\"spec\":$(spec "$@" | tr -d '\n')}"; }
start_daemon() {
  "$BIN" --auth same-uid --dns-backend none --socket "$SOCK" --state-dir "$WORK/state" --resolv-conf "$WORK/resolv.conf" >>"$WORK/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 50); do [[ -S "$SOCK" ]] && ipc '{"id":0,"cmd":"hello","protocol":1}' >/dev/null 2>&1 && return 0; sleep 0.1; done
  echo "daemon did not start"; cat "$WORK/daemon.log"; exit 1
}
KS_ON='{"kill_switch":true,"allow_lan":false,"ipv4_enabled":true,"ipv6_enabled":true,"dns_leak_protection":true,"custom_dns":[],"auto_reconnect":true}'

echo "== baseline"
send 198.51.100.10;          check "no daemon: traffic leaves via physical link (sanity)" arrived_from 192.0.2.1

start_daemon
echo "== kill switch (protected, no tunnel)"
policy "$KS_ON" >/dev/null
check "state becomes protected" wait_state protected
check "firewall verified by kernel read-back" test "$(status "d['result']['Ok']['data']['kill_switch']['firewall_verified']")" = True
send 198.51.100.10;          check "IPv4 blocked while protected" not_arrived
send 2001:db8:ff::10;        check "IPv6 blocked while protected" not_arrived

echo "== connect profile A"
connect A 10.66.0.2/32 fd66::2/128 51820 "$SPUB" >/dev/null
check "state connected" wait_state connected
send 198.51.100.10;          check "IPv4 traffic goes through tunnel" arrived_from 10.66.0.2
send 2001:db8:ff::10;        check "IPv6 traffic goes through tunnel" arrived_from fd66::2
send 198.51.100.10 veth0;    check "IPv4 leak via SO_BINDTODEVICE(physical) blocked" not_arrived
send 2001:db8:ff::10 veth0;  check "IPv6 leak via SO_BINDTODEVICE(physical) blocked" not_arrived
before=$(grep -c "^RAW 192.0.2.1$" "$WORK/dns.log")
$H send 198.51.100.53 53 xxxxxxxxxxxxxxxxxx veth0 2>/dev/null; sleep 0.5
check "DNS to physical interface blocked (DNS leak)" test "$(grep -c "^RAW 192.0.2.1$" "$WORK/dns.log")" = "$before"
$H send 198.51.100.53 53 xxxxxxxxxxxxxxxxxx 2>/dev/null; sleep 0.5
check "DNS through tunnel allowed" grep -q "^RAW 10.66.0.2$" "$WORK/dns.log"

echo "== IPv6 disabled"
policy "${KS_ON/\"ipv6_enabled\":true/\"ipv6_enabled\":false}" >/dev/null
check "reconnected after family change" wait_state connected
send 2001:db8:ff::10;        check "IPv6 blocked (even inside tunnel)" not_arrived
send 198.51.100.10;          check "IPv4 still works" arrived_from 10.66.0.2
policy "$KS_ON" >/dev/null; wait_state connected
echo "== IPv4 disabled"
policy "${KS_ON/\"ipv4_enabled\":true/\"ipv4_enabled\":false}" >/dev/null
check "reconnected after family change" wait_state connected
send 198.51.100.10;          check "IPv4 blocked (even inside tunnel)" not_arrived
send 2001:db8:ff::10;        check "IPv6 still works" arrived_from fd66::2
policy "$KS_ON" >/dev/null; wait_state connected

echo "== split tunnelling (IP rules)"
ipc '{"id":4,"cmd":"set_split","config":{"enabled":true,"rules":[
 {"id":"r1","target":{"type":"ip","net":"198.51.100.10/32"},"action":"direct","enabled":true,"priority":100},
 {"id":"r2","target":{"type":"ip","net":"2001:db8:ff::10/128"},"action":"direct","enabled":true,"priority":100},
 {"id":"r3","target":{"type":"ip","net":"198.51.100.0/24"},"action":"vpn","enabled":true,"priority":100}]}}' >/dev/null
sleep 0.5
send 198.51.100.10;          check "IPv4 /32 Direct rule bypasses tunnel (with kill switch on)" arrived_from 192.0.2.1
send 198.51.100.11;          check "non-matching IPv4 still uses tunnel" arrived_from 10.66.0.2
send 2001:db8:ff::10;        check "IPv6 Direct rule bypasses tunnel" arrived_from 2001:db8:1::1
send 2001:db8:ff::11;        check "non-matching IPv6 still uses tunnel" arrived_from fd66::2
send 198.51.100.11 veth0;    check "kill switch still blocks non-bypassed leak" not_arrived

echo "== split tunnelling (domain rules, TTL, CNAME)"
ipc '{"id":5,"cmd":"set_split","config":{"enabled":true,"rules":[
 {"id":"d1","target":{"type":"domain","domain":"bank.example.test","mode":"exact"},"action":"direct","enabled":true,"priority":100},
 {"id":"d2","target":{"type":"domain","domain":"www.bank.example.test","mode":"exact"},"action":"direct","enabled":true,"priority":100}]}}' >/dev/null
sleep 1.5
send 198.51.100.20;          check "resolved domain address bypasses tunnel" arrived_from 192.0.2.1
send 198.51.100.22;          check "CNAME-chain target address bypasses tunnel" arrived_from 192.0.2.1
send 198.51.100.10;          check "address of removed rule uses tunnel again" arrived_from 10.66.0.2
check "resolver queried the DNS server through the tunnel" grep -q "^10.66.0.2 bank.example.test 1$" "$WORK/dns.log"
RT=$(ipc '{"id":6,"cmd":"test_route","query":"bank.example.test"}')
check "routing test tool: kernel set membership verified" test "$(echo "$RT" | field "d['result']['Ok']['data']['entries'][0]['in_kernel_direct_set']")" = True
check "routing test tool: intended path is bypass" grep -q "bypass" <<<"$RT"
sed -i 's/198.51.100.20/198.51.100.21/' "$WORK/records.json"
echo "   (waiting for TTL-driven refresh, up to 45 s)"
for _ in $(seq 1 45); do grep -q "^10.66.0.2 bank.example.test 1$" <(tail -n 3 "$WORK/dns.log") && sleep 2; send 198.51.100.21; grep -q "^192.0.2.1 $PAYLOAD\$" "$WORK/recv.log" && break; sleep 1; done
check "new DNS answer after TTL expiry is routed direct" grep -q "^192.0.2.1 $PAYLOAD\$" "$WORK/recv.log"
send 198.51.100.20;          check "expired address kept during grace period" arrived_from 192.0.2.1
ipc '{"id":7,"cmd":"set_split","config":{"enabled":false,"rules":[]}}' >/dev/null

echo "== firewall tamper recovery"
nft delete table inet alizy
sleep 3
check "table re-applied after deletion by another program" nft list table inet alizy
send 198.51.100.10 veth0;    check "leak still blocked after tamper" not_arrived
# Subtle tamper: keep the table and its tag, but insert an accept-all at the top.
nft insert rule inet alizy output position 0 accept 2>/dev/null || nft insert rule inet alizy output accept
sleep 0.3
# Detection latency is one supervisor interval (2 s): within 3 s the daemon must
# either report "not verified" or have already re-applied the table.
detected() { for _ in $(seq 1 15); do
  [[ "$(status "d['result']['Ok']['data']['kill_switch']['firewall_verified']")" != True ]] && { echo "reported unverified"; return 0; }
  nft list chain inet alizy output | grep -qE '^\s*accept\s*$' || { echo "already re-applied"; return 0; }
  sleep 0.2; done; return 1; }
check "tamper detected within one supervisor interval" detected
sleep 3
check "inserted accept rule removed by re-apply" bash -c "! nft list chain inet alizy output | grep -qE '^\s*accept\s*$'"
send 198.51.100.10 veth0;    check "leak blocked after subtle-tamper recovery" not_arrived

echo "== profile switch A -> B (atomic)"
( for i in $(seq 1 60); do $H send 198.51.100.10 9999 "switchleak" veth0 2>/dev/null; sleep 0.02; done ) &
LP=$!
connect B 10.67.0.2/32 fd67::2/128 51821 "$S2PUB" >/dev/null
wait $LP
check "state connected on profile B" wait_state connected
check "no packet leaked during switch" bash -c "! grep -q switchleak '$WORK/recv.log'"
send 198.51.100.10;          check "traffic uses new tunnel" arrived_from 10.67.0.2

echo "== unexpected VPN disconnection"
ip link del alizy0
send 198.51.100.10;          check "traffic blocked while tunnel is down" not_arrived
check "daemon detects the loss" wait_state reconnecting 30
check "daemon reconnects automatically" wait_state connected 75
send 198.51.100.10;          check "traffic flows again after reconnect" arrived_from 10.67.0.2

echo "== daemon crash"
kill -9 "$DPID"; wait "$DPID" 2>/dev/null; DPID=""
send 198.51.100.10 veth0;    check "kill switch persists after daemon crash (SIGKILL)" not_arrived
check "foreign table untouched" nft list table inet othertool
start_daemon
check "daemon recovers into protected state" wait_state protected
send 198.51.100.10;          check "traffic blocked after restart recovery" not_arrived
check "leftover interface removed on recovery" bash -c "! ip link show alizy0 2>/dev/null"

echo "== disconnect / disable"
connect A 10.66.0.2/32 fd66::2/128 51820 "$SPUB" >/dev/null; wait_state connected
ipc '{"id":8,"cmd":"disconnect"}' >/dev/null
check "disconnect with kill switch -> protected" wait_state protected
send 198.51.100.10;          check "blocked after disconnect" not_arrived
policy "${KS_ON/\"kill_switch\":true/\"kill_switch\":false}" >/dev/null
check "kill switch off -> disconnected" wait_state disconnected
send 198.51.100.10;          check "normal traffic restored after kill switch off" arrived_from 192.0.2.1
check "Alizy table removed when nothing to enforce" bash -c "! nft list table inet alizy 2>/dev/null"
check "foreign table still untouched" nft list table inet othertool
check "no private key in daemon log" bash -c "! grep -qF '$CPRIV' '$WORK/daemon.log'"

echo
echo "RESULT: $PASS passed, $FAIL failed"
for f in "${FAILED[@]}"; do echo "  - $f"; done
[[ $FAIL -eq 0 ]] || { echo "--- daemon log (tail)"; tail -n 40 "$WORK/daemon.log"; }
exit $(( FAIL > 0 ))
