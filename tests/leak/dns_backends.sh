#!/usr/bin/env bash
# DNS backend integration test for the `file` (plain /etc/resolv.conf, e.g.
# NetworkManager-managed) and `resolvconf` (openresolv) backends.
#
# Runs alizyd in unprivileged user + network + MOUNT namespaces with a private
# tmpfs over /etc and /run, so the host's real /etc/resolv.conf is never
# touched. A WireGuard server runs in a second namespace (as in run.sh).
#
# Usage: tests/leak/dns_backends.sh file|resolvconf
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
BACKEND=${1:-file}

if [[ "${ALIZY_IN_NS:-}" != 1 ]]; then
  [[ "${NO_BUILD:-}" == 1 ]] || (cd "$ROOT" && cargo build -q -p alizyd) || exit 1
  if [[ $BACKEND == resolvconf ]] && ! command -v resolvconf >/dev/null; then
    echo "SKIP: resolvconf (openresolv) is not installed"; exit 77
  fi
  exec env ALIZY_IN_NS=1 unshare -rnm --kill-child -- bash "$0" "$@"
fi

PASS=0; FAIL=0; FAILED=()
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
check(){ local n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }

BIN="$ROOT/target/debug/alizyd"
H="python3 $DIR/helper.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/alizy-dns.XXXXXX")
DPID=""
trap '[[ -n "$DPID" ]] && kill $DPID 2>/dev/null; kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"' EXIT

# ── private /etc and /run ───────────────────────────────────────────────────
mkdir -p "$WORK/etc"
for f in passwd group nsswitch.conf hosts resolvconf.conf protocols services ld.so.cache; do
  [[ -e /etc/$f ]] && cp -L "/etc/$f" "$WORK/etc/" 2>/dev/null
done
[[ -d /etc/iproute2 ]] && cp -rL /etc/iproute2 "$WORK/etc/"
mount -t tmpfs tmpfs /etc && cp -a "$WORK/etc/." /etc/
mount -t tmpfs tmpfs /run
ORIGINAL="# original resolv.conf (simulated NetworkManager)
nameserver 192.0.2.2
search home.example"
case $BACKEND in
  file) printf '%s\n' "$ORIGINAL" > /etc/resolv.conf ;;
  resolvconf)
    mkdir -p /run/resolvconf
    printf 'resolv_conf=/etc/resolv.conf\n' > /etc/resolvconf.conf
    printf 'nameserver 192.0.2.2\nsearch home.example\n' | resolvconf -a veth0.dhcp
    cp /etc/resolv.conf "$WORK/orig.resolv.conf" ;;
esac
ORIG_SUM=$(sha256sum /etc/resolv.conf | cut -d' ' -f1)

# ── topology (as run.sh) ────────────────────────────────────────────────────
unshare -n sleep infinity & SPID=$!; sleep 0.3
S() { nsenter -t "$SPID" -n -- "$@"; }
ip link set lo up
ip link add veth0 type veth peer name veth1; ip link set veth1 netns "$SPID"
ip addr add 192.0.2.1/24 dev veth0; ip link set veth0 up; ip route add default via 192.0.2.2
S ip link set lo up; S ip addr add 192.0.2.2/24 dev veth1; S ip link set veth1 up
S ip link add dummy0 type dummy; S ip addr add 198.51.100.53/32 dev dummy0; S ip link set dummy0 up
umask 077
CPRIV=$(wg genkey); CPUB=$(echo "$CPRIV" | wg pubkey); SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
echo "$SPRIV" > "$WORK/s.key"
S ip link add wgs type wireguard
S wg set wgs listen-port 51820 private-key "$WORK/s.key" peer "$CPUB" allowed-ips 10.66.0.2/32
S ip addr add 10.66.0.1/24 dev wgs; S ip link set wgs up
echo '{"vpn.test": {"A": ["198.51.100.53"], "ttl": 30}}' > "$WORK/records.json"
nsenter -t "$SPID" -n -- python3 "$DIR/helper.py" dns 198.51.100.53 "$WORK/records.json" "$WORK/dns.log" &
sleep 0.4

SOCK="$WORK/s.sock"
ipc() { $H ipc "$SOCK" "$(tr -d '\n' <<<"$1")"; }
state() { ipc '{"id":1,"cmd":"get_status"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['result']['Ok']['data']['state'])"; }
wait_state() { for _ in $(seq 1 50); do [[ "$(state)" == "$1" ]] && return 0; sleep 0.2; done; return 1; }
start() {
  "$BIN" --auth same-uid --dns-backend "$BACKEND" --socket "$SOCK" --state-dir "$WORK/state" >>"$WORK/d.log" 2>&1 & DPID=$!
  for _ in $(seq 1 50); do [[ -S $SOCK ]] && ipc '{"id":0,"cmd":"hello","protocol":1}' >/dev/null 2>&1 && return; sleep 0.1; done
  echo "daemon failed"; cat "$WORK/d.log"; exit 1
}
connect() {
  ipc "{\"id\":3,\"cmd\":\"connect\",\"spec\":{\"profile_id\":\"A\",\"profile_name\":\"A\",\"config\":{\"interface\":{\"private_key\":\"$CPRIV\",\"addresses\":[\"10.66.0.2/32\"],\"dns\":[\"198.51.100.53\"],\"dns_search\":[],\"mtu\":null,\"listen_port\":null},\"peers\":[{\"public_key\":\"$SPUB\",\"preshared_key\":null,\"allowed_ips\":[\"0.0.0.0/0\"],\"endpoint\":{\"host\":{\"kind\":\"ip\",\"value\":\"192.0.2.2\"},\"port\":51820},\"persistent_keepalive\":5}]},\"cached_endpoints\":[]}}" >/dev/null
}
resolv_has_vpn() { grep -q "^nameserver 198.51.100.53" /etc/resolv.conf; }
resolv_original() { [[ "$(sha256sum /etc/resolv.conf | cut -d' ' -f1)" == "$ORIG_SUM" ]]; }
query_ok() { NS=${1:-} python3 - <<'EOF'
import os
import socket,struct,sys,random
q=struct.pack("!HHHHHH",random.randint(0,65535),0x100,1,0,0,0)+b"\x03vpn\x04test\x00\x00\x01\x00\x01"
ns=os.environ.get("NS") or [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")][0]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(q,(ns,53))
try: s.recv(512); sys.exit(0)
except Exception: sys.exit(1)
EOF
}

echo "== DNS backend: $BACKEND"
start
connect
check "connected" wait_state connected
check "VPN DNS installed in resolv.conf" resolv_has_vpn
check "lookup via VPN DNS works through the tunnel" query_ok
check "query reached the DNS server from the tunnel address" grep -q "^RAW 10.66.0.2$" "$WORK/dns.log"
if [[ $BACKEND == file ]]; then
  printf 'nameserver 192.0.2.99\n# rewritten by NetworkManager\n' > /etc/resolv.conf
  sleep 3
  check "overwrite by another manager is re-asserted within 3 s" resolv_has_vpn
  ORIG_SUM=$(printf 'nameserver 192.0.2.99\n# rewritten by NetworkManager\n' | sha256sum | cut -d' ' -f1)
fi
ipc '{"id":4,"cmd":"disconnect"}' >/dev/null
check "disconnected" wait_state disconnected
check "resolv.conf restored after disconnect" resolv_original

connect; wait_state connected
kill -9 "$DPID"; wait "$DPID" 2>/dev/null; DPID=""
check "VPN DNS still present right after daemon SIGKILL (expected)" resolv_has_vpn
start
check "daemon recovered" wait_state disconnected
check "resolv.conf restored by crash recovery" resolv_original

ipc '{"id":5,"cmd":"set_policy","policy":{"kill_switch":true,"allow_lan":false,"ipv4_enabled":true,"ipv6_enabled":true,"dns_leak_protection":true,"custom_dns":["198.51.100.53"],"auto_reconnect":true}}' >/dev/null
connect; wait_state connected
check "custom DNS applied with kill switch" resolv_has_vpn
ipc '{"id":6,"cmd":"disconnect"}' >/dev/null; wait_state protected
check "resolv.conf restored while kill switch stays on" resolv_original
not() { ! "$@"; }
check "lookup blocked while protected (no tunnel)" not query_ok 198.51.100.53
ipc '{"id":7,"cmd":"set_policy","policy":{"kill_switch":false,"allow_lan":true,"ipv4_enabled":true,"ipv6_enabled":true,"dns_leak_protection":true,"custom_dns":[],"auto_reconnect":true}}' >/dev/null
check "kill switch off" wait_state disconnected
check "same DNS server reachable again once kill switch is off (control)" query_ok 198.51.100.53
check "no backup file left behind" bash -c "! ls $WORK/state/resolv.conf.* 2>/dev/null | grep -q ."

if [[ $BACKEND == file ]]; then
  echo "== hostname endpoint + kill switch (DNS blocked on reconnect)"
  echo '{"vpn.test": {"A": ["198.51.100.53"], "ttl": 30}, "endpoint.test": {"A": ["192.0.2.2"], "ttl": 30}}' > "$WORK/records.json"
  printf 'nameserver 198.51.100.53\n' > /etc/resolv.conf
  connect_host() {
    ipc "{\"id\":8,\"cmd\":\"connect\",\"spec\":{\"profile_id\":\"H\",\"profile_name\":\"H\",\"config\":{\"interface\":{\"private_key\":\"$CPRIV\",\"addresses\":[\"10.66.0.2/32\"],\"dns\":[\"198.51.100.53\"],\"dns_search\":[],\"mtu\":null,\"listen_port\":null},\"peers\":[{\"public_key\":\"$SPUB\",\"preshared_key\":null,\"allowed_ips\":[\"0.0.0.0/0\"],\"endpoint\":{\"host\":{\"kind\":\"name\",\"value\":\"endpoint.test\"},\"port\":51820},\"persistent_keepalive\":5}]},\"cached_endpoints\":[]}}"
  }
  connect_host >/dev/null
  check "hostname endpoint resolved via DNS and connected" wait_state connected
  ipc '{"id":9,"cmd":"disconnect"}' >/dev/null; wait_state disconnected
  ipc '{"id":10,"cmd":"set_policy","policy":{"kill_switch":true,"allow_lan":false,"ipv4_enabled":true,"ipv6_enabled":true,"dns_leak_protection":true,"custom_dns":[],"auto_reconnect":true}}' >/dev/null
  check "protected" wait_state protected
  check "DNS really blocked while protected" not query_ok 198.51.100.53
  out=$(connect_host)
  check "reconnect while DNS is blocked uses the remembered endpoint address" wait_state connected
  [[ $(state) == connected ]] || echo "    daemon said: $out"
  kill -9 "$DPID"; wait "$DPID" 2>/dev/null; DPID=""; start
  check "remembered endpoint survives a daemon restart (persisted)" bash -c "grep -q 'endpoint.test:51820' $WORK/state/state.json && echo persisted"
  ipc '{"id":11,"cmd":"set_policy","policy":{"kill_switch":false,"allow_lan":true,"ipv4_enabled":true,"ipv6_enabled":true,"dns_leak_protection":true,"custom_dns":[],"auto_reconnect":true}}' >/dev/null
fi

echo; echo "RESULT ($BACKEND): $PASS passed, $FAIL failed"
for f in "${FAILED[@]}"; do echo "  - $f"; done
[[ $FAIL -eq 0 ]] || tail -n 30 "$WORK/d.log"
exit $(( FAIL > 0 ))
