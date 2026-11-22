# Shared helpers for the real-system validation scripts.
# These scripts run as the NORMAL USER (inside `sg alizy`), and use `sudo` only
# for the specific root operations noted. They never print private keys.

set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CTL="$ROOT/target/debug/examples/alizyctl"
H="python3 $ROOT/tests/leak/helper.py"
OUT=${OUT:-$ROOT/target/system-validation}
mkdir -p "$OUT"
RESULTS="$OUT/results.tsv"
PHYS=${PHYS:-wlan0}
# Test profiles (names as shown in Alizy) and, optionally, a NetworkManager
# connection that must be taken down during tests and always restored after.
PROFILE_A=${ALIZY_TEST_PROFILE_A:?set ALIZY_TEST_PROFILE_A to the name of an imported profile}
PROFILE_B=${ALIZY_TEST_PROFILE_B:-}
KEEP_CONN=${ALIZY_KEEP_CONN:-}
keep_down() { [[ -n $KEEP_CONN ]] && nmcli con down "$KEEP_CONN" >/dev/null 2>&1; true; }
keep_up() { [[ -z $KEEP_CONN ]] && return 0; for _ in 1 2 3; do nmcli con up "$KEEP_CONN" >/dev/null 2>&1 && return 0; sleep 3; done; }
ROUTER_DNS=${ROUTER_DNS:-192.168.0.1}
PASS=0; FAIL=0

say()    { printf '\n\033[1m== %s\033[0m\n' "$*"; echo "== $*" >> "$OUT/transcript.log"; }
record() { # name result evidence
  printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\n\t' '  ' <<<"$3" | cut -c1-600)" >> "$RESULTS"
  printf '  %-6s %s\n' "$2" "$1"
  [[ $2 == PASS ]] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
}
# check NAME EVIDENCE-CMD -- TEST-CMD...   (evidence captured from the test command's output)
check() {
  local name=$1; shift
  local ev; ev=$("$@" 2>&1); local rc=$?
  if [[ $rc -eq 0 ]]; then record "$name" PASS "$ev"; else record "$name" FAIL "$ev"; fi
}
not() { ! "$@"; }
# Run a command as this user with group alizy active (sg/newgrp are not
# installed everywhere). Same login session, so polkit sees an active subject.
asgroup() { sudo -E -u "$USER" -g alizy -- bash -c "$1"; }

ctl()   { "$CTL" "$@"; }
# Raw socket hello using only the system python (works for any uid).
SOCK_HELLO='import socket,sys
s=socket.socket(socket.AF_UNIX)
try:
    s.connect("/run/alizy/alizyd.sock")
except OSError as e:
    print("refused:", e); sys.exit(1)
s.sendall(b"{\"id\":1,\"cmd\":\"hello\",\"protocol\":1}\n"); r=s.recv(4096).decode()
print(r or "closed by daemon"); sys.exit(0 if "protocol" in r else 1)'

jq_()   { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
state() { ctl status 2>/dev/null | jq_ "d['data']['state']" 2>/dev/null || echo unreachable; }
wait_state() { local want=$1 t=${2:-40}; for _ in $(seq 1 $((t*5))); do [[ $(state) == "$want" ]] && { echo "state=$want"; return 0; }; sleep 0.2; done; echo "state=$(state), wanted $want"; return 1; }
verified() { ctl status | jq_ "d['data']['kill_switch']['firewall_verified']"; }
profile_id() { ctl list | awk -v n="$1" '$2==n {print $1}'; }

# Traffic probes — real packets, real interfaces.
pub_ip()     { curl -4 -s --max-time 8 https://api.ipify.org; }
internet()   { curl -4 -s -o /dev/null --max-time 6 -w '%{http_code}' https://www.google.com/generate_204 | grep -q 204 && echo "internet reachable"; }
# Leak probe: a socket forced onto the physical interface (SO_BINDTODEVICE, needs root).
leak_tcp()   { sudo curl -4 -s -o /dev/null --max-time 5 --interface "$PHYS" -w '%{http_code}' https://1.1.1.1/ ; }
leak_blocked() { local c; c=$(leak_tcp); [[ -z $c || $c == 000 ]] && echo "physical-interface TCP to ${LEAK_URL:-1.1.1.1} blocked (code=${c:-none})"; }
is_verified() { [[ $(verified) == True ]] && echo "firewall_verified=true"; }
leak_open()  { local c; c=$(leak_tcp); [[ -n $c && $c != 000 ]] && echo "physical-interface TCP reached ${LEAK_URL:-1.1.1.1} (code=$c)"; }
dns_leak_blocked() { sudo $H dnsq "$ROUTER_DNS" example.com "$PHYS" 2>&1 && return 1; echo "DNS to router $ROUTER_DNS via $PHYS got no answer"; }
dns_works()  { getent ahostsv4 example.com >/dev/null && echo "system resolver answered example.com"; }

ruleset_snapshot() { sudo nft list ruleset; }
foreign_tables() { sudo nft list tables | grep -v 'inet alizy' | sort; }

net_policy() { # ks lan v4 v6 dnsleak customdns(json array) autoreconnect
  echo "{\"kill_switch\":$1,\"allow_lan\":$2,\"ipv4_enabled\":$3,\"ipv6_enabled\":$4,\"dns_leak_protection\":$5,\"custom_dns\":$6,\"auto_reconnect\":$7}"
}
POLICY_OFF=$(net_policy false true true true true '[]' true)
POLICY_KS=$(net_policy true false true true true '[]' true)

# Always leave the machine usable: Alizy off, kill switch off, $KEEP_CONN back up.
restore_connectivity() {
  echo; echo "-- restoring connectivity (Alizy disconnect, kill switch off${KEEP_CONN:+, $KEEP_CONN up})"
  ctl set-policy "$POLICY_OFF" >/dev/null 2>&1
  ctl disconnect >/dev/null 2>&1
  ctl set-split <(echo '{"enabled":false,"rules":[]}') >/dev/null 2>&1
  nmcli radio wifi on >/dev/null 2>&1
  keep_up
  internet || echo "WARNING: internet not reachable after restore"
  echo "summary: $PASS passed, $FAIL failed (details: $RESULTS)"
  date > "$OUT/DONE"
}
