#!/usr/bin/env bash
# Real-system validation of Alizy SSH profiles (see tests/ssh/README.md).
# Usage: tests/ssh/run.sh <host-lan-ip> <password-file> <pkg-dir> [log]
# Runs as your user; uses sudo for install and root-only inspection.
set -u
HOST=$1; PWF=$2; PKG=$3; LOG=${4:-/tmp/alizy-ssh-test.log}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTL="$ROOT/target/debug/examples/alizyctl"
exec > >(tee "$LOG") 2>&1
step() { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; }
#key() { python3 -c 'import json,sys; e=json.loads(sys.stdin.read()).get("result",{}).get("Err") or json.loads(sys.argv[1])["result"].get("Err",{}); print(e["host_key"]["key_type"], e["host_key"]["key_b64"])' "$1" <<<"$1" 2>/dev/null; }

step "install"
if [ -z "${SKIP_INSTALL:-}" ]; then
sudo pacman -S --needed --noconfirm badvpn
sudo pacman -U --noconfirm "$PKG"/alizyd-0.1.0-7-*.pkg.tar.zst "$PKG"/alizy-0.1.0-7-*.pkg.tar.zst
sudo systemctl daemon-reload && sudo systemctl restart alizyd && sleep 2
fi
systemctl is-active alizyd && id alizy-ssh && ls -ld /run/alizy/ssh
ORIG_POLICY=$("$CTL" policy | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["data"]))')
echo "original policy: $ORIG_POLICY"
"$CTL" set-policy "$(python3 -c 'import json,sys; p=json.loads(sys.argv[1]); p["kill_switch"]=True; print(json.dumps(p))' "$ORIG_POLICY")" >/dev/null

step "first connect (expect host_key_unknown)"
R=$("$CTL" ssh-connect "$HOST" 2222 alice < "$PWF"); echo "$R" | cut -c1-300
read -r KT KB <<<"$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); e=r["result"]["Err"]; print(e["code"], e["host_key"]["key_type"], e["host_key"]["key_b64"])' "$R" | cut -d' ' -f2-)"
[ -n "${KB:-}" ] && pass "host key returned ($KT)" || fail "no host key"
"$CTL" status | grep -E '"state"'

step "connect with pinned key"
T0=$(date +%s); R=$("$CTL" ssh-connect "$HOST" 2222 alice "$KT" "$KB" < "$PWF"); echo "$R" | cut -c1-300; echo "took $(( $(date +%s)-T0 ))s"
"$CTL" status | grep -E '"state"|"interface"|tunnel_kind'
ps -o user=,comm= -C ssh,badvpn-tun2socks
ip -4 addr show alizy0 | grep inet

step "traffic through the tunnel"
curl -s -m 10 http://10.99.0.1/ | grep -q via-ssh-tunnel && pass "HTTP via tunnel" || fail "HTTP via tunnel"
resolvectl query alizy-test.example 2>&1 | head -2
getent hosts alizy-test.example | grep -q 10.99.0.1 && pass "DNS via forwarder (resolver)" || fail "DNS via forwarder"
python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"x",("10.99.0.1",9999)); s.recvfrom(10); print("FAIL: UDP not rejected")
except ConnectionRefusedError: print("PASS: UDP rejected fast (ECONNREFUSED)")
except socket.timeout: print("FAIL: UDP timed out (not rejected fast)")
except OSError as e: print("PASS: UDP blocked:", e)
PY
"$CTL" verify | grep -E 'verified|true|false' | head -3
sudo nft list table inet alizy > /tmp/alizy-ssh-nft.txt && grep -cE 'ssh_mark|ssh_nat|ssh_pre|l4proto udp reject' /tmp/alizy-ssh-nft.txt
sudo ls -l /run/alizy/ssh/

step "kill switch while server down"
podman stop -t 1 alizy-test-sshd >/dev/null; sleep 50
"$CTL" status | grep -E '"state"'
curl -s -m 5 http://1.0.0.1/ >/dev/null && fail "traffic leaked with server down" || pass "traffic blocked with server down"
step "recovery"
SP=$(dirname "$PWF"); podman run -d --rm --name alizy-test-sshd --cap-add NET_ADMIN -p 2222:22 -v "$PWF":/run/secrets/alice_pw:ro,Z alizy-test-sshd >/dev/null
for i in $(seq 1 30); do "$CTL" status | grep -q '"state": "connected"' && break; sleep 3; done
"$CTL" status | grep -E '"state"'
curl -s -m 10 http://10.99.0.1/ | grep -q via-ssh-tunnel && pass "recovered after server restart" || fail "no recovery (new host key in container restart is expected to block: check state above)"

step "disconnect + wrong password"
"$CTL" disconnect >/dev/null
KEY2=$(podman exec alizy-test-sshd cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1, $2}')
T0=$(date +%s); R=$(echo wrong-password | "$CTL" ssh-connect "$HOST" 2222 alice $KEY2); echo "$R" | cut -c1-200; echo "took $(( $(date +%s)-T0 ))s"
echo "$R" | grep -q auth_failed && pass "auth_failed" || fail "expected auth_failed"
sleep 6; "$CTL" status | grep -E '"state"|reconnect_attempt'

step "changed host key"
R=$("$CTL" ssh-connect "$HOST" 2222 alice "$KT" "$KB" < "$PWF"); echo "$R" | cut -c1-200
echo "$R" | grep -qE 'host_key_changed' && pass "host_key_changed detected" || echo "INFO: (same key reused by container?)"

step "cleanup"
"$CTL" disconnect >/dev/null; "$CTL" set-policy "$ORIG_POLICY" >/dev/null
"$CTL" status | grep -E '"state"'; ip link show alizy0 2>&1 | head -1
pgrep -u alizy-ssh -l || echo "no alizy-ssh processes left"
echo; echo "Log: $LOG"
