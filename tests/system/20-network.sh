#!/usr/bin/env bash
# Real-host network validation: tunnel, kill switch, leaks, DNS (systemd-resolved),
# split tunnelling, profile switching, GUI kill, Wi-Fi change, family toggles,
# DNS failure, daemon SIGKILL/restart, cleanup.
#
# Run as the normal user, inside the alizy group, from the desktop terminal:
#   sudo -E -u $USER -g alizy bash tests/system/20-network.sh
# Takes NetworkManager's $KEEP_CONN down for the duration and ALWAYS brings it back
# (trap), together with: Alizy disconnected, kill switch off, split rules cleared.
source "$(dirname "$0")/lib.sh"
rm -f "$OUT/DONE"
sudo -v || exit 1
( while sleep 50; do sudo -n -v 2>/dev/null; done ) & KEEPALIVE=$!
trap 'kill $KEEPALIVE 2>/dev/null; restore_connectivity' EXIT INT TERM

A=$(profile_id "$PROFILE_A"); B=$(profile_id "$PROFILE_B")
[[ -n $A && -n $B ]] || { echo "set ALIZY_TEST_PROFILE_A/B to two imported profiles"; exit 1; }

say "take NetworkManager $KEEP_CONN down (restored at the end)"
keep_down; sleep 2
say "baseline ($KEEP_CONN down, Alizy idle)"
foreign_tables > "$OUT/tables.before"
ip rule > "$OUT/iprule.before"; ip -6 rule > "$OUT/ip6rule.before"
resolvectl status "$PHYS" 2>&1 | grep -E 'DNS Servers|DNS Domain|Default Route' > "$OUT/resolved.before"
readlink -f /etc/resolv.conf > "$OUT/resolvconf.before"
record "baseline captured" PASS "$(cat "$OUT/tables.before" | tr '\n' ' ') | resolv.conf -> $(cat "$OUT/resolvconf.before")"

# Choose a leak-probe target that is reachable directly over $PHYS right now,
# so a blocked probe later means "blocked by Alizy", not "blocked by the ISP".
LEAK_URL=""
for u in https://1.1.1.1/ https://8.8.8.8/ http://$ROUTER_DNS/; do
  c=$(sudo curl -4 -sk -o /dev/null --max-time 5 --interface "$PHYS" -w '%{http_code}' "$u")
  if [[ -n $c && $c != 000 ]]; then LEAK_URL=$u; break; fi
done
leak_tcp() { sudo curl -4 -sk -o /dev/null --max-time 5 --interface "$PHYS" -w '%{http_code}' "$LEAK_URL"; }
if [[ -n $LEAK_URL ]]; then record "control: direct traffic over $PHYS works without Alizy" PASS "target $LEAK_URL reachable"
else record "control: direct traffic over $PHYS works without Alizy" FAIL "no direct target reachable; leak verdicts below are not meaningful"; fi
DIRECT_DNS_OK=no; sudo $H dnsq "$ROUTER_DNS" example.com "$PHYS" 2>/dev/null && DIRECT_DNS_OK=yes
record "control: router DNS answers over $PHYS without Alizy" "$([[ $DIRECT_DNS_OK == yes ]] && echo PASS || echo FAIL)" "router $ROUTER_DNS"

say "connect profile A (kill switch off)"
ctl set-policy "$POLICY_OFF" >/dev/null
check "connect profile A" ctl connect "$A"
check "daemon state connected" wait_state connected
sleep 2
check "internet works through alizy0" internet
VPN_A=$(pub_ip); check "public IP obtained through tunnel" test -n "$VPN_A"
check "resolved: alizy0 has VPN DNS and ~. routing domain" bash -c "resolvectl status alizy0 | tee /dev/stderr | grep -q '~\.' && resolvectl dns alizy0 | grep -q 1.1.1.1"
check "system resolver works while connected" dns_works
check "DNS leak protection: router DNS over $PHYS blocked (kill switch off)" dns_leak_blocked

say "kill switch on"
check "enable kill switch" ctl set-policy "$POLICY_KS"
check "kill switch verified against kernel" is_verified
check "kernel table inet alizy present with kill-switch rule" bash -c "sudo nft list table inet alizy | grep -c kill-switch"
check "internet still works through tunnel" internet
check "leak: TCP forced onto $PHYS is blocked" leak_blocked
check "DNS leak: router DNS over $PHYS blocked" dns_leak_blocked
check "foreign nftables tables unchanged" bash -c "diff <(cat $OUT/tables.before) <(sudo nft list tables | grep -v 'inet alizy' | sort) && echo identical"

say "split tunnelling: Direct exception for api.ipify.org"
echo '{"enabled":true,"rules":[{"id":"t1","target":{"type":"domain","domain":"api.ipify.org","mode":"exact"},"action":"direct","enabled":true,"priority":100,"category":null,"note":null}]}' > "$OUT/split.json"
check "apply split rule" ctl set-split "$OUT/split.json"
sleep 4
DIRECT_IP=$(pub_ip)
check "Direct domain bypasses the tunnel (ipify sees a different IP than the VPN)" bash -c "[[ -n '$DIRECT_IP' && '$DIRECT_IP' != '$VPN_A' ]] && echo 'ipify via physical: differs from VPN IP'"
check "other sites still use the tunnel" bash -c "ip=\$(curl -4 -s --max-time 8 https://icanhazip.com); [[ \$ip == '$VPN_A' ]] && echo 'icanhazip sees VPN IP'"
check "routing test tool confirms kernel set membership" bash -c "$CTL route-test api.ipify.org | tee /dev/stderr | grep -q '\"in_kernel_direct_set\": true'"
check "leak still blocked for non-bypassed traffic" leak_blocked
check "DNS still never bypasses (router DNS blocked)" dns_leak_blocked
ctl set-split <(echo '{"enabled":false,"rules":[]}') >/dev/null

say "profile switch A -> B while protected, under continuous leak probing"
( n=0; for i in $(seq 1 40); do c=$(leak_tcp); [[ -n $c && $c != 000 ]] && n=$((n+1)); sleep 0.2; done; echo $n > "$OUT/switch.leaks" ) &
PROBE=$!
check "switch to profile B" ctl connect "$B"
wait $PROBE
check "zero probe packets leaked during the switch" bash -c "n=\$(cat $OUT/switch.leaks); echo \"leaked=\$n\"; [[ \$n == 0 ]]"
check "connected on profile B" wait_state connected
check "internet works on profile B" internet

say "kill the GUI process"
if command -v alizy >/dev/null; then
  (alizy >/dev/null 2>&1 &) ; sleep 6
  check "GUI started as normal user" pgrep -u "$USER" -x alizy
  pkill -9 -u "$USER" -x alizy; sleep 1
  check "after GUI SIGKILL: kill switch still verified" is_verified
  check "after GUI SIGKILL: tunnel still carries traffic" internet
  check "after GUI SIGKILL: leak still blocked" leak_blocked
fi

say "network change: Wi-Fi off/on"
nmcli radio wifi off; sleep 4
check "while Wi-Fi is off, nothing leaks (no route, rules intact)" bash -c "sudo nft list table inet alizy | grep -q kill-switch && echo rules-present"
nmcli radio wifi on
for _ in $(seq 1 30); do nmcli -t -f STATE general | grep -q '^connected' && break; sleep 1; done
check "back to connected after Wi-Fi returns" wait_state connected 60
check "internet works after network change" internet
check "leak blocked after network change" leak_blocked
check "firewall verified after network change" is_verified

say "IPv6 disabled / IPv4 disabled"
check "disable IPv6" ctl set-policy "$(net_policy true false true false true '[]' true)"
check "connected after IPv6-off rebuild" wait_state connected
check "kernel blocks IPv6 (rule present)" bash -c "sudo nft list table inet alizy | grep -c ipv6-disabled"
check "IPv4 internet unaffected" internet
check "disable IPv4 (IPv6 on)" ctl set-policy "$(net_policy true false false true true '[]' true)"
sleep 3
check "IPv4 traffic blocked when IPv4 is disabled" not internet
check "warning raised: profile cannot carry traffic" bash -c "$CTL events | grep -q 'cannot carry any traffic' && echo warned"
check "re-enable both families" ctl set-policy "$POLICY_KS"
check "connected again" wait_state connected
check "internet back" internet

say "DNS failure and recovery"
check "set unreachable custom DNS" ctl set-policy "$(net_policy true false true true true '["10.255.255.1"]' true)"
check "connected with custom DNS" wait_state connected
sleep 2
check "lookups fail with dead DNS (no fallback leak)" not getent ahostsv4 "probe-$RANDOM.example.com"
check "router DNS still blocked during DNS failure" dns_leak_blocked
check "restore profile DNS" ctl set-policy "$POLICY_KS"
check "connected" wait_state connected
sleep 2
check "lookups recover" dns_works

say "daemon SIGKILL"
sudo systemctl kill -s KILL alizyd
check "immediately after SIGKILL: leak blocked (kernel rules persist)" leak_blocked
sleep 4
check "systemd restarted the daemon" systemctl is-active alizyd
check "recovered into protected state" wait_state protected 20
check "while protected: no internet" not internet
check "while protected: leak blocked" leak_blocked
check "while protected: firewall verified" is_verified
check "reconnect profile A after recovery" ctl connect "$A"
check "connected" wait_state connected
check "internet back" internet

say "disconnect with kill switch, restart daemon"
check "disconnect" ctl disconnect
check "state protected" wait_state protected
check "no internet while protected" not internet
check "DNS blocked while protected" not dns_works
check "alizy0 DNS gone after disconnect" bash -c "! resolvectl status alizy0 2>/dev/null | grep -q 'DNS Servers' && echo removed"
sudo systemctl restart alizyd; sleep 2
check "after service restart: still protected" wait_state protected 20
check "after service restart: leak blocked" leak_blocked

say "kill switch off: full cleanup"
check "kill switch off" ctl set-policy "$POLICY_OFF"
check "state disconnected" wait_state disconnected
check "Alizy nft table removed" bash -c "! sudo nft list table inet alizy >/dev/null 2>&1 && echo removed"
check "ip rules identical to baseline" bash -c "diff $OUT/iprule.before <(ip rule) && diff $OUT/ip6rule.before <(ip -6 rule) && echo identical"
check "foreign nftables tables identical to baseline" bash -c "diff $OUT/tables.before <(sudo nft list tables | grep -v 'inet alizy' | sort) && echo identical"
check "resolved config of $PHYS identical to baseline" bash -c "diff $OUT/resolved.before <(resolvectl status $PHYS 2>&1 | grep -E 'DNS Servers|DNS Domain|Default Route') && echo identical"
check "/etc/resolv.conf still points to the resolved stub" bash -c "[[ \$(readlink -f /etc/resolv.conf) == \$(cat $OUT/resolvconf.before) ]] && echo identical"
check "no private key in the daemon journal" bash -c "! sudo journalctl -u alizyd -b --no-pager | grep -E '[A-Za-z0-9+/]{43}=' && echo 'no key-shaped strings'"
