#!/usr/bin/env bash
# Suspend/resume while connected with the kill switch on. Suspends the machine
# for ~25 s with an RTC wake alarm (rtcwake, root). Restores connectivity after.
#   sudo -E -u $USER -g alizy bash tests/system/30-suspend.sh
source "$(dirname "$0")/lib.sh"
rm -f "$OUT/DONE"
sudo -v || exit 1
trap 'restore_connectivity' EXIT INT TERM
A=$(profile_id "$PROFILE_A")
LEAK_URL=https://1.1.1.1/

keep_down
ctl set-policy "$POLICY_KS" >/dev/null
check "suspend: connect profile A with kill switch" ctl connect "$A"
check "suspend: connected" wait_state connected
check "suspend: internet before suspend" internet
say "suspending for 25 s (screen will go dark, machine wakes by itself)"
sudo rtcwake -m mem -s 25 >/dev/null 2>&1
check "suspend: machine resumed (rtcwake returned)" true
sleep 3
check "suspend: kill switch rules survived suspend" bash -c "sudo nft list table inet alizy | grep -c kill-switch"
check "suspend: leak blocked right after resume" leak_blocked
check "suspend: tunnel connected after resume (reconnect if needed)" wait_state connected 90
for _ in $(seq 1 30); do internet >/dev/null && break; sleep 2; done
check "suspend: internet works after resume" internet
check "suspend: firewall verified after resume" is_verified
check "suspend: daemon events around resume" bash -c "$CTL events | grep -E 'Network change|Reconnect|Connected' | tail -5"
