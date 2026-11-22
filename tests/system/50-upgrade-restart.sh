#!/usr/bin/env bash
# Upgrade to a new package while connected with the kill switch on, then check
# that the NEW GUI reconnects by itself after a service restart.
# Always ends connected (falls back to alizyctl if the GUI does not reconnect).
#   bash tests/system/50-upgrade-restart.sh <alizyd.pkg> <alizy.pkg> <profile-id>
source "$(dirname "$0")/lib.sh"
rm -f "$OUT/DONE"
PKG_D=$1; PKG_G=$2; PID_PROFILE=$3
sudo -v || exit 1
st() { ctl status 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin)['data'];print(d['state'])" 2>/dev/null || echo unreachable; }
ensure_connected() { [[ $(st) == connected ]] || ctl connect "$PID_PROFILE" >/dev/null 2>&1; wait_state connected 30 >/dev/null; }
trap 'ensure_connected; internet; echo "summary: $PASS passed, $FAIL failed"; date > "$OUT/DONE"' EXIT

say "upgrade while connected (old GUI cannot reconnect: reconnect via CLI)"
OLD=$(systemctl show alizyd -p MainPID --value)
sudo pacman -U --noconfirm "$PKG_D" "$PKG_G" 2>&1 | tail -4
NEW=$(systemctl show alizyd -p MainPID --value)
check "daemon restarted by the upgrade" bash -c "[[ $OLD != $NEW ]] && echo '$OLD -> $NEW'"
check "unit is Type=notify and active" bash -c "systemctl show alizyd -p Type -p ActiveState | tee /dev/stderr | grep -q Type=notify && systemctl is-active alizyd"
check "journal: readiness signalled after protection" bash -c "sudo journalctl -u alizyd -n 40 --no-pager -o cat | grep -E 'Kill switch restored|signalled readiness' | tee /dev/stderr | tail -1 | grep -q signalled"
check "after upgrade: protected (tunnel cannot survive a restart)" bash -c "s=\$($CTL status | python3 -c \"import json,sys;print(json.load(sys.stdin)['data']['state'])\"); echo \$s; [[ \$s == protected ]]"
ensure_connected
check "reconnected after upgrade" wait_state connected 30
check "internet back after upgrade" internet

say "restart GUI onto the new version"
pkill -x alizy; sleep 1
(setsid /usr/bin/alizy >/dev/null 2>&1 &); sleep 7
check "new GUI running" pgrep -x alizy

say "service restart: the NEW GUI must reconnect by itself"
sudo systemctl restart alizyd
T0=$(date +%s)
ok=0
for i in $(seq 1 30); do sleep 1; [[ $(st) == connected ]] && { ok=1; break; }; done
if [[ $ok == 1 ]]; then record "GUI reconnected the previous profile after service restart" PASS "connected again $(( $(date +%s) - T0 )) s after restart, no manual action"
else record "GUI reconnected the previous profile after service restart" FAIL "still $(st) after 30 s; falling back to alizyctl"; fi
check "internet after automatic reconnect" internet
check "GUI log shows the reconnect" bash -c "sqlite3 $HOME/.local/share/io.alizy.app/alizy.db \"select message from events where message like '%service restart%' order by id desc limit 2\" | tee /dev/stderr | grep -q 'Reconnecting the previous profile'"
