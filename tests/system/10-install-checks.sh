#!/usr/bin/env bash
# Post-install checks: service, socket, group, authorization, GUI root refusal.
# Run as the normal user from a terminal in the active desktop session:
#   bash tests/system/10-install-checks.sh
# (it uses `sg alizy` and `sudo` itself where needed). Non-disruptive.
source "$(dirname "$0")/lib.sh"
rm -f "$OUT/DONE"
sudo -v || exit 1

say "service"
check "alizyd.service active under systemd" systemctl is-active alizyd
check "alizyd runs as root, unit hardening present" bash -c "systemctl show alizyd -p MainPID -p User -p NoNewPrivileges -p LimitCORE -p CapabilityBoundingSet | tee /dev/stderr | grep -q 'NoNewPrivileges=yes'"
check "socket exists with 0660 root:alizy" bash -c "stat -c '%a %U:%G %F' /run/alizy/alizyd.sock | tee /dev/stderr | grep -q '^660 root:alizy socket'"
check "state dir is 0700 root" bash -c "sudo stat -c '%a %U' /var/lib/alizy | tee /dev/stderr | grep -q '^700 root'"
check "group alizy exists and contains $USER" bash -c "getent group alizy | tee /dev/stderr | grep -qw $USER"
check "journal shows clean start" bash -c "sudo journalctl -u alizyd -b --no-pager -n 30 | tee /dev/stderr | grep -q 'listening on /run/alizy/alizyd.sock'"

say "authorization"
# This shell started before the group was added, so it is NOT in group alizy.
if id -nG | grep -qw alizy; then
  record "user outside group alizy is refused by socket permissions" "NOT TESTED" "this shell already has group alizy"
else
  check "user outside group alizy is refused by socket permissions" not python3 -c "$SOCK_HELLO"
fi
check "user 'nobody' is refused" not sudo -u nobody python3 -c "$SOCK_HELLO"
check "group member can read status" asgroup "$CTL hello"
check "group member in active session may change policy (polkit allow_active)" asgroup "$CTL set-policy '$POLICY_OFF'"
check "group member WITHOUT a login session is denied by polkit" bash -c "out=\$(sudo systemd-run --quiet --wait --pipe --uid=$(id -u) --gid=$(id -g) -p SupplementaryGroups=alizy -E XDG_DATA_HOME=$HOME/.local/share $CTL set-policy '$POLICY_OFF' 2>&1); echo \"\$out\"; grep -q Unauthorized <<<\"\$out\""
check "same no-session member can still read status (read-only)" bash -c "sudo systemd-run --quiet --wait --pipe --uid=$(id -u) --gid=$(id -g) -p SupplementaryGroups=alizy $CTL hello"
check "test_route also requires authorization (no-session denied)" bash -c "out=\$(sudo systemd-run --quiet --wait --pipe --uid=$(id -u) --gid=$(id -g) -p SupplementaryGroups=alizy $CTL route-test example.com 2>&1); echo \"\$out\"; grep -q Unauthorized <<<\"\$out\""
check "malformed request is rejected, daemon survives" asgroup "printf '{\"id\":1,\"cmd\":\"exec\",\"argv\":[\"sh\"]}\n' | python3 -c \"import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect('/run/alizy/alizyd.sock');s.sendall(sys.stdin.buffer.read());print(s.recv(4096).decode())\" | tee /dev/stderr | grep -q bad_request && $CTL hello >/dev/null"

say "GUI"
check "GUI refuses to run as root" bash -c "out=\$(sudo /usr/bin/alizy 2>&1); echo \"\$out\"; grep -q 'must not run as root' <<<\"\$out\""
check "desktop entry and icon installed" bash -c "ls /usr/share/applications/io.alizy.app.desktop /usr/share/icons/hicolor/128x128/apps/io.alizy.app.png && desktop-file-validate /usr/share/applications/io.alizy.app.desktop"

say "firewall untouched by install"
check "no Alizy table when kill switch is off (default)" bash -c "! sudo nft list table inet alizy >/dev/null 2>&1 && echo 'table inet alizy absent'"
check "kill switch NOT enabled by installation" bash -c "sudo -u $USER -g alizy $CTL policy | tee /dev/stderr | grep -q '\"kill_switch\": false'"

echo; echo "summary: $PASS passed, $FAIL failed (details: $RESULTS)"
date > "$OUT/DONE"
