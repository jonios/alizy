#!/usr/bin/env bash
# Real-system test of the AUR packages (packaging/aur). Run as the NORMAL USER
# (member of group alizy) from a terminal in the desktop session; sudo is used
# only for pacman, systemctl, nft, ip and reading /var/lib/alizy/state.json.
#
#   bash tests/system/60-aur-package.sh upgrade DIR   upgrade the installed packages to DIR's
#   bash tests/system/60-aur-package.sh remove  DIR   remove GUI, remove service, reinstall from DIR
#
# DIR holds alizyd-*.pkg.tar.zst and alizy-*.pkg.tar.zst (e.g. target/aur-test).
# Profiles, keys, settings and service state are compared by digest only; no
# private key or password is ever printed. Results: target/system-validation/aur-<phase>.tsv
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTL="$ROOT/target/debug/examples/alizyctl"
OUT=$ROOT/target/system-validation
mkdir -p "$OUT"
PHASE=${1:?phase: upgrade|remove}
PKGDIR=$(realpath "${2:?directory with the packages}")
RESULTS=$OUT/aur-$PHASE.tsv
: > "$RESULTS"
DATA=${XDG_DATA_HOME:-$HOME/.local/share}/io.alizy.app
PASS=0
FAIL=0

record() { # name PASS|FAIL|INFO evidence
  printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\n\t' '  ' <<<"$3" | cut -c1-500)" >> "$RESULTS"
  printf '  %-4s %s\n' "$2" "$1"
  case $2 in PASS) PASS=$((PASS+1)) ;; FAIL) FAIL=$((FAIL+1)) ;; esac
}
check() { # name cmd...
  local n=$1; shift
  local ev rc
  ev=$("$@" 2>&1); rc=$?
  if [[ $rc -eq 0 ]]; then record "$n" PASS "$ev"; else record "$n" FAIL "$ev"; fi
}
say() { printf '\n== %s\n' "$*"; }
trap 'printf "\nsummary (%s): %d passed, %d failed  ->  %s\n" "$PHASE" "$PASS" "$FAIL" "$RESULTS"; date > "$OUT/aur-$PHASE.done"' EXIT

PKG_D=$(ls "$PKGDIR"/alizyd-[0-9]*.pkg.tar.zst 2>/dev/null | sort -V | tail -1)
PKG_G=$(ls "$PKGDIR"/alizy-[0-9]*.pkg.tar.zst 2>/dev/null | sort -V | tail -1)
[[ -n $PKG_D && -n $PKG_G ]] || { echo "no packages in $PKGDIR"; exit 1; }
NEWVER=$(basename "$PKG_D" | sed -E 's/^alizyd-(.*)-(x86_64|aarch64|any)\.pkg\.tar\.zst$/\1/')
[[ -x $CTL ]] || { echo "missing $CTL (cargo build -p alizy-store --example alizyctl)"; exit 1; }

# --- daemon helpers -------------------------------------------------------
js() { "$CTL" status 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print($1)" 2>/dev/null; }
state() { js "d['state']" || echo unreachable; }
wait_state() { # want seconds
  local i
  for i in $(seq 1 $(( ${2:-30} * 5 ))); do
    [[ $(state) == "$1" ]] && { echo "state=$1 after $((i/5)) s"; return 0; }
    sleep 0.2
  done
  echo "state=$(state), wanted $1"; return 1
}
internet() { curl -4 -s -o /dev/null --max-time 8 -w '%{http_code}' https://www.google.com/generate_204 | grep -q 204 && echo "internet reachable"; }
is_true() { [[ $1 == True ]]; }

# --- data fingerprints (digests only) -------------------------------------
db() { sqlite3 -readonly "$DATA/alizy.db" "$1"; }
snapshot() {
  echo "profiles_count $(db 'select count(*) from profiles')"
  echo "profiles_digest $(db 'select id,name,category,favorite,fingerprint,public_config,kind,ssh_public from profiles order by id' | sha256sum | cut -c1-16)"
  echo "settings_digest $(db 'select key,value from settings order by key' | sha256sum | cut -c1-16)"
  echo "secret_files $(find "$DATA/secrets" -type f 2>/dev/null | wc -l)"
  echo "secret_files_digest $( (cd "$DATA/secrets" 2>/dev/null && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) | sha256sum | cut -c1-16)"
  echo "secret_backends_digest $(for id in $(db 'select id from profiles order by id'); do "$CTL" secret-check "$id" 2>&1; done | sha256sum | cut -c1-16)"
  echo "service_state_digest $(sudo python3 -c 'import json,hashlib; d=json.load(open("/var/lib/alizy/state.json")); print(hashlib.sha256(json.dumps({k: d.get(k) for k in ("policy","split","lan_proxy")}, sort_keys=True).encode()).hexdigest()[:16])' 2>&1)"
}
history_count() { db 'select count(*) from history'; }
compare_snapshots() { # before after label
  local key before after
  while read -r key before; do
    after=$(awk -v k="$key" '$1==k {print $2}' "$2")
    if [[ $before == "$after" ]]; then record "$3: $key unchanged" PASS "$before"
    else record "$3: $key unchanged" FAIL "before $before, after $after"; fi
  done < "$1"
}

# --- kill-switch monitor: samples `nft list table inet alizy` every 0.1 s --
MON_STOP=$OUT/aur-monitor.stop
monitor_start() {
  rm -f "$MON_STOP" "$OUT/aur-monitor.txt"
  sudo bash -c "while [ ! -e '$MON_STOP' ]; do if nft list table inet alizy >/dev/null 2>&1; then echo 1; else echo 0; fi; sleep 0.1; done" > "$OUT/aur-monitor.txt" 2>/dev/null &
  MON_PID=$!
  sleep 0.5
}
monitor_stop() { touch "$MON_STOP"; wait "$MON_PID" 2>/dev/null; }
monitor_result() { # prints samples/absent; ok when never absent
  local n z
  n=$(wc -l < "$OUT/aur-monitor.txt"); z=$(grep -c '^0' "$OUT/aur-monitor.txt")
  echo "$n samples, table absent in $z"; [[ $n -gt 10 && $z -eq 0 ]]
}

reconnect() { # profile-id: wait for the GUI's own reconnect, fall back to alizyctl
  local pid=$1 r
  if [[ -n $(pgrep -x alizy) ]] && r=$(wait_state connected 30); then
    record "reconnected the previous profile automatically (GUI)" PASS "$r"
  else
    record "reconnected the previous profile automatically (GUI)" INFO "GUI not running or did not reconnect: $(state); connecting with alizyctl"
    "$CTL" connect "$pid" >/dev/null 2>&1
    check "reconnected with alizyctl" wait_state connected 30
  fi
}

sudo -v || exit 1
( while sleep 50; do sudo -n -v 2>/dev/null || exit; done ) &
KEEPALIVE=$!
trap 'kill $KEEPALIVE 2>/dev/null; printf "\nsummary (%s): %d passed, %d failed  ->  %s\n" "$PHASE" "$PASS" "$FAIL" "$RESULTS"; date > "$OUT/aur-$PHASE.done"' EXIT

say "baseline"
record "packages under test" INFO "$(basename "$PKG_D") $(basename "$PKG_G")"
record "installed before" INFO "$(pacman -Q alizyd alizy 2>&1 | tr '\n' ' ')"
B_STATE=$(state); B_KS=$(js "d['kill_switch']['enabled']"); PREV=$(js "d['profile_id'] or ''")
record "daemon state before" INFO "state=$B_STATE kill_switch=$B_KS profile_id=${PREV:-none}"
B_POLICY=$(js "json.dumps(d['policy'], sort_keys=True)")
snapshot > "$OUT/aur-$PHASE-before.txt"
B_HIST=$(history_count)
B_RESOLV="$(readlink /etc/resolv.conf) $(sha256sum < /etc/resolv.conf | cut -c1-16)"

case $PHASE in
upgrade)
  OLDPID=$(systemctl show alizyd -p MainPID --value)
  GUI_WAS=$(pgrep -x alizy)
  say "upgrade with pacman -U (kill-switch monitor running)"
  monitor_start
  sudo pacman -U --noconfirm "$PKG_D" "$PKG_G" 2>&1 | tee "$OUT/aur-upgrade-pacman.log" | tail -12
  sleep 3
  monitor_stop
  check "pacman installed $NEWVER for both packages" bash -c "pacman -Q alizyd alizy | tee /dev/stderr | grep -c ' $NEWVER\$' | grep -qx 2"
  NEWPID=$(systemctl show alizyd -p MainPID --value)
  check "daemon restarted onto the new binary" bash -c "[[ $OLDPID != $NEWPID && $NEWPID != 0 ]] && echo '$OLDPID -> $NEWPID'"
  check "service active, Type=notify, still enabled" bash -c "p=\$(systemctl show alizyd -p Type -p ActiveState -p UnitFileState); echo \$p; grep -qx Type=notify <<<\"\$p\" && grep -qx ActiveState=active <<<\"\$p\" && grep -qx UnitFileState=enabled <<<\"\$p\""
  check "no 'unit changed on disk' warning (daemon-reload ran first)" bash -c "! grep -qi 'changed on disk' '$OUT/aur-upgrade-pacman.log' && echo none"
  check "journal: protection applied before readiness" bash -c "sudo journalctl -u alizyd _PID=$NEWPID --no-pager -o cat | grep -E 'Kill switch restored|signalled readiness' | tee /dev/stderr | tail -1 | grep -q signalled"
  if is_true "$B_KS"; then
    check "kill-switch table present in every sample during the upgrade" monitor_result
    check "kill switch verified against the kernel after upgrade" bash -c "[[ \$($CTL status | python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['kill_switch']['firewall_verified'])\") == True ]] && echo verified"
  else
    record "kill-switch monitor" INFO "kill switch was off before the upgrade: $(monitor_result)"
  fi
  check "policy unchanged by the upgrade" bash -c "[[ '$B_POLICY' == \"\$($CTL status | python3 -c \"import json,sys; print(json.dumps(json.load(sys.stdin)['data']['policy'], sort_keys=True))\")\" ]] && echo same"
  if [[ $B_STATE == connected && -n $PREV ]]; then reconnect "$PREV"; check "internet through the tunnel after upgrade" internet; fi

  say "data preserved"
  snapshot > "$OUT/aur-upgrade-after.txt"
  compare_snapshots "$OUT/aur-upgrade-before.txt" "$OUT/aur-upgrade-after.txt" "upgrade"
  check "history kept (rows before <= after)" bash -c "a=\$(sqlite3 -readonly '$DATA/alizy.db' 'select count(*) from history'); echo '$B_HIST ->' \$a; [[ \$a -ge $B_HIST ]]"

  say "installed files and permissions"
  check "alizyd files" bash -c "pacman -Qlq alizyd | grep -v '/$' | tee /dev/stderr | grep -c -E '^/usr/(bin/alizyd|lib/systemd/system/alizyd.service|lib/sysusers.d/alizy.conf|share/polkit-1/actions/io.alizy.policy|share/doc/alizyd/SECURITY.md)$' | grep -qx 5"
  check "alizy files (binary, desktop entry, 6 icons, README)" bash -c "pacman -Qlq alizy | grep -v '/$' | tee /dev/stderr | grep -c -E '^/usr/(bin/alizy|share/applications/io.alizy.app.desktop|share/icons/hicolor/.*/apps/io.alizy.app.(png|svg)|share/doc/alizy/README.md)$' | grep -qx 9"
  check "pacman -Qkk: files match the package" bash -c "pacman -Qkk alizyd alizy 2>&1 | tail -2 | tee /dev/stderr | grep -c ' 0 altered files' | grep -qx 2"
  check "/usr/bin/alizyd is 0755 root:root" bash -c "stat -c '%a %U:%G' /usr/bin/alizyd | tee /dev/stderr | grep -qx '755 root:root'"
  check "socket is 0660 root:alizy" bash -c "stat -c '%a %U:%G %F' /run/alizy/alizyd.sock | tee /dev/stderr | grep -q '^660 root:alizy socket'"
  check "/var/lib/alizy is 0700 root" bash -c "sudo stat -c '%a %U' /var/lib/alizy | tee /dev/stderr | grep -qx '700 root'"
  check "group alizy and user alizy-ssh exist" bash -c "getent group alizy && getent passwd alizy-ssh"

  say "socket access"
  HELLO='import socket,sys
s=socket.socket(socket.AF_UNIX)
try: s.connect("/run/alizy/alizyd.sock")
except OSError as e: print("refused:", e); sys.exit(1)
s.sendall(b"{\"id\":1,\"cmd\":\"hello\",\"protocol\":1}\n"); r=s.recv(4096).decode(); print(r.strip()); sys.exit(0 if "protocol" in r else 1)'
  check "group member reaches the daemon (hello)" python3 -c "$HELLO"
  check "user 'nobody' is refused by socket permissions" bash -c "! sudo -u nobody python3 -c '$HELLO'"

  say "application launch (new GUI)"
  if [[ -n $GUI_WAS ]]; then pkill -x alizy; sleep 1; fi
  setsid -f /usr/bin/alizy >/dev/null 2>&1
  sleep 8
  check "new GUI process running" bash -c "pgrep -ax alizy"
  check "GUI connected to the service (event log)" bash -c "sqlite3 -readonly '$DATA/alizy.db' \"select message from events where message like '%Connected to the Alizy service%' and ts >= strftime('%s','now') - 60 limit 1\" 2>/dev/null | grep -q . && echo logged || { sqlite3 -readonly '$DATA/alizy.db' 'select message from events order by id desc limit 3'; false; }"
  ;;

remove)
  [[ $B_STATE == connected && -n $PREV ]] || echo "note: not connected; removal is still tested, reconnect steps are skipped"
  say "remove the GUI only: the service must keep running"
  pkill -x alizy; sleep 1
  OLDPID=$(systemctl show alizyd -p MainPID --value)
  sudo pacman -R --noconfirm alizy 2>&1 | tail -4
  check "alizy removed" bash -c "! pacman -Q alizy 2>/dev/null"
  check "alizyd still installed, active, same process" bash -c "pacman -Q alizyd && [[ \$(systemctl show alizyd -p MainPID --value) == $OLDPID ]] && systemctl is-active alizyd"
  check "daemon state unchanged ($B_STATE)" bash -c "s=\$($CTL status | python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['state'])\"); echo \$s; [[ \$s == $B_STATE ]]"
  if is_true "$B_KS"; then check "kill switch still in the kernel" bash -c "sudo nft list table inet alizy >/dev/null && echo present"; fi
  [[ $B_STATE == connected ]] && check "internet still through the tunnel" internet

  say "remove the service"
  sudo pacman -R --noconfirm alizyd 2>&1 | tee "$OUT/aur-remove-pacman.log" | tail -25
  check "alizyd removed" bash -c "! pacman -Q alizyd 2>/dev/null"
  check "service stopped and unit gone" bash -c "! systemctl is-active -q alizyd; systemctl show alizyd -p LoadState | tee /dev/stderr | grep -q not-found"
  check "nftables table inet alizy removed" bash -c "! sudo nft list table inet alizy >/dev/null 2>&1 && echo absent"
  check "interface alizy0 removed" bash -c "! ip link show alizy0 >/dev/null 2>&1 && echo absent"
  check "Alizy routing rules (prio 19029-19034) removed" bash -c "r=\$(ip rule; ip -6 rule); ! grep -E '^190(29|3[0-4]):' <<<\"\$r\" && echo none"
  check "/etc/resolv.conf as before" bash -c "now=\"\$(readlink /etc/resolv.conf) \$(sha256sum < /etc/resolv.conf | cut -c1-16)\"; echo \$now; [[ \$now == '$B_RESOLV' ]]"
  check "network works without Alizy" internet
  check "/var/lib/alizy kept" bash -c "sudo test -f /var/lib/alizy/state.json && echo kept"
  check "group alizy and user alizy-ssh kept" bash -c "getent group alizy && getent passwd alizy-ssh"
  check "post_remove message printed" bash -c "grep -q 'Kept on purpose' '$OUT/aur-remove-pacman.log' && echo shown"
  snapshot > "$OUT/aur-remove-after-removal.txt"
  compare_snapshots "$OUT/aur-remove-before.txt" "$OUT/aur-remove-after-removal.txt" "after removal"

  say "reinstall: nothing may start or change by itself"
  sudo pacman -U --noconfirm "$PKG_D" "$PKG_G" 2>&1 | tee "$OUT/aur-reinstall-pacman.log" | tail -20
  check "both packages installed" bash -c "pacman -Q alizyd alizy"
  check "post_install message printed" bash -c "grep -q 'Nothing is running yet' '$OUT/aur-reinstall-pacman.log' && echo shown"
  check "service not enabled or started by the install" bash -c "! systemctl is-active -q alizyd && systemctl is-enabled alizyd 2>&1 | tee /dev/stderr | grep -qx disabled"
  check "no firewall table after install" bash -c "! sudo nft list table inet alizy >/dev/null 2>&1 && echo absent"
  check "network still works after install" internet

  say "enable the service: saved policy and rules come back"
  sudo systemctl enable --now alizyd 2>&1 | tail -2
  check "service active" bash -c "systemctl is-active alizyd"
  if is_true "$B_KS"; then
    check "kill switch restored from saved state (protected)" wait_state protected 15
    check "kill switch verified" bash -c "[[ \$($CTL status | python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['kill_switch']['firewall_verified'])\") == True ]] && echo verified"
  else
    check "disconnected, kill switch off" wait_state disconnected 15
  fi
  check "policy as before removal" bash -c "[[ '$B_POLICY' == \"\$($CTL status | python3 -c \"import json,sys; print(json.dumps(json.load(sys.stdin)['data']['policy'], sort_keys=True))\")\" ]] && echo same"
  setsid -f /usr/bin/alizy >/dev/null 2>&1
  sleep 8
  check "GUI starts after reinstall" bash -c "pgrep -ax alizy"
  if [[ $B_STATE == connected && -n $PREV ]]; then
    # The GUI's auto-connect setting decides which profile it connects at launch.
    if r=$(wait_state connected 30); then
      record "connected after GUI launch (auto-connect)" PASS "$r, profile $(js "d['profile_id']")"
    elif [[ $(db "select kind from profiles where id='$PREV'") == ssh ]]; then
      record "connected after GUI launch (auto-connect)" INFO "not connected; previous profile is an SSH profile, which alizyctl can only connect with a typed password"
    else
      "$CTL" connect "$PREV" >/dev/null 2>&1
      check "connect the previous profile with its stored key (alizyctl)" wait_state connected 30
    fi
    [[ $(state) == connected ]] && check "internet through the tunnel" internet
  fi
  snapshot > "$OUT/aur-remove-after-reinstall.txt"
  compare_snapshots "$OUT/aur-remove-before.txt" "$OUT/aur-remove-after-reinstall.txt" "after reinstall"
  ;;
*) echo "unknown phase $PHASE"; exit 2 ;;
esac
