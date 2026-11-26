#!/usr/bin/env bash
# Real-host test: move an Arch machine from the pacman packages (alizy/alizyd)
# to the release installer + AppImage, then reinstall over itself while the VPN
# is connected. Run as the NORMAL USER in a desktop terminal; sudo is used for
# pacman, the installer and nft/journal reads. Data is compared by digest only.
#
#   bash tests/system/70-installer-migration.sh [DIST_DIR]      (default dist-release/)
#
# DISRUPTIVE: removing the pacman packages turns the kill switch off and
# disconnects the VPN until the new service is running (about a minute).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIST=$(realpath "${1:-$ROOT/dist-release}")
CTL="$ROOT/target/debug/examples/alizyctl"
OUT=$ROOT/target/system-validation
mkdir -p "$OUT"
RES=$OUT/installer-migration.tsv
: > "$RES"
DATA=${XDG_DATA_HOME:-$HOME/.local/share}/io.alizy.app
INST=$DIST/alizy-installer-x86_64
PASS=0 FAIL=0
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\n\t' '  ' <<<"$3" | cut -c1-500)" >> "$RES"; printf '  %-4s %s\n' "$2" "$1"; case $2 in PASS) PASS=$((PASS+1)) ;; FAIL) FAIL=$((FAIL+1)) ;; esac; }
check() { local n=$1; shift; local ev; ev=$("$@" 2>&1); if [[ $? -eq 0 ]]; then record "$n" PASS "$ev"; else record "$n" FAIL "$ev"; fi; }
say() { printf '\n== %s\n' "$*"; }
js() { "$CTL" status 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print($1)" 2>/dev/null; }
state() { js "d['state']" || echo unreachable; }
wait_state() { local i; for i in $(seq 1 $(( ${2:-30} * 5 ))); do [[ $(state) == "$1" ]] && { echo "state=$1 after $((i/5)) s"; return 0; }; sleep 0.2; done; echo "state=$(state), wanted $1"; return 1; }
internet() { curl -4 -s -o /dev/null --max-time 8 -w '%{http_code}' https://www.google.com/generate_204 | grep -q 204 && echo "internet reachable"; }
db() { sqlite3 -readonly "$DATA/alizy.db" "$1"; }
snapshot() {
  echo "profiles_count $(db 'select count(*) from profiles')"
  echo "profiles_digest $(db 'select id,name,category,favorite,fingerprint,public_config,kind,ssh_public from profiles order by id' | sha256sum | cut -c1-16)"
  echo "settings_digest $(db 'select key,value from settings order by key' | sha256sum | cut -c1-16)"
  echo "secret_files_digest $( (cd "$DATA/secrets" 2>/dev/null && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) | sha256sum | cut -c1-16)"
  echo "secret_backends_digest $(for id in $(db 'select id from profiles order by id'); do "$CTL" secret-check "$id" 2>&1; done | sha256sum | cut -c1-16)"
  echo "service_state_digest $(sudo python3 -c 'import json,hashlib; d=json.load(open("/var/lib/alizy/state.json")); print(hashlib.sha256(json.dumps({k: d.get(k) for k in ("policy","split","lan_proxy")}, sort_keys=True).encode()).hexdigest()[:16])' 2>&1)"
}
compare() { local key before after; while read -r key before; do after=$(awk -v k="$key" '$1==k {print $2}' "$2"); [[ $before == "$after" ]] && record "$3: $key unchanged" PASS "$before" || record "$3: $key unchanged" FAIL "before $before, after $after"; done < "$1"; }
reconnect() { # profile id, label
  if r=$(wait_state connected 40); then record "$2: reconnected by the app" PASS "$r"
  else
    record "$2: reconnected by the app" INFO "$(state); connecting with alizyctl"
    if [[ $(db "select kind from profiles where id='$1'") == ssh ]]; then
      local wg; wg=$(db "select id from profiles where kind!='ssh' order by last_connected_at desc limit 1")
      record "$2: previous profile is SSH (needs a typed password)" INFO "using WireGuard profile $wg"
      "$CTL" connect "$wg" >/dev/null 2>&1
    else "$CTL" connect "$1" >/dev/null 2>&1; fi
    check "$2: connected" wait_state connected 30
  fi
}

[[ -x $INST && -f $DIST/Alizy-x86_64.AppImage ]] || { echo "release assets missing in $DIST"; exit 1; }
sudo -v || exit 1
( while sleep 50; do sudo -n -v 2>/dev/null || exit; done ) & KEEP=$!
trap 'kill $KEEP 2>/dev/null; printf "\nsummary: %d passed, %d failed -> %s\n" "$PASS" "$FAIL" "$RES"' EXIT

say "baseline"
check "release checksums" bash -c "cd '$DIST' && sha256sum -c SHA256SUMS"
record "installed before" INFO "$(pacman -Q alizyd alizy 2>&1 | tr '\n' ' ')"
B_STATE=$(state); B_KS=$(js "d['kill_switch']['enabled']"); PREV=$(js "d['profile_id'] or ''")
record "daemon before" INFO "state=$B_STATE kill_switch=$B_KS profile=${PREV:-none}"
snapshot > "$OUT/migration-before.txt"
B_RESOLV="$(readlink /etc/resolv.conf) $(sha256sum < /etc/resolv.conf | cut -c1-16)"

say "the installer refuses to touch the pacman packages"
check "installer stops: package-managed" bash -c "out=\$('$INST' --yes 2>&1); rc=\$?; echo \"\$out\" | tail -2; [[ \$rc != 0 ]] && grep -q 'already installed by package' <<<\"\$out\""
check "nothing changed: same service process, same files" bash -c "pacman -Q alizyd && ! test -e /usr/local/bin/alizyd && systemctl is-active alizyd"

say "migrate: remove the pacman packages (data kept), run the installer"
pkill -x alizy; sleep 1
sudo pacman -R --noconfirm alizy alizyd 2>&1 | tail -3
check "packages removed, firewall/routes/interface gone" bash -c "! pacman -Q alizyd 2>/dev/null && ! sudo nft list table inet alizy >/dev/null 2>&1 && ! ip link show alizy0 >/dev/null 2>&1 && echo clean"
check "installer: install + AppImage + group" bash -c "'$INST' --yes --appimage '$DIST/Alizy-x86_64.AppImage' > '$OUT/migration-install.log' 2>&1; rc=\$?; tail -8 '$OUT/migration-install.log'; [[ \$rc == 0 ]]"
check "service active from /usr/local, Type=notify" bash -c "systemctl show alizyd -p FragmentPath -p Type -p ActiveState | tr '\n' ' ' | tee /dev/stderr | grep -q '/usr/local/lib/systemd/system/alizyd.service' && systemctl show -p Type --value alizyd | grep -qx notify && systemctl is-active alizyd"
check "saved kill switch restored (protected) and verified" bash -c "[[ '$B_KS' != True ]] || { s=\$($CTL status | python3 -c \"import json,sys; d=json.load(sys.stdin)['data']; print(d['state'], d['kill_switch']['firewall_verified'])\"); echo \$s; [[ \$s == 'protected True' || \$s == 'connected True' ]]; }"
check "socket 0660 root:alizy" bash -c "stat -c '%a %U:%G' /run/alizy/alizyd.sock | tee /dev/stderr | grep -qx '660 root:alizy'"
check "AppImage and menu entry for this user" bash -c "test -x ~/Applications/Alizy.AppImage && grep -q Applications/Alizy.AppImage ~/.local/share/applications/io.alizy.app.desktop && echo ok"

say "the AppImage on this machine"
setsid -f ~/Applications/Alizy.AppImage >/dev/null 2>&1
sleep 8
check "AppImage GUI running" bash -c "pgrep -af 'Alizy.AppImage|squashfs|/tmp/.mount_Alizy' | head -2 | grep -q . && echo running"
check "GUI connected to the service (event log)" bash -c "sqlite3 -readonly '$DATA/alizy.db' \"select message from events where message like '%Connected to the Alizy service%' and ts >= strftime('%s','now') - 60 limit 1\" | grep -q . && echo logged"
[[ $B_STATE == connected && -n $PREV ]] && reconnect "$PREV" "after migration"
check "internet through the tunnel" internet
snapshot > "$OUT/migration-after.txt"
compare "$OUT/migration-before.txt" "$OUT/migration-after.txt" "migration"

say "reinstall over itself while connected (service restart, kill switch monitored)"
rm -f "$OUT/mig-mon.stop"
sudo bash -c "while [ ! -e '$OUT/mig-mon.stop' ]; do if nft list table inet alizy >/dev/null 2>&1; then echo 1; else echo 0; fi; sleep 0.1; done" > "$OUT/mig-mon.txt" 2>/dev/null & MON=$!
sleep 1
OLDPID=$(systemctl show -p MainPID --value alizyd)
check "reinstall succeeds" bash -c "'$INST' --yes --appimage '$DIST/Alizy-x86_64.AppImage' > '$OUT/migration-reinstall.log' 2>&1; rc=\$?; tail -5 '$OUT/migration-reinstall.log'; [[ \$rc == 0 ]]"
sleep 2; touch "$OUT/mig-mon.stop"; wait $MON 2>/dev/null
check "kill-switch table present in every sample" bash -c "n=\$(wc -l < '$OUT/mig-mon.txt'); z=\$(grep -c '^0' '$OUT/mig-mon.txt'); echo \"\$n samples, absent in \$z\"; [[ \$n -gt 10 && \$z -eq 0 ]]"
check "service restarted" bash -c "n=\$(systemctl show -p MainPID --value alizyd); echo $OLDPID '->' \$n; [[ \$n != $OLDPID ]]"
[[ $B_STATE == connected ]] && reconnect "$PREV" "after reinstall"
check "internet after reinstall" internet
check "/etc/resolv.conf as before" bash -c "now=\"\$(readlink /etc/resolv.conf) \$(sha256sum < /etc/resolv.conf | cut -c1-16)\"; echo \$now; [[ \$now == '$B_RESOLV' ]]"
snapshot > "$OUT/migration-final.txt"
compare "$OUT/migration-before.txt" "$OUT/migration-final.txt" "final"
check "installer status" bash -c "/usr/local/lib/alizy/alizy-installer status"
