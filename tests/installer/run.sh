#!/usr/bin/env bash
# Installer lifecycle test in a systemd-booted container (rootless podman).
# Nothing on the host is changed: the service, firewall, tunnel and DNS live in
# the container's own network namespace. A second container is a real
# WireGuard peer, so "connected" means a real handshake.
#
#   tests/installer/run.sh ubuntu22|ubuntu24|debian12|fedora [DIST_DIR]
#
# DIST_DIR defaults to dist-release/ (scripts/release/build-in-container.sh).
# Images: podman build --build-arg BASE=... -t localhost/alizy-itest:<tag> tests/installer
# Results: target/installer-tests/<tag>.tsv
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TAG=${1:?distribution tag}
DIST=$(realpath "${2:-$ROOT/dist-release}")
IMG=localhost/alizy-itest:$TAG
C=alizy-itest-$TAG
PEER=alizy-itest-peer-$TAG
NET=alizy-itest
OUTD=$ROOT/target/installer-tests
mkdir -p "$OUTD"
RES=$OUTD/$TAG.tsv
: > "$RES"
PASS=0 FAIL=0
WORK=$(mktemp -d)

record() { printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\n\t' '  ' <<<"$3" | cut -c1-400)" >> "$RES"; printf '  %-4s %s\n' "$2" "$1"; [[ $2 == PASS ]] && PASS=$((PASS+1)); [[ $2 == FAIL ]] && FAIL=$((FAIL+1)); true; }
check() { local n=$1; shift; local ev; ev=$("$@" 2>&1); if [[ $? -eq 0 ]]; then record "$n" PASS "$ev"; else record "$n" FAIL "$ev"; fi; }
R() { podman exec "$C" bash -c "$1"; }                                    # root in the container
T() { podman exec -u tester -w /home/tester/Downloads "$C" bash -c "$1"; } # the desktop user
say() { printf '\n== %s\n' "$*"; }
cleanup() { podman rm -f "$C" "$PEER" >/dev/null 2>&1; rm -rf "$WORK"; }
trap 'cleanup; printf "\nsummary (%s): %d passed, %d failed -> %s\n" "$TAG" "$PASS" "$FAIL" "$RES"' EXIT

INST=alizy-installer-x86_64
# Versions come from the installer under test; the variants are newer by suffix.
VER=$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$DIST/$INST" | head -1)
UP=$VER.1
BROKEN=$VER.2
python3 "$ROOT/tests/installer/variant.py" "$DIST/$INST" "$WORK/up" "$UP"
python3 "$ROOT/tests/installer/variant.py" "$DIST/$INST" "$WORK/broken" "$BROKEN" --broken

podman network exists $NET || podman network create $NET >/dev/null
podman rm -f "$C" "$PEER" >/dev/null 2>&1

say "boot $IMG and a WireGuard peer"
# --dns=none: /etc/resolv.conf is a real file (not a bind mount), as on a host, so
# the daemon's file DNS backend can replace and restore it.
podman run -d --name "$C" --hostname itest --systemd=always --network $NET --dns=none \
  --cap-add NET_ADMIN --cap-add NET_RAW "$IMG" >/dev/null
CPRIV=$(wg genkey); CPUB=$(wg pubkey <<<"$CPRIV"); SPRIV=$(wg genkey); SPUB=$(wg pubkey <<<"$SPRIV")
podman run -d --name "$PEER" --network $NET --cap-add NET_ADMIN docker.io/library/alpine:3.20 sh -c "
  apk add -q --no-cache wireguard-tools-wg iproute2 >/dev/null &&
  ip link add wg0 type wireguard && echo '$SPRIV' > /k && wg set wg0 private-key /k listen-port 51820 peer '$CPUB' allowed-ips 10.66.0.2/32 &&
  ip addr add 10.66.0.1/24 dev wg0 && ip link set wg0 up && touch /ready && sleep infinity" >/dev/null
for _ in $(seq 1 60); do R 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 1; done
for _ in $(seq 1 60); do podman exec "$PEER" test -f /ready 2>/dev/null && break; sleep 1; done
GW=$(podman network inspect $NET -f '{{(index .Subnets 0).Gateway}}')
R "rm -f /etc/resolv.conf; echo 'nameserver $GW' > /etc/resolv.conf; cp /etc/resolv.conf /tmp/resolv.host"
PEER_IP=$(podman inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$PEER")
record "distribution" INFO "$(R '. /etc/os-release; echo "$PRETTY_NAME, systemd $(systemctl --version | sed -n 1p | cut -d" " -f2), glibc $(ldd --version 2>&1 | sed -n "1s/.* //p")"')"
podman exec "$C" mkdir -p /home/tester/Downloads
for f in "$DIST/$INST" "$DIST/Alizy-x86_64.AppImage" "$DIST/SHA256SUMS" "$WORK/up" "$WORK/broken" "$ROOT/tests/installer/ipc.py"; do podman cp "$f" "$C:/home/tester/Downloads/"; done
R 'chown -R tester: /home/tester; chmod +x /home/tester/Downloads/{up,broken,ipc.py}'
R 'mkdir -p /home/tester/.local/share/io.alizy.app && echo "user data must survive" > /home/tester/.local/share/io.alizy.app/alizy.db && chown -R tester: /home/tester/.local'
IPC="python3 /home/tester/Downloads/ipc.py"

say "download verification"
check "SHA256SUMS verifies both assets" T 'sha256sum -c SHA256SUMS'
T "head -c -100 $INST > tampered && head -c 100 /dev/urandom >> tampered && chmod +x tampered"
check "a damaged installer refuses to run" bash -c "out=\$(podman exec -u tester -w /home/tester/Downloads $C ./tampered --yes 2>&1); rc=\$?; echo \"\$out\" | tail -2; [[ \$rc != 0 ]] && grep -q 'checksum mismatch' <<<\"\$out\" && ! podman exec $C test -e /usr/local/bin/alizyd"

say "fresh install without the required packages"
check "installer stops and names the missing packages" bash -c "out=\$(podman exec -u tester -w /home/tester/Downloads $C ./$INST --yes 2>&1); rc=\$?; echo \"\$out\" | grep -E 'required|installed with' ; [[ \$rc != 0 ]] && grep -q 'Missing packages can be installed with' <<<\"\$out\""
check "nothing was installed by the refused run" R '! test -e /usr/local/bin/alizyd && ! test -e /usr/local/lib/alizy'

say "install with --install-deps"
check "install succeeds (installs packages, service, app)" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./$INST --yes --install-deps > $WORK/install.log 2>&1; rc=\$?; tail -12 $WORK/install.log; [[ \$rc == 0 ]]"
check "service active and enabled, unit from /usr/local" R 'systemctl is-active alizyd && systemctl is-enabled alizyd && systemctl show -p FragmentPath alizyd | grep -q /usr/local/lib/systemd/system/alizyd.service'
check "files and permissions" R 'stat -c "%n %a %U:%G" /usr/local/bin/alizyd /usr/local/lib/systemd/system/alizyd.service /usr/local/lib/sysusers.d/alizy.conf /usr/share/polkit-1/actions/io.alizy.policy /usr/local/lib/alizy/alizy-installer && stat -c "%a %U:%G" /usr/local/bin/alizyd | grep -qx "755 root:root"'
check "socket 0660 root:alizy, state dir 0700" R 'stat -c "%a %U:%G" /run/alizy/alizyd.sock | grep -qx "660 root:alizy" && stat -c "%a" /var/lib/alizy | grep -qx 700'
check "group alizy and user alizy-ssh created; tester added" R 'getent group alizy | grep -q tester && getent passwd alizy-ssh'
check "AppImage and menu entry installed for the user" T 'test -x ~/Applications/Alizy.AppImage && grep -qx "Exec=\"/home/tester/Applications/Alizy.AppImage\"" ~/.local/share/applications/io.alizy.app.desktop && test -f ~/.local/share/icons/hicolor/256x256/apps/io.alizy.app.png'
check "logout/login guidance printed" grep -q 'Log out completely' "$WORK/install.log"
check "status works without root" T "./$INST status | tee /dev/stderr | grep -q 'installed by this installer: $VER'"
check "group member reaches the daemon" T "$IPC hello"

say "kill switch and a real tunnel"
check "kill switch on, verified" bash -c "podman exec $C $IPC kill-switch on && sleep 1 && [[ \$(podman exec $C $IPC verified) == True ]] && podman exec $C nft list table inet alizy >/dev/null"
check "connect to the WireGuard peer" bash -c "podman exec $C $IPC connect '$CPRIV' '$SPUB' '$PEER_IP' 51820 && sleep 2 && [[ \$(podman exec $C $IPC state) == connected ]]"
check "DNS points to the VPN while connected (file backend)" R 'grep -q "^nameserver 10.66.0.1" /etc/resolv.conf && cat /etc/resolv.conf | head -3'
check "real WireGuard handshake with the peer" R 'hs=$(wg show alizy0 latest-handshakes) && echo "$hs" && [ "$(echo "$hs" | awk "{print \$2}")" -gt 0 ]'

monitor() { R "rm -f /tmp/mon.stop; (while [ ! -e /tmp/mon.stop ]; do nft list table inet alizy >/dev/null 2>&1 && echo 1 || echo 0; sleep 0.1; done) > /tmp/mon.txt 2>&1 &"; sleep 1; }
monitor_end() { sleep 1; R 'touch /tmp/mon.stop; sleep 0.3; n=$(wc -l < /tmp/mon.txt); z=$(grep -c ^0 /tmp/mon.txt); echo "$n samples, table absent in $z"; [ "$n" -gt 10 ] && [ "$z" -eq 0 ]'; }

say "upgrade $VER -> $UP while connected with the kill switch on"
OLDPID=$(R 'systemctl show -p MainPID --value alizyd')
monitor
check "upgrade succeeds" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./up --yes > $WORK/up.log 2>&1; rc=\$?; tail -6 $WORK/up.log; [[ \$rc == 0 ]]"
check "kill-switch table present in every sample during the upgrade" monitor_end
check "service restarted onto the new files" bash -c "n=\$(podman exec $C systemctl show -p MainPID --value alizyd); echo $OLDPID '->' \$n; [[ \$n != $OLDPID && \$n != 0 ]] && podman exec $C cat /usr/local/lib/alizy/VERSION | grep -qx $UP"
check "after the restart: protected, kill switch verified (keys are never kept by the daemon)" bash -c "s=\$(podman exec $C $IPC state); echo \$s; [[ \$s == protected && \$(podman exec $C $IPC verified) == True ]]"
check "reconnect after the upgrade" bash -c "podman exec $C $IPC connect '$CPRIV' '$SPUB' '$PEER_IP' 51820 && sleep 2 && [[ \$(podman exec $C $IPC state) == connected ]]"

say "failed upgrade rolls back"
monitor
check "broken upgrade is refused and rolled back" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./broken --yes > $WORK/broken.log 2>&1; rc=\$?; tail -4 $WORK/broken.log; [[ \$rc != 0 ]] && grep -q 'was restored and is running' $WORK/broken.log"
check "kill-switch table present in every sample during the failed upgrade" monitor_end
check "previous version running again" bash -c "podman exec $C systemctl is-active alizyd && podman exec $C cat /usr/local/lib/alizy/VERSION | grep -qx $UP && podman exec $C /usr/local/bin/alizyd --version | grep -qx 'alizyd $VER'"
check "kill switch still verified after the rollback" bash -c "[[ \$(podman exec $C $IPC verified) == True ]]"

say "uninstall while the daemon is down, kill switch rules in the kernel, DNS left modified"
R 'systemctl stop alizyd'
check "a clean stop restores DNS (daemon)" R '[ "$(sha256sum < /etc/resolv.conf)" = "$(sha256sum < /tmp/resolv.host)" ] && echo identical'
check "state: service stopped, kill-switch table still present (fail closed)" R '! systemctl is-active -q alizyd && nft list table inet alizy >/dev/null'
R 'cp /etc/resolv.conf /tmp/resolv.orig && cp /etc/resolv.conf /var/lib/alizy/resolv.conf.backup && echo "nameserver 10.66.0.1 # written by alizy" > /etc/resolv.conf'
check "uninstall without confirmation in a non-interactive shell is refused" bash -c "! podman exec -u tester -w /home/tester/Downloads $C ./$INST uninstall < /dev/null"
check "uninstall succeeds" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./$INST uninstall --yes > $WORK/un.log 2>&1; rc=\$?; tail -5 $WORK/un.log; [[ \$rc == 0 ]]"
check "firewall table, interface and routing rules removed" R '! nft list table inet alizy 2>/dev/null && ! ip link show alizy0 2>/dev/null && ! ip rule | grep -E "^190(29|3[0-4]):"'
check "/etc/resolv.conf restored" R '[ "$(sha256sum < /etc/resolv.conf)" = "$(sha256sum < /tmp/resolv.orig)" ] && echo identical'
check "service files removed" R '! test -e /usr/local/bin/alizyd && ! test -e /usr/local/lib/systemd/system/alizyd.service && ! test -e /usr/share/polkit-1/actions/io.alizy.policy && ! test -e /usr/local/lib/alizy && systemctl show -p LoadState alizyd | grep -q not-found'
check "service state, group and user kept" R 'test -f /var/lib/alizy/state.json && getent group alizy && getent passwd alizy-ssh'
check "user data untouched" T 'grep -qx "user data must survive" ~/.local/share/io.alizy.app/alizy.db'
check "AppImage kept (removed separately)" T 'test -x ~/Applications/Alizy.AppImage'

say "reinstall restores the saved kill-switch setting"
check "reinstall warns that the saved kill switch is on" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./$INST --yes > $WORK/re.log 2>&1; rc=\$?; [[ \$rc == 0 ]] && grep -q 'kill' $WORK/re.log && grep -q 'switch ON' $WORK/re.log"
check "service running, protected, kill switch verified" bash -c "s=\$(podman exec $C $IPC state); echo \$s; [[ \$s == protected && \$(podman exec $C $IPC verified) == True ]]"
check "connect after reinstall" bash -c "podman exec $C $IPC connect '$CPRIV' '$SPUB' '$PEER_IP' 51820 && sleep 2 && [[ \$(podman exec $C $IPC state) == connected ]]"

say "remove the app, then purge the service"
check "remove-app removes only the AppImage and menu entry" bash -c "podman exec -u tester $C /home/tester/Downloads/$INST remove-app --yes && podman exec -u tester $C bash -c '! test -e ~/Applications/Alizy.AppImage && ! test -e ~/.local/share/applications/io.alizy.app.desktop' && podman exec $C systemctl is-active alizyd"
check "uninstall --purge" bash -c "podman exec -u tester -w /home/tester/Downloads $C ./$INST uninstall --purge --yes > $WORK/purge.log 2>&1; rc=\$?; tail -3 $WORK/purge.log; [[ \$rc == 0 ]]"
check "purge removed state, group and user; network clean" R '! test -e /var/lib/alizy && ! getent group alizy && ! getent passwd alizy-ssh && ! nft list table inet alizy 2>/dev/null && ! ip link show alizy0 2>/dev/null'
check "user data still untouched after purge" T 'grep -qx "user data must survive" ~/.local/share/io.alizy.app/alizy.db'
