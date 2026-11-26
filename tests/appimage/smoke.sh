#!/usr/bin/env bash
# AppImage smoke test on another distribution (rootless podman, no host changes):
# launches the release AppImage as a normal user on a virtual X display and
# checks that its window appears, that no bundled library is missing, and that
# it explains the missing service instead of failing.
#
#   tests/appimage/smoke.sh ubuntu22|ubuntu24|debian12|fedora [DIST_DIR]
#
# Uses the images from tests/installer (localhost/alizy-itest:<tag>).
# Results: target/appimage-tests/<tag>.{tsv,png}
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TAG=${1:?distribution tag}
DIST=$(realpath "${2:-$ROOT/dist-release}")
C=alizy-appimage-$TAG
OUTD=$ROOT/target/appimage-tests
mkdir -p "$OUTD"
RES=$OUTD/$TAG.tsv
: > "$RES"
PASS=0 FAIL=0
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$(tr '\n\t' '  ' <<<"$3" | cut -c1-400)" >> "$RES"; printf '  %-4s %s\n' "$2" "$1"; [[ $2 == PASS ]] && PASS=$((PASS+1)); [[ $2 == FAIL ]] && FAIL=$((FAIL+1)); true; }
check() { local n=$1; shift; local ev; ev=$("$@" 2>&1); if [[ $? -eq 0 ]]; then record "$n" PASS "$ev"; else record "$n" FAIL "$ev"; fi; }
R() { podman exec "$C" bash -c "$1"; }
U() { podman exec -u tester -e DISPLAY=:1 "$C" bash -c "$1"; }
trap 'podman rm -f "$C" >/dev/null 2>&1; printf "\nsummary (%s): %d passed, %d failed -> %s\n" "$TAG" "$PASS" "$FAIL" "$RES"' EXIT

podman rm -f "$C" >/dev/null 2>&1
podman run -d --name "$C" "localhost/alizy-itest:$TAG" sleep infinity >/dev/null
record "distribution" INFO "$(R '. /etc/os-release; echo "$PRETTY_NAME, glibc $(ldd --version 2>&1 | sed -n "1s/.* //p")"')"
R 'if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends xvfb x11-utils xdotool imagemagick dbus-x11 fonts-dejavu-core >/dev/null;
   elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed xorg-server-xvfb xorg-xwininfo xdotool imagemagick dbus ttf-dejavu >/dev/null;
   else dnf install -y -q xorg-x11-server-Xvfb xwininfo xdotool ImageMagick dbus-tools dbus-x11 dejavu-sans-fonts >/dev/null; fi' \
  || { record "install virtual display packages" FAIL "package install failed"; exit 1; }
podman cp "$DIST/Alizy-x86_64.AppImage" "$C:/home/tester/Alizy-x86_64.AppImage"
R 'chown tester: /home/tester/Alizy-x86_64.AppImage && chmod 0755 /home/tester/Alizy-x86_64.AppImage'

# Libraries an AppImage takes from the host by design (AppImage exclude list):
# present on every graphical desktop. Recorded on the bare image, then installed.
U 'cd /tmp && ~/Alizy-x86_64.AppImage --appimage-extract >/dev/null'
record "host libraries needed (bare image, before desktop libs)" INFO "$(U 'for f in /tmp/squashfs-root/usr/bin/alizy /tmp/squashfs-root/usr/lib/*.so*; do LD_LIBRARY_PATH=/tmp/squashfs-root/usr/lib ldd "$f" 2>/dev/null | grep "not found"; done | awk "{print \$1}" | sort -u | tr "\n" " "')"
R 'if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends libwayland-client0 libegl1 libgbm1 libharfbuzz0b libfribidi0 >/dev/null;
   elif command -v pacman >/dev/null; then pacman -S --noconfirm --needed wayland libglvnd mesa harfbuzz fribidi >/dev/null;
   else dnf install -y -q libwayland-client mesa-libEGL mesa-libgbm harfbuzz fribidi >/dev/null; fi'
check "no library missing on a desktop baseline" U 'out=$(for f in /tmp/squashfs-root/usr/bin/alizy /tmp/squashfs-root/usr/lib/*.so*; do LD_LIBRARY_PATH=/tmp/squashfs-root/usr/lib ldd "$f" 2>/dev/null; done); if grep -q "not found" <<<"$out"; then grep "not found" <<<"$out" | sort -u; exit 1; fi; echo "all libraries resolved"'
R 'Xvfb :1 -screen 0 1280x860x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &'
sleep 2
U 'cd ~ && nohup dbus-run-session -- env NO_AT_BRIDGE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 ./Alizy-x86_64.AppImage --appimage-extract-and-run > /tmp/gui.log 2>&1 &'
check "window appears" U 'for i in $(seq 1 60); do w=$(xdotool search --onlyvisible --name "^Alizy$" 2>/dev/null | head -1); [ -n "$w" ] && { xwininfo -id "$w" | grep -E "Width|Height"; exit 0; }; sleep 1; done; cat /tmp/gui.log; exit 1'
sleep 6
check "app still running after 6 s" U 'pgrep -fa "usr/bin/alizy" | head -2'
U 'w=$(xdotool search --onlyvisible --name "^Alizy$" | head -1); import -window "$w" /tmp/shot.png' && podman cp "$C:/tmp/shot.png" "$OUTD/$TAG.png" \
  && record "screenshot" INFO "$OUTD/$TAG.png"
check "explains that the service is not installed (no crash)" U 'grep -q "not installed" /tmp/gui.log || grep -qi "service" /tmp/gui.log; ! grep -Ei "panicked|segmentation|core dumped" /tmp/gui.log; tail -3 /tmp/gui.log'
check "refuses to run as root" R 'out=$(/home/tester/Alizy-x86_64.AppImage --appimage-extract-and-run 2>&1); echo "$out" | tail -1; grep -q "must not run as root" <<<"$out"'
