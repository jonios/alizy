#!/usr/bin/env bash
# Starts the isolated screenshot environment (see Containerfile) from the
# release assets in dist-release/, imports demo profiles and launches the real
# AppImage on a virtual display. Screens are then driven with xdotool and
# captured with ImageMagick inside the container:
#
#   tests/screenshots/shoot.sh start         build + start everything
#   tests/screenshots/shoot.sh x CMD...      run a command on the virtual display (as demo)
#   tests/screenshots/shoot.sh grab NAME     capture the Alizy window to docs/screenshots/NAME.png
#   tests/screenshots/shoot.sh stop
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
C=alizy-shots
IMG=localhost/alizy-shots
BIN=$ROOT/target/shots-bin
OUT=$ROOT/docs/screenshots

x() { podman exec -u demo -e DISPLAY=:1 "$C" "$@"; }

case ${1:-} in
start)
  podman build -q -t "$IMG" "$ROOT/tests/screenshots" >/dev/null
  mkdir -p "$BIN" "$OUT"
  # The exact alizyd shipped in the installer payload.
  python3 - "$ROOT/dist-release/alizy-installer-x86_64" "$BIN/alizyd" <<'PY'
import io, sys, tarfile
data = open(sys.argv[1], "rb").read()
m = b"__ALIZY_PAYLOAD_" + b"BELOW__\n"
t = tarfile.open(fileobj=io.BytesIO(data[data.index(b"\n" + m) + 1 + len(m):]), mode="r:gz")
open(sys.argv[2], "wb").write(t.extractfile("./bin/alizyd").read())
PY
  chmod 0755 "$BIN/alizyd"
  # Test client (imports profiles like the GUI does), built on the release baseline.
  if [[ ! -x $BIN/alizyctl ]]; then
    SNAP=$(mktemp); git -C "$ROOT" ls-files -co --exclude-standard -z | tar -C "$ROOT" --null -T - -cf "$SNAP"; chmod 0644 "$SNAP"
    podman rm -f alizy-shots-ctl >/dev/null 2>&1 || true
    podman run --name alizy-shots-ctl --user 1000:1000 -e HOME=/tmp/home -v alizy-cargo-registry:/opt/cargo/registry:U \
      -v alizy-build-target:/build-target:U -v "$SNAP":/src.tar:ro localhost/alizy-build:ubuntu22.04 \
      bash -c 'mkdir -p /tmp/src && tar -xf /src.tar -C /tmp/src && cd /tmp/src && CARGO_TARGET_DIR=/build-target cargo build -q --locked --release -p alizy-store --example alizyctl'
    podman cp alizy-shots-ctl:/build-target/release/examples/alizyctl "$BIN/alizyctl"
    podman rm -f alizy-shots-ctl >/dev/null
    rm -f "$SNAP"
  fi
  cp "$ROOT/dist-release/Alizy-x86_64.AppImage" "$BIN/"
  podman rm -f "$C" >/dev/null 2>&1 || true
  podman run -d --name "$C" --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --sysctl net.ipv4.ping_group_range="0 65534" \
    -v "$BIN":/dist:ro -v "$ROOT/tests/screenshots":/shots-src:ro -v "$ROOT/tests/leak/helper.py":/shots/helper.py:ro \
    -v "$OUT":/out "$IMG" >/dev/null
  podman exec "$C" bash /shots-src/setup.sh
  podman exec -u demo "$C" bash -c 'cd ~ && dbus-run-session -- /dist/alizyctl import demo-profiles/Frankfurt.conf demo-profiles/Amsterdam.conf demo-profiles/Tokyo.conf'
  podman exec -u demo -d "$C" bash -c 'cd ~ && exec dbus-run-session -- env DISPLAY=:1 NO_AT_BRIDGE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 APPIMAGE_EXTRACT_AND_RUN=1 /dist/Alizy-x86_64.AppImage > /tmp/gui.log 2>&1'
  for _ in $(seq 1 60); do x xdotool search --onlyvisible --name '^Alizy$' >/dev/null 2>&1 && break; sleep 1; done
  x xdotool search --onlyvisible --name '^Alizy$' >/dev/null || { podman exec "$C" cat /tmp/gui.log; exit 1; }
  echo "running; window: $(x xdotool search --onlyvisible --name '^Alizy$' | head -1)"
  ;;
x) shift; x "$@" ;;
grab)
  name=${2:?name}
  wid=$(x xdotool search --onlyvisible --name '^Alizy$' | head -1)
  x import -window "$wid" "/tmp/$name.png"
  podman exec "$C" bash -c "cp /tmp/$name.png /out/$name.png"
  echo "$OUT/$name.png"
  ;;
stop) podman rm -f "$C" >/dev/null; echo stopped ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
