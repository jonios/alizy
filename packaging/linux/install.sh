#!/usr/bin/env bash
# Install Alizy from a source build (any systemd-based distribution).
# Usage: sudo packaging/linux/install.sh [--user NAME]
# Builds are expected in target/release (run `npx tauri build --no-bundle` and
# `cargo build --release -p alizyd` first). Nothing is downloaded or installed
# from package repositories; missing dependencies are reported instead.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX=${PREFIX:-/usr}
USER_TO_ADD=${SUDO_USER:-}
[[ "${1:-}" == "--user" ]] && USER_TO_ADD=$2

[[ $EUID -eq 0 ]] || { echo "run with sudo (only this installer needs root; the app never does)"; exit 1; }
for b in alizyd alizy; do
  [[ -x "$ROOT/target/release/$b" ]] || { echo "missing $ROOT/target/release/$b — build first (see README)"; exit 1; }
done

echo "== dependency check"
"$ROOT/target/release/alizyd" --probe | python3 -c '
import json,sys
r=json.load(sys.stdin); bad=False
for f in r["findings"]:
    print(f"  [{f[\"severity\"]}] {f[\"message\"]}")
    if f["fix"]: print(f"      fix: {f[\"fix\"]}")
    bad |= f["severity"]=="blocker"
sys.exit(1 if bad else 0)' || { echo "Resolve the blockers above, then re-run."; exit 1; }

install -Dm755 "$ROOT/target/release/alizyd" "$PREFIX/bin/alizyd"
install -Dm755 "$ROOT/target/release/alizy" "$PREFIX/bin/alizy"
install -Dm644 "$ROOT/packaging/linux/alizyd.service" /usr/lib/systemd/system/alizyd.service
install -Dm644 "$ROOT/packaging/linux/alizy.sysusers" /usr/lib/sysusers.d/alizy.conf
install -Dm644 "$ROOT/packaging/linux/io.alizy.policy" /usr/share/polkit-1/actions/io.alizy.policy
install -Dm644 "$ROOT/packaging/linux/io.alizy.app.desktop" /usr/share/applications/io.alizy.app.desktop
install -Dm644 "$ROOT/src-tauri/icons/128x128.png" /usr/share/icons/hicolor/128x128/apps/io.alizy.app.png
systemd-sysusers /usr/lib/sysusers.d/alizy.conf
systemctl daemon-reload
systemctl enable --now alizyd.service
if [[ -n "$USER_TO_ADD" ]]; then
  usermod -aG alizy "$USER_TO_ADD"
  echo "Added $USER_TO_ADD to group alizy — log out and back in for it to take effect."
fi
echo "Installed. Start Alizy from your application menu (as your normal user)."
