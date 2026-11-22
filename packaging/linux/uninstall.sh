#!/usr/bin/env bash
# Remove Alizy. Removes ONLY Alizy's firewall table, routing rules and
# interface; other firewall configuration is never touched.
# Usage: sudo packaging/linux/uninstall.sh [--purge]   (--purge also deletes /var/lib/alizy)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
PREFIX=${PREFIX:-/usr}
systemctl disable --now alizyd.service 2>/dev/null || true
[[ -x "$PREFIX/bin/alizyd" ]] && "$PREFIX/bin/alizyd" --remove-firewall || true
# Restore resolv.conf if the service was stopped while connected without resolved.
if [[ -f /var/lib/alizy/resolv.conf.backup ]]; then
  if [[ -f /var/lib/alizy/resolv.conf.link ]]; then ln -sfn "$(cat /var/lib/alizy/resolv.conf.link)" /etc/resolv.conf
  else cp /var/lib/alizy/resolv.conf.backup /etc/resolv.conf; fi
fi
rm -f "$PREFIX/bin/alizyd" "$PREFIX/bin/alizy" \
  /usr/lib/systemd/system/alizyd.service /usr/lib/sysusers.d/alizy.conf \
  /usr/share/polkit-1/actions/io.alizy.policy /usr/share/applications/io.alizy.app.desktop \
  /usr/share/icons/hicolor/128x128/apps/io.alizy.app.png
systemctl daemon-reload
[[ "${1:-}" == "--purge" ]] && rm -rf /var/lib/alizy
echo "Alizy removed. The 'alizy' group and 'alizy-ssh' user were kept (remove with: groupdel alizy; userdel alizy-ssh)."
echo "Per-user data remains in ~/.local/share/io.alizy.app and the keyring entries 'io.alizy.app'."
