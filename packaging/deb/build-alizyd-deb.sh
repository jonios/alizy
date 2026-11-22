#!/usr/bin/env bash
# Build the alizyd .deb (Debian, Ubuntu, Linux Mint, Pop!_OS) with dpkg-deb.
# The GUI .deb is produced by the Tauri bundler and depends on this package.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VER=0.1.0
ARCH=$(dpkg --print-architecture)
OUT="$ROOT/target/deb/alizyd_${VER}_${ARCH}"
rm -rf "$OUT"; mkdir -p "$OUT/DEBIAN"
install -Dm755 "$ROOT/target/release/alizyd" "$OUT/usr/bin/alizyd"
install -Dm644 "$ROOT/packaging/linux/alizyd.service" "$OUT/lib/systemd/system/alizyd.service"
install -Dm644 "$ROOT/packaging/linux/alizy.sysusers" "$OUT/usr/lib/sysusers.d/alizy.conf"
install -Dm644 "$ROOT/packaging/linux/io.alizy.policy" "$OUT/usr/share/polkit-1/actions/io.alizy.policy"
cat > "$OUT/DEBIAN/control" <<CTL
Package: alizyd
Version: $VER
Architecture: $ARCH
Maintainer: Alizy developers <noreply@alizy.invalid>
Depends: wireguard-tools, nftables, iproute2, polkitd | policykit-1, systemd
Recommends: resolvconf | openresolv
Section: net
Priority: optional
Description: Alizy VPN service (WireGuard, nftables kill switch, split tunnelling)
 Privileged service used by the Alizy desktop client. Owns an isolated
 nftables table (inet alizy) and never modifies other firewall rules.
CTL
cat > "$OUT/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
systemd-sysusers /usr/lib/sysusers.d/alizy.conf || addgroup --system alizy || true
systemctl daemon-reload || true
echo "Enable with: sudo systemctl enable --now alizyd ; sudo usermod -aG alizy \$USER"
SH
cat > "$OUT/DEBIAN/prerm" <<'SH'
#!/bin/sh
systemctl disable --now alizyd.service 2>/dev/null || true
/usr/bin/alizyd --remove-firewall 2>/dev/null || true
SH
chmod 755 "$OUT/DEBIAN/postinst" "$OUT/DEBIAN/prerm"
dpkg-deb --root-owner-group --build "$OUT"
echo "built $OUT.deb"
