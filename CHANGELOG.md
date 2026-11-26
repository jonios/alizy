# Changelog

## 0.2.0 (unreleased)

First release distributed through GitHub Releases.

### Distribution
- **AppImage** (`Alizy-x86_64.AppImage`): the desktop app as one portable file, built on
  Ubuntu 22.04 and running on glibc 2.34+ (Ubuntu 22.04+, Debian 12+, Fedora 36+, Arch).
- **System installer** (`alizy-installer-x86_64`): installs, upgrades and removes the
  `alizyd` service. Checks and offers to install dependencies per distribution, upgrades
  with automatic rollback while the kill-switch rules stay in the kernel, and on
  uninstall removes Alizy's firewall, routing and DNS state (also after a crash) without
  touching profiles or keys. `remove-app` removes the AppImage and its menu entry.
- `SHA256SUMS` for both assets; releases are built by a GitHub Actions workflow as drafts.

### Fixes
- WireGuard carried no data on systems with strict reverse-path filtering
  (`rp_filter=1` on every interface). The firewall now restores the WireGuard mark on
  the server's replies, as wg-quick does.
- With systemd-resolved stopped, systemd's `resolvconf` compatibility shim was used as
  resolvconf and connecting failed (e.g. Fedora). Alizy now manages `/etc/resolv.conf`
  directly in that case.
- Connecting no longer fails where `/proc/sys` is read-only if the needed sysctl is
  already set.

### App
- Clear message when the service is not installed, with what to do.
- Warning when the app and the service versions differ.
- Settings → About → *Check for updates*: asks GitHub on request only; downloads nothing.
- LAN proxy: share the VPN with other devices over HTTP and SOCKS5 (no password; see
  `LAN_PROXY.md`).

### Development
- Minimum Rust version is now 1.88 (the code already required it).
- Container-based tests for the installer lifecycle and the AppImage on Ubuntu 22.04/24.04,
  Debian 12, Fedora 45 and Arch; results in `docs/TESTING.md`.

## 0.1.0

WireGuard and SSH tunnel client with an nftables kill switch, DNS leak protection, split
tunnelling and profile management; Linux packages built from source (Arch PKGBUILD).
