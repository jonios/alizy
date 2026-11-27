# Changelog

## Unreleased

### New
- **Proxy mode** (Network → Connection mode). The tunnel comes up without touching
  system routes or DNS; a local SOCKS5 (`127.0.0.1:10808`, with UDP) and HTTP
  (`127.0.0.1:10809`) proxy carries only the apps you point at it. While the VPN is
  down the proxy refuses connections instead of going direct, and the firewall rejects
  proxy traffic on any interface but the tunnel. **Tunnel mode** (all traffic, as
  before) stays the default. Switching modes reconnects and cleans up the previous
  mode's routes, rules and DNS first.
- **Kill switch only in tunnel mode.** In proxy mode it is inactive and shown as such;
  the setting is kept and returns with tunnel mode.
- **VPN sharing: UDP and login.** The SOCKS5 proxy now supports UDP ASSOCIATE (relay on
  the same port; replies pass the kill switch like TCP). Optional username/password for
  both proxies (SOCKS5 RFC 1929, HTTP `Proxy-Authorization: Basic`); the service stores
  only a salted SHA-256 verifier.
- **Persian** interface (Settings → Language), right-to-left, also in the tray menu.
  English stays the default. `README.fa.md`.

### Internal
- Protocol adapter layer: WireGuard and SSH run as drivers behind one connection
  lifecycle (`alizyd::driver`, `alizy-core::protocol`); the IPC wire format is unchanged.
  Design and the plan for sing-box and subscriptions: `docs/MULTI_PROTOCOL.md`.
- CI rejects AI co-author attribution in commit messages (`scripts/check-attribution.sh`);
  `npm run build` fails when a UI string lacks a Persian translation.

### Fixes
- Installer: the upgrade plan and status now report the kill switch from its saved
  setting. 0.2.1 said "nothing leaks" during the service restart whenever Alizy's
  firewall table existed, which is also the case with the kill switch off while a
  WireGuard tunnel is up (behaviour was correct; only the message was wrong).

## 0.2.1

First release distributed through GitHub Releases. (The `v0.2.0` tag exists but its
release build failed on a path bug in the release script; there is no 0.2.0 release.)

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
