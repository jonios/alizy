# Alizy

A WireGuard desktop client built around a **real, OS-level kill switch**:
nftables rules owned by a small privileged service, verified by reading them
back from the kernel, persisted across crashes and reboots, and never removed
to perform an update.

* Kernel WireGuard (no userspace re-implementation); keys handed to `wg` over stdin.
* Kill switch, independent IPv4/IPv6 blocking and DNS leak protection in one
  isolated nftables table (`inet alizy`), replaced atomically.
* Split tunnelling: VPN by default, explicit Direct exceptions by IP/CIDR or
  domain (with a TTL-aware resolution engine, CNAME support, shared-CDN warnings
  and a routing test tool that reads the kernel state).
* Profiles: import single/bulk/folder/drag-and-drop/paste, validation and
  sanitisation (hook scripts are stripped and never executed), duplicate
  detection, edit, duplicate, favourites, categories, export, backup/restore.
  Private keys live in the OS keyring, never in SQLite.
* Unprivileged GUI (Tauri 2 + React) with tray, notifications, logs and history.
* Multi-distribution Linux support through runtime capability detection.

**Status:** Linux is implemented. Windows and macOS are documented but **not
implemented** — see [docs/PLATFORMS.md](docs/PLATFORMS.md).

## Architecture in one picture

```
GUI (user)  ──Tauri commands──►  alizy (Tauri shell, SQLite, keyring)
                                     │ JSON over /run/alizy/alizyd.sock (0660 root:alizy + polkit)
                                     ▼
                                 alizyd (root, systemd)  ──►  wg / ip / nft / resolvectl
```

Details: [ARCHITECTURE.md](ARCHITECTURE.md) · Security: [SECURITY.md](SECURITY.md),
[ROUTING_SECURITY.md](ROUTING_SECURITY.md) · Split tunnelling:
[SPLIT_TUNNELING.md](SPLIT_TUNNELING.md), [DOMAIN_ROUTING.md](DOMAIN_ROUTING.md),
[DNS_ROUTING.md](DNS_ROUTING.md) · Distros: [LINUX_COMPATIBILITY.md](LINUX_COMPATIBILITY.md)

## Requirements (build)

* Rust ≥ 1.80, Node.js ≥ 20 + npm
* WebKitGTK 4.1 and GTK 3 development files, `libayatana-appindicator` (tray)
* Runtime: kernel WireGuard, `wireguard-tools`, `nftables`, `iproute2`, `polkit`, systemd

Check a machine at any time (prints exact missing requirements and the install
command for pacman/apt/dnf/zypper — nothing is installed automatically):

```bash
cargo run -p alizyd -- --probe
```

## Build

```bash
npm ci
cargo build --release -p alizyd
npx tauri build --no-bundle
```

Bundles: `npx tauri build --bundles deb,rpm,appimage` (GUI) ·
`packaging/arch/PKGBUILD` (split `alizyd` + `alizy`) ·
`packaging/rpm/alizyd.spec` (Fedora/openSUSE) · `packaging/deb/build-alizyd-deb.sh`.
The privileged service is always a separate package from the GUI.
**Only the Arch package has been installed and validated on a real system** (see
[docs/REAL_SYSTEM_VALIDATION.md](docs/REAL_SYSTEM_VALIDATION.md)); the DEB, RPM and
AppImage outputs are untested.

## Install

Arch-based:

```bash
cd packaging/arch && makepkg -si
```

Any systemd distribution, from a source build:

```bash
sudo packaging/linux/install.sh
```

Then, once:

```bash
sudo systemctl enable --now alizyd
```

```bash
sudo usermod -aG alizy "$USER"
```

Reboot (a re-login is not enough when the systemd user manager lingers, e.g. with `loginctl enable-linger` or uwsm), then start **Alizy** from the application menu as your
normal user. The GUI refuses to run as root.

## Uninstall

```bash
sudo packaging/linux/uninstall.sh
```

This disables the service and removes **only** Alizy's nftables table, routing
rules and interface, then restores `/etc/resolv.conf` if Alizy had replaced it.
Add `--purge` to delete `/var/lib/alizy`. Per-user data stays in
`~/.local/share/io.alizy.app` and the keyring (`io.alizy.app`).

## Closing the window vs. stopping protection

Closing the window hides Alizy to the tray; **Quit Alizy** exits only the UI.
Neither touches the kill switch — it is kernel state owned by `alizyd`. To stop
protection, turn the kill switch off in Network Settings, or stop the service
(`systemctl stop alizyd` keeps the kill switch in place by design; use
`alizyd --remove-firewall` to remove it entirely).

## Tests

```bash
cargo test --workspace          # unit + integration (parser, firewall renderer, routing, split engine, DNS codec, store)
tests/leak/run.sh               # real kernel, unprivileged namespaces: kill switch, leaks, split tunnelling, recovery
npm run build                   # type-check + bundle the UI
```

See [tests/leak/README.md](tests/leak/README.md) for exactly what the
namespace suite proves and what it does not.

## Development

```bash
npm run tauri dev               # GUI with hot reload (needs a running alizyd)
sudo ./target/debug/alizyd      # dev daemon on /run/alizy/alizyd.sock (requires group alizy)
```

`cargo fmt --all`, `cargo clippy --workspace --all-targets` (kept at zero
warnings) and `npm run typecheck`.
