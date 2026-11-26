<p align="center">
  <img src="src-tauri/icons/128x128.png" alt="Alizy" width="96" />
</p>

<h1 align="center">Alizy</h1>

<p align="center">
  A WireGuard desktop client for Linux with a <strong>real, OS-level kill switch</strong>.<br>
  Kernel nftables rules owned by a small privileged service, verified by reading them back from the kernel, persisted across crashes, reboots and updates — never silently removed.
</p>

<p align="center">
  <a href="#features">Features</a>&ensp;&bull;&ensp;
  <a href="#installation">Installation</a>&ensp;&bull;&ensp;
  <a href="#quick-start">Quick Start</a>&ensp;&bull;&ensp;
  <a href="#use-cases">Use Cases</a>&ensp;&bull;&ensp;
  <a href="#configuration">Configuration</a>&ensp;&bull;&ensp;
  <a href="#troubleshooting">Troubleshooting</a>&ensp;&bull;&ensp;
  <a href="#architecture">Architecture</a>&ensp;&bull;&ensp;
  <a href="#security">Security</a>
</p>

---

## What Is Alizy?

Alizy is a WireGuard VPN client that takes leak prevention seriously. Instead of a user-space packet filter that disappears when the app crashes, Alizy installs **kernel-level nftables rules** owned by a system service (`alizyd`) that runs independently of the GUI. If the app crashes, if the daemon is killed, if you reboot — the kill switch stays in the kernel and blocks everything outside the tunnel.

The GUI is an unprivileged [Tauri 2](https://v2.tauri.app/) + React app that talks to the daemon over a Unix socket. It never runs as root.

**Status:** Linux is implemented and [validated on a real system](docs/REAL_SYSTEM_VALIDATION.md). Windows and macOS are documented but **not implemented** — see [docs/PLATFORMS.md](docs/PLATFORMS.md).

## Features

### Kill Switch

- **Real nftables rules in the kernel** — not a user-space packet filter.
- Independent IPv4 and IPv6 blocking — disable one family without affecting the other.
- DNS leak protection: UDP/TCP port 53 and DoT (853) blocked on every non-tunnel interface while connected.
- Atomic firewall updates — the drop rule is never absent, not even for a millisecond during a profile switch.
- Survives GUI crashes, daemon crashes (`Restart=always`), reboots (`Type=notify`, ordered before `network-pre.target`), and package upgrades.
- Verified every 2 seconds by reading the kernel table back and comparing it to the expected state. If a third party flushes the ruleset, it is re-applied.
- Protected mode: kill switch on with no tunnel means only loopback, DHCP and (optionally) LAN are allowed.

### Split Tunnelling

- **VPN by default**, explicit bypass rules for traffic that should go direct.
- Rules by IP, CIDR range, or domain name (with CNAME support and shared-CDN warnings).
- TTL-aware DNS resolution engine — bypass addresses update when DNS answers change.
- Deterministic precedence: longest prefix wins; a VPN rule always overrides a Direct rule at equal specificity.
- Routing test tool reads the kernel state and tells you exactly how a given address will be routed.
- Bulk import/export: paste, TXT, CSV, JSON.

Details: [SPLIT_TUNNELING.md](SPLIT_TUNNELING.md), [DOMAIN_ROUTING.md](DOMAIN_ROUTING.md), [DNS_ROUTING.md](DNS_ROUTING.md).

### LAN Proxy

Share this machine's VPN connection with other devices on your Wi-Fi — a smart TV, a phone, a game console — by turning on an HTTP and SOCKS5 forward proxy. The other device sets a manual proxy to your machine's local IP. The proxy's outbound traffic goes through the tunnel (or through split-tunnel Direct rules), and the kill switch covers it.

Details: [LAN_PROXY.md](LAN_PROXY.md).

### SSH Tunnel Profiles

Besides WireGuard, a profile can be a VPN-style tunnel over SSH: the daemon runs `ssh -D` and `badvpn-tun2socks` as an unprivileged system user (`alizy-ssh`) and routes the system through a TUN device. The same kill switch, split tunnelling, DNS management and auto-reconnect apply. Only TCP is tunnelled; UDP is blocked (no leaks) and DNS is forwarded over TCP through the SOCKS proxy.

SSH profiles use trust-on-first-use host key verification, a one-shot askpass socket for the password, and all SSH processes run with dropped privileges.

### Profile Management

- Import: single file, bulk files, folder, drag-and-drop, clipboard paste.
- Validation and sanitisation: `PostUp`/`PreDown`/etc. hook scripts are stripped and **never executed**.
- Duplicate detection, edit, duplicate, favourites, categories.
- Export and full backup/restore.
- Private keys stored in the OS keyring (GNOME Keyring, KWallet, KeePassXC) with automatic migration; a 0600-file fallback is used when no keyring is available, and the UI says so.

### Desktop Integration

- Unprivileged GUI: Tauri 2, React, Tailwind CSS, system tray, notifications, light and dark themes.
- Close-to-tray: closing the window hides the app; **Quit** exits only the UI. Neither touches the kill switch.
- Launch at startup (XDG autostart).
- Auto-connect: reconnect your last profile on login or after a service restart/upgrade.
- Connection history, event logs, system check screen.

### Multi-Distribution Support

Runtime capability detection (`alizyd --probe`) adapts to the running system. The probe checks for kernel WireGuard, required executables, the DNS backend (systemd-resolved / resolvconf / plain file), and the firewall framework, then tells you exactly what is missing and the install command for your package manager (pacman / apt / dnf / zypper).

Details: [LINUX_COMPATIBILITY.md](LINUX_COMPATIBILITY.md).

## System Requirements

### Runtime

| Component | Required? | Packages |
|---|---|---|
| Linux kernel &ge; 5.6 (or WireGuard module) | yes | (in kernel) |
| `wg` (wireguard-tools) | yes | `wireguard-tools` |
| `ip` (iproute2) | yes | `iproute2` |
| `nft` (nftables) | yes | `nftables` |
| polkit (`pkcheck`) | yes | `polkit` |
| systemd | yes | (init system) |
| WebKitGTK 4.1 | yes (GUI) | `webkit2gtk-4.1` |
| GTK 3 | yes (GUI) | `gtk3` |
| Ayatana AppIndicator | recommended | `libayatana-appindicator` |
| Secret Service provider | recommended | `gnome-keyring` / KWallet / KeePassXC |
| systemd-resolved **or** resolvconf **or** writable `/etc/resolv.conf` | one of | `openresolv` (if no resolved) |
| OpenSSH &ge; 8.4 | SSH profiles only | `openssh` |
| `badvpn-tun2socks` | SSH profiles only | `badvpn` (Arch: official `extra` repo) |

On Arch Linux every package above, required and optional, is in the official `core`/`extra` repositories.

### Build

| Tool | Version |
|---|---|
| Rust | &ge; 1.80 |
| Node.js | &ge; 20 |
| npm | (ships with Node.js) |
| Tauri CLI | (installed via `npm ci`) |
| WebKitGTK 4.1 dev files | (for Tauri) |

## Installation

### Arch Linux (AUR)

```bash
yay -S alizy
```

or

```bash
paru -S alizy
```

Without an AUR helper:

```bash
git clone https://aur.archlinux.org/alizy.git
cd alizy && makepkg -si
```

This installs two packages built from one source: **`alizyd`** (the system service) and **`alizy`** (the app). Then, once:

```bash
sudo systemctl enable --now alizyd
```

```bash
sudo usermod -aG alizy "$USER"
```

**Log out completely and log back in**, check that `id -nG` lists `alizy`, and start **Alizy** from your application menu. If `alizy` is missing after logging back in, your systemd user manager outlived the logout (lingering, uwsm, another open session): reboot once.

The full Arch guide covers optional packages, desktop environments, updating, uninstalling and troubleshooting: [docs/ARCH_LINUX.md](docs/ARCH_LINUX.md).

### Arch Linux (from a local checkout)

For development: packages your working tree, including uncommitted changes.

```bash
cd packaging/arch && makepkg -si
```

### Other Systemd Distributions (from source)

Install build dependencies — for example on Debian/Ubuntu:

```bash
sudo apt install build-essential curl wget libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
  librsvg2-dev libssl-dev pkg-config wireguard-tools nftables iproute2 policykit-1
```

Install [Rust](https://rustup.rs/) (&ge; 1.80) and [Node.js](https://nodejs.org/) (&ge; 20), then:

```bash
git clone https://github.com/jonios/alizy.git
cd alizy
npm ci
cargo build --release -p alizyd
npx tauri build --no-bundle
sudo packaging/linux/install.sh
```

The install script checks for missing dependencies before installing, enables the service, and adds your user to the `alizy` group if you run it with sudo from your normal account.

Log out completely and log back in (reboot if `id -nG` still lacks `alizy`), then start Alizy from the application menu.

### Verifying Your System

At any time, check whether your system has everything Alizy needs:

```bash
alizyd --probe
```

This prints every requirement with its status, and the exact install command for your package manager if something is missing. Nothing is installed automatically.

## Quick Start

1. **Launch Alizy** from your application menu (or run `alizy` from a terminal).
2. **Import a WireGuard profile**: click **Import** on the Configurations screen and choose a `.conf` file, paste a configuration, drag-and-drop files, or select a folder of configs.
3. **Connect**: select a profile and click **Connect**.
4. **Enable the kill switch** (recommended): go to **Network Settings** and turn on the kill switch. This blocks all traffic outside the tunnel — including if the connection drops.

That's it. Your traffic is now routed through the VPN, DNS leaks are blocked, and the kill switch protects you even if the app or daemon crashes.

### Closing the Window vs. Stopping Protection

| Action | What happens |
|---|---|
| Close the window | Hides to tray. VPN and kill switch unchanged. |
| Tray &rarr; Quit Alizy | Exits the GUI. VPN and kill switch unchanged (they are kernel state). |
| Network Settings &rarr; Kill switch off | Removes firewall rules. Traffic flows directly. |
| `systemctl stop alizyd` | Stops the daemon. Kill switch rules **stay in the kernel** (by design). |
| `alizyd --remove-firewall` | Removes Alizy's nftables table entirely. |

## Use Cases

### Privacy on Untrusted Networks

Connect to a VPN on public Wi-Fi with the kill switch on. If the Wi-Fi drops, the VPN reconnects, or the system suspends and resumes, the kill switch blocks all traffic until the tunnel is back. No packets leak during the transition.

### Domain-Based Split Tunnelling

Route most traffic through the VPN but let your bank's website (`bank.example.com`) go direct to avoid geo-blocks. Add it as a Direct rule; Alizy resolves the domain, tracks CNAME chains, refreshes when DNS TTLs expire, and warns you if the domain shares addresses with a CDN.

### Sharing Your VPN with a Smart TV

Turn on the LAN proxy in Network Settings. Set a manual HTTP proxy on your TV to this machine's local IP and port 8080. The TV's traffic now exits with your VPN's public IP. For apps like Telegram that use SOCKS5, point them to port 1080 instead.

### SSH as a VPN

Don't have a WireGuard server? Create an SSH profile with your server's address, username and password. Alizy tunnels your system's TCP traffic through an SSH SOCKS proxy + TUN device, with the same kill switch and leak protection as WireGuard. UDP is blocked to prevent leaks.

### Servers and Headless Systems

The daemon (`alizyd`) works without the GUI. Control it over the Unix socket with JSON commands (the protocol is documented in the architecture). The daemon handles connection state, the kill switch, split tunnelling and DNS independently.

## Configuration

### Network Settings

| Setting | Default | Description |
|---|---|---|
| Kill switch | off | Block all traffic outside the tunnel. |
| Allow LAN while protected | on | Let local network traffic through when the kill switch is on. |
| IPv4 | on | Allow IPv4 through the tunnel. Turn off to block all IPv4. |
| IPv6 | on | Allow IPv6 through the tunnel. Turn off to block all IPv6. |
| DNS leak protection | on | Block DNS on port 53/853 outside the tunnel. |
| Custom DNS | (profile DNS) | Override the profile's DNS servers. |
| Auto-reconnect | on | Reconnect after a network change or daemon restart. |
| Share VPN (LAN proxy) | off | HTTP (8080) + SOCKS5 (1080) proxy for other devices. |

### Split Tunnelling

Add rules under the **Split Tunnelling** screen:

- **IP / CIDR**: `192.168.1.0/24`, `203.0.113.10`, `2001:db8::/32`
- **Domain**: `example.com`, `*.cdn.example.com`, `.example.com`
- **Action**: Direct (bypass VPN) or VPN (force through tunnel)

Rules can be imported in bulk from TXT, CSV, or JSON files.

### Profile Settings

Each WireGuard profile supports the standard `[Interface]` and `[Peer]` sections. Alizy strips and ignores `PostUp`, `PreDown`, `PostDown`, `PreUp`, `SaveConfig`, and `Table` keys — these run arbitrary shell commands and are a security risk.

### Data Locations

| Data | Location |
|---|---|
| Profiles, settings, history, logs | `~/.local/share/io.alizy.app/alizy.db` |
| Private keys | OS keyring (`io.alizy.app`) or `~/.local/share/io.alizy.app/secrets/` |
| Daemon state, split rules, DNS cache | `/var/lib/alizy/state.json` |
| IPC socket | `/run/alizy/alizyd.sock` |

## Troubleshooting

### "Permission denied" when launching the GUI

Your user is not in the `alizy` group, or the group membership hasn't taken effect yet.

```bash
sudo usermod -aG alizy "$USER"
```

Then log out completely and log back in, and check `id -nG`. If `alizy` is still missing, reboot: your systemd user manager outlived the logout (lingering, uwsm, another open session) and kept the old group list.

### "The Alizy service (alizyd) is not running"

The daemon is not running.

```bash
sudo systemctl start alizyd
sudo systemctl status alizyd
```

If it fails to start, check the journal:

```bash
journalctl -u alizyd -e
```

### Kill switch is on and I have no internet

This is by design when the VPN is not connected (Protected mode). To restore internet:

- **In the GUI**: go to Network Settings and turn the kill switch off.
- **From a terminal** (if the GUI is not available):

```bash
sudo alizyd --remove-firewall
```

### DNS is not working while connected

Check which DNS backend is in use:

```bash
resolvectl status
```

If `alizy0` does not show your tunnel's DNS servers, the connection may not have set them correctly. Check the daemon log:

```bash
journalctl -u alizyd --since "5 min ago"
```

### Split tunnelling rule doesn't seem to work

Use the routing test tool (in the Split Tunnelling screen or via the daemon) to check how a given address is routed. It reads the kernel nftables sets and policy rules and tells you whether the address would go through the VPN or direct.

### No tray icon

The tray requires `libayatana-appindicator` and a StatusNotifier host. On GNOME, install the [AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/). Without a tray, closing the window quits the UI (protection keeps running).

### System check says something is missing

Run the built-in probe to see exact requirements and install commands:

```bash
alizyd --probe
```

Or open **Settings &rarr; System Check** in the GUI.

### LAN proxy: other device can't connect

If your distribution's firewall (ufw, firewalld) is active, it may block incoming connections to the proxy port. Allow the ports from your local network:

```bash
# ufw
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 1080 proto tcp

# firewalld
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --add-port=1080/tcp --permanent
sudo firewall-cmd --reload
```

## Architecture

```
GUI (user)  ──Tauri commands──►  alizy (Tauri shell, SQLite, keyring)
                                     │ JSON over /run/alizy/alizyd.sock (0660 root:alizy + polkit)
                                     ▼
                                 alizyd (root, systemd)  ──►  wg / ip / nft / resolvectl
```

Alizy is split into two processes:

- **`alizy`** — the unprivileged GUI (Tauri 2 + React). Manages profiles in SQLite, stores keys in the OS keyring, and talks to the daemon over a Unix socket. Never runs as root.
- **`alizyd`** — the privileged daemon (systemd service). Manages WireGuard interfaces, nftables rules, routing, DNS, and the kill switch. Authorizes requests via polkit.

Business logic (what firewall rules to install, what routes to add, which state transitions are legal) lives in the `alizy-core` crate as pure functions that return data structures. The daemon only executes those plans. This keeps the security-critical logic unit-testable without root.

| Crate | Purpose |
|---|---|
| `crates/alizy-core` | Config parser, firewall renderer, routing/DNS plans, split-tunnel engine, DNS codec, state machine, system probe, IPC protocol |
| `crates/alizy-store` | SQLite schema, profile manager, settings, history, keyring secret store |
| `crates/alizyd` | Privileged daemon; Linux platform adapter |
| `src-tauri` | GUI shell, tray, Tauri commands, daemon client, status poller |

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Security

The security model is documented in full in [SECURITY.md](SECURITY.md). Key properties:

- **Fail closed**: if the firewall cannot be confirmed active, connect aborts. If the daemon crashes, kernel rules stay. If the daemon restarts, it re-applies protection before signalling readiness to systemd.
- **No shell**: every external process is spawned with an argv vector, a cleared environment, and a fixed `PATH`. There is no shell anywhere.
- **No hook execution**: `PostUp`/`PreDown`/etc. from imported configs are stripped.
- **IPC authorization**: the socket is `0660 root:alizy`; the daemon checks `SO_PEERCRED` and authorizes with polkit.
- **Key handling**: private keys are `Zeroizing`, `Debug` prints `[redacted]`, never logged, never stored in SQLite. Stored in the OS keyring with a 0600-file fallback.
- **SSH privilege separation**: `ssh`, `ssh-keyscan`, and `badvpn-tun2socks` run as the unprivileged `alizy-ssh` user with dropped supplementary groups and a cleared environment.
- **Systemd hardening**: `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, `LimitCORE=0`, and more.

An independent adversarial security review found and fixed 15 issues before the first real-system validation. See [docs/REAL_SYSTEM_VALIDATION.md](docs/REAL_SYSTEM_VALIDATION.md) for the full report.

Report vulnerabilities privately to the maintainers; do not open public issues for security bugs.

## Building from Source

```bash
npm ci
cargo build --release -p alizyd
npx tauri build --no-bundle
```

Arch package (split `alizyd` + `alizy`):

```bash
cd packaging/arch && makepkg -si
```

## Tests

```bash
cargo test --workspace
```

Unit and integration tests cover the config parser, firewall renderer, routing engine, split-tunnel compiler, DNS wire codec, store operations, and state machine transitions (77 tests).

```bash
tests/leak/run.sh
```

Real-kernel tests in unprivileged user/network namespaces: kill switch enforcement, leak probes, split tunnelling, crash recovery, DNS backends, firewall tamper detection (55 tests). No root required.

```bash
npm run build
```

Type-check and bundle the UI.

See [tests/leak/README.md](tests/leak/README.md) for what the namespace suite proves and what it does not.

## Development

```bash
npm run tauri dev               # GUI with hot reload (needs a running alizyd)
sudo ./target/debug/alizyd      # dev daemon on /run/alizy/alizyd.sock (requires group alizy)
```

Code quality: `cargo fmt --all`, `cargo clippy --workspace --all-targets` (zero warnings), `npm run typecheck`.

## Updating

Arch: `yay -Syu` or `paru -Syu`. Profiles, keys, settings and split rules are kept. The service restarts onto the new version and the app reconnects your previous profile; with the kill switch on, nothing leaks during the restart. Details: [docs/ARCH_LINUX.md](docs/ARCH_LINUX.md#6-updating).

## Uninstall

Arch: remove only the app (the service keeps running):

```bash
sudo pacman -R alizy
```

Remove app and service:

```bash
sudo pacman -Rs alizy
```

Removing the service stops it and deletes Alizy's firewall table, routing rules and interface, and restores DNS, so the network works normally right away. Profiles, keys and `/var/lib/alizy` are kept; pacman prints how to delete them for a complete removal.

Other distributions:

```bash
sudo packaging/linux/uninstall.sh
```

This disables the service and removes **only** Alizy's nftables table, routing rules and interface, then restores `/etc/resolv.conf` if Alizy had replaced it. Add `--purge` to also delete `/var/lib/alizy`. Per-user data stays in `~/.local/share/io.alizy.app` and the keyring (`io.alizy.app`).

## License

[GPL-3.0-or-later](LICENSE)
