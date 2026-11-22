# Linux Compatibility

Alizy has **one** Linux implementation. Behaviour is decided at runtime from
detected capabilities (`alizyd --probe`, also shown in Settings → System Check):
`/etc/os-release`, kernel WireGuard module, required executables, systemd,
firewalld/ufw/iptables flavour, NetworkManager, DNS manager and `resolv.conf`
ownership. The distribution name is only used to phrase install commands
(pacman / apt / dnf / zypper adapters; Alizy never installs packages itself).
Unsupported setups produce an exact message (e.g. *"Required executable `wg`
was not found (WireGuard tools). Fix: sudo apt install wireguard-tools"*).

## Requirements

| Component | Needed by | Packages (pacman / apt / dnf / zypper) |
|---|---|---|
| Kernel WireGuard (Linux ≥ 5.6 or module) | daemon | in kernel |
| `wg` | daemon | wireguard-tools (all) |
| `ip` | daemon | iproute2 / iproute2 / iproute / iproute2 |
| `nft` + nf_tables | daemon | nftables (all) |
| `pkcheck` | daemon auth | polkit / polkitd / polkit / polkit |
| systemd | service unit, boot-time protection | — |
| systemd-resolved **or** resolvconf **or** writable `/etc/resolv.conf` | DNS | optional openresolv / resolvconf |
| WebKitGTK 4.1 | GUI | webkit2gtk-4.1 / libwebkit2gtk-4.1-0 / webkit2gtk4.1 / libwebkit2gtk-4_1-0 |
| Ayatana AppIndicator | tray (optional) | libayatana-appindicator / libayatana-appindicator3-1 / libayatana-appindicator-gtk3 / libayatana-appindicator3-1 |
| Secret Service (GNOME Keyring, KWallet, KeePassXC) | key storage (optional; 0600 file fallback) | — |
| OpenSSH client ≥ 8.4 (`ssh`, `ssh-keyscan`) | SSH profiles (optional) | openssh / openssh-client / openssh-clients / openssh-clients |
| `badvpn-tun2socks` | SSH profiles (optional) | badvpn (all; may need a third-party repository) |
| `alizy-ssh` system user | SSH profiles | created by the packages (`sysusers.d`) |

SSH dependencies are optional: when missing, System Check shows an
informational note and WireGuard is unaffected. The OpenSSH version is checked
by running `ssh -V` as `alizy-ssh` (never as root); `alizyd --probe` only
checks that the executables exist.

## Tested matrix

Only configurations that were actually exercised are marked tested.

| Distribution | Version | Kernel | Firewall | DNS backend | Desktop | Status |
|---|---|---|---|---|---|---|
| Omarchy / Ryoku (Arch-based) | rolling, 2026-11 | 7.2.8 | nftables 1.1.7, ufw active (iptables-nft) | systemd-resolved (real host); file + resolvconf (isolated) | Hyprland 0.57 (Lua) | **Tested, installed package** (`0.1.0-5`): see docs/REAL_SYSTEM_VALIDATION.md. Not tested here: Secret Service keyring path (no default keyring), Ethernet, NM-managed resolv.conf on the host |
| Arch Linux / Manjaro / EndeavourOS | — | — | — | — | — | untested (same code path as above expected) |
| Debian 12+, Ubuntu 22.04+, Linux Mint, Pop!_OS | — | — | — | — | — | untested |
| Fedora 39+ | — | — | firewalld (nftables backend) | — | — | untested |
| openSUSE Tumbleweed / Leap | — | — | firewalld | — | — | untested |

The namespace suite (`tests/leak/run.sh`) needs no root and is the
recommended first check on any new distribution.

## Known limitations

* **Group membership after install:** if the systemd user manager lingers (`loginctl enable-linger`, uwsm), logging out is not enough — reboot so the session gets the `alizy` group.

* **Non-systemd init:** the daemon runs, but no unit/boot-time protection is shipped.
* **resolv.conf managed by NetworkManager without resolved:** Alizy re-asserts its
  file every 2 s; brief overwrites are possible, but the firewall still blocks DNS
  outside the tunnel, so they cannot leak.
* **firewalld:** coexists (separate table). A `firewall-cmd --reload` does not
  remove `inet alizy`; if anything does, the daemon re-applies it within 2 s.
  firewalld's IPv6 rpfilter can drop replies for IPv6 split-tunnel Direct rules.
* **iptables-legacy rules** from other tools still apply; a drop in either
  framework is final, so they cannot weaken the kill switch.
* **Tray:** requires an AppIndicator library and a StatusNotifier host (GNOME
  needs the AppIndicator extension). Without it the app runs trayless and
  closing the window quits the UI (protection keeps running).
* **Autostart:** XDG autostart `.desktop` entry; desktops that ignore XDG
  autostart need manual setup.
