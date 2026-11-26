# What has been tested

Results for the AppImage + installer release workflow, recorded 2026-11-26 against the
release build of version 0.1.0 (the assets `scripts/release/build-in-container.sh`
produces). Older validation of the daemon and the Arch packages:
[REAL_SYSTEM_VALIDATION.md](REAL_SYSTEM_VALIDATION.md).

**PASS** = run and verified. **Not tested** = not run; no claim is made.

## Release build

| Check | Result |
|---|---|
| Build on Ubuntu 22.04 (Rust 1.100.0, Node 24.22.3) | PASS |
| `cargo test --workspace` in the release environment | 238 passed, 0 failed, 2 ignored |
| glibc floor of `alizyd` and the AppImage's `alizy` | glibc ≤ 2.34 (target 2.35) |
| AppImage contents (AppRun, desktop file), installer header syntax, payload marker, `--help` version, `alizyd --version` | PASS |
| `SHA256SUMS` generated and verified | PASS |
| `cargo fmt --check`, `cargo clippy -D warnings`, `npm run build` on Rust 1.100 | see the commit's CI run |
| Real-kernel namespace suite (`tests/leak/run.sh`): kill switch, TCP/DNS leaks, split tunnelling, crash recovery, firewall tamper | 55 passed, 0 failed |

## Installer lifecycle: `tests/installer/run.sh <distro>`

Each run boots the distribution with systemd in a rootless container **without**
Alizy's dependencies, plus a second container as a real WireGuard server. 43 checks:

1. `sha256sum -c SHA256SUMS`; a damaged installer refuses to run (payload checksum).
2. Without dependencies the installer stops, names the missing packages and the exact
   command, and installs nothing.
3. `--install-deps` installs them with the distribution's package manager, then installs
   the service: unit loaded from `/usr/local`, active and enabled, files and permissions
   (`alizyd` 0755 root), socket `0660 root:alizy`, `/var/lib/alizy` 0700, `alizy` group
   and `alizy-ssh` user created, user added to the group, AppImage in `~/Applications`
   with a menu entry, logout guidance printed, `status` works without root, the user
   reaches the daemon.
4. Kill switch on and verified against the kernel; connect to the WireGuard server; DNS
   written to `/etc/resolv.conf` (file backend); a real handshake.
5. **Upgrade 0.1.0 → 0.1.1 while connected with the kill switch on:** the nftables table
   was present in every sample (every 0.1 s) during the upgrade; the service restarted
   onto the new files; it came back protected and verified; reconnect works.
6. **Failed upgrade** (a daemon that cannot start): the installer reports it, restores
   the previous version and starts it; the kill-switch table stayed present in every
   sample; the kill switch is verified afterwards.
7. A clean stop restores DNS (daemon).
8. **Uninstall with the daemon stopped, the kill-switch table still in the kernel and
   `/etc/resolv.conf` left modified** (the state after a crash): refused without
   confirmation in a non-interactive shell; with `--yes` it removes the firewall table,
   interface and routing rules, restores `/etc/resolv.conf`, removes the files and keeps
   `/var/lib/alizy`, the group, the user, the user's data and the AppImage.
9. Reinstall warns that the saved kill switch is on; the service comes back protected and
   verified; connect works.
10. `remove-app` removes only the AppImage and menu entry (service still running);
    `uninstall --purge` removes state, group and user, the network is clean, and user
    data is still untouched.

| Distribution | systemd | glibc | Result |
|---|---|---|---|
| Ubuntu 22.04.5 LTS | 249 | 2.35 | **43 / 43 PASS** |
| Ubuntu 24.04.5 LTS | 255 | 2.39 | **43 / 43 PASS** |
| Debian 12 (bookworm) | 252 | 2.36 | **43 / 43 PASS** |
| Fedora 45 | 262 | 2.44 | **43 / 43 PASS** |
| Arch Linux | 262 | 2.44 | **43 / 43 PASS** |

Container limits: no desktop session (polkit's "active session" rule is exercised as root),
systemd-resolved masked (the file DNS backend is tested; resolved is tested on the real
host below), one CPU architecture.

## AppImage: `tests/appimage/smoke.sh <distro>`

On the same five distributions, as a normal user on a virtual X display: no library
missing on a desktop baseline, the window appears, the app is still running after 6 s,
it explains that the service is not installed (no crash), and it refuses to run as root.
**5 / 5 PASS on each of Ubuntu 22.04, Ubuntu 24.04, Debian 12, Fedora 45, Arch Linux.**

Host libraries the AppImage expects, found missing on the bare (non-desktop) images
before the desktop baseline was installed: `libEGL.so.1`, `libgbm.so.1`,
`libwayland-client.so.0`, `libharfbuzz.so.0`, `libfribidi.so.0` (varies by image). These
are excluded from AppImages on purpose and present on desktop installations.

## Real machine: Omarchy (Arch), Hyprland, systemd-resolved, ufw, Wi-Fi

`tests/system/70-installer-migration.sh`, run on the maintainer's machine, which had the
pacman packages `alizy`/`alizyd 0.1.0-11` installed and a WireGuard profile connected
(kill switch **off** at the time): **32 / 32 PASS**.

- The installer refused the pacman-managed install and changed nothing.
- `pacman -R alizy alizyd` removed Alizy's firewall table, routes and interface.
- The installer installed the service, the AppImage and the menu entry; the unit runs
  from `/usr/local` as `Type=notify`; socket `0660 root:alizy`.
- The AppImage started on this machine, connected to the service and reconnected the
  profile; internet through the tunnel.
- Profiles, settings, private-key files, key backends and service state were unchanged
  (digests).
- Reinstalling while connected: the nftables table was present in all 35 samples, the
  service restarted, the app reconnected by itself, and `/etc/resolv.conf` (resolved
  stub) was unchanged.

The kill-switch-**on** variant of upgrade/restart on this machine is in
[REAL_SYSTEM_VALIDATION.md](REAL_SYSTEM_VALIDATION.md) (pacman packages, §7.5, §13).

## Bugs these tests found and fixed

| Found by | Problem | Fix |
|---|---|---|
| screenshot environment (strict `rp_filter=1`) | WireGuard connected but carried no data on systems with strict reverse-path filtering on every interface: the server's encrypted replies were dropped | the firewall now saves the WireGuard socket's mark to conntrack and restores it on replies (`wg_mark`/`wg_pre` chains), as wg-quick does; verified: 0 % → 100 % ping replies, 324 KB/s both ways, leak suite 55/55 |
| Fedora container | with systemd-resolved inactive, systemd's `resolvconf` shim was taken for real resolvconf, so connecting failed | the shim (a link to `resolvectl`) is no longer treated as resolvconf; Alizy manages `/etc/resolv.conf` instead |
| Fedora container | after a failed upgrade, systemd's start rate limit refused the restored version | the installer clears it (`reset-failed`) before starting |
| containers | `/proc/sys` read-only: connecting failed although `src_valid_mark` was already 1 | the daemon only writes sysctls that are not already set |
| Ubuntu container | installer exited 1 after successful uninstall/remove-app; the menu entry was not written (icons in a root-only temp dir) | fixed |
| release build | the existing AppImage needed glibc 2.39 (Ubuntu 24.04+ only) | releases are built on Ubuntu 22.04 |

## Not tested

- A real desktop session of Ubuntu, Debian or Fedora (only containers with a virtual
  display): tray icon, notifications, keyring, file-manager double-click there.
- openSUSE, Linux Mint, Pop!_OS, Manjaro, EndeavourOS.
- The GitHub Actions release workflow itself (it runs on the first tag push; the same
  build script was run locally in the same base image).
- aarch64.
- SSH tunnel profiles through the installer-installed service (covered by
  `tests/ssh/` against the pacman install earlier).
- KDE Plasma, GNOME and other desktops (Hyprland only).
