# Alizy — Implementation Plan

Environment inspected 2026-11-19: Arch-based (Omarchy), kernel 7.2 with the
`wireguard` module, rustc/cargo 1.99.1 (no rustup), Node 26 / npm 11,
wireguard-tools 1.0.20260223, nftables 1.1.7, iproute2, systemd 262 with
systemd-resolved active, NetworkManager, polkit 128, WebKitGTK 4.1,
libayatana-appindicator. No passwordless sudo (root-only tests cannot run in
the dev sandbox).

| # | Milestone | Status |
|---|---|---|
| 1 | Workspace, Tauri 2 shell, premium UI (all screens) | done — UI type-checks and bundles; not yet exercised end-to-end against an installed service |
| 2 | Config parser/validator/sanitiser, duplicate detection, SQLite + migrations, keyring secrets, import (file/bulk/dir/paste/drag-drop), export, backup/restore | done — unit + store integration tests |
| 3 | `alizyd`, Unix-socket IPC, peer-cred + polkit auth, Linux WireGuard engine | done — verified in namespaces; polkit path untested on a real install |
| 4 | State machine, supervisor, auto-reconnect, statistics, tray | done — reconnect verified; tray untested on this compositor |
| 5 | nftables firewall + kill switch, persistence, boot/crash recovery, tamper recovery | done — real-kernel verified |
| 6 | IPv4/IPv6 toggles, DNS leak protection, custom DNS, DNS backends | done — firewall side real-kernel verified; resolved/resolvconf backends not exercised by the suite |
| 6b | Split tunnelling (IP + domain), resolution engine, routing test tool | done — real-kernel verified; app-based routing **not implemented** |
| 6c | Multi-distro detection, package-manager guidance | done — tested on one distro only |
| 7 | Security tests (namespaces) | done — 52/52 |
| 8 | PKGBUILD, deb, rpm, systemd/sysusers/polkit, install/uninstall | Arch package built, installed, upgraded 4× (to 0.1.0-5) and validated on a real system (docs/REAL_SYSTEM_VALIDATION.md); deb/rpm inspected only |
| 9 | Windows/macOS adapters | documented, **not implemented** |
| 10 | Cross-platform validation, release | pending |

See `docs/MILESTONES.md` for the per-milestone log.
