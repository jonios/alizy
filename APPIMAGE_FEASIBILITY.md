> **Status (2026-11-26): implemented, and partly superseded.** The release workflow
> now ships the AppImage plus a separate system installer; see
> [docs/APPIMAGE.md](docs/APPIMAGE.md), [docs/INSTALLATION.md](docs/INSTALLATION.md) and
> [docs/TESTING.md](docs/TESTING.md). Two statements below proved wrong when checked
> against the code and the distributions: Ubuntu 22.04 **does** ship WebKitGTK 4.1
> (2.50 in jammy-updates), and the existing AppImage needed **glibc 2.39** because it
> was built on Arch. Releases are now built on Ubuntu 22.04 (glibc ≤ 2.34 needed).
> Kept for its reasoning.

# Alizy — AppImage Packaging Feasibility

> **خلاصه فارسی (TL;DR).** بله، بسته‌بندی به‌صورت AppImage ممکن است و در عمل
> همین‌الان هم انجام شده است (`target/release/bundle/appimage/Alizy_0.1.0_amd64.AppImage`
> توسط Tauri bundler ساخته می‌شود و commit `a71b899` تأیید می‌کند که روی
> سیستم واقعی اجرا شده و به daemon متصل می‌شود). **اما AppImage فقط می‌تواند
> رابط گرافیکی (`alizy`) را حمل کند، نه سرویس امتیازدار (`alizyd`).** سرویس
> `alizyd` باید root، `systemd`، `polkit`، `nftables`، `wireguard-tools`،
> `CAP_NET_ADMIN`، گروه سیستمی `alizy`، کاربر `alizy-ssh`، unit فایل و polkit
> policy داشته باشد — هیچ‌کدام از این‌ها در sandbox یک AppImage جا نمی‌گیرد.
> بنابراین مدل پیشنهادی **هیبریدی** است: AppImage برای GUI + یک نصب‌کننده
> سبک برای daemon (پکیج توزیع یا اسکریپت `install.sh` موجود).

---

## 1. Verdict

**PARTIALLY — AppImage works for the GUI only (and already does).**

| Component | AppImage-able? | Reason |
|---|---|---|
| `alizy` (Tauri GUI, unprivileged) | **YES — already working** | Tauri bundler emits `.AppImage`; the `a71b899` commit (`docs: AppImage builds and launches on a real system`) confirms real-host launch and successful connection to the daemon. The image sits at `target/release/bundle/appimage/Alizy_0.1.0_amd64.AppImage`. |
| `alizyd` (privileged daemon) | **NO** | Requires systemd unit, polkit action, sysusers (`alizy` group, `alizy-ssh` user), `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_SETUID`/`CAP_SETGID`/`CAP_KILL`/`CAP_NET_BIND_SERVICE`/`CAP_CHOWN` bounding set, `/run/alizy/alizyd.sock` at `0660 root:alizy`, state in `/var/lib/alizy`, boot-before-network ordering (`Before=network-pre.target`). AppImages are user-mode, single-file archives with no install step and no root context — none of this is expressible. |
| Full "self-contained" bundle | **NO** | Deliberate architectural split; see `ARCHITECTURE.md:6-30`. |

The authoritative statement already lives in the project docs:

- `README.md:80-84` — "The AppImage ships the GUI only: the privileged `alizyd` service still has to be installed separately."
- `docs/MILESTONES.md:62-65` — "the AppImage was extracted and launched on a real system; only the Arch package was installed and validated."

---

## 2. Project architecture & tech stack

Two-process design, platform-neutral Rust core, Linux-only daemon adapter.

| Crate | Role | File |
|---|---|---|
| `crates/alizy-core` | Config/firewall/routing/DNS/split-tunnel pure logic + IPC protocol | `crates/alizy-core/src/{firewall,routing,ipc,split,sysprobe,...}.rs` |
| `crates/alizy-store` | SQLite (SQLx) store, migrations, keyring + 0600 fallback | — |
| `crates/alizyd` | Privileged daemon (Linux) | `crates/alizyd/src/main.rs:1-80`, `server.rs`, `engine.rs`, `linux/`, `lan_proxy.rs`, `lan_socks.rs` |
| `src-tauri` | Tauri 2 shell, tray, allow-listed commands | `src-tauri/Cargo.toml:26-33`, `src-tauri/tauri.conf.json` |
| `src/` | React + Vite + Tailwind + Radix + Zustand UI (`index.html`, `vite.config.ts`) | — |

**Tauri 2** with WebKitGTK 4.1 renderer, plugins: `dialog`, `notification`, `autostart`, `single-instance`, tray-icon (`src-tauri/Cargo.toml:27-33`). GUI refuses to run as root (`src-tauri/src/lib.rs:19-21`).

---

## 3. Current build & packaging matrix

| Target | Script / config | Status |
|---|---|---|
| Arch split package (`alizyd` + `alizy`) | `packaging/arch/PKGBUILD` | **Only one validated on a real system** (Omarchy, `0.1.0-5`; see `docs/REAL_SYSTEM_VALIDATION.md`). Pre-built artifacts shipped under `packaging/arch/*.pkg.tar.zst`. |
| Fedora / openSUSE RPM (daemon) | `packaging/rpm/alizyd.spec` | Untested. |
| Debian / Ubuntu `.deb` (daemon) | `packaging/deb/build-alizyd-deb.sh` | Untested. |
| Tauri GUI bundles (`.deb`, `.rpm`, `.AppImage`) | `src-tauri/tauri.conf.json:31-42` (`"targets": ["deb", "rpm", "appimage"]`) | **AppImage built & launched** (commit `a71b899`); `.deb` / `.rpm` outputs untested. |
| From-source installer for any systemd distro | `packaging/linux/install.sh` | Written, static-analysed; depends on `--probe` self-check. |

Tauri Linux bundle depends on `alizyd` for `.deb`/`.rpm` (`tauri.conf.json:39-40`).

---

## 4. Runtime dependencies

**Daemon (`alizyd`), from `PKGBUILD:35-38`, `alizyd.spec:12-19`, `build-alizyd-deb.sh:19-20`:**
- Required: `wireguard-tools`, `nftables`, `iproute2`, `polkit`, `systemd`, kernel WireGuard module (≥ 5.6).
- Optional: `openresolv` (non-resolved DNS), `openssh` (SSH profiles), `badvpn` (`badvpn-tun2socks` for SSH-tunnel TUN).

**GUI (`alizy`), from `PKGBUILD:50-52`, `LINUX_COMPATIBILITY.md:23-25`:**
- `webkit2gtk-4.1`, `gtk3`, `libayatana-appindicator` (tray; graceful degrade without it), Secret Service provider (GNOME Keyring / KWallet; otherwise 0600 file fallback).

**External binaries spawned by the daemon:** `wg`, `ip`, `nft`, `pkcheck`, optionally `ssh`, `ssh-keyscan`, `badvpn-tun2socks`, `resolvectl` or writes to `/etc/resolv.conf`. Spawn is centralised in `crates/alizyd/src/exec.rs` (no shell, cleared env, fixed `PATH`).

---

## 5. GUI framework & launch flow

- Tauri 2 + WebKitGTK; app id `io.alizy.app`; window hidden until ready (`tauri.conf.json:5,14-23`).
- Single-instance, tray, close-to-tray, autostart (`src-tauri/Cargo.toml:27-30`).
- Desktop entry: `packaging/linux/io.alizy.app.desktop` (`Exec=alizy`, `StartupWMClass=alizy`).
- Icons at `src-tauri/icons/{32x32,128x128,128x128@2x,icon.png}` (`tauri.conf.json:37`).
- CSP forces `connect-src ipc: http://ipc.localhost` only — the UI never speaks to the network itself (`tauri.conf.json:27`).
- **IPC path (hard-coded):** `/run/alizy/alizyd.sock` — `crates/alizy-core/src/ipc.rs:13` (`SOCKET_PATH`), overridable via `ALIZY_SOCKET` (`src-tauri/src/daemon_client.rs:21`).

---

## 6. Background service & systemd integration (`packaging/linux/alizyd.service`)

- `Type=notify`, `NotifyAccess=main`, ready only after firewall applied (`alizyd.service:12-16`).
- **Early-boot ordering**: `DefaultDependencies=no`, `Before=network-pre.target`, `Wants=network-pre.target` (`:5-8`) — the kill switch is up before any network interface.
- Runtime/state dirs via systemd: `RuntimeDirectory=alizy` (`0755`, wiped each stop), `StateDirectory=alizy` (`0700`); `/run/alizy/ssh` is created by the daemon itself to survive the wipe (see comment `:30-34` and `README.md:55-59`).
- Hardening: `NoNewPrivileges`, `ProtectSystem=true`, `ProtectHome`, `PrivateTmp`, `ProtectControlGroups`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6`, `LimitCORE=0` (no coredumps — keys in memory) (`:39-52`).
- **Capability bounding set:** `CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE` (`:35`) — needed for netlink/nftables, DNS port 53, dropping privileges to `alizy-ssh`, signalling `ssh`/`tun2socks` children, handing askpass files over.

---

## 7. Networking components

- **TUN / nftables kill switch:** nft table `inet alizy`, atomically replaced; renderer `crates/alizy-core/src/firewall.rs`, applier `crates/alizyd/src/linux/firewall*` (per `ARCHITECTURE.md:26-29`).
- **WireGuard:** kernel module via `wg setconf` on stdin, no temp files (`ARCHITECTURE.md:21`).
- **SSH profiles:** `ssh -N -D` + `badvpn-tun2socks` run as `alizy-ssh` system user, with capability drops on setuid (`README.md:48-59`, `ARCHITECTURE.md:97-120`). Pinned host key, SOCKS-greeting readiness probe, own DNS-over-TCP forwarder on `127.77.0.1:53` (`alizyd::socks_dns`).
- **LAN proxy:** HTTP + SOCKS5 listeners on `0.0.0.0:8080/1080`; sources `crates/alizyd/src/lan_proxy.rs`, `crates/alizyd/src/lan_socks.rs`; firewall reply-rule via `lan_proxy_port`; persisted in `/var/lib/alizy/state.json` so it comes back on boot (`LAN_PROXY.md:27-29`).
- **DNS backends:** systemd-resolved (per-link) | resolvconf | file-with-backup (`ARCHITECTURE.md:24`, `LINUX_COMPATIBILITY.md:22`).

---

## 8. Required permissions / capabilities

| Need | Source |
|---|---|
| Root (daemon) + `CAP_NET_ADMIN`, `CAP_NET_RAW` | `alizyd.service:35` |
| `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`, `CAP_NET_BIND_SERVICE` | same |
| `alizy` system group (socket ACL) | `packaging/linux/alizy.sysusers:2` |
| `alizy-ssh` system user (SSH child workers) | `packaging/linux/alizy.sysusers:4` |
| polkit action `io.alizy.daemon.control`, `allow_active=yes` | `packaging/linux/io.alizy.policy:6-13` |
| Peer-credential check (SO_PEERCRED + group membership + polkit `pid+start-time`) | `crates/alizyd/src/{auth,server}.rs` (see `docs/MILESTONES.md:20-22`) |
| User must be added to group `alizy`, then log out / reboot | `install.sh:38-41`, `README.md:106-111`, `LINUX_COMPATIBILITY.md:52` |

---

## 9. Config, data, executable paths

| Data | Path | Mode | Source |
|---|---|---|---|
| Daemon binary | `/usr/bin/alizyd` | `0755` (also acts as `SSH_ASKPASS`) | `PKGBUILD:41`, `README.md:59` |
| GUI binary | `/usr/bin/alizy` | `0755` | `PKGBUILD:54` |
| systemd unit | `/usr/lib/systemd/system/alizyd.service` | `0644` | `PKGBUILD:42` |
| sysusers | `/usr/lib/sysusers.d/alizy.conf` | `0644` | `PKGBUILD:43` |
| polkit action | `/usr/share/polkit-1/actions/io.alizy.policy` | `0644` | `PKGBUILD:44` |
| Desktop entry | `/usr/share/applications/io.alizy.app.desktop` | — | `PKGBUILD:55` |
| Icons | `/usr/share/icons/hicolor/{32,128}x{32,128}/apps/io.alizy.app.png` | — | `PKGBUILD:56-57` |
| IPC socket | `/run/alizy/alizyd.sock` | `0660 root:alizy` | `ipc.rs:13`, `ARCHITECTURE.md:17` |
| Daemon state (policy, KS flag, split rules, DNS cache) | `/var/lib/alizy/state.json` | `0600 root` | `ARCHITECTURE.md:127-129` |
| `resolv.conf` backup | `/var/lib/alizy/resolv.conf.backup` | `0600 root` | `ARCHITECTURE.md:130` |
| Per-user DB | `$XDG_DATA_HOME/io.alizy.app/alizy.db` | dir `0700`, file `0600` | `ARCHITECTURE.md:126` |
| Private keys | Secret Service; fallback `$XDG_DATA_HOME/io.alizy.app/secrets/<id>.json` | `0600` | `ARCHITECTURE.md:128` |

---

## 10. What **can** be bundled in an AppImage

- The Tauri GUI binary `alizy` and its runtime: libwebkit2gtk-4.1, libgtk-3, libayatana-appindicator, GLib/Cairo/Pango stack. `linuxdeploy` + `linuxdeploy-plugin-gtk` already does this for Tauri; the current Tauri-emitted AppImage uses exactly this path.
- The `.desktop` file, icons, and the daemon-client code that talks to `/run/alizy/alizyd.sock`.
- The per-user SQLite store (`$XDG_DATA_HOME/io.alizy.app/alizy.db`) initialises itself on first launch; no install step needed for user data.

That is exactly what the existing `Alizy_0.1.0_amd64.AppImage` contains.

## 11. What **cannot** be bundled

- `alizyd` service and its systemd/polkit/sysusers scaffolding — needs root to install, not re-expressible as an AppImage first-run.
- The `alizy` group and `alizy-ssh` user (sysusers.d is read by systemd-sysusers at boot).
- `CAP_NET_ADMIN` etc. on the daemon binary (AppImage FUSE mount is `nosuid`; file capabilities are stripped).
- `wg` / `nft` / `ip` kernel-side tools: must match the running kernel's netlink ABI and are better left to distro packages.
- `badvpn-tun2socks` (unmaintained upstream; distro builds differ; capability needs vary).
- `polkit` daemon, `systemd-resolved`, Secret Service providers.

Even if you tried to vendor `nft`/`wg`/`badvpn-tun2socks` into the GUI AppImage, they would be useless there — they are invoked by the *daemon*, which runs as root and lives outside the AppImage.

---

## 12. Per-distro notes

| Distro | Daemon install | GUI install | Risks |
|---|---|---|---|
| **Arch / Omarchy** | `packaging/arch/PKGBUILD` (split pkgs) — validated | AUR / `pacman -U` or AppImage | None known; reference target. |
| **Debian / Ubuntu / Mint / Pop!_OS** | `packaging/deb/build-alizyd-deb.sh` (untested) | Tauri `.deb` (untested) or AppImage | WebKitGTK 4.1 only on 23.10+ / Debian 12+; Ubuntu 22.04 ships 4.0 (needs PPA) — relevant for either `.deb` or AppImage GUI. |
| **Fedora 39+** | `packaging/rpm/alizyd.spec` (untested) | Tauri `.rpm` or AppImage | firewalld coexistence covered (`LINUX_COMPATIBILITY.md:58-60`); SELinux may require `semanage` for polkit-launched helpers in future. |
| **openSUSE Tumbleweed / Leap** | same `alizyd.spec` (SUSE branch at `:14`) | AppImage | AppArmor on Leap may need a profile for the bundled WebKit. |
| **Non-systemd (Void, Devuan, Gentoo-OpenRC)** | Not shipped | — | `LINUX_COMPATIBILITY.md:54` — daemon still runs but no unit / boot-time protection; AppImage of the GUI would launch but find no daemon. |

---

## 13. Comparison of packaging strategies

| Strategy | Daemon | GUI | Trade-off |
|---|---|---|---|
| **AppImage only** | ❌ cannot install | ✅ | Impossible as a *complete* product — daemon has nowhere to live. |
| **AppImage + first-run installer** (GUI prompts for sudo and runs `install.sh` on first launch) | ✅ scripted | ✅ bundled | One download, but AppImages traditionally promise "no install"; breaks the contract, and the daemon still needs distro-matching deps. |
| **Flatpak** | ❌ (sandbox cannot own `/run/alizy`, bind privileged ports, hold `CAP_NET_ADMIN`, modify `/etc/resolv.conf`, write `nftables`) | ✅ | Daemon incompatible with Flatpak sandbox. Portal-based networking is read-only client-side. |
| **Native packages only** (current `.pkg.tar.zst`, `.deb`, `.rpm`) | ✅ | ✅ | What the project already ships. Distro-specific; no "generic Linux" download. |
| **Hybrid: distro package for daemon + AppImage for GUI** | ✅ via `.deb` / `.rpm` / `PKGBUILD` | ✅ portable AppImage | **Recommended.** Matches the project's own split-process model and the statement in `README.md:80-84`. |
| **Hybrid: `install.sh` (daemon) + AppImage (GUI)** | ✅ systemd-only distros | ✅ portable | Good fallback for distros without a native package; works today with the existing `install.sh`. |

---

## 14. Recommended architecture

1. Keep the existing Tauri-emitted AppImage as the canonical, portable **GUI** artifact. Treat `target/release/bundle/appimage/Alizy_0.1.0_amd64.AppImage` as a release deliverable.
2. Ship **three** daemon artifacts (`.pkg.tar.zst`, `.deb`, `.rpm`) + the generic `packaging/linux/install.sh`. The GUI AppImage pre-flight should surface `alizyd --probe` output when the socket is missing and point users to the daemon install.
3. Teach the AppImage to show a clear, non-fatal "daemon not found / not in group `alizy`" state (GUI already does — "service unavailable" screen per `docs/PLATFORMS.md:11`). Add a one-click "Copy install command" so a brand-new user is not stuck.
4. Do **not** attempt to put the daemon inside the AppImage. Document the split prominently in release notes (the README already does).

---

## 15. Implementation complexity

Because the AppImage already builds and runs, work is **small (≈ 1–2 engineer-days)** and mostly polish:

| Task | Effort |
|---|---|
| Pin a `tauri build --bundles appimage` CI job, archive the artifact | S |
| Add GUI first-run check: detect missing `alizyd`, missing group membership, show one-screen install hint per detected distro (reuse `alizy-core::sysprobe`'s `pacman/apt/dnf/zypper` adapter) | S–M |
| Compatibility banner in the AppImage for WebKitGTK < 4.1 hosts (Ubuntu 22.04) | S |
| Bundle an updater (`appimageupdate`) only if signed releases are planned | M |
| Smoke-test the AppImage on Ubuntu 24.04, Debian 12, Fedora 40, openSUSE TW | M (pure QA) |

Not needed: no new build infra, no new install logic, no sandbox changes.

---

## 16. Compatibility risks

- **WebKitGTK ABI:** Tauri 2 requires 4.1; older LTS distros ship 4.0. Mitigation: bundle via `linuxdeploy-plugin-gtk` *or* document minimum distro versions.
- **libayatana-appindicator presence:** tray degrades gracefully (`docs/MILESTONES.md:56-57`); no risk, just missing tray on some setups.
- **glibc floor:** AppImage inherits the glibc of the build host. Build on the **oldest** supported distro (Debian 12 / Ubuntu 22.04 is a common floor) to avoid "symbol GLIBC_2.XX not found" at runtime.
- **FUSE on hardened hosts:** some corporate images disable FUSE 2 — users must extract (`--appimage-extract-and-run`) or install `libfuse2`. Document.
- **Secret Service missing in AppImage sandbox?** AppImages don't sandbox, so D-Bus access to `org.freedesktop.secrets` works unchanged. Low risk; 0600-file fallback exists anyway.
- **Hard-coded `/run/alizy/alizyd.sock`** (`ipc.rs:13`): fine for AppImage because the socket lives on the host, not in the image. Only a concern if someone later Flatpaks the GUI.
- **AppImage is `nosuid`:** irrelevant because no setuid bits are needed (the daemon lives on the host).
- **Appstream metadata / icon theming:** Tauri bundler supplies the essentials; add `AppStream` XML if targeting software-centre listings.

---

## 17. Step-by-step implementation plan

1. **Reproduce the existing build on a clean, old-glibc host.**
   `rustup target add x86_64-unknown-linux-gnu` → on Debian 12 → `npm ci && npx tauri build --bundles appimage`. Confirm output at `target/release/bundle/appimage/Alizy_<ver>_amd64.AppImage`.
2. **Capture the AppImage recipe in CI.** Add a GitHub Actions job (matrix: amd64; later aarch64) using an `ubuntu-22.04` / `debian:12` container and caching cargo + npm.
3. **Add first-run self-check to the GUI.** When `/run/alizy/alizyd.sock` is missing *or* `EACCES`, call `alizyd --probe` via `pkexec` if present, else show a modal with the distro-specific install command (data already in `alizy-core::sysprobe`). Reuses the Settings → System Check screen.
4. **Pair the AppImage release with daemon artifacts.** Publish `alizyd-<ver>.pkg.tar.zst`, `alizyd_<ver>_amd64.deb`, `alizyd-<ver>.rpm` from the same tag; the AppImage release notes link to the right one per distro.
5. **Document the model in `README.md` and `docs/MILESTONES.md`** — update the "AppImage ships the GUI only" paragraph to point to the new installers.
6. **(Optional) Signed, zsync-updatable AppImage.** Add `gpg2 --detach-sign` + `zsync` manifest if update-in-place is wanted; otherwise rely on distro updates.
7. **Smoke matrix on real systems.** Minimum: Debian 12 + Ubuntu 24.04 + Fedora 40 + openSUSE Tumbleweed + Arch. Record in `docs/REAL_SYSTEM_VALIDATION.md` style.
8. **Do not merge:** an AppImage that tries to bundle `alizyd`, `nft`, `wg`, `badvpn-tun2socks`, or asks the user to run the AppImage as root. All break the project's security model (`SECURITY.md`, `ROUTING_SECURITY.md`).

---

### References

Key files inspected (paths relative to the repository root):

- `README.md`
- `ARCHITECTURE.md`
- `LAN_PROXY.md`
- `LINUX_COMPATIBILITY.md`
- `docs/MILESTONES.md`
- `docs/PLATFORMS.md`
- `docs/REAL_SYSTEM_VALIDATION.md`
- `src-tauri/tauri.conf.json`
- `src-tauri/Cargo.toml`
- `src-tauri/src/lib.rs` (root-refusal at `:19-21`)
- `src-tauri/src/daemon_client.rs` (socket override `:21`)
- `crates/alizy-core/src/ipc.rs` (`SOCKET_PATH` `:13`)
- `crates/alizyd/src/main.rs`
- `packaging/linux/alizyd.service`
- `packaging/linux/io.alizy.policy`
- `packaging/linux/alizy.sysusers`
- `packaging/linux/io.alizy.app.desktop`
- `packaging/linux/install.sh`
- `packaging/arch/PKGBUILD`
- `packaging/rpm/alizyd.spec`
- `packaging/deb/build-alizyd-deb.sh`
- Git: commit `a71b899` (`docs: AppImage builds and launches on a real system`)
- Existing artifact: `target/release/bundle/appimage/Alizy_0.1.0_amd64.AppImage`
