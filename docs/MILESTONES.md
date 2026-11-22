# Milestone log

Environment: Omarchy (Arch-based), kernel 7.2.8, rustc 1.99.1, Node 26,
nftables 1.1.7, wireguard-tools 1.0.20260223, systemd 262 + resolved,
NetworkManager, ufw active. No passwordless sudo: everything requiring root was
tested inside unprivileged user + network namespaces against the real kernel.

## M0 — Environment & documents
ARCHITECTURE.md, IMPLEMENTATION_PLAN.md, SECURITY.md, README.md.

## M2 — Configuration core (`crates/alizy-core`)
`config.rs` (parser/validator/sanitiser, hook stripping, size/control-char
limits, wg-quick and `wg setconf` rendering), `keys.rs` (zeroized, redacted
keys, X25519 public-key derivation), `profile.rs` (fingerprints, names),
`state.rs` (state machine), `firewall.rs` (nft renderer), `routing.rs`
(route/DNS plans, owned rule priorities, compatibility warnings), `ipc.rs`.
Tests: unit tests incl. RFC 7748 vector, invalid-config matrix, round trips.

## M3–M6 — Daemon (`crates/alizyd`)
`engine.rs` (connect/switch/disconnect, fail-closed ordering, supervisor,
reconnect with backoff, tamper re-apply, network-change handling, route test),
`server.rs` + `auth.rs` (bounded NDJSON, SO_PEERCRED, group check, polkit with
pid+start-time), `linux/` (firewall apply/verify, WireGuard via stdin, DNS
backends with backup/re-assert/restore, `ip monitor`), `persist.rs`,
`events.rs`, `exec.rs` (no shell, cleared env, fixed PATH, stderr redaction).
Bugs found by the real-kernel suite and fixed: `/sys/class/net` is not
netns-aware (switched to `/proc/net/dev`); DNS answer changes dropped old
addresses immediately (now retired after a grace period).

## Multi-distribution support
`sysprobe.rs`: os-release parsing, kernel WireGuard detection, executables,
systemd, firewalld/ufw/iptables flavour, NetworkManager, DNS backend choice from
facts, pacman/apt/dnf/zypper guidance, findings with exact fixes.
`alizyd --probe`, Settings → System Check, LINUX_COMPATIBILITY.md.

## Split tunnelling
`split.rs` (rules, matching, precedence, interval compilation, import formats,
shared-IP/CDN warnings), `dnswire.rs` (codec), `resolver.rs` (TTL cache,
grace, backoff, persistence), nft sets + route/NAT/prerouting chains, fwmark
rule, routing test tool. Docs: SPLIT_TUNNELING.md, DOMAIN_ROUTING.md,
DNS_ROUTING.md, ROUTING_SECURITY.md. App-based routing: not implemented.

## M7 — Real-network suite (`tests/leak/run.sh`)
55 checks, all passing (grew from 52 as regressions found during real-system
validation were added). DNS backend suite: `tests/leak/dns_backends.sh` (file 21,
resolvconf 15). See tests/leak/README.md.

## M2 (storage) — `crates/alizy-store`
SQLx/SQLite with migrations, 0700/0600 permissions, keyring secret store with
0600 fallback, profile manager (import text/files/dirs, duplicates, edit with
`<redacted>` placeholders, duplicate, export, backup/restore), history, logs
with redaction and retention. 5 integration tests incl. "key never in DB/WAL".

## M1/M4 — GUI (`src-tauri`, `src/`)
Tauri commands (allow-listed, path validation), daemon client, status poller
(history, notifications, daemon-event sync), tray with graceful degradation,
close-to-tray, single instance, autostart, root refusal. React UI: see below.

## M8 — Packaging
systemd unit (hardened, before network-pre), sysusers, polkit action, desktop
file, install/uninstall scripts, Arch split PKGBUILD, RPM spec (Fedora +
openSUSE), deb build script, Tauri bundles for the GUI (DEB/RPM/AppImage untested;
only the Arch package was installed and validated). Static validation:
`systemd-analyze verify` clean, polkit XML valid, scripts parse.

## Real-system validation (2026-11-19/20)
Installed Arch package on the development machine, upgraded 0.1.0-1 → 0.1.0-5.
Ten product bugs found and fixed; full evidence in docs/REAL_SYSTEM_VALIDATION.md.
