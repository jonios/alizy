# Alizy — Architecture

Alizy is a WireGuard desktop client split into **two processes with different
privilege levels** plus a set of platform-neutral Rust crates.

```
┌──────────────────────────── user session (unprivileged) ───────────────────────────┐
│  React/TS UI (Vite, Tailwind, Radix, Zustand)                                       │
│        │  Tauri invoke() — typed, allow-listed commands only                        │
│  alizy (Tauri 2 shell, src-tauri/)                                                  │
│    commands.rs ── profile_manager / settings_manager / statistics / logging         │
│        │                    │                                                       │
│        │            alizy-store (SQLx + SQLite, migrations, secret store)           │
│        │                                                                            │
│    daemon_client.rs ── newline-delimited JSON over a Unix socket                    │
└────────┼────────────────────────────────────────────────────────────────────────────┘
         │  /run/alizy/alizyd.sock  (0660 root:alizy, SO_PEERCRED + polkit check)
┌────────┼──────────────────────────── root (systemd service) ───────────────────────┐
│  alizyd (crates/alizyd)                                                              │
│    system_service ── socket server, authorization, request validation               │
│    connection_manager ── state machine, supervisor, auto-reconnect                  │
│    platform::linux                                                                  │
│      wireguard_engine  (ip link / wg setconf via stdin, no temp files)              │
│      routing_manager   (iproute2, policy routing with owned rule priorities)        │
│      dns_manager       (systemd-resolved per-link DNS; resolv.conf fallback+backup) │
│      firewall_manager  (nftables: one owned table `inet alizy`, atomic replace)     │
│      kill_switch       (policy → firewall plan, verification, persistence)          │
│      network_manager   (`ip monitor` change detection, integrity re-checks)         │
│    state persistence  /var/lib/alizy/state.json (no secrets)                        │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Purpose | Depends on Tauri? | OS-specific? |
|---|---|---|---|
| `crates/alizy-core` | Config parser/validator/sanitiser, key types (zeroized, redacted `Debug`), profile fingerprints, connection state machine, firewall **ruleset renderer**, routing/DNS **plans**, split-tunnel engine, DNS wire codec, system probe, IPC protocol, platform trait | no | no (probe reads Linux files) |
| `crates/alizy-store` | SQLite schema + migrations, profile manager (import/edit/export/backup), settings/history/log repositories, OS keyring secret store with 0600-file fallback | no | no |
| `crates/alizyd` | Privileged daemon; Linux adapter executes the plans produced by `alizy-core` | no | Linux implementation; other OSes compile to an explicit "unsupported" binary |
| `src-tauri` | GUI shell, tray, Tauri commands, daemon client, status poller | yes | no |

Business logic (what rules to install, what routes to add, which transitions are
legal) lives in `alizy-core` as **pure functions** that return data
(`FirewallPlan` → nft script, `RoutePlan` → argv vectors). The daemon only
executes those plans. This keeps the security-critical logic unit-testable
without root and without Tauri.

## Logical module map

| Spec module | Location |
|---|---|
| profile_manager | `alizy-core::config`, `alizy-core::profile`, `alizy-store::profiles`, `src-tauri/src/commands/profiles.rs` |
| connection_manager | `alizy-core::state`, `alizyd::engine` |
| wireguard_engine | `alizyd::linux::wireguard` |
| network_manager | `alizyd::linux::netmon` |
| firewall_manager | `alizy-core::firewall` (render), `alizyd::linux::firewall` (apply/verify) |
| kill_switch | `alizyd::engine` (policy → plan), persisted in `alizyd::persist` |
| dns_manager | `alizy-core::dns`, `alizyd::linux::dns` |
| routing_manager | `alizy-core::routing`, `alizyd::linux::routing` |
| platform_adapter | `alizy-core::platform` trait, `alizyd::linux` impl |
| system_service | `alizyd::server`, `alizyd::auth`, packaging/linux |
| settings_manager | `alizy-store::settings`, `src-tauri/src/commands/settings.rs` |
| statistics_manager | `alizy-store::history`, `src-tauri/src/poller.rs` |
| logging_manager | `tracing` in both processes, `alizy-store::db` events table (redacted), Logs screen |
| split tunnelling (rules, precedence, compile) | `alizy-core::split` |
| domain resolution engine | `alizy-core::dnswire` (codec), `alizyd::resolver` (I/O, TTL cache) |
| Linux distribution / capability detection | `alizy-core::sysprobe` (`alizyd --probe`, Settings → System Check) |

## Connection state machine

```
             connect                 tunnel up
Disconnected ───────► Connecting ───────────────► Connected
   ▲   ▲                 │ fail (KS on → Protected, off → Error)   │ handshake stale / link lost
   │   │                 ▼                                         ▼ (auto-reconnect)
   │   └────────── Disconnecting ◄──── disconnect ──────────── Reconnecting
   │                     │ (KS on)                                  │ fail
   │                     ▼                                          ▼
   └── KS off ───── Protected ◄─────────────────────────────────  Error
```

`Protected` means *no tunnel, kill switch blocking*. Legal transitions are
encoded in `alizy-core::state::transition` and covered by unit tests; the daemon
refuses to move along an illegal edge.

## Profile switching (atomic)

1. Resolve the new endpoint(s).
2. Render the firewall plan for the **new** tunnel and apply it in a single nft
   transaction (`table`/`delete table`/`table {…}` in one `nft -f -` run). The
   kill-switch drop rule is never removed — only the endpoint allow-rule changes.
3. Tear down the old interface (traffic is now dropped, not leaked).
4. Bring up the new interface, routes, DNS.
5. On any failure the rules from step 2 remain → fail closed.

## Data locations

| Data | Location | Permissions |
|---|---|---|
| Profiles, settings, history, logs | `$XDG_DATA_HOME/io.alizy.app/alizy.db` | dir 0700, file 0600 |
| Split rules + DNS cache | `/var/lib/alizy/state.json` (daemon-owned so protection works before login) | 0600 root |
| Private keys / PSKs | Secret Service (libsecret/KWallet) via `keyring`; fallback `$XDG_DATA_HOME/io.alizy.app/secrets/<id>.json` | 0600, dir 0700 |
| Daemon state (policy, kill-switch flag) | same file | 0600 root |
| resolv.conf backup (non-resolved systems only) | `/var/lib/alizy/resolv.conf.backup` | 0600 root |
| IPC socket | `/run/alizy/alizyd.sock` | 0660 root:alizy |

## Platform adapters

The `PlatformAdapter` trait in `alizy-core::platform` describes capabilities
(tunnel up/down, firewall apply/verify, DNS). Only Linux is implemented.
Windows (WireGuardNT + embeddable service + WFP) and macOS (WireGuardKit +
NEPacketTunnelProvider) are **documented, not implemented** — see
`docs/PLATFORMS.md`. The daemon binary on those targets exits with an explicit
"unsupported platform" error rather than pretending to work.
