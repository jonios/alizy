# Multi-protocol architecture

Status legend used throughout: **[implemented]** is in the code and covered by
tests; **[planned]** is a design only. No protocol beyond WireGuard and SSH is
implemented, and no subscription or import code exists.

## 1. Where Alizy started (before this change)

The split between `alizy-core` (pure planning) and `alizyd` (privileged
execution) was already sound, and the connection state machine
(`alizy-core::state`) was already protocol-independent. Protocol knowledge
leaked into four places:

| Problem | Where | Consequence |
|---|---|---|
| `PlatformAdapter::tunnel_up` took a `WgConfig` | `alizy-core::platform` | The OS contract was WireGuard-shaped; SSH needed a separate path |
| SSH operations on the generic `Backend` trait (`ssh_up`, `keyscan`, `ssh_missing`, `ssh_try_exited`, WireGuard's `set_endpoint`) | `alizyd::engine` | Every protocol would widen the platform trait |
| `bring_up_inner` / `bring_up_ssh` and `TunnelKind` matches in health checks, DNS re-assertion, firewall rules and status | `alizyd::engine` | Every protocol would edit the connection manager in five places |
| `TunnelSpec { config: WgConfig, ssh: Option<SshConfig> }` | `alizy-core::ipc` | SSH carried a fake WireGuard config; every protocol would add an optional field |

## 2. Layers and boundaries [implemented]

```
GUI (src-tauri)          builds TunnelSpec { tunnel: TunnelConfig }   — configuration management
   │ IPC (wire format unchanged)
alizyd::engine           Connection Manager: one lifecycle, state machine, kill switch,
   │                     reconnect, cancellation, split tunnelling, LAN proxy
   ├── driver::TunnelDriver   Protocol Adapter Layer (one impl per protocol)
   │      ├── WireGuardDriver<WgOps>   → linux::wireguard (ip link / wg)
   │      └── SshDriver<SshOps>        → linux::ssh (ssh, tun2socks, forwarder)
   └── Backend: PlatformAdapter   Network Integration Layer: nftables, routes, DNS,
                                  split rule, interface teardown
alizy-core               pure planning: protocol::TunnelConfig → TunnelPlan,
                         routing::route_plan, firewall::FirewallPlan, state::transition
```

Rules each layer keeps:

- **Exactly one place per crate names protocols.** `alizy-core::protocol`
  (the `TunnelConfig` enum and its pure planning) and the driver list in
  `alizyd/src/main.rs`. The engine has no protocol names in non-test code.
- **Drivers never touch firewall, routes or system DNS.** They return
  `TunnelRules` (data) and create an interface; the engine plans and applies
  everything else through the platform adapter. A driver therefore cannot
  open a second network-management path or weaken the kill switch.
- **Each driver splits again at the OS boundary** (`WgOps`, `SshOps`). The
  driver holds protocol logic (host-key decisions, DNS upstream choice, error
  mapping, firewall exceptions); the ops trait only runs tools. The engine
  tests run the real drivers with faked ops.

## 2a. Connection modes [implemented]

`NetworkPolicy.mode` is `tunnel` (default) or `proxy`. The engine plans from
`NetworkPolicy::effective()`: in proxy mode the kill switch, IPv4/IPv6 blocking,
DNS leak protection and split tunnelling are off for planning (the user's
preferences are kept for tunnel mode). Each protocol adds one thing:
`TunnelDriver::proxy_egress` — WireGuard: sockets marked `PROXY_MARK`
(`0x4a5c`) with names resolved over TCP through the tunnel's DNS; SSH: through
`ssh -D`. Routing (`routing::route_plan`) installs the tunnel's prefixes only in
Alizy's table, reached by `ip rule fwmark 0x4a5c`; system DNS is not applied.
The firewall's `proxy_guard` rejects marked packets on any interface but the
tunnel and restores the mark on replies (strict `rp_filter`). Egress for every
proxy (`alizyd::egress`) is `Blocked` unless the tunnel is connected, so proxy
mode never falls back to a direct connection. A future sing-box driver gets
proxy mode by implementing `proxy_egress` (its own mixed inbound, or the same
marked-socket approach).

## 3. Connection lifecycle [implemented]

`Engine::connect` → `bring_up` → `bring_up_inner`, identical for every protocol:

1. `TunnelConfig::sanitize` — re-validate untrusted GUI input (core).
2. `driver.preflight` — dependencies and system users (before the lock).
3. Cancellation check — a newer connect/disconnect wins.
4. `TunnelConfig::plan(policy)` → interface description + DNS plan (core).
5. Switching protocol? Stop the old data plane and remove its interface; the
   old firewall stays in place meanwhile.
6. Resolve endpoints (`TunnelConfig::endpoints`) with the daemon and client
   caches, so a blocked DNS doesn't block reconnects.
7. `driver.prepare` → `Session` (runtime facts such as a local proxy port).
8. Firewall: `driver.firewall_rules` → `FirewallPlan` → atomic apply + read-back.
9. `driver.verify` — checks that need the new firewall but must not disturb
   the running tunnel (SSH: unknown host key stops here for confirmation).
10. Remove the previous tunnel of the same protocol / any leftover interface.
11. `driver.start` — interface and data plane.
12. `platform.network_up` — routes, system DNS, interface still present.
13. Split-tunnel rule re-sync; state → `Connected`.

Failure at any step: `driver.stop` for every driver, `platform.tunnel_down`,
re-apply the no-tunnel firewall (kill switch stays), state → `Protected` or
`Error`. If the attempt was cancelled, the result is `Cancelled` for **every**
protocol (previously SSH only) and ends like a disconnect.

Supervision (`tick`, every 2 s) is also generic: firewall re-verification,
`driver.exited` → reconnect, interface-presence check, `driver.stats` and the
stale-handshake watchdog, DNS re-assertion from the stored `DnsPlan`.
Network changes re-resolve hostname endpoints, re-plan the firewall, then call
`driver.update_endpoints`.

## 4. Protocol adapter interface [implemented]

`crates/alizyd/src/driver/mod.rs`:

| Method | Required | Purpose |
|---|---|---|
| `kind` | yes | `ProtocolKind` the driver serves |
| `firewall_rules(iface, endpoints, session)` | yes | Exceptions the tunnel's own traffic needs; pure |
| `start(ctx)` | yes | Create interface and data plane |
| `stats(iface)` | yes | Counters + liveness timestamp |
| `preflight` | default ok | Missing dependencies |
| `prepare` | default empty session | Per-attempt runtime facts |
| `verify(ctx)` | default ok | Pre-teardown checks |
| `stop` | default no-op | Idempotent; runs before interface teardown |
| `exited` | default none | Data plane died on its own |
| `update_endpoints` | default no-op | Follow endpoint address changes |
| `augment_report` | default no-op | Add readiness to the System Check report |

Methods return a boxed future so drivers live in a `Vec<Box<dyn TunnelDriver>>`
(no new dependency). `Ctx` gives a driver read-only access to the config,
resolved endpoints, session, policy, event log and cancel token.

### Adding a protocol (checklist)

1. `alizy-core::protocol`: add a `TunnelConfig` variant, its `kind`,
   `sanitize`, `endpoints` and `plan` arms. Extend the IPC wire mapping in
   `ipc::WireTunnelSpec` with a new optional field (old daemons reject unknown
   protocols instead of misreading them).
2. `alizyd::driver::<name>`: implement `TunnelDriver` over an `<Name>Ops` trait.
3. Register it in `alizyd/src/main.rs`.
4. If its traffic shape is new, extend `TunnelRules` once (see §6).

No change to `engine.rs`, `state.rs`, `routing.rs`, the split-tunnel engine or
the LAN proxy is needed. `lifecycle_is_driven_only_by_the_driver_trait` tests
that the engine runs the whole lifecycle through the trait alone.

## 5. Configuration management [implemented / planned]

**[implemented]** `TunnelSpec { profile_id, profile_name, tunnel: TunnelConfig,
cached_endpoints }`. The JSON on the socket is byte-identical to before
(golden tests `wg_connect_json_unchanged`, `ssh_connect_json_unchanged`), so an
AppImage GUI and an installed daemon of different versions keep working.

**[planned]** Profile storage (`alizy-store`) is still WireGuard-first: SSH
rows keep a placeholder `public_config` beside `ssh_public`. The normalised
model, introduced with the first new protocol (migration 0003):

```
profiles  + protocol    TEXT   ('wireguard' | 'ssh' | …)      replaces kind
          + public_json TEXT   protocol-specific non-secret JSON
          + source      TEXT   'manual' | 'subscription'
          + subscription_id TEXT NULL  → subscriptions.id
          + remote_key  TEXT NULL     stable id inside the subscription
secrets: unchanged (OS keyring / 0600 file, keyed by profile id)
```

Manual profiles are never modified by subscription sync; subscription profiles
are read-only in the editor except for name/favourite/category, which survive
refreshes.

## 6. Network security integration

The firewall planner is generic for two traffic shapes today:

| Shape | `TunnelRules` fields | Used by |
|---|---|---|
| Kernel socket marked `FWMARK`, UDP | `endpoints` | WireGuard |
| User-space client as its own uid, TCP | `tcp_endpoints`, `ssh_uid`, `socks_port`, `block_udp` | SSH |

**Gap (for sing-box) [planned]:** QUIC-based protocols (Hysteria2, TUIC) need
UDP from a user-space client, which neither shape allows. The preferred fix is
for the sing-box process to set `routing_mark = FWMARK` on its outbound
sockets, which needs `CAP_NET_ADMIN`. Then one new shape, "marked socket,
TCP+UDP", covers every sing-box protocol: `TunnelRules.endpoints` gains a
per-endpoint transport (`udp`/`tcp`/`both`) instead of separate lists. This
changes the plan's serialisation and so its tag, which is harmless: the
firewall is just re-applied. It is deferred until a consumer exists. The
`ssh_uid`/`socks_port` field names stay because they are part of the plan tag.

Kill switch, DNS leak protection, split tunnelling, IPv4/IPv6 blocking and the
LAN proxy all depend only on `FirewallPlan`, `RoutePlan` and `DnsPlan`, so a
new driver inherits them with no extra code.

## 7. sing-box integration design [planned]

Nothing here is downloaded, bundled or executed.

**Driver shape.** `SingBoxDriver<SingBoxOps>`, one driver for every sing-box
protocol (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS,
SOCKS/HTTP upstreams). `TunnelConfig::SingBox(SingBoxOutbound)` holds a
validated, normalised outbound. WireGuard stays on the kernel driver and SSH
on OpenSSH: both are audited and faster, and they don't depend on a third-party
binary.

**Config generation (pure, `alizy-core::singbox`).**
`render(outbound, session, policy) -> serde_json::Value` emits exactly:
- one `tun` inbound: `interface_name = alizy0`, the Alizy TUN addresses,
  `auto_route = false`, `auto_redirect = false`, `strict_route = false`
  (Alizy owns routes and nftables);
- one `dns` server whose detour is the proxy outbound, listening on a
  loopback forwarder address (the same pattern as SSH's `127.77.0.1`), so
  `DnsPlan` points the system resolver at it;
- the single proxy outbound with `routing_mark = FWMARK`, plus `direct` and
  `block`;
- no `clash_api`, no remote rule sets, no `experimental` cache file.

It is golden-tested like the nft renderer. The config is passed on stdin
(`sing-box run -c /dev/stdin`) or a 0600 file in the runtime dir, never argv.

**Process lifecycle.** Spawned with the existing `unprivileged_command` helper
as the system user `alizy-engine`, with only `CAP_NET_ADMIN` as an ambient
capability (for `SO_MARK` and the TUN). The process gets a cleared
environment, `PR_SET_PDEATHSIG`, `kill_on_drop`, and its stderr is captured
into a bounded `TailBuf` for error classification. `verify` runs
`sing-box check` before the old tunnel is torn down. `start` waits for
readiness: the TUN is up and the DNS listener is owned by `alizy-engine`.
`exited` uses `try_wait`, and `stats` reads `/sys/class/net/alizy0/statistics`.

**Crash recovery.** If the daemon dies, PDEATHSIG kills sing-box. On restart,
`recover` calls every driver's `stop` and the platform teardown, as it does
today. If sing-box dies, `exited` triggers the normal reconnect path while the
kill switch stays in place.

**Binaries and versions.** sing-box runs inside `alizyd`, not the GUI, so it
ships with the daemon, not in the AppImage:
- installer payload: `/usr/local/lib/alizy/sing-box`, with the version and
  SHA-256 pinned in `scripts/release` and verified at build time;
- AUR/pacman: a dependency on the distribution `sing-box` package;
- `preflight` checks `sing-box version` against a minimum version, as SSH
  checks `ssh -V`.

sing-box is GPL-3.0-or-later, which is compatible with Alizy's licence.

**Unknowns to verify before implementing:** whether sing-box attaches to a
pre-created TUN owned by its uid, or must create it (and so needs
`CAP_NET_ADMIN` for the TUN as well); and how UDP from `routing_mark`ed QUIC
sockets interacts with `rp_filter` (the existing wg_mark conntrack copy should
cover it).

## 8. Subscription management design [planned]

| Concern | Location | Notes |
|---|---|---|
| Fetch (HTTPS, size cap, timeout, ETag) | `src-tauri` (user process) | The daemon never fetches URLs |
| Parse: base64 list, share URIs, Clash/Mihomo YAML, sing-box/Xray JSON, `.conf` | `alizy-core::import` (pure) | Each parser returns `Vec<ImportedProfile { remote_key, name, TunnelConfig }>` plus warnings; untrusted input, same rules as `config::parse` |
| Store and sync | `alizy-store::subscriptions` | Diff by `remote_key`: add, update and mark stale. Never delete the connected profile; manual profiles are never touched |
| Schedule | `src-tauri` poller | Per-subscription interval; manual refresh |

## 9. Migration decisions

| Decision | Why |
|---|---|
| Closed enum for configs, trait objects for behaviour | The IPC stays a closed, validated set; behaviour stays open for extension |
| Wire format kept via `serde(from/into)` | The GUI and daemon ship separately (AppImage vs installer) |
| Engine owns teardown ordering (driver stop → platform down) | Same order as before, and it now holds for every protocol |
| Cancellation generalised | Behaviour change, deliberate: a WireGuard attempt superseded by a disconnect now reports `Cancelled` rather than an error |
| `TunnelRules` field names untouched | Renaming changes the plan tag; nothing would use it yet |
| No store migration yet | Nothing would use the new columns yet |

## 10. Tests [implemented]

- `alizy-core::protocol`: sanitising, endpoints, and plans equal to the
  existing planners.
- `alizy-core::ipc`: WireGuard and SSH connect JSON goldens.
- `alizyd::driver::{wireguard,ssh}`: golden firewall rules, system-user
  requirement.
- `alizyd::engine`: all previous lifecycle tests now run through the real
  drivers, plus:
  - `lifecycle_is_driven_only_by_the_driver_trait`
  - `cancellation_is_generic_for_every_driver`
  - `unregistered_protocol_is_unsupported_and_touches_nothing`
  - `wg_bring_up_order_and_dns_unchanged`

Not covered by unit tests: real kernel or `ssh` bring-up. Run
`tests/system` and `tests/ssh` on a real machine for that
([REAL_SYSTEM_VALIDATION.md](REAL_SYSTEM_VALIDATION.md)).
