# SSH tunnel profiles — design

Date: 2026-11-22 · Status: approved 2026-11-22

## Intent

Alizy today is a WireGuard-only client whose value is OS-level protection: the
kill switch, split tunnelling and leak protection, all enforced by `alizyd`.
The user wants a **second tunnel type, SSH**, that behaves exactly like a
WireGuard profile: listed with the other profiles, connected from the same
controls, and protected by the same kill switch, split tunnelling and leak
protection. Traffic is routed through a remote SSH server, which needs nothing
more than a normal `sshd` with password login.

It is **not** a terminal/session launcher.

## Goals

- New profile kind "SSH" created from a form: **Connection Name, Server IP
  Address, Port (default 22), Username, Password**.
- SSH profiles appear in Configurations, Dashboard, Quick Switcher and tray
  exactly like WireGuard ones (connect, disconnect, switch, favourite, category,
  edit, duplicate, delete, history, logs).
- While an SSH tunnel is up: kill switch, IPv4/IPv6 controls, DNS leak
  protection, split tunnelling (IP/CIDR, domain, routing test) and auto-reconnect
  work as they do for WireGuard.
- Password stored in the OS keyring (same `ProfileSecrets` mechanism), never in
  SQLite, argv, environment, logs or files on disk.

## Non-goals

- SSH key / agent authentication (form is password-only for now; the data model
  should not make adding it later hard).
- Hostnames in the server field (the form says IP address; IPv4 and IPv6 accepted).
- UDP through the tunnel (see Constraints).
- Windows/macOS (Linux only, like the rest of Alizy).
- Anything installed or configured on the remote server.

## Anti-goals (failure even if it "works")

- Any change in WireGuard behaviour, firewall output, routes or IPC wire format
  for existing WireGuard profiles. Existing WireGuard tests must pass unmodified;
  the nft script rendered for a WireGuard plan must be byte-identical.
- Traffic escaping the kill switch while SSH is connecting, reconnecting or dead.
- The password reaching argv, `/proc/*/environ`, the journal, backups, or disk
  (other than the existing keyring file fallback).
- UDP leaving outside the tunnel while an SSH tunnel is up *(user decision)*:
  SSH plans always render an explicit fast `reject` for UDP to `alizy0`, except
  DNS to the local forwarder, **whether or not the kill switch is on**, and UDP is
  never routed via the physical interface (split-tunnel Direct rules still apply
  as for any traffic).
- Silently trusting a changed server host key (MITM).
- `ssh` or `tun2socks` running as root.

## Constraints discovered in the code

- Everything in the daemon keys off one interface, `alizy0`
  (`TUNNEL_IFACE`), and the policy-routing scheme in `alizy-core/src/routing.rs`:
  `not fwmark 0x4a5a → table 19034` (default route via `alizy0`) plus
  `suppress_prefixlength 0`. WireGuard escapes its own tunnel because the kernel
  sets `fwmark 0x4a5a` on its UDP packets.
- Firewall endpoint exceptions (`FirewallPlan::endpoint_rules`) are written for
  **UDP** and require `meta mark 0x4a5a`.
- `TunnelSpec` / `Command::Connect` carry a `WgConfig`; the GUI's
  `connect_profile` builds it from `full_config(id)`.
- `PlatformAdapter::tunnel_up/down/stats` are WireGuard-shaped
  (`wireguard::create`, `wg show`).
- `sysprobe` lists required/optional executables per distro.

## Approaches considered

1. **OpenSSH `-D` (SOCKS5) + tun2socks → `alizy0`** — *chosen by the user.*
   Works with any stock sshd using password auth. One new runtime dependency
   (a tun2socks binary). TCP only: SSH dynamic forwarding has no UDP, so UDP
   (QUIC, games, VoIP/WebRTC) is blocked by the kill switch rather than leaked
   or carried; DNS is carried over TCP by a forwarder in `alizyd`.
2. OpenSSH `-w` layer-3 tunnel. Carries UDP, but needs `PermitTunnel`, IP
   forwarding/NAT and usually root on the server — incompatible with the
   name/IP/user/password form. Rejected.
3. sshuttle. Installs its own firewall redirects (fights `inet alizy`) and needs
   Python on the server. Rejected.

## Design

### Data model

- `alizy-core`: introduce `TunnelConfig` = `Wireguard(WgConfig)` |
  `Ssh(SshConfig)`. `SshConfig { host: IpAddr, port: u16, username: String,
  password: Zeroizing<String>, host_key: Option<HostKey>, dns: Vec<IpAddr> }`,
  with a `split()` into public part + secret like `WgConfig`.
  Validation: port 1–65535, username non-empty, ≤ 64 chars, POSIX-ish charset
  (no whitespace/control, no leading `-`), password non-empty and ≤ 1024 bytes.
- IPC *(builder-check call)*: the change is **additive, no protocol bump**.
  `TunnelSpec` keeps `config: WgConfig` exactly as today and gains
  `#[serde(default, skip_serializing_if = "Option::is_none")] ssh: Option<SshConfig>`;
  when `ssh` is present the daemon ignores `config` (the GUI sends an empty
  placeholder). A WireGuard `Connect` is therefore byte-identical on the wire,
  `Hello` stays at the current `PROTOCOL_VERSION`, and an old daemon simply
  rejects an SSH spec as an invalid config. The daemon re-validates SSH configs
  from scratch, as it re-parses WG.
- Store: profiles table gets a `kind` column (`wireguard` default via
  migration); SSH public fields stored as JSON in the existing config column or
  a sibling column (builder's call); password in the keyring via
  `ProfileSecrets`. Duplicate detection fingerprint for SSH =
  `sha256("alizy-ssh-v1", host, port, username)`.
- Backup/restore/export include SSH profiles **without the password**
  *(user decision)*. A restored SSH profile is marked "password needed" and the
  GUI prompts for it on first connect or edit. The keyring file fallback is used
  for SSH passwords exactly as for WG keys. The backup format gains an optional
  SSH entry; WG entries are unchanged. `.conf` import stays WG-only.

### Daemon bring-up (`alizyd`)

Order mirrors WireGuard: **firewall first, interface second**.

1. Firewall plan includes the SSH endpoint as a **TCP** exception
   (`meta mark 0x4a5a ip daddr H tcp dport P accept`, and the inbound
   counterpart). *(Builder-check call)* `TunnelRules` gains a parallel field
   `#[serde(default, skip_serializing_if = "Vec::is_empty")] tcp_endpoints:
   Vec<SocketAddr>` (and SSH-only fields likewise skipped when empty) rather
   than changing `endpoints`' type, so WireGuard plans serialise, hash (nft
   tag) and render byte-identically and existing tests compile unmodified.
   "Tests unmodified" is literal for `#[test]` code; non-test call sites such as
   `commands.rs` and `alizyctl.rs` may change.
2. Marking: OpenSSH cannot set `SO_MARK`, so `ssh` runs as a dedicated system
   user **`alizy-ssh`** (created by packaging) and a `type route hook output`
   chain marks `meta skuid "alizy-ssh" ip daddr H tcp dport P meta mark set 0x4a5a`.
   The existing `not fwmark` ip rule then sends it via the main table. Only
   rendered for SSH plans.
3. Create `alizy0` as a TUN device owned by `alizy-ssh`
   (`ip tuntap add dev alizy0 mode tun user alizy-ssh`), then apply the normal
   `route_plan` with a fixed point-to-point address pair (e.g. `198.18.0.1/30`,
   IPv6 ULA pair when IPv6 is enabled) and MTU 1500.
4. Start `ssh` as `alizy-ssh`:
   `ssh -N -D 127.0.0.1:<ephemeral> -p P -o ExitOnForwardFailure=yes
   -o ServerAliveInterval=15 -o ServerAliveCountMax=3
   -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/alizy/ssh/<id>.known_hosts
   -o PreferredAuthentications=password,keyboard-interactive
   -o PubkeyAuthentication=no -F /dev/null user@H`.
   Password delivery *(builder-check call; `ssh` closes inherited fds above 2,
   so an fd pipe cannot work)*: `SSH_ASKPASS_REQUIRE=force` with `SSH_ASKPASS`
   pointing at `alizyd --askpass`. For each connect the daemon opens a one-shot
   Unix socket `/run/alizy/ssh/<id>.askpass` (0600, owned `alizy-ssh`), checks
   the peer's `SO_PEERCRED` uid is `alizy-ssh`, requires a random per-connect
   token passed in the env, serves the password once, then removes the socket.
   The env carries only the socket path and token, never the password.
   Requires OpenSSH ≥ 8.4.
5. Start `tun2socks` as `alizy-ssh` attached to `alizy0`, forwarding to the
   SOCKS port. Wait for the SOCKS port to accept and for a test CONNECT through
   it before declaring the tunnel up.
6. DNS: `alizyd` runs a small forwarder on `127.77.0.1:53` (UDP+TCP) that sends
   queries as DNS-over-TCP through the SOCKS proxy to the profile's DNS servers
   (default `1.1.1.1, 9.9.9.9`; Network settings' custom DNS overrides as
   today). `dns_plan` for SSH points the backend at `127.77.0.1`. Loopback is
   already accepted by the output chain, so DNS leak protection still blocks
   every other resolver.
7. Process supervision: both children are owned by the engine; if either exits,
   the engine goes to the same degraded/reconnect path WireGuard uses, with the
   firewall left in place. `tunnel_down` kills both, removes the TUN and runs
   the normal teardown.
8. Stats: rx/tx from `/sys/class/net/alizy0/statistics`; `last_handshake` =
   last successful keepalive/health probe time; endpoint = `H:P`.

Implement as a second backend behind the adapter (`linux/ssh.rs` beside
`linux/wireguard.rs`) dispatched on the config kind; WireGuard code paths are
untouched.

### Host key (trust on first use)

- On first connect (no pinned key), the daemon fetches the key
  (`ssh-keyscan -p P H`, run as `alizy-ssh`, through the endpoint exception)
  and returns a new error code `HostKeyUnknown { fingerprint, key_type }`.
- The GUI shows "Verify server identity" with the SHA256 fingerprint; on
  confirm it stores the key in the profile and reconnects.
- If the server's key later differs, connect fails with `HostKeyChanged`;
  the GUI explains the risk and offers "Trust new key" only behind an explicit
  confirmation. Edit dialog shows the pinned fingerprint and can clear it.

### GUI

- Configurations: "Add" gains "SSH connection" next to the existing import
  options; opens a form dialog with the five fields (Port prefilled `22`),
  client-side validation mirroring core validation, password field with reveal
  toggle. Edit dialog for SSH profiles uses the same form (password left blank
  = unchanged).
- Profile rows/details show an "SSH" badge and `user@ip:port` instead of
  WireGuard peer info. Everything else (favourite, category, connect) is shared.
- Dashboard TunnelCard shows "SSH" and hides WireGuard-only fields (handshake
  wording becomes "last keepalive").
- A persistent note on SSH profiles: "Only TCP traffic is carried; UDP is
  blocked while connected."

### Packaging / system check

- New runtime deps for SSH profiles: `openssh` (client ≥ 8.4) and a tun2socks
  implementation. They are **optional**: missing deps produce a sysprobe
  finding and disable connecting SSH profiles, never affect WireGuard.
- Packaging creates the `alizy-ssh` system user (sysusers.d) and the
  `/run/alizy/ssh` runtime dir (tmpfiles.d, 0750 root:alizy-ssh).

## Testing

- Core unit tests: SSH config validation, fingerprint, firewall render for an
  SSH plan (TCP exception + skuid mark chain), **golden test that WireGuard
  plans render byte-identically to before**, route/DNS plans for SSH.
- IPC: a WireGuard `Connect` serialises identically to before (golden JSON).
- Daemon: askpass helper never echoes; process-exit → degraded path.
- Manual/real-system: connect to a test sshd (container), verify kill switch
  blocks everything when `ssh` is killed, DNS leak test, split rule bypass,
  routing test tool, reconnect after network change.

## Left to the builder

- Which tun2socks implementation (criteria: SOCKS5 client, attaches to an
  existing TUN by name, runs unprivileged, packaged on Arch at least;
  `hev-socks5-tunnel` is the first candidate) — confirm packaging before coding.
- Exact column layout for SSH fields in SQLite.
- Point-to-point address ranges for the TUN.
- Whether the loopback SOCKS port is restricted to `alizy-ssh`/root via an nft
  `meta skuid` rule on `lo` (recommended, so other local users can't use it).
