# SSH Tunnel Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SSH profiles (name, server IP, port, username, password) that bring up `alizy0` as a VPN-style tunnel through a remote sshd, protected by the existing kill switch, split tunnelling and leak protection, with WireGuard unchanged.

**Architecture:** `alizyd` runs OpenSSH (`ssh -N -D`) and `badvpn-tun2socks` as the unprivileged system user `alizy-ssh`; tun2socks attaches to a pre-created TUN named `alizy0`, so the existing routing/firewall machinery applies. The SSH TCP connection escapes the tunnel via an nft `meta skuid` mark of `0x4a5a`. DNS is served by a forwarder in `alizyd` on `127.77.0.1:53` that speaks DNS-over-TCP through the SOCKS proxy. All new IPC and firewall fields are additive and skipped when empty, so WireGuard output is byte-identical.

**Tech Stack:** Rust (tokio, serde, nix, sqlx), nftables, iproute2, OpenSSH ≥ 8.4, badvpn-tun2socks, Tauri 2 + React/TypeScript.

**Spec:** `docs/superpowers/specs/2026-11-22-ssh-tunnel-design.md`

## Global Constraints

- WireGuard: nft script, plan tag, IPC JSON and existing `#[test]` code must be **byte-identical / unmodified**. Every new serde field is `#[serde(default, skip_serializing_if = ...)]`.
- `PROTOCOL_VERSION` stays `1`.
- Password never in argv, environment, logs, SQLite, backups or exports. Use `Zeroizing<String>`.
- `ssh`, `ssh-keyscan` and `badvpn-tun2socks` never run as root; they run as user `alizy-ssh`.
- Executables resolved only via `sysprobe::find_exe` (fixed `SAFE_PATH`).
- Port default `22`, range 1–65535. Username: 1–64 chars, no whitespace/control chars, no leading `-`, no `@`. Password: 1–1024 bytes, no NUL/newline. Host: an IP address literal (v4 or v6).
- Fixed values: TUN v4 `198.18.0.1/30` (tun2socks netif `198.18.0.2`), TUN v6 `fd4a:5a00::1/126` (netif `fd4a:5a00::2`), TUN MTU `1500`, DNS forwarder `127.77.0.1:53`, default SSH DNS `1.1.1.1, 9.9.9.9`, runtime dir `/run/alizy/ssh` (0750 root:alizy-ssh).
- `ssh` options exactly: `-N -D 127.0.0.1:<port> -p <P> -F /dev/null -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<runtime>/<id>.known_hosts -o GlobalKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 -o BatchMode=no -- <user>@<host>`.
- UDP: an SSH plan always rejects UDP out `alizy0` (except to `127.77.0.1:53` which is on `lo`), kill switch on or off.
- Backups/exports never contain the SSH password; restored SSH profiles are flagged `password_needed`.
- SSH deps are optional: missing ones disable SSH connect with a clear error and a sysprobe finding; WireGuard unaffected.
- Repository has no commits yet: **do not commit** unless the user says so; leave changes in the working tree.

## Review Focus

1. **Wrong password / auth failure** → connect fails fast (≤ 20 s) with "authentication failed", firewall back to no-tunnel policy, no reconnect loop hammering the server. Test in Task 9 (`ssh_exit_auth_failure_maps_to_error`).
2. **`ssh` dies mid-session (server reboot, network drop)** → engine goes degraded, kill switch keeps blocking, auto-reconnect retries. Test in Task 9 (`child_exit_triggers_degraded`).
3. **Server key changed** → `HostKeyChanged`, never a silent connect. Test in Task 9 (`known_hosts_mismatch_maps_to_host_key_changed`).
4. **Switching WG ↔ SSH while connected** → old backend fully torn down (children killed, TUN removed) before the new one, protection never lifted. Test in Task 9 (`switch_kind_tears_down_previous_backend`).
5. **Local user other than `alizy-ssh`/root using the SOCKS port** → rejected by nft on `lo`. Test in Task 3 (`ssh_plan_restricts_socks_port_to_alizy_ssh`).

---

### Task 1: Core SSH config model

**Files:**
- Create: `crates/alizy-core/src/ssh.rs`
- Modify: `crates/alizy-core/src/lib.rs` (add `pub mod ssh;` and re-exports)

**Interfaces:**
- Produces:
  - `pub struct HostKey { pub key_type: String, pub key_b64: String }` with `fn fingerprint_sha256(&self) -> String` (OpenSSH format `SHA256:<base64-no-pad>`) and `fn known_hosts_line(&self, host: IpAddr, port: u16) -> String` (`[h]:p type key` when port ≠ 22, else `h type key`; IPv6 host in brackets when port ≠ 22).
  - `pub struct SshPublic { pub host: IpAddr, pub port: u16, pub username: String, #[serde(default)] pub host_key: Option<HostKey>, #[serde(default)] pub dns: Vec<IpAddr> }` (Serialize/Deserialize/Clone/PartialEq).
  - `pub struct SshConfig { pub public: SshPublic, pub password: Zeroizing<String> }` (Serialize/Deserialize; `Debug` impl redacts password).
  - `pub const DEFAULT_SSH_PORT: u16 = 22; pub const DEFAULT_SSH_DNS: [IpAddr; 2]` (1.1.1.1, 9.9.9.9).
  - `pub fn validate_public(p: &SshPublic) -> Result<(), String>`, `pub fn validate(c: &SshConfig) -> Result<(), String>` per Global Constraints; host must not be unspecified/multicast/loopback.
  - `pub fn fingerprint(p: &SshPublic) -> String` = first 16 bytes hex of `sha256("alizy-ssh-v1\0" host "\0" port "\0" username)`.
  - `impl SshPublic { pub fn dns_servers(&self) -> Vec<IpAddr> }` → `dns` or `DEFAULT_SSH_DNS`.

- [ ] **Step 1: Write failing tests** in `ssh.rs` `mod tests`: `validate_accepts_minimal` (`192.0.2.10`, 22, `"alice"`, `"pw"` → Ok); `validate_rejects_each_bad_field` (port 0; username `""`, `"-oProxyCommand=x"`, `"a b"`, `"a@b"`, 65 chars; password `""`, `"a\nb"`, 1025 bytes; host `0.0.0.0`, `127.0.0.1`, `224.0.0.1` → each Err); `fingerprint_stable_and_ignores_password_and_dns`; `debug_redacts_password` (`!format!("{c:?}").contains("hunter2")`); `known_hosts_line_formats` (`192.0.2.1`,22 → `"192.0.2.1 ssh-ed25519 AAA"`; `2001:db8::1`,2222 → `"[2001:db8::1]:2222 ssh-ed25519 AAA"`); `sha256_fingerprint_matches_openssh` (use a fixed ed25519 key b64 and the fingerprint `ssh-keygen -lf` prints for it — generate once with `ssh-keygen -t ed25519 -f /tmp/k -N ''` and paste both).
- [ ] **Step 2:** `cargo test -p alizy-core ssh::` → FAIL (module missing).
- [ ] **Step 3:** Implement the interfaces above. Use `base64` (workspace dep) for decode/encode.
- [ ] **Step 4:** `cargo test -p alizy-core` → all PASS (existing tests unchanged).

### Task 2: IPC additions

**Files:**
- Modify: `crates/alizy-core/src/ipc.rs`

**Interfaces:**
- Consumes: `SshConfig`, `HostKey` (Task 1).
- Produces:
  - `TunnelSpec` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub ssh: Option<SshConfig>`. When `Some`, `config` is ignored (GUI sends `WgConfig::placeholder()` — add `pub fn placeholder() -> WgConfig` in `config.rs`: zero key, no peers).
  - `ErrorCode` gains `HostKeyUnknown`, `HostKeyChanged`, `AuthFailed`, `MissingDependency`.
  - `IpcError` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub host_key: Option<HostKey>` (set for the two host-key codes).
  - `TunnelStats` unchanged; `DaemonStatus` gains `#[serde(default, skip_serializing_if = "Option::is_none")] pub tunnel_kind: Option<String>` (`"ssh"` only; absent for WG).

- [ ] **Step 1: Failing tests:** `wg_connect_json_unchanged` — build a WG `Command::Connect` from `config::tests::sample()` and assert `serde_json::to_string` equals a golden string captured **before** editing the struct (capture it first by running the current code); `ssh_spec_roundtrips`; `ipc_error_without_host_key_json_unchanged` (golden).
- [ ] **Step 2:** Run → new ssh test FAILS, golden tests PASS on old code (that is the point: capture first).
- [ ] **Step 3:** Add the fields/variants.
- [ ] **Step 4:** `cargo test -p alizy-core` → PASS, goldens unchanged.

### Task 3: Firewall rules for SSH plans

**Files:**
- Modify: `crates/alizy-core/src/firewall.rs`

**Interfaces:**
- Produces: `TunnelRules` gains (all `#[serde(default, skip_serializing_if = ...)]`):
  `pub tcp_endpoints: Vec<SocketAddr>`, `pub ssh_uid: Option<u32>`, `pub socks_port: Option<u16>`, `pub block_udp: bool` (skip if false).
  `FirewallPlan::render` behaviour when these are set:
  - output chain: `meta mark 0x4a5a {fam} daddr H tcp dport P accept` per tcp endpoint (before kill-switch reject); input chain: `{fam} saddr H tcp sport P accept`.
  - new chain `ssh_mark` (`type route hook output priority mangle - 1`): `meta skuid {uid} {fam} daddr H tcp dport P meta mark set 0x4a5a`.
  - output chain, right after `oifname "lo" accept` is replaced for SSH plans by: `oifname "lo" tcp dport {socks_port} meta skuid != {uid} meta skuid != 0 reject` then `oifname "lo" accept`.
  - when `block_udp`: `oifname "alizy0" meta l4proto udp reject` placed **before** the existing `oifname "alizy0" accept`.
  - `needs_table()` true whenever `tunnel.block_udp`.

- [ ] **Step 1: Failing tests:** `wg_plan_render_and_tag_unchanged` (golden render + tag for the existing test plan, captured before edits); `ssh_plan_allows_tcp_endpoint_marked`; `ssh_plan_marks_by_skuid`; `ssh_plan_restricts_socks_port_to_alizy_ssh`; `ssh_plan_rejects_udp_on_tunnel_even_without_kill_switch` (kill_switch false → script contains the udp reject and it precedes `oifname "alizy0" accept`).
- [ ] **Step 2:** Run → new tests FAIL, golden PASS.
- [ ] **Step 3:** Implement. Validate the rendered script with `nft -c -f` if available in the test environment (skip test when `nft` absent or not root, as existing tests do if they do; otherwise string assertions only).
- [ ] **Step 4:** `cargo test -p alizy-core firewall` → PASS.

### Task 4: Routing and DNS plans for SSH

**Files:**
- Modify: `crates/alizy-core/src/routing.rs`

**Interfaces:**
- Produces: `pub fn ssh_public_config(p: &SshPublic, policy: &NetworkPolicy) -> PublicConfig` — synthesises a `PublicConfig` with addresses `198.18.0.1/30` (+ `fd4a:5a00::1/126` if IPv6 enabled), `mtu: Some(1500)`, `dns: vec![127.77.0.1]`, one synthetic full-tunnel peer (allowed `0.0.0.0/0`, `::/0`, no endpoint) so the **existing** `route_plan`, `dns_plan` and `compatibility_warnings` are reused unchanged. `pub const SSH_DNS_FORWARDER: SocketAddr = 127.77.0.1:53`, `pub const SSH_TUN_V4`, `SSH_NETIF_V4`, `SSH_TUN_V6`, `SSH_NETIF_V6`.
- Note: `policy.custom_dns` overriding must NOT replace the forwarder address in the system DNS plan for SSH; instead the forwarder's upstreams are `custom_dns` if non-empty else `SshPublic::dns_servers()`. Add `pub fn ssh_dns_plan(policy) -> DnsPlan` returning servers `[127.77.0.1]`, search `~.`, and `pub fn ssh_upstreams(p: &SshPublic, policy) -> Vec<IpAddr>`.

- [ ] **Step 1: Failing tests:** `ssh_route_plan_defaults_to_tun` (contains `ip -4 route replace 0.0.0.0/0 dev alizy0 table 19034`, address `198.18.0.1/30`, mtu 1500); `ssh_route_plan_omits_v6_when_disabled`; `ssh_dns_plan_points_to_forwarder_even_with_custom_dns`; `ssh_upstreams_prefer_custom_dns`.
- [ ] **Step 2–4:** fail → implement → `cargo test -p alizy-core routing` PASS.

### Task 5: System probe for SSH dependencies

**Files:**
- Modify: `crates/alizy-core/src/sysprobe.rs`

**Interfaces:**
- Produces: `Dependency::OpenSsh` (label `"OpenSSH client (ssh ≥ 8.4)"`, packages: pacman `openssh`, apt `openssh-client`, dnf `openssh-clients`, zypper `openssh-clients`) and `Dependency::Tun2Socks` (label `"tun2socks (badvpn-tun2socks)"`, packages: `badvpn` on all four). Add `ssh`, `ssh-keyscan`, `badvpn-tun2socks` to `OPTIONAL_EXES`. `SystemReport` gains `#[serde(default)] pub ssh_ready: bool` and `pub ssh_missing: Vec<Dependency>`. `analyse` emits one **Warning** (not blocker) finding "SSH profiles unavailable" listing missing packages with the install command. Add `pub fn openssh_version_ok(ssh_v_output: &str) -> bool` (parses `OpenSSH_X.Yp…`, true when ≥ 8.4).
- [ ] **Step 1: Failing tests:** `ssh_missing_is_warning_not_blocker`; `openssh_version_parse` (`"OpenSSH_10.6p2, OpenSSL…"` → true, `"OpenSSH_8.3p1"` → false, `"OpenSSH_8.4p1"` → true, garbage → false); package names per manager.
- [ ] **Step 2–4:** fail → implement → `cargo test -p alizy-core sysprobe` PASS.

### Task 6: Store — SSH profiles, secrets, backup

**Files:**
- Create: `crates/alizy-store/migrations/0002_ssh_profiles.sql`
- Modify: `crates/alizy-store/src/db.rs`, `secrets.rs`, `manager.rs`
- Test: `crates/alizy-store/tests/ssh_profiles.rs`

**Interfaces:**
- Migration: `ALTER TABLE profiles ADD COLUMN kind TEXT NOT NULL DEFAULT 'wireguard'; ALTER TABLE profiles ADD COLUMN ssh_public TEXT; ALTER TABLE profiles ADD COLUMN password_needed INTEGER NOT NULL DEFAULT 0;` SSH rows store `WgConfig::placeholder().split().0` JSON in `public_config`.
- `ProfileRow` gains `pub kind: ProfileKind` (`enum ProfileKind { Wireguard, Ssh }`, serde snake_case, default Wireguard), `pub ssh: Option<SshPublic>`, `pub password_needed: bool` — all `#[serde(default)]`.
- `SecretStore`: `pub fn put_ssh_password(&self, id: &str, pw: &str) -> Result<(), SecretError>`, `pub fn get_ssh_password(&self, id: &str) -> Result<Zeroizing<String>, SecretError>`; stored under key `"ssh:" + id` using the same backend (keyring or file fallback). `delete(id)` also removes `"ssh:" + id`.
- `ProfileManager`:
  - `pub async fn create_ssh(&self, name: &str, public: SshPublic, password: Zeroizing<String>) -> Result<ProfileRow, ManagerError>` (validates, sanitises name, duplicate check by `ssh::fingerprint`).
  - `pub async fn update_ssh(&self, id: &str, name: &str, public: SshPublic, password: Option<Zeroizing<String>>) -> Result<ProfileRow, ManagerError>` (`None` = keep; clears `password_needed` when `Some`; if host/port changed, clears `host_key`).
  - `pub async fn set_ssh_host_key(&self, id: &str, key: Option<HostKey>) -> Result<(), ManagerError>`.
  - `pub async fn full_ssh_config(&self, id: &str) -> Result<SshConfig, ManagerError>` (error `ManagerError::PasswordNeeded` when flagged or secret missing).
  - `duplicate` copies the password secret; `delete` removes it; `export` of an SSH profile returns `ManagerError::Unsupported("SSH profiles cannot be exported as .conf")`.
  - `backup`: SSH rows written as `BackupProfile` with new optional `ssh: Option<SshPublic>` field and **no** password; backup `version` stays 1 (field is optional, so old readers ignore it). `restore`: SSH entries created with `password_needed = true`.
- [ ] **Step 1: Failing tests** (`tests/ssh_profiles.rs`, using `SecretStore::file(tempdir)` like `tests/profiles.rs`): `create_and_load_ssh_profile`; `password_not_in_sqlite` (read the DB file bytes, assert password absent); `duplicate_ssh_rejected`; `update_without_password_keeps_it`; `host_change_clears_host_key`; `backup_excludes_password_and_restore_flags_needed` (backup file bytes lack the password; restored row `password_needed`; `full_ssh_config` → `PasswordNeeded`); `delete_removes_secret`; `existing_wireguard_rows_get_kind_wireguard_after_migration`.
- [ ] **Step 2:** `cargo test -p alizy-store` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p alizy-store` → all PASS (incl. existing `tests/profiles.rs` unmodified).

### Task 7: Daemon askpass helper

**Files:**
- Create: `crates/alizyd/src/askpass.rs`
- Modify: `crates/alizyd/src/main.rs` (dispatch askpass client mode before any daemon setup. It triggers when argc == 2, `ALIZY_ASKPASS_SOCK` is set and euid ≠ 0, which is how ssh execs `SSH_ASKPASS "<prompt>"`, or on the explicit `--askpass PROMPT` form)

**Interfaces:**
- Produces:
  - `pub struct AskpassServer` with `pub async fn start(dir: &Path, id: &str, password: Zeroizing<String>, allowed_uid: u32) -> io::Result<AskpassServer>` — binds `dir/<id>.askpass` (mode 0600, chown to `allowed_uid`), random 32-byte hex token; rejects `allowed_uid == 0` and passwords containing `\n`/`\r`; `pub fn env(&self) -> Vec<(String, String)>` returning `SSH_ASKPASS=<path to current alizyd exe>`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=:0` (unused but some builds require it), `ALIZY_ASKPASS_SOCK=<path>`, `ALIZY_ASKPASS_TOKEN=<token>`; serves exactly one request whose peer `SO_PEERCRED` uid == `allowed_uid` and whose first line equals the token, writes the password + `\n`, then removes the socket. `Drop` removes the socket.
  - `pub fn run_client() -> i32` for `alizyd "<prompt>"`, which is how ssh invokes `SSH_ASKPASS` (env-selected), or `alizyd --askpass <prompt>`: connects, sends token, requires the trailing `\n` of the reply, prints the password + `\n` to stdout, exit 0; any failure → exit 1 with no output. If the prompt contains "passphrase" or "yes/no", exit 1 (never answer host-key prompts).
- [ ] **Step 1: Failing tests:** `serves_once_to_matching_uid_and_token` (uid = current uid); `wrong_token_gets_nothing`; `second_request_gets_nothing`; `socket_removed_after_use_and_on_drop`; `client_refuses_yes_no_prompt`.
- [ ] **Step 2–4:** fail → implement with `tokio::net::UnixListener` + `nix::sys::socket::getsockopt(PeerCredentials)` → `cargo test -p alizyd askpass` PASS.

### Task 8: DNS-over-SOCKS forwarder

**Files:**
- Create: `crates/alizyd/src/socks_dns.rs`

**Interfaces:**
- Consumes: `routing::SSH_DNS_FORWARDER`, `alizy_core::dnswire` (only for validating a query header).
- Produces: `pub struct DnsForwarder` with `pub async fn start(listen: SocketAddr, socks: SocketAddr, upstreams: Vec<IpAddr>) -> io::Result<DnsForwarder>` and `pub fn stop(self)`. UDP and TCP listeners on `listen` (add `127.77.0.1` to `lo` with `ip addr add 127.77.0.1/32 dev lo` is NOT needed — all of 127/8 is local on Linux). Per query: SOCKS5 no-auth CONNECT to `upstream:53`, send 2-byte length + query, read reply, return to client (truncate to 512 + TC bit for UDP clients if larger and no EDNS). Try upstreams in order, 3 s each. Max 256 in-flight queries.
- Also `pub async fn socks5_connect(socks: SocketAddr, dst: SocketAddr) -> io::Result<TcpStream>` (reused by Task 9 readiness probe).
- [ ] **Step 1: Failing tests:** spin up an in-test minimal SOCKS5 server and a fake TCP DNS server on loopback: `forwards_udp_query_via_socks`; `forwards_tcp_query`; `falls_back_to_second_upstream`; `socks5_connect_rejects_non_success_reply`.
- [ ] **Step 2–4:** fail → implement → `cargo test -p alizyd socks_dns` PASS.

### Task 9: SSH backend and engine integration

**Files:**
- Create: `crates/alizyd/src/linux/ssh.rs`
- Modify: `crates/alizyd/src/linux/mod.rs`, `crates/alizyd/src/engine.rs`, `crates/alizyd/src/main.rs` (runtime dir, `alizy-ssh` uid lookup at startup → `Option<u32>`)

**Interfaces:**
- Consumes: Tasks 1–8.
- Produces in `linux/ssh.rs`:
  - `pub struct SshTunnel { ssh: Child, tun2socks: Child, dns: DnsForwarder, askpass: Option<AskpassServer>, socks_port: u16, endpoint: SocketAddr }`.
  - `pub async fn keyscan(uid: u32, host: IpAddr, port: u16) -> Result<HostKey, String>` (`ssh-keyscan -T 8 -t ed25519,ecdsa,rsa -p P H`, first key, preference ed25519 > ecdsa > rsa).
  - `pub async fn start(iface: &str, cfg: &SshConfig, uid: u32, runtime: &Path, upstreams: Vec<IpAddr>) -> Result<SshTunnel, SshError>`; steps: write known_hosts (0640 root:alizy-ssh) → `ip tuntap add dev alizy0 mode tun user alizy-ssh` → pick free loopback port (bind :0, read, drop) → start askpass → spawn ssh with uid/gid via `Command::uid/gid`, `env_clear()`, `PATH=SAFE_PATH`, `HOME=runtime`, plus `AskpassServer::env()` (`SSH_ASKPASS` is the bare `alizyd` path with no `--askpass`; ssh execs it as `alizyd "<prompt>"` and alizyd selects client mode via `ALIZY_ASKPASS_SOCK` + non-root euid), stdin null, stderr captured → wait until `socks5_connect(127.0.0.1:port, upstream0:53)` succeeds (poll 250 ms, deadline 20 s, abort early if ssh exits) → spawn `badvpn-tun2socks --tundev alizy0 --netif-ipaddr 198.18.0.2 --netif-netmask 255.255.255.252 --socks-server-addr 127.0.0.1:<port> --loglevel warning` (+ `--netif-ip6addr fd4a:5a00::2` when IPv6 enabled) as alizy-ssh → start DnsForwarder.
  - `pub enum SshError { HostKeyChanged(HostKey), AuthFailed, MissingDependency(String), Other(String) }` + `pub fn classify_ssh_stderr(stderr: &str) -> Option<SshError>` (`"REMOTE HOST IDENTIFICATION HAS CHANGED"` / `"Host key verification failed"` → HostKeyChanged — fetch new key via keyscan for the error payload; `"Permission denied"` → AuthFailed).
  - `impl SshTunnel { pub async fn stop(self); pub fn try_exited(&mut self) -> Option<String>; pub fn stats(&self, iface) -> TunnelStats }` (rx/tx from `/sys/class/net/<iface>/statistics/{rx,tx}_bytes`, `last_handshake` = last successful liveness check, `endpoint`).
- `LinuxAdapter` gains `ssh: tokio::sync::Mutex<Option<SshTunnel>>` and `pub async fn ssh_up(&self, iface, cfg, uid, runtime, upstreams, routes, dns_plan) -> AdapterResult<()>`; `tunnel_down` stops any `SshTunnel` first and also runs `ip tuntap del dev alizy0 mode tun`; `tunnel_stats` uses the SSH stats when an `SshTunnel` exists. WireGuard functions untouched.
- `Engine`:
  - `connect`: if `spec.ssh.is_some()` → `ssh::validate`, check deps (`MissingDependency`), then the same state machine as WG. Inside `bring_up_inner`, the firewall is enforced **first** (so with the kill switch on, `ssh-keyscan` running as `alizy-ssh` is let out by the `ssh_mark` chain and the TCP endpoint exception). If `host_key` is `None`, run `keyscan`, then fail the bring-up with `ErrorCode::HostKeyUnknown` carrying `host_key`; the normal failure path restores the no-tunnel firewall. This failure must not count as a reconnect attempt or flip the state to `error`. Add the test `host_key_unknown_does_not_trigger_reconnect`.
  - `bring_up_inner` branches on kind: SSH sets `Active.public = routing::ssh_public_config(..)`, `Active.endpoints = vec![Some(host:port)]`, and a new `Active.kind: TunnelKind`; `desired_plan` fills `tcp_endpoints`, `ssh_uid`, `socks_port`, `block_udp = true` for SSH and leaves `endpoints` empty; WG path builds `TunnelRules` exactly as now.
  - `tick`/`health_check`: for SSH, `try_exited()` → `degraded("SSH connection lost: …")` → existing reconnect path. `resolve_endpoints`/`set_endpoint` paths skipped for SSH.
  - Status: `tunnel_kind = Some("ssh")`.
- [ ] **Step 1: Failing tests** (unit, no root): `classify_ssh_stderr` cases → `ssh_exit_auth_failure_maps_to_error`, `known_hosts_mismatch_maps_to_host_key_changed`; `ssh_argv_exact` (build argv via a pure `fn ssh_argv(cfg, port, runtime) -> Vec<String>` and assert it equals the Global Constraints list and contains no password); `desired_plan_for_ssh_sets_tcp_and_udp_block`; `desired_plan_for_wg_unchanged` (golden); `child_exit_triggers_degraded` and `switch_kind_tears_down_previous_backend` using the engine's existing test seams if any — if the engine has none, add a `trait Backend` seam only for these two tests and keep the WG path calling the same functions.
- [ ] **Step 2:** `cargo test -p alizyd` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace` → PASS; `cargo clippy --workspace -- -D warnings` clean.

### Task 10: Packaging

**Files:**
- Modify: `packaging/linux/alizy.sysusers` (add `u alizy-ssh - "Alizy SSH tunnel" /run/alizy/ssh /usr/bin/nologin`), create `packaging/linux/alizy.tmpfiles` (`d /run/alizy/ssh 0750 root alizy-ssh -`), `packaging/linux/install.sh`/`uninstall.sh`, `packaging/arch/PKGBUILD` (install tmpfiles; `optdepends=('openssh: SSH profiles' 'badvpn: SSH profiles (tun2socks)')`), `packaging/rpm/alizyd.spec` (`Recommends: openssh-clients badvpn`), `packaging/deb/build-alizyd-deb.sh` (`Recommends: openssh-client, badvpn`), `packaging/linux/alizyd.service` only if `RuntimeDirectory`/capability lists need `CAP_SETUID`/`CAP_SETGID`/`CAP_CHOWN` to spawn as `alizy-ssh` (check `CapabilityBoundingSet`).
- [ ] **Step 1:** `bash -n` all edited shell scripts; `namcap packaging/arch/PKGBUILD` if available.
- [ ] **Step 2:** `systemd-analyze verify packaging/linux/alizyd.service` → no new errors.

### Task 11: Tauri commands

**Files:**
- Modify: `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs` (register), `crates/alizy-store/examples/alizyctl.rs` (compile fix only)

**Interfaces:**
- Produces commands: `profile_create_ssh(name, host, port, username, password) -> ProfileSummary`, `profile_update_ssh(id, name, host, port, username, password: Option<String>) -> ProfileSummary`, `profile_trust_host_key(id, key: HostKey)`, `profile_clear_host_key(id)`. Passwords wrapped in `Zeroizing` immediately.
- `connect_profile`: for `kind == Ssh` build `TunnelSpec { config: WgConfig::placeholder(), ssh: Some(full_ssh_config) , cached_endpoints: vec![] , .. }`. On `HostKeyUnknown`/`HostKeyChanged` emit the error unchanged to the GUI (with `host_key`); on `PasswordNeeded` return a GUI error code `password_needed`.
- `ProfileSummary` (Rust + TS) gains `kind: "wireguard" | "ssh"`, `ssh: { host, port, username, host_key_fingerprint: string | null } | null`, `password_needed: boolean`. For SSH: `endpoint = "host:port"` (IPv6 bracketed), `addresses = []`, `full_tunnel = true`.
- [ ] **Step 1:** `cargo build -p alizy` (src-tauri crate name per its Cargo.toml) → PASS; `cargo test --workspace` → PASS.

### Task 12: GUI

**Files:**
- Create: `src/screens/configurations/SshProfileDialog.tsx`, `src/screens/configurations/HostKeyDialog.tsx`
- Modify: `src/lib/types.ts`, `src/lib/api.ts`, `src/lib/validate.ts`, `src/screens/configurations/Configurations.tsx`, `ProfileRow.tsx`, `ProfileDetails.tsx`, `src/screens/dashboard/TunnelCard.tsx`, `src/store/profiles.ts` (connect flow)

**Interfaces:**
- `api.createSsh`, `api.updateSsh`, `api.trustHostKey`, `api.clearHostKey` mirroring Task 11.
- `validateSsh({name, host, port, username, password}, {editing}) -> Record<field, string>` in `validate.ts`, same rules as Global Constraints (password optional when editing).
- Copy (exact): dialog title "New SSH connection" / "Edit SSH connection"; labels "Connection Name", "Server IP Address", "Port", "Username", "Password"; edit-mode password placeholder "Leave blank to keep the current password"; note "Only TCP traffic is carried over SSH. UDP (e.g. QUIC, voice and video calls, games) is blocked while connected."; host key dialog title "Verify server identity", body "First connection to {host}:{port}. Make sure this fingerprint matches the server's:" + monospace fingerprint, buttons "Trust and connect" / "Cancel"; changed-key title "Server identity changed", body "The key for {host}:{port} is different from the one you trusted. This can mean someone is intercepting the connection.", buttons "Cancel" (default) / "Trust new key" (destructive style, requires a second confirm click).
- Configurations "Add" dropdown gains "SSH connection". SSH rows show an "SSH" badge and `user@host:port`; WG-only actions (reveal key, export .conf, edit text) hidden for SSH. TunnelCard: label "SSH", "Last keepalive" instead of handshake. Connect flow: on `host_key_unknown`/`host_key_changed` open HostKeyDialog → `trustHostKey` → reconnect; on `password_needed` open SshProfileDialog in edit mode focused on Password.
- [ ] **Step 1:** `npx tsc --noEmit` → PASS; `npm run build` → PASS.
- [ ] **Step 2:** `npx tauri dev`, add an SSH profile with port prefilled 22, check validation messages for each bad field, edit/duplicate/delete/favourite work, WG profiles look unchanged (screenshot both).

### Task 13: Real-system verification

**Files:**
- Create: `tests/ssh/README.md` (how to run), `tests/ssh/run.sh`

- [ ] **Step 1:** Start a disposable sshd: `docker run -d --name alizy-sshd -p 2222:2222 -e PASSWORD_ACCESS=true -e USER_NAME=alice -e USER_PASSWORD=<generated> -e DOCKER_MODS=linuxserver/mods:openssh-server-ssh-tunnel lscr.io/linuxserver/openssh-server` (AllowTcpForwarding must be yes; the mod enables it). Record the generated test password in `tests/ssh/.env.example`-style local file, not in chat.
- [ ] **Step 2:** Install the built packages (or `install.sh`), add profile (server = host LAN IP, port 2222), connect; confirm the TOFU dialog fingerprint equals `ssh-keyscan -p 2222 <ip> | ssh-keygen -lf -`.
- [ ] **Step 3:** With kill switch on: `curl https://ifconfig.co` shows the server's egress IP; `dig example.com` works and `tcpdump -ni <phys> port 53` shows nothing; `nc -u 1.1.1.1 443` fails fast; `docker stop alizy-sshd` → curl fails (blocked, not leaked), status Reconnecting; `docker start` → recovers.
- [ ] **Step 4:** Kill switch off: UDP still rejected; split Direct rule for an IP routes direct (`Routing test` tool shows Direct).
- [ ] **Step 5:** Wrong password → "authentication failed" within 20 s; change container host key → "Server identity changed".
- [ ] **Step 6:** Regression: connect a WireGuard profile, run `tests/leak` and `tests/system` suites as before; `nft list table inet alizy` diff vs. pre-change capture is empty.
- [ ] **Step 7:** `grep -r <test password>` over `~/.local/share/alizy`, the backup file, `journalctl -u alizyd` → no matches.
