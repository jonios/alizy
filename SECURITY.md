# Alizy — Security Model

## Threats addressed

| Threat | Mitigation |
|---|---|
| Traffic leaks outside the tunnel (IPv4/IPv6) | nftables kill switch in an owned table; drop/reject is final in nftables regardless of other tables' accepts |
| DNS leaks | DNS (53/udp+tcp, 853/tcp) blocked on every non-tunnel interface while a tunnel is up; resolved routes `~.` to the tunnel link |
| Leak during profile switch | rules for the new tunnel are installed atomically before the old interface is removed; the drop rule never disappears |
| Leak after app/UI crash | rules live in the kernel and are owned by the daemon, not the UI. UI exit never touches them |
| Leak after daemon crash | rules stay in the kernel (fail closed). On restart the daemon re-reads `/var/lib/alizy/state.json` and re-applies |
| Leak after reboot | `alizyd.service` is ordered `Before=network-pre.target` and re-applies the protect-only ruleset before networking starts |
| Third party flushes the ruleset | the daemon verifies the table every supervisor tick (2 s) and re-applies it; event logged as a firewall event |
| Malicious `.conf` (PostUp etc.) | hook keys are stripped with a warning and **never executed**; config is parsed into typed data and re-serialised; wg receives a regenerated config over stdin |
| Shell injection | no shell anywhere. Every process is spawned with an argv vector, a cleared environment and a fixed `PATH` |
| Unauthorised local users controlling the VPN | socket is `0660 root:alizy`; daemon checks `SO_PEERCRED` and authorises the peer PID with polkit (`io.alizy.daemon.control`) |
| Private-key disclosure | keys are `Zeroizing`, `Debug` prints `[redacted]`, never logged, never in SQLite; stored in the OS keyring (or a 0600 file fallback, clearly reported in the UI) |
| GUI running as root | the GUI refuses to start with euid 0 |
| SSH password disclosure | stored like private keys (OS keyring, or the 0600 file fallback), never in SQLite, argv, the environment, logs or backups (restored SSH profiles ask for it again). It reaches ssh only through the one-shot askpass socket below |
| SSH server impersonation (MITM) | trust on first use: an unknown server's key is fetched with `ssh-keyscan` and shown as a SHA256 fingerprint the user must confirm; it is then pinned (`StrictHostKeyChecking=yes`, a per-connection known_hosts file, no global known_hosts). A changed key aborts the connection with the new fingerprint and is never accepted silently |
| Local users abusing the SOCKS proxy (`ssh -D`) | the loopback SOCKS port is restricted by nftables `meta skuid` rules (only alizy-ssh and root may connect to it, only alizy-ssh may answer from it); before use the daemon also checks in `/proc/net/tcp(6)` that every listener on the port belongs to alizy-ssh |
| Privileged SSH tooling | `ssh`, `ssh-keyscan`, `ssh -V` and `badvpn-tun2socks` never run as root: they run as the unprivileged `alizy-ssh` system user (uid and gid set, supplementary groups dropped and re-checked, cleared environment, fixed `PATH`, killed with the daemon) |
| Password helper hijack | the askpass socket is one-shot, `0600` owned by alizy-ssh, accepts only peers whose `SO_PEERCRED` uid is alizy-ssh and that present the random token issued for that connection attempt; it is unlinked after the first answer or after 60 s |
| UDP leaking around a TCP-only tunnel | while an SSH profile is up, UDP into the tunnel interface is always rejected (output and forward), so nothing silently falls back; DNS goes through the daemon's DNS-over-TCP forwarder |
| Tampered or truncated download | release assets ship with `SHA256SUMS` (verify before running); the installer checks its embedded payload against a SHA-256 in its own header before using it |
| Installer overwriting a package-managed install | the installer refuses when `alizyd` belongs to pacman/dpkg/rpm or a manual install; it only removes files listed in its own manifest |
| Upgrade leaving the network unprotected or broken | kernel rules stay in place during the service restart; a new service that fails to start is rolled back to the previous version; uninstall refuses to finish while any Alizy table, interface or rule is left |
| Update mechanism executing unverified code | there is none: the app only shows whether a newer release exists (on request) and never downloads or runs anything |

## Firewall ownership model

* Alizy owns exactly **one** nftables table: `inet alizy`. It never runs
  `flush ruleset`, never touches other tables, never edits iptables.
* Updates are atomic: a single `nft -f -` transaction containing
  `table inet alizy` (ensure exists), `delete table inet alizy`,
  `table inet alizy { … }`. Either the whole new table is live or the old one is.
* Each rendered ruleset embeds a comment tag `alizy:<plan-hash>`. Activation is
  only reported after `nft list table inet alizy` returns that tag.
* Base chains use priority `filter - 10`. Because a drop verdict in any base
  chain is final, other software's `accept` rules cannot open a hole.
* Routing rules are installed at owned priorities (19030/19031) and removed by
  priority, so `wg-quick` or other software's rules are untouched.
* Removal: `alizyd --remove-firewall` (and the uninstall script) deletes only
  `inet alizy`.

## Kill switch semantics

* Enabled + no tunnel ⇒ **Protected**: only loopback, DHCP, IPv6 ND and (optionally) LAN are allowed.
* Enabled + tunnel ⇒ only the tunnel interface, the WireGuard endpoint
  (`meta mark` = Alizy fwmark **and** endpoint ip/port), or for SSH profiles
  the SSH server's TCP address:port used by the alizy-ssh user, and the above.
* If the firewall cannot be confirmed active, connect aborts (fail closed).
* Disabling the kill switch is an explicit, authorised IPC command.

### Known limitations (honest list)

* Hostname endpoints must be resolved before the tunnel exists. While the
  kill switch is in Protected mode, DNS is blocked, so the daemon uses the last
  successfully resolved address cached with the profile. Prefer IP endpoints.
* Traffic from other network namespaces/containers is covered by the `forward`
  chain only when routed through this host's stack.
* The secret-file fallback is plaintext on disk with 0600 permissions; it is
  only used when no Secret Service is reachable, and the UI says so.
* Leak tests require root; see `tests/leak/README.md`.
* SSH bring-up (keyscan, waiting for ssh to authenticate) runs under the
  daemon's engine lock. Disconnect and connect cancel it within about a second,
  but the 2 s firewall re-verification tick pauses for the length of the
  attempt (up to about 40 s). The firewall is applied and verified before the
  slow steps start and stays in place throughout.

## Reporting

Report vulnerabilities privately to the maintainers; do not open public issues
for security bugs.
