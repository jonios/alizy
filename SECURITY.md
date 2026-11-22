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
  (`meta mark` = Alizy fwmark **and** endpoint ip/port) and the above.
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

## Reporting

Report vulnerabilities privately to the maintainers; do not open public issues
for security bugs.
