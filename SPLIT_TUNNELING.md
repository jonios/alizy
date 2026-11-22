# Split Tunnelling

**Default: everything uses the VPN.** Only traffic that matches an enabled
`Direct` rule may use the physical network. Rules are evaluated by one shared
module (`crates/alizy-core/src/split.rs`) and enforced by a native adapter.

## Rule types and actions

| Target | Examples | Notes |
|---|---|---|
| IP / CIDR | `192.0.2.10`, `192.0.2.0/24`, `2001:db8::10`, `2001:db8:100::/48` | must be canonical (`192.0.2.10/24` is rejected with a hint) |
| Domain | `bank.example.com`, `*.bank.example.com`, `.example.com` | see [DOMAIN_ROUTING.md](DOMAIN_ROUTING.md) |
| Application | `/usr/bin/firefox` | **not implemented on Linux yet** (see below) |

Actions: **Direct** (bypass), **VPN** (force tunnel, overrides weaker Direct
rules), and **Disabled** (rule kept but `enabled = false`).

## Precedence (deterministic)

1. **IP / CIDR rules** — longest prefix wins; equal prefixes: lower `priority` number wins; still equal: `VPN` wins.
2. **Exact domain rules** (and a Parent rule matching its own apex).
3. **Wildcard / parent-domain rules** — longest matching suffix wins, then priority, then `VPN`.
4. **Application rules** (where supported).
5. **Default: VPN.**

Overlaps are resolved by *interval painting* over the address space
(`split::compile`): weaker rules are painted first and stronger rules overwrite
them, so a `VPN` `/25` inside a `Direct` `/24` correctly leaves a hole, and a
`VPN` exact-domain rule that shares an address with a `Direct` wildcard wins for
that whole address (and a warning is raised).

## Import / export

Bulk paste or files: TXT (one per line, `#` comments, commas/whitespace),
CSV (`target,action,category` with optional header), JSON (`["a.com", …]`,
`[{"target":…,"action":…,"category":…}]` or `{"rules":[…]}`). Duplicates
(against existing rules and within the import) are counted and skipped; invalid
entries are reported per line. Export writes JSON in a form that re-imports.

## Linux enforcement

Everything lives in the single owned nftables table `inet alizy`, replaced
atomically:

* `set direct4` / `set direct6` (interval sets) hold the compiled bypass ranges.
* `chain split_route` (`type route hook output`) marks packets to those sets with
  `0x4a5b` (only if unmarked) and copies the mark to conntrack.
* `ip rule fwmark 0x4a5b lookup main priority 19029` sends marked packets to the
  main table (physical default route) ahead of the tunnel rules.
* `chain split_nat` masquerades marked packets leaving a non-tunnel interface
  (sockets may have picked the tunnel address as source).
* `chain split_pre` restores the mark on replies so reverse-path filtering
  (with `src_valid_mark=1`) accepts them.
* With the kill switch on, `output` accepts `@direct4/@direct6` *after* the DNS
  leak rules and *before* the final reject — so bypass is explicit and DNS never
  bypasses.

## Application-based split tunnelling

| Platform | Status |
|---|---|
| Linux | **Not implemented.** The planned mechanism is cgroup v2: apps launched by Alizy into a dedicated systemd user slice, matched with nftables `socket cgroupv2`. Not shipped until it is tested. |
| Windows | Not implemented (planned: WFP ALE layer filters by application identity). |
| macOS | Not implemented. Per-app VPN (`NEAppProxyProvider`/per-app rules) is an MDM-managed capability; consumer apps cannot offer it generally. |

The UI's Applications tab states this instead of offering non-functional controls.

## Verified behaviour (real kernel, `tests/leak/run.sh`)

IPv4 and IPv6 `/32`/`/128` Direct rules bypass the tunnel with the kill switch
on; non-matching addresses still use the tunnel; a broader `VPN` CIDR does not
override a more specific `Direct` rule; leaks to non-bypassed addresses stay
blocked; domain-derived addresses (including via a CNAME chain) bypass; removed
rules stop bypassing; a changed DNS answer is picked up after TTL expiry; the
old address is kept during the grace period; the routing-test tool reports
kernel set membership.
