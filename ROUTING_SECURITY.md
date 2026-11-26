# Routing Security

How split tunnelling, the kill switch, IPv4/IPv6 controls and DNS protection
interact. All of it is one nftables table, `inet alizy`, rendered from one plan
(`FirewallPlan`) and applied in one transaction.

## Output chain order (kill switch on, tunnel up)

1. `oifname lo accept`
2. WireGuard transport: `meta mark 0x4a5a` **and** endpoint ip **and** port → accept
3. Link maintenance: DHCPv4/DHCPv6 client, IPv6 neighbour discovery
4. Disabled family → reject (applies inside the tunnel too)
5. DNS (53, 853) to any non-tunnel interface → reject
6. `oifname alizy0 accept`
7. Split-tunnel bypass: `ip daddr @direct4` / `ip6 daddr @direct6` → accept
8. LAN ranges → accept (only if "allow LAN")
9. everything else → `reject with icmpx admin-prohibited` (tagged `alizy:<hash> kill-switch`)

`forward` mirrors this for routed traffic; `input` enforces disabled families.

## Guarantees and how they are achieved

| Requirement | Mechanism | Verified by |
|---|---|---|
| Rule updates never open a window | table replaced in one `nft -f -` transaction; the reject rule is part of every version | atomic-switch test (60 leak probes during a profile switch, 0 arrived) |
| Kill switch never disabled to update bypass rules | bypass changes only edit set elements inside the same atomic replacement | split tests with kill switch on |
| Direct rules may use the physical interface; nothing else may | explicit accept for set members only; final reject | IPv4/IPv6 bypass + leak tests |
| Endpoint traffic stays allowed | mark + exact endpoint match | tunnel tests |
| IPv4/IPv6 independent | per-family rules and sets; disabled family's ranges are removed from bypass sets | family tests |
| VPN disconnection does not expose non-bypassed traffic | rules are kernel state, independent of the interface | `ip link del alizy0` test |
| App/UI/daemon crash does not remove protection | kernel keeps the table; daemon restart re-applies from persisted state | SIGKILL test |
| Fail closed | firewall applied and read back *before* the tunnel is created; any failure aborts | unit + integration tests |
| Other software's rules preserved | only `inet alizy` is ever created/deleted; routing rules use owned priorities 19029–19031 | foreign-table test |
| Tampering | supervisor re-verifies every 2 s and re-applies | tamper test |

## Known interactions

* **firewalld IPv6 rpfilter** runs at raw priority, before Alizy restores the
  split mark; IPv6 *Direct* replies may be dropped there. IPv4 uses the kernel's
  `rp_filter` with `src_valid_mark=1` and works.
* **Strict reverse-path filtering** (`rp_filter=1` on every interface): the
  WireGuard socket marks its packets; chains `wg_mark` (postrouting) and `wg_pre`
  (prerouting) copy that mark to conntrack and back onto the server's replies, so
  with `src_valid_mark=1` the encrypted replies are looked up outside the tunnel
  instead of dropped (wg-quick does the same). SSH profiles use `ssh_mark`/`ssh_pre`.
  Verified in a namespace with `rp_filter=1`: [docs/TESTING.md](docs/TESTING.md).
* **Containers** (Docker etc.): forwarded traffic is covered by the `forward`
  chain; split-tunnel bypass marking applies to locally generated traffic only.
* **Hostname endpoints** are resolved before the tunnel exists; with DNS blocked
  the last successfully used address is reused.
