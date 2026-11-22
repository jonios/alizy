# Real-network test suite

`tests/leak/run.sh` runs the real `alizyd` binary against the real kernel —
nftables, WireGuard, policy routing, conntrack/NAT — inside **unprivileged
user + network namespaces**, so it needs no root and cannot affect the host.

```
client netns ── veth (192.0.2.0/24, 2001:db8:1::/64) ── "internet" netns
  alizyd, alizy0                                         wgs :51820, wgs2 :51821
                                                         UDP sinks on 198.51.100.x / 2001:db8:ff::x
                                                         test DNS server 198.51.100.53
```

Every verdict is based on **which packets actually arrived at the far end and
with which source address** (tunnel `10.66.0.2` vs physical `192.0.2.1`),
never on what the daemon reports. Leak probes use `SO_BINDTODEVICE` on the
physical interface — the strongest way an application can try to bypass routing.

Covered: kill switch (protected mode, tunnel mode), IPv4/IPv6 leaks, DNS leak
and DNS-through-tunnel, IPv4-off and IPv6-off (blocked even inside the tunnel),
IP and domain split tunnelling with the kill switch on (incl. CNAME chain,
TTL-driven refresh, grace period, removed rules), routing-test tool reading the
kernel set, firewall tamper recovery, atomic profile switch under continuous
leak probing, unexpected tunnel loss and auto-reconnect, SIGKILL of the daemon,
restart recovery, foreign nftables tables left untouched, kill-switch-off
restores normal traffic and removes the table, no private key in daemon logs.

```bash
tests/leak/run.sh          # builds alizyd, prints PASS/FAIL per check
KEEP=1 tests/leak/run.sh   # keep the work dir (daemon log, packet logs)
```

Requires `unshare` (util-linux), `nsenter`, `wg`, `nft`, `ip`, `python3`, and
unprivileged user namespaces (exit code 77 = skipped when disabled).

Not covered here (needs a real host): polkit authorisation, the systemd unit,
systemd-resolved/resolvconf backends (the suite uses `--dns-backend none` and a
private resolv.conf), reboot.
