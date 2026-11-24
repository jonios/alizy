# DNS Routing and Leak Protection

## Backends (chosen from detected facts, never from the distro name)

| Detected | Backend | How DNS is set | How it is restored |
|---|---|---|---|
| systemd-resolved active **and** `/etc/resolv.conf` points into `/run/systemd/resolve/` | `systemd_resolved` | `resolvectl dns/domain alizy0 …`, `~.` routing domain and `default-route yes` for full tunnels | link-scoped; vanishes with the interface (`resolvectl revert` as well) |
| `resolvconf` binary (openresolv or Debian resolvconf) | `resolvconf` | `resolvconf -a alizy0 -m 0 -x` (falls back without `-x`) | `resolvconf -d alizy0 -f` |
| neither (incl. NetworkManager writing resolv.conf itself) | `resolv_conf_file` | back up `/etc/resolv.conf` (symlink target preserved) to `/var/lib/alizy/`, write VPN DNS atomically, **re-assert every 2 s** if another manager overwrites it | restore the backup (or re-create the symlink); a pending backup is also restored at daemon start after a crash |

Custom DNS servers (Network Settings) override the profile's `DNS=`; servers of
a disabled address family are dropped.

## SSH profiles

An SSH tunnel carries only TCP, so the system resolver is pointed at a
forwarder inside the daemon on `127.77.0.1:53` (UDP and TCP; `~.` routing on
systemd-resolved). It relays every query as DNS-over-TCP through ssh's SOCKS
proxy, so lookups are resolved from the SSH server's side. Upstreams: Custom
DNS servers, else the profile's DNS, else 1.1.1.1 and 9.9.9.9. Custom DNS
servers on the local network (private, link-local, loopback, ULA) can't be
reached from the server and are ignored with a warning in the log. Oversized
UDP answers are truncated (TC bit) so clients retry over TCP. If another DNS
service (e.g. dnsmasq on `0.0.0.0:53`) already holds port 53 on `127.77.0.1`,
SSH connections fail with a message saying so.

## Leak protection (independent of the backend)

While a tunnel is up and DNS leak protection is on, nftables rejects
`udp/tcp dport 53` and `tcp dport 853` on **every interface except the tunnel**
— before any bypass rule, so split-tunnel Direct rules never let DNS out. With
the kill switch on and no tunnel, all non-LAN traffic (DNS included) is blocked.
Verified with real packets in `tests/leak/run.sh` (a socket bound to the
physical interface with `SO_BINDTODEVICE` cannot reach a DNS server; queries
through the tunnel succeed).

## Direct-routed domains

Lookups for Direct domains are also resolved through the tunnel's DNS. This
keeps the DNS path consistent (no leak, no split-horizon confusion) and
matches what applications using the system resolver see; only the resulting
*connections* bypass.

## DNS-over-HTTPS / encrypted DNS

Alizy does **not** intercept or rewrite DNS traffic. DoH (TCP 443) travels
inside the VPN like any other traffic and keeps working. Consequences:
domain rules may not match for applications using their own resolver (traffic
stays in the VPN), and DoH is not a "leak" from the tunnel's perspective
because it is tunnelled. DoT on port 853 to a non-tunnel interface is blocked.

## Failure handling

DNS setup failure aborts the connection (fail closed, firewall stays). A
resolver failure in the split-tunnel engine is logged once per outage and the
previous addresses are kept for the grace period.
