# LAN Proxy — share this computer's VPN with other devices

Alizy can run an **HTTP forward proxy** and a **SOCKS5 proxy** on this machine
so that other devices on your Wi-Fi (a smart TV, a phone, a console) browse
through *your* VPN connection. The HTTP proxy handles browsers and most apps;
the SOCKS5 proxy carries any TCP traffic — including Telegram, SSH and other
apps that don't speak HTTP.

> **There is no password (phase A).** Anyone on your local network who reaches
> these ports uses your VPN — and your bandwidth. Turn the proxy off when you
> don't need it. This is a deliberate, documented trade-off; a credentials-based
> variant is deferred (see [Roadmap](#roadmap)).

## Using it

1. Open **Settings → Network → Share VPN with other devices** and switch it on.
2. Note the addresses shown — for example `192.168.1.23:8080` (HTTP) and
   `192.168.1.23:1080` (SOCKS5).
3. On the TV/device:
   - **Browsers / streaming:** set a **manual HTTP proxy** to `192.168.1.23:8080`.
   - **Telegram:** open Settings → Data and Storage → Proxy → Add Proxy, choose
     **SOCKS5**, host `192.168.1.23`, port `1080`.
   - **Other apps:** use whichever proxy type the app supports (HTTP or SOCKS5).
4. The device's traffic now exits with the VPN's public IP. Turn the switch off
   to stop both proxies.

The listener binds `0.0.0.0:<port>` (IPv4) and starts with the service, coming
back after a reboot or a daemon restart because the setting is persisted in
`/var/lib/alizy/state.json` next to the network policy.

## What it supports — and what it doesn't

| | |
|---|---|
| ✅ HTTPS | via HTTP `CONNECT` (what TVs and browsers use for nearly everything) |
| ✅ Plain HTTP | absolute-form requests are forwarded (`Connection: close`, one request per connection) |
| ✅ SOCKS5 CONNECT | any TCP connection — Telegram (MTProto), SSH, IRC, raw TCP |
| ✅ SOCKS5 domain resolution | ATYP 0x03; names are resolved by the daemon's tunnel-aware resolver |
| ✅ DNS | resolved by the daemon's resolver, which points at the tunnel while connected — lookups don't leak |
| ❌ UDP / QUIC | **TCP only.** Neither proxy carries UDP; SOCKS5 `UDP ASSOCIATE` is not implemented |
| ❌ Devices without a proxy setting | the device must let you configure a proxy (HTTP or SOCKS5) |
| ❌ IPv6 destinations | listeners are IPv4; IPv6 is not relayed (phase A) |

**Kill switch:** the firewall gains two extra rules while the proxies run —
replies from each proxy's source port to the local network are accepted even
when *Allow local network while protected* is off, because you turned this
on deliberately. Everything else about the kill switch is unchanged: the
proxy's own outbound connections still have to go through the tunnel, so there
is no leak path around it.

**Host firewall (ufw / firewalld):** Alizy owns its own nftables table and does
not touch your distribution's firewall. If `ufw` is active with a default deny
on incoming connections, the TV's first packet to the proxy port is dropped
before Alizy ever sees it:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp comment 'alizy-lan-http'
sudo ufw allow from 192.168.1.0/24 to any port 1080 proto tcp comment 'alizy-lan-socks5'
sudo ufw reload
```

Replace the subnet with yours (the GUI shows the address it is listening on).
`firewalld`: `sudo firewall-cmd --add-port=8080/tcp --permanent && sudo
firewall-cmd --reload`, or better, a trusted-zone source rule.

**Rate/size limits:** up to 64 concurrent clients (extra connections are
refused immediately), 16 KiB of request headers, 10 s to resolve and connect,
5 minutes of complete silence before a relay is closed.

## How it reaches the internet

Both proxies run **inside `alizyd`** (root, tokio):
- HTTP: `crates/alizyd/src/lan_proxy.rs`
- SOCKS5: `crates/alizyd/src/lan_socks.rs`

Both follow the same listener pattern as the DNS forwarder
(`crates/alizyd/src/socks_dns.rs`). Outbound connections are ordinary TCP
sockets created by the daemon, so the kernel's policy routing applies to them
exactly as it does to any other daemon traffic: while a tunnel is up they are
carried by it, and with split tunnelling enabled a `Direct` rule applies to
them like any other connection.

Nothing in the packet path is special-cased — neither proxy needs its own
mark, its own chain, or an exception for its *outbound* side. The only firewall
changes are the inbound-reply rules described above, carried as
`FirewallPlan::lan_proxy_port` and `lan_socks_port` (absent when the proxy is
off, so every existing plan and its tag are byte-identical).

Configuration flows through the ordinary IPC commands `get_lan_proxy` /
`set_lan_proxy`; `SetLanProxy` is privileged (same list as `set_policy`), the
port is validated (1–65535) before anything is bound, and a bind failure is
reported in the status (`error` + `listening: false`) rather than raised — the
setting stays persisted so it retries on the next start.

## Roadmap

* **Phase B — per-device split tunneling for the proxy:** decide per
  connection (from the `CONNECT` hostname) whether it should use `split::evaluate`
  and, for a `Direct` decision, open the socket with `SO_MARK=0x4a5b` so it
  leaves via the physical interface while everything else still goes through
  the VPN. The intended first use: YouTube on the TV goes direct, the rest of
  the TV's traffic stays in the tunnel.
* **Authentication:** a username/password on the listener (`Proxy-Authorization`),
  so "no password" stops being a property of the feature.
