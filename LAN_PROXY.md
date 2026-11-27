# LAN Proxy — share this computer's VPN with other devices

Alizy can run an **HTTP forward proxy** and a **SOCKS5 proxy** on this machine
so that other devices on your Wi-Fi (a smart TV, a phone, a console) browse
through *your* VPN connection. The HTTP proxy handles browsers and most apps;
the SOCKS5 proxy carries any TCP traffic — including Telegram, SSH and other
apps that don't speak HTTP — and UDP through SOCKS5 `UDP ASSOCIATE`.

> **No password by default.** Anyone on your local network who reaches these
> ports uses your VPN — and your bandwidth. Turn on **Require a username and
> password** (see [Authentication](#authentication)), or turn the proxy off when
> you don't need it.

The same two servers also implement proxy mode's local proxy on `127.0.0.1`
(see [docs/MULTI_PROTOCOL.md](docs/MULTI_PROTOCOL.md) and the README).

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
| ✅ SOCKS5 domain resolution | ATYP 0x03; names are resolved the way the current egress resolves them (below) |
| ✅ DNS | tunnel mode: the system resolver, which points at the tunnel while connected; proxy mode: through the tunnel (WireGuard) or on the SSH server — lookups don't leak |
| ✅ SOCKS5 UDP ASSOCIATE | UDP datagrams relayed through the tunnel on the **same port number** as the SOCKS5 listener (UDP), so one firewall exception covers it. Fragmented datagrams (FRAG ≠ 0) are dropped |
| ✅ Username/password | SOCKS5 RFC 1929 and HTTP `Proxy-Authorization: Basic` (407 otherwise) |
| ❌ UDP over SSH tunnels | OpenSSH forwards TCP only; with an SSH tunnel, UDP ASSOCIATE answers "command not supported" |
| ❌ HTTP proxy UDP | an HTTP proxy cannot carry UDP; use SOCKS5 |
| ❌ Devices without a proxy setting | the device must let you configure a proxy (HTTP or SOCKS5) |
| ❌ IPv6 destinations | listeners are IPv4; IPv6 is not relayed (phase A) |

**Kill switch:** the firewall gains extra rules while the proxies run —
replies from each proxy's source port (TCP, and UDP for the SOCKS5 relay) to
the local network are accepted even when *Allow local network while
protected* is off, because you turned this on deliberately. Everything else about the kill switch is unchanged: the
proxy's own outbound connections still have to go through the tunnel, so there
is no leak path around it.

**Host firewall (ufw / firewalld):** Alizy owns its own nftables table and does
not touch your distribution's firewall. If `ufw` is active with a default deny
on incoming connections, the TV's first packet to the proxy port is dropped
before Alizy ever sees it:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp comment 'alizy-lan-http'
sudo ufw allow from 192.168.1.0/24 to any port 1080 comment 'alizy-lan-socks5'   # TCP and UDP
sudo ufw reload
```

Replace the subnet with yours (the GUI shows the address it is listening on).
`firewalld`: `sudo firewall-cmd --add-port=8080/tcp --permanent && sudo
firewall-cmd --reload`, or better, a trusted-zone source rule.

**Rate/size limits:** up to 64 concurrent clients (extra connections are
refused immediately), 16 KiB of request headers, 10 s to resolve and connect,
5 minutes of complete silence before a relay is closed.

## Authentication

*Require a username and password* applies to both proxies. The GUI sends the
password to the daemon once; the daemon stores only `salt$sha256(salt ||
password)` (16 random bytes of salt) in `/var/lib/alizy/state.json` (root,
0600), never the password, and never reports either back — the status shows
only the username. Changing the username needs a new password; leaving the
password empty keeps the current one. Checks are constant-time.

- **SOCKS5:** with credentials configured the server only accepts method 0x02
  (username/password, RFC 1929); clients that offer only "no authentication"
  are refused. A UDP association is accepted only from the IP address of a
  client that holds an authenticated control connection, and ends when that
  connection closes.
- **HTTP:** every request must carry `Proxy-Authorization: Basic …`; otherwise
  the proxy answers `407 Proxy Authentication Required`. Basic auth is
  **unencrypted** on your LAN — anyone who can sniff it can reuse the login.
  SOCKS5 has the same property. Treat this as access control on a trusted
  network, not as encryption.

## How it reaches the internet

Both proxies run **inside `alizyd`** (root, tokio):
- HTTP: `crates/alizyd/src/lan_proxy.rs`
- SOCKS5: `crates/alizyd/src/lan_socks.rs`

Every outbound connection goes through the engine's current *egress*
(`crates/alizyd/src/egress.rs`):

| Mode / state | Egress |
|---|---|
| Tunnel mode | ordinary sockets: the kernel's policy routing carries them through the tunnel, and a split-tunnel `Direct` rule applies like to any connection |
| Proxy mode, WireGuard connected | sockets marked `PROXY_MARK` (`0x4a5c`), which only the tunnel's routing table carries; names resolved over TCP through the tunnel's DNS |
| Proxy mode, SSH connected | through `ssh -D` (names resolved on the server); TCP only |
| Proxy mode, not connected | **refused** — never a direct connection |

In tunnel mode nothing in the packet path is special-cased. In proxy mode the
firewall adds a guard that rejects any `PROXY_MARK` packet leaving through an
interface other than the tunnel. The inbound-reply rules described above are
carried as `FirewallPlan::lan_proxy_port` and `lan_socks_port` (absent when the
proxy is off, so plans without it keep their tag).

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
