# Domain Routing

Operating systems route **packets by destination IP address**, not by domain
name. Alizy therefore turns domain rules into IP ranges with a Domain
Resolution Engine and is explicit about where that is approximate.

## Matching semantics (exact, label-based)

| Pattern | Mode | Matches | Does **not** match |
|---|---|---|---|
| `bank.example.com` | Exact | `bank.example.com` | `www.bank.example.com`, `notbank.example.com` |
| `*.bank.example.com` | Wildcard | `a.bank.example.com`, `a.b.bank.example.com` | `bank.example.com`, `evilbank.example.com` |
| `.bank.example.com` (UI: "domain + subdomains") | Parent | `bank.example.com` and every subdomain | `xbank.example.com`, `bank.example.com.evil.net` |

Comparison is case-insensitive, ignores a trailing dot, and always on whole
labels. Single-label patterns (`com`) and wildcards anywhere but the leftmost
label are rejected.

## Resolution engine (`crates/alizyd/src/resolver.rs`)

* Queries the **system resolver** (nameservers from `/etc/resolv.conf`, normally
  the systemd-resolved stub) so answers match what local applications receive;
  with DNS leak protection those queries travel through the tunnel.
* A and AAAA are queried concurrently (max 8 domains in parallel); CNAME chains
  are followed (up to 16 hops) and shown in the UI; every address keeps its own
  TTL expiry.
* Never re-resolves before the TTL expires (refresh at `min(TTL)` clamped to
  30 s–1 h). Failures back off 30 s → 5 min.
* **Safe expiry:** addresses that disappear from an answer or whose refresh
  fails are kept for a 15-minute grace period after their TTL, so a connection
  opened just before a change is not cut, then removed.
* Every change recompiles the rules and replaces the nftables table in **one
  atomic transaction** — no window with stale or missing protection.
* The cache is persisted (`/var/lib/alizy/state.json`) so bypass ranges survive
  a reboot while the kill switch blocks DNS.
* UDP with TCP fallback on truncation; responses are matched by id, name and
  type; spoofed/unrelated datagrams are ignored.

## Limitations (honest)

* **Wildcard rules** have no concrete name to pre-resolve. They are evaluated
  correctly by the routing-test tool, but only addresses for names Alizy
  resolves can be enforced. Add the specific subdomains you need as Exact rules.
  (Planned: learning names from systemd-resolved's monitor interface.)
* **Applications with their own DNS** (DNS-over-HTTPS in browsers, DoT, hard-coded
  resolvers) may receive different addresses (e.g. other CDN nodes) than the
  system resolver. Their traffic then does not match a Direct rule and **stays
  in the VPN** — the failure mode is towards protection, not leakage.
* **Shared addresses / CDNs.** Routing is per address. If `bank.example` and an
  unrelated site share an address, bypassing one bypasses both. Alizy warns when
  two configured domains share an address, when Direct and VPN rules collide on
  one address, when an IP rule overrides a domain's address, and when an address
  is in a known shared CDN range (partial built-in list: Cloudflare, Fastly,
  CloudFront, Akamai).

See [DNS_ROUTING.md](DNS_ROUTING.md) for how DNS itself is routed.
