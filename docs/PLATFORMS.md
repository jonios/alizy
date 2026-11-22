# Platform Status

| Feature | Linux | Windows | macOS |
|---|---|---|---|
| Tunnel | **implemented** (kernel WireGuard, `wg setconf` via stdin) | not implemented | not implemented |
| Kill switch | **implemented** (nftables `inet alizy`) | not implemented | not implemented |
| IPv4/IPv6 blocking | **implemented** | not implemented | not implemented |
| DNS protection | **implemented** (resolved / resolvconf / file) | not implemented | not implemented |
| Split tunnel: IP + domain | **implemented** | not implemented | not implemented |
| Split tunnel: per-app | not implemented | not implemented | not implemented |
| GUI, profiles, tray | builds on all Tauri targets; GUI shows "service unavailable" without a daemon | | |

`alizyd` compiles on non-Linux targets to a binary that exits with *"this
platform is not implemented yet"*. No fake adapters are shipped.

## Windows plan

* Tunnel: the official **WireGuard embeddable DLL service** (`tunnel.dll`) with
  **WireGuardNT**, run as a Windows service (`alizyd` as a service, named-pipe
  IPC with an ACL restricted to the interactive user + Administrators).
* Kill switch / family blocking / DNS leak protection / bypass: **Windows
  Filtering Platform** with a dedicated provider and sublayer, persistent
  filters (`FWPM_FILTER_FLAG_PERSISTENT`) plus boot-time filters for restart
  protection; ALE `FWPM_CONDITION_ALE_APP_ID` for per-application rules.
* DNS: per-interface DNS via `SetInterfaceDnsSettings`; NRPT for the `~.` case.
* Packaging: MSI/NSIS via Tauri bundler + the service installer; code signing
  (Authenticode, EV certificate recommended) is required for the driver-backed
  service.

## macOS plan

* Tunnel: **WireGuardKit** inside a **Network Extension Packet Tunnel Provider**
  (system extension, signed with the `com.apple.developer.networking.networkextension`
  entitlement `packet-tunnel-provider`), containing app talks via
  `NETunnelProviderManager`.
* Kill switch: `includeAllNetworks` / `enforceRoutes` on the tunnel
  configuration; IPv4/IPv6 control and bypass via `NEPacketTunnelNetworkSettings`
  `includedRoutes` / `excludedRoutes`, updated dynamically with
  `setTunnelNetworkSettings`.
* DNS: `NEDNSSettings` with `matchDomains = [""]`.
* Per-app VPN is an MDM-managed capability; it will not be advertised for
  consumer installs. No `pf` or routing-table hacks.
* Packaging: notarised DMG; Developer ID + system-extension approval flow.
