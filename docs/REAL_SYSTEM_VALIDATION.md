# Real-System Validation — Alizy 0.1.0 on Linux

**Machine:** Omarchy / Ryoku (Arch-based), kernel 7.2.8, Hyprland 0.57.2, Intel Wi-Fi only
(no Ethernet port), NetworkManager 1.58 + iwd, systemd-resolved (stub mode), ufw active,
gnome-keyring 51, polkit 128, nftables 1.1.7. The user's own NetworkManager WireGuard
connection `wg0` is normally up and is required for the user's internet access.

**Dates:** 2026-11-19/20. **Packages tested:** `0.1.0-1` (install) → `0.1.0-2` (§2–§6) →
`0.1.0-3` (§7.2–7.4) → `0.1.0-4` (§7.5) → **`0.1.0-5` (§7.6–7.7, final installed version)**.
Every upgrade was a real `pacman -U` on this machine.

**Method.** Root steps were run by the user in the desktop Terminal panel (the user typed
the sudo password; Claude never handled it). Traffic verdicts are based on **real packets**:
`curl` through the tunnel, `curl --interface wlan0` (SO_BINDTODEVICE, root) as a leak probe,
and raw DNS queries bound to `wlan0` against the router. Every leak verdict has a **control**:
the same probe is first shown to succeed with Alizy idle. Test servers: the user's own
WireGuard profiles, referred to here as **profile A** and **profile B** (hostname endpoints, IPv4-only tunnels). Scripts:
`tests/system/*.sh`; raw results: `target/system-validation/*.tsv`. Public IP addresses are
redacted in this report; no private key appears in any log or report (checked).

Legend: **PASS** (run and verified), **FAIL** (run, did not meet the requirement), **BLOCKED** (cannot be
performed on this machine), **NOT TESTED** (could be run but was not). A FAIL followed by "→ fixed" was
re-run after the fix; the re-run result is given in the same row or section.

## Summary

**Verdict:** On this machine (Arch-based, Hyprland, NetworkManager + systemd-resolved, Wi-Fi), the
installed Alizy `0.1.0-5` operated safely as a desktop VPN application in every scenario that could
be executed: the kill switch failed closed through daemon SIGKILL, service restart, upgrade,
suspend/resume, Wi-Fi loss, profile switching and two reboots (the second with the final
`Type=notify` ordering), with real-packet leak probes
(controlled) showing zero leaks; unrelated firewall, routing and DNS state was left identical.
This is evidence for **one** distribution and one hardware setup; it is not a claim for others.

**Real bugs found by this validation and fixed** (each re-tested on the real system):

1. Reconnect to hostname endpoints failed whenever DNS was legitimately blocked (protected after restart, IPv4 disabled) — daemon now persists last-good endpoint addresses (§3).
2. Private keys silently fell back to 0600 files with no reason shown and no migration path — migration + visible reason (§9).
3. Install instructions said "log in again"; on systems with a lingering user manager a reboot is required (§7.1).
4. Dashboard leak-protection card showed "Protected" while nothing was protected (§7.3).
5. Editing a duplicated profile (or its original) was refused as a duplicate (§7.3).
6. Boot ordering: unit was `Type=simple`, so networking could start ~1 s before the kill switch existed — now `Type=notify` after protection is applied (§7.4).
7. A service restart/upgrade left the user protected but offline — GUI now reconnects the previous profile (§7.5).
8. Close-to-tray discarded the hide error (`let _ =`) — now deferred and logged (§7.2).
9. RPM spec referenced a non-existent sysusers path (§10).
10. Error for non-configuration text was unclear (§7.3).
11. Paste dialog: the example config was a placeholder inside the real input and the optional Name field came first; a user typed into the wrong field (§7.7).
12. Split Tunneling "Applied" badge conflated "verified firewall state" with "rules affecting traffic" (also in the Active Rules tab) (§7.7).
Plus 15 findings of the independent security review (§8), all fixed before the real-system runs.

**Test-harness bugs** (not product bugs), found and fixed during the runs: `sg` not installed, an nft
error message matched a grep, network baseline captured while `wg0` was up, a racy 0.3 s status
check (detection latency is one 2 s supervisor interval), Lua-syntax `hyprctl` commands.

**Totals (final runs):** install checks 18/18 · real-host network suite 77/77 · suspend 10/10 ·
tray/notifications 12/12 (one transient failure in run 1, not reproduced) · upgrade + restart 10/10 ·
final reboot all checks PASS (§7.6) · real-kernel namespace suite 55/55 · DNS file backend 21/21 ·
resolvconf backend 15/15 (openresolv since removed; suite now SKIPs) · Rust unit/integration 77 ·
`cargo fmt --check`, `cargo check`, `cargo clippy -D warnings`, `tsc`, `vite build` clean (§12).

**BLOCKED (environment):** Wi-Fi↔Ethernet switch (no Ethernet port) · storing keys in the Secret
Service keyring (this machine has no default keyring collection; the 0600-file fallback was used).
**NOT TESTED:** NetworkManager writing resolv.conf on the real host (mechanism covered in isolation) ·
key migration file → keyring · "start minimized" · split-tunnel badges in the *disconnected* states
(connected state verified on screen; other states by code review only) · DEB, RPM and AppImage
packages on their target distributions · Windows and macOS (not implemented; no support claimed).

---

## 1. Inspection before changes

| Item | Result | Evidence |
|---|---|---|
| Existing Alizy installation / config | PASS (none) | no `/var/lib/alizy`, no `alizy` group, no unit; user data dir backed up to `/tmp/claude-1000/io.alizy.app.backup-*` before tests |
| Root commands identified | PASS | `pacman -U/-S/-R`, `usermod -aG alizy`, `systemctl enable/restart/kill`, `nft list` (verification), `curl --interface` / raw sockets with `SO_BINDTODEVICE` (leak probes), `rtcwake`, `systemd-run --uid` (no-session polkit test), `journalctl -u alizyd` |
| Kill switch not enabled by installation | PASS | see §2 |
| Unrelated firewall/DNS/network config untouched | PASS | §3 baseline diffs; `/etc/resolv.conf` symlink and content hash unchanged across all tests |

## 2. Installation (Arch package)

`makepkg` built split packages `alizyd` + `alizy` (+ `-debug`), `check()` ran the unit
tests (pass). `namcap`: only warnings about runtime-exec dependencies (`wg`, `nft`, `ip`,
`pkcheck` are executed, not linked) and implicit libraries — expected.
Install: `pacman -U` → sysusers hook created group `alizy` (GID 954); snapper pre/post
snapshots 13/14; `systemctl enable --now alizyd` active.
**Upgrade** `0.1.0-1 → 0.1.0-2`: pacman's systemd hook restarted the daemon onto the new
binary (PID 263750 → 286516, `ActiveEnterTimestamp` 23:03:23); no manual step needed.

Post-install checks (`tests/system/10-install-checks.sh`, run 2):

| Test | Result | Evidence |
|---|---|---|
| alizyd.service active under systemd | PASS | `active` |
| alizyd runs as root, unit hardening present | PASS | `MainPID=238841 LimitCORE=0 CapabilityBoundingSet=cap_chown cap_net_admin cap_net_raw User= NoNewPrivileges=yes` |
| socket exists with 0660 root:alizy | PASS | `660 root:alizy socket` |
| state dir is 0700 root | PASS | `700 root` |
| group alizy exists and contains <user> | PASS | `alizy:x:954:<user>` |
| journal shows clean start | PASS | `Nov 19 22:38:01 omarchy systemd[1]: Started Alizy VPN service (WireGuard tunnels, kill switch, split tunnelling). Nov 19 22:38:01 omarchy alizyd[238841]:  INFO ufw is active. Its rules are preserved; Alizy's drop rules are enforced in addition to them. Nov 19 ` |
| user outside group alizy is refused by socket permissions | PASS | `refused: [Errno 13] Permission denied` |
| user 'nobody' is refused | PASS | `refused: [Errno 13] Permission denied` |
| group member can read status | PASS | `{   "type": "hello",   "data": {     "protocol": 1,     "version": "0.1.0"   } }` |
| group member in active session may change policy (polkit allow_active) | PASS | `{   "type": "ok" }` |
| group member WITHOUT a login session is denied by polkit | PASS | `alizyctl: Unauthorized: polkit denied the request: `pkcheck --action-id io.alizy.daemon.control` failed: Not authorized.` |
| same no-session member can still read status (read-only) | PASS | `{   "type": "hello",   "data": {     "protocol": 1,     "version": "0.1.0"   } }` |
| test_route also requires authorization (no-session denied) | PASS | `alizyctl: Unauthorized: polkit denied the request: `pkcheck --action-id io.alizy.daemon.control` failed: Not authorized.` |
| malformed request is rejected, daemon survives | PASS | `{"id":0,"result":{"Err":{"code":"bad_request","message":"malformed request"}}}` |
| GUI refuses to run as root | PASS | `Alizy must not run as root. Start it as your normal user; privileged work is done by the alizyd service.` |
| desktop entry and icon installed | PASS | `/usr/share/applications/io.alizy.app.desktop /usr/share/icons/hicolor/128x128/apps/io.alizy.app.png /usr/share/applications/io.alizy.app.desktop: hint: value item "Security" in key "Categories" in group "Desktop Entry" can be extended with another category amo` |
| no Alizy table when kill switch is off (default) | PASS | `table inet alizy absent` |
| kill switch NOT enabled by installation | PASS | `{   "type": "policy",   "data": {     "kill_switch": false,     "allow_lan": true,     "ipv4_enabled": true,     "ipv6_enabled": true,     "dns_leak_protection": true,     "custom_dns": [],     "auto_reconnect": true   } }` |

Run 1 of these checks had 5 FAILs that were **test-harness bugs**, not product bugs:
`sg` is not installed on this distribution (replaced by `sudo -u $USER -g alizy`), and a
check grepped nft's error text for the word "table". Fixed and re-run → 18/18.

**Polkit prompts.** By design no interactive prompt is shown: `allow_active=yes` authorises
group members in the active local session silently, and the daemon calls `pkcheck` without
`--allow-user-interaction`, so any other subject (SSH, no session, other users) is denied
outright rather than prompted. Verified both outcomes above.

## 3. Network, kill switch, DNS (systemd-resolved), split tunnelling, recovery

`tests/system/20-network.sh`, run 2 (after fixes) — **77 / 77 PASS**:

| Test | Result | Evidence |
|---|---|---|
| baseline captured | PASS | `table ip6 filter table ip filter  \| resolv.conf -> /run/systemd/resolve/stub-resolv.conf` |
| control: direct traffic over wlan0 works without Alizy | PASS | `target https://1.1.1.1/ reachable` |
| control: router DNS answers over wlan0 without Alizy | PASS | `router 192.168.0.1` |
| connect profile A | PASS | `{   "type": "ok" }` |
| daemon state connected | PASS | `state=connected` |
| internet works through alizy0 | PASS | `internet reachable` |
| public IP obtained through tunnel | PASS | |
| resolved: alizy0 has VPN DNS and ~. routing domain | PASS | `Link 9 (alizy0)     Current Scopes: DNS          Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported Current DNS Server: 8.8.8.8        DNS Servers: 1.1.1.1 8.8.8.8         DNS Domain: ~.      Default Route: yes` |
| system resolver works while connected | PASS | `system resolver answered example.com` |
| DNS leak protection: router DNS over wlan0 blocked (kill switch off) | PASS | `no answer: [Errno 1] Operation not permitted DNS to router 192.168.0.1 via wlan0 got no answer` |
| enable kill switch | PASS | `{   "type": "ok" }` |
| kill switch verified against kernel | PASS | `firewall_verified=true` |
| kernel table inet alizy present with kill-switch rule | PASS | `2` |
| internet still works through tunnel | PASS | `internet reachable` |
| leak: TCP forced onto wlan0 is blocked | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| DNS leak: router DNS over wlan0 blocked | PASS | `no answer: [Errno 1] Operation not permitted DNS to router 192.168.0.1 via wlan0 got no answer` |
| foreign nftables tables unchanged | PASS | `identical` |
| apply split rule | PASS | `{   "type": "ok" }` |
| Direct domain bypasses the tunnel (ipify sees a different IP than the VPN) | PASS | `ipify via physical: differs from VPN IP` |
| other sites still use the tunnel | PASS | `icanhazip sees VPN IP` |
| routing test tool confirms kernel set membership | PASS | `{   "type": "route_test",   "data": {     "query": "api.ipify.org",     "domain_decision": {       "action": "direct",       "tier": "exact_domain",       "rule_id": "t1",       "explanation": "Domain rule api.ipify.org matches api.ipify.org."     },     "cnam` |
| leak still blocked for non-bypassed traffic | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| DNS still never bypasses (router DNS blocked) | PASS | `no answer: [Errno 1] Operation not permitted DNS to router 192.168.0.1 via wlan0 got no answer` |
| switch to profile B | PASS | `{   "type": "ok" }` |
| zero probe packets leaked during the switch | PASS | `leaked=0` |
| connected on profile B | PASS | `state=connected` |
| internet works on profile B | PASS | `internet reachable` |
| GUI started as normal user | PASS | `273472` |
| after GUI SIGKILL: kill switch still verified | PASS | `firewall_verified=true` |
| after GUI SIGKILL: tunnel still carries traffic | PASS | `internet reachable` |
| after GUI SIGKILL: leak still blocked | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| while Wi-Fi is off, nothing leaks (no route, rules intact) | PASS | `rules-present` |
| back to connected after Wi-Fi returns | PASS | `state=connected` |
| internet works after network change | PASS | `internet reachable` |
| leak blocked after network change | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| firewall verified after network change | PASS | `firewall_verified=true` |
| disable IPv6 | PASS | `{   "type": "ok" }` |
| connected after IPv6-off rebuild | PASS | `state=connected` |
| kernel blocks IPv6 (rule present) | PASS | `3` |
| IPv4 internet unaffected | PASS | `internet reachable` |
| disable IPv4 (IPv6 on) | PASS | `{   "type": "ok" }` |
| IPv4 traffic blocked when IPv4 is disabled | PASS | |
| warning raised: profile cannot carry traffic | PASS | `warned` |
| re-enable both families | PASS | `{   "type": "ok" }` |
| connected again | PASS | `state=connected` |
| internet back | PASS | `internet reachable` |
| set unreachable custom DNS | PASS | `{   "type": "ok" }` |
| connected with custom DNS | PASS | `state=connected` |
| lookups fail with dead DNS (no fallback leak) | PASS | |
| router DNS still blocked during DNS failure | PASS | `no answer: [Errno 1] Operation not permitted DNS to router 192.168.0.1 via wlan0 got no answer` |
| restore profile DNS | PASS | `{   "type": "ok" }` |
| connected | PASS | `state=connected` |
| lookups recover | PASS | `system resolver answered example.com` |
| immediately after SIGKILL: leak blocked (kernel rules persist) | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| systemd restarted the daemon | PASS | `active` |
| recovered into protected state | PASS | `state=protected` |
| while protected: no internet | PASS | |
| while protected: leak blocked | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| while protected: firewall verified | PASS | `firewall_verified=true` |
| reconnect profile A after recovery | PASS | `{   "type": "ok" }` |
| connected | PASS | `state=connected` |
| internet back | PASS | `internet reachable` |
| disconnect | PASS | `{   "type": "ok" }` |
| state protected | PASS | `state=protected` |
| no internet while protected | PASS | |
| DNS blocked while protected | PASS | |
| alizy0 DNS gone after disconnect | PASS | `removed` |
| after service restart: still protected | PASS | `state=protected` |
| after service restart: leak blocked | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| kill switch off | PASS | `{   "type": "ok" }` |
| state disconnected | PASS | `state=disconnected` |
| Alizy nft table removed | PASS | `removed` |
| ip rules identical to baseline | PASS | `identical` |
| foreign nftables tables identical to baseline | PASS | `identical` |
| resolved config of wlan0 identical to baseline | PASS | `identical` |
| /etc/resolv.conf still points to the resolved stub | PASS | `identical` |
| no private key in the daemon journal | PASS | `no key-shaped strings` |

### Run 1 (before fixes): 64 PASS / 13 FAIL — what was found

| Failure | Cause | Fix | Status |
|---|---|---|---|
| "re-enable both families", "reconnect profile A after recovery" → `resolving the endpoint(s) timed out`, plus 7 cascading tunnel checks | **Product bug.** Profiles use hostname endpoints. While DNS is legitimately blocked (kill switch protected after a daemon restart, or IPv4 disabled) the hostname cannot be resolved. A security fix made earlier the same day (F8: concurrent endpoint resolution with an overall deadline) dropped the fallback to the last-known address, and that fallback was only fed by the GUI poller. | Daemon now persists the last successfully resolved address per `host:port` in `/var/lib/alizy/state.json`; each lookup has its own 4 s deadline and falls back to it. Regression test added to `tests/leak/dns_backends.sh` (hostname endpoint, reconnect while DNS blocked, persists across restart) — real-kernel PASS. | fixed, verified in run 2 |
| "foreign tables / ip rules / resolved config identical to baseline" | **Harness bug:** baseline was captured while the user's `wg0` was still up; the test itself then took `wg0` down, so `nm-wg-wg0` tables and wg0's ip rules were legitimately absent later. | Baseline is now captured after `wg0` is down. | fixed, PASS in run 2 |

## 4. Suspend / resume

`tests/system/30-suspend.sh` — connected to profile A with kill switch on, `rtcwake -m mem -s 25`.
Kernel log confirms a real suspend: `PM: suspend entry (s2idle)` 23:09:52 → `PM: suspend exit` 23:10:18.

| Test | Result | Evidence |
|---|---|---|
| suspend: connect profile A with kill switch | PASS | `{   "type": "ok" }` |
| suspend: connected | PASS | `state=connected` |
| suspend: internet before suspend | PASS | `internet reachable` |
| suspend: machine resumed (rtcwake returned) | PASS | |
| suspend: kill switch rules survived suspend | PASS | `2` |
| suspend: leak blocked right after resume | PASS | `physical-interface TCP to https://1.1.1.1/ blocked (code=000)` |
| suspend: tunnel connected after resume (reconnect if needed) | PASS | `state=connected` |
| suspend: internet works after resume | PASS | `internet reachable` |
| suspend: firewall verified after resume | PASS | `firewall_verified=true` |
| suspend: daemon events around resume | PASS | `"message": "Network change detected: wlan0 …" (truncated)` |

## 5. DNS backends

| Backend | How tested | Result |
|---|---|---|
| systemd-resolved | real host (§3): per-link DNS + `~.` on `alizy0`, lookups through tunnel, router DNS over `wlan0` blocked with kill switch on **and** off, DNS failure (dead custom DNS → lookups fail, no fallback leak) and recovery, link DNS gone after disconnect, `wlan0` resolved config identical to baseline after cleanup, resolv.conf symlink unchanged | **PASS** |
| plain `/etc/resolv.conf` (NetworkManager-managed file) | `tests/leak/dns_backends.sh file`: real alizyd + WireGuard + nftables in unprivileged user/net/**mount** namespaces with a private `/etc`; NM-style overwrite re-asserted within 3 s; restored after disconnect, after SIGKILL + restart (crash recovery), while kill switch stays on; DNS blocked while protected (with control); hostname-endpoint reconnect while DNS blocked | **PASS 21/21** (isolated; NetworkManager itself not driving resolv.conf) |
| resolvconf (openresolv 3.17.4) | openresolv installed temporarily, same isolated suite with `--dns-backend resolvconf`, then removed (`pacman -R`); host resolv.conf hash unchanged | **PASS 15/15** (isolated) |
| NetworkManager integration (NM managing DNS without resolved) | not possible here without reconfiguring the user's NetworkManager | **NOT TESTED** on real host (file-backend behaviour above covers the mechanism) |

## 6. Kill switch & crash-recovery scenarios (summary)

| Scenario | Result | Where |
|---|---|---|
| Enable kill switch, disconnect VPN | PASS — protected, no internet, TCP/DNS leaks blocked | §3 |
| Kill GUI process (SIGKILL) | PASS — verified, tunnel carries traffic, leak blocked | §3 |
| Kill daemon (SIGKILL) | PASS — leak blocked immediately (kernel rules persist); systemd restart → protected; reconnect works | §3 |
| Restart daemon (`systemctl restart`) while protected | PASS | §3 |
| Change active network interface (Wi-Fi off/on) | PASS — rules intact while down, auto-reconnect, verified | §3 |
| Switch Wi-Fi ↔ Ethernet | **BLOCKED** — machine has no Ethernet port | — |
| Suspend / resume | PASS | §4 |
| Restart VPN connection / change profile while protected | PASS — profile A → profile B under 40 continuous leak probes: **0 leaked** | §3 |
| Restart the system | PASS (kill switch active before networking; autostart + auto-connect restored connectivity) | §7.4 |
| Unrelated nftables tables untouched | PASS — `ufw`/`nm-wg-wg0`/other tables identical to baseline | §3 |
| Firewall tamper (rule inserted / table deleted by another program) | PASS (real-kernel namespace suite, 55/55) | `tests/leak/run.sh` |

## 7. Reboot, desktop integration, UI against the real backend

### 7.1 Group activation after install

| Test | Result | Evidence / issue |
|---|---|---|
| Group `alizy` effective after log-out/log-in | **FAIL → documentation fixed** | After re-login the session still had groups `960 998 1000`. Cause: the account has `Linger=yes`; the systemd user manager (PID 1270, running since 18:54) survived logout and the new Hyprland session (23:17) was spawned from it with the stale group list. A **reboot** was required. Install message (`alizyd.install`), README and the GUI's permission-denied hint said "log in again"; corrected to "reboot (a re-login is not enough when the user manager lingers)". |
| Group effective after reboot | PASS | `groups=…,954(alizy),…`; `alizyctl status` reachable |

### 7.2 Desktop integration (Hyprland 0.57.2, Ryoku shell, `alizy 0.1.0-3`)

Driven through the same interfaces a user's click uses: the tray's `com.canonical.dbusmenu`
`Event(id, "clicked")`, Hyprland's own close dispatcher (`hl.dsp.window.close()`), and
D-Bus `org.freedesktop.Notifications.Notify` recorded with `dbus-monitor`. Screenshots with `grim`.

| Test | Result | Evidence |
|---|---|---|
| GUI launches as normal user | PASS | `/usr/bin/alizy` pid 9525 → window mapped, log `Connected to the Alizy service` |
| System tray icon visible (registered with the shell's StatusNotifierWatcher) | PASS | watcher items 2 → 3, new `:1.103/org/ayatana/NotificationItem/tray_icon_tray_app_alizy_tray` |
| Tray menu reflects daemon state | PASS | header `Disconnected` → `Connected · profile A` after connect |
| Tray: Connect › profile A | PASS | daemon `connected` after menu click (tests/system/40-tray-notify.sh) |
| Tray: Disconnect | PASS | daemon `disconnected` |
| Tray: Open Alizy | PASS | window mapped and visible again after being hidden |
| Tray: Quit (UI only) | PASS | GUI exited; `alizyd` still active, same PID 44542 |
| Notifications | PASS | `Notify` calls captured: "Connected to profile A", "Disconnected" |
| Internet through tunnel after tray connect | PASS (run 2) / FAIL (run 1) | run 1 failed once; separate probe showed traffic flowing 1.3 s after connect; run 2 12/12 PASS. Classified transient (not reproduced in 2 further attempts). |
| Close window → hide to tray, daemon keeps running | PASS | Hyprland close request → handler `close_to_tray=true`, window unmapped, process alive, tray registered, `alizyd` active |
| Note on an earlier false FAIL | — | the first close tests used `hyprctl dispatch closewindow`, which is a Lua syntax error on this Hyprland (`rc=7`, output was discarded) — the window never received a close request. Test bug, not product bug. The hide call was nevertheless made robust: deferred to after the close event (GTK/Wayland ignore a hide from inside the handler) and errors are now logged instead of discarded (`let _ =` removed). |
| Start minimized | NOT TESTED | setting exists; not exercised |
| Application icon + desktop entry | PASS | installed, `desktop-file-validate` clean (§2) |
| Autostart / launch after login | PASS | "Launch at startup" toggled in the GUI created `~/.config/autostart/Alizy.desktop` (`Exec=/usr/bin/alizy`); after reboot the GUI started at 00:10:25 |

### 7.3 UI against the real backend (`alizy 0.1.0-3`)

| Test | Result | Evidence / issue |
|---|---|---|
| Dashboard state matches daemon | PASS | screenshot: Disconnected / kill switch Off; matches `alizyctl status` |
| Kill-switch status reflects verified kernel state | PASS | card and sidebar use `firewall_verified` (source + live) |
| **Leak-protection card showed "Protected" while unprotected** | **FAIL → fixed** | screenshot (0.1.0-2): IPv4/IPv6/DNS "Protected" while disconnected with kill switch off — a success state derived from policy toggles. Fixed: chips derive from tunnel state + verified kill switch; screenshot (0.1.0-3): IPv4/IPv6/DNS **Exposed** (red). |
| Duplicate / rename / favourite (user, in GUI) | PASS | DB: `UI-test` favourite=1 |
| **Edit configuration of a duplicated profile** | **FAIL → fixed** | user got *"this configuration duplicates profile profile B"* when adding `MTU = 1380` to the copy. Cause: copies share the original's identity fingerprint; the edit check refused any edit. Fixed (refuse only identity changes into another profile); regression test `editing_original_or_copy_is_not_a_duplicate_but_identity_collision_is`; retried in 0.1.0-3 → DB `UI-test` MTU 1380 PASS. Private key shown only as `<redacted>` in the editor (PASS). |
| Delete profile (user, in GUI) | PASS | row gone, secret file gone, no orphans, log *Profile "UI-test" deleted (including its stored keys)* |
| Split rule added in GUI is applied by the daemon | PASS | `whatismyip.com` Direct → daemon resolved 2 A + 2 AAAA |
| Shared-CDN warnings, resolution status, TTL visibility | PASS | screenshot: 4 Cloudflare warnings, "Shared IP" badge, "resolved 11 s ago · refresh in 2 m 58 s" |
| Split rules persist across reboot | PASS | after reboot: "4 bypass ranges" in the startup firewall log |
| Invalid configuration → understandable error | PASS with improvement | `hello` → *line 1: expected `Key = Value`*, Import disabled. Message improved in source to *"this does not look like a WireGuard configuration — it must start with an [Interface] section"* (in 0.1.0-4). |
| No mock data / hardcoded success | PASS after fix | the leak card above was the one hardcoded-looking success state found; none other in source audit |
| UX observations | fixed in 0.1.0-5 | paste dialog placeholder confusion; split page "Applied" ambiguity — see §7.7 |

### 7.4 Reboot with kill switch on, auto-connect and launch-at-startup

Setup by the user in the GUI: Launch at startup on, auto-connect profile A, `wg0` down, connect
profile A, kill switch on (confirm dialog). Then reboot.

| Time (journal) | Event |
|---|---|
| 00:10:20.761 | systemd: started alizyd |
| 00:10:21.697 | systemd: starting NetworkManager |
| 00:10:21.725 | alizyd: *Firewall policy applied and verified (kill switch on, …, 4 bypass ranges)* · *Kill switch restored at startup* |
| 00:10:25.99 – 26.18 | wlan0 associated, DHCP, activated |
| 00:10:25 | GUI autostarted |
| 00:10:26 | auto-connect: **connected profile A** (hostname endpoint resolved from the daemon's endpoint cache while DNS was blocked) |

| Test | Result | Notes |
|---|---|---|
| Protection before any interface can carry traffic | PASS | rules in place 4.3 s before wlan0 associated |
| Autostart + auto-connect restore connectivity after login | PASS | state connected, kill switch verified, default route via `alizy0`, `wg0` down |
| **Boot ordering guarantee** | **weakness found → fixed** | unit was `Type=simple`: systemd treated alizyd as started (releasing `network-pre.target`) ~1 s before the rules existed; NetworkManager began starting before the kill switch. Part of the delay was the daemon running its system probe before recovery. Fixed: protection is applied first; `Type=notify` — the daemon sends `READY=1` only after the firewall is applied and verified, so `network-pre.target` waits. Verified under real systemd (transient `Type=notify` unit reported *Started* only after *signalled readiness (protection in place)*). Re-verified by a real reboot in §7.6: PASS. |
| **Tunnel lost on service restart/upgrade** | **found → fixed** | a daemon restart (package upgrade, crash) leaves the user protected but offline, since the daemon never stores keys and auto-connect only ran at GUI start. Fixed: daemon reports `daemon_started`; the GUI reconnects the previous profile after a service restart when auto-reconnect is on. |


### 7.5 Upgrade while connected, and automatic reconnect after a service restart (`0.1.0-3 → 0.1.0-4`)

`tests/system/50-upgrade-restart.sh` (connected to profile A, kill switch on):

| Test | Result | Evidence |
|---|---|---|
| daemon restarted by the upgrade | PASS | PID 1060 → 42420 |
| unit is `Type=notify` and active | PASS | `Type=notify`, `ActiveState=active` |
| readiness signalled only after protection | PASS | journal: *Kill switch restored at startup* precedes *signalled readiness to systemd (protection in place)* |
| after upgrade: protected (no tunnel survives a restart, by design) | PASS | state `protected` |
| reconnect after upgrade (old GUI → via CLI) | PASS | connected, internet reachable |
| new GUI reconnects the previous profile after `systemctl restart alizyd` | PASS | connected again **1 s** after the restart, no manual action |
| internet after automatic reconnect | PASS | |
| GUI log records it | PASS | *The Alizy service restarted.* / *Reconnecting the previous profile after the service restart.* |

### 7.6 Final reboot with `0.1.0-5` (`Type=notify`), kill switch on, auto-connect

Before the reboot the user received the exact steps and three recovery paths (GUI connect; GUI
kill switch off + `nmcli con up wg0`; `systemctl stop alizyd && alizyd --remove-firewall`).
None was needed.

| Time (journal, this boot) | Event |
|---|---|
| 00:54:45.418 | systemd: *Starting* alizyd |
| 00:54:46.392 | alizyd: firewall applied and verified (kill switch on, IPv6 off, 3 bypass ranges); *Kill switch restored at startup* |
| 00:54:46.392 | alizyd: *signalled readiness to systemd (protection in place)* |
| 00:54:46.405 | systemd: *Started* alizyd (only after READY) |
| 00:54:46.424 | systemd: *Starting* NetworkManager |
| 00:54:50.380 → 50.797 | wlan0 prepare → activated |
| 00:54:50 | GUI autostarted |
| 00:54:51.594 | auto-connect: connected profile A |

| Test | Result | Evidence |
|---|---|---|
| Kill switch active before any interface can carry traffic | PASS | monotonic timestamps: `alizyd.service` active 14.7196 s → `network-pre.target` 14.7372 s → `NetworkManager.service` 15.1883 s; wlan0 activated ~4 s later |
| Unit is `Type=notify` and readiness follows protection | PASS | `Type=notify`; journal order above |
| Profile A auto-connects after login | PASS | state `connected`, since 00:54:51, kill switch verified |
| Traffic through `alizy0`, not `wg0` | PASS | `ip route get 1.1.1.1` → `dev alizy0 table 19034`; no `wg0` interface |
| Split-tunnel rules survive the reboot | PASS | 2 rules present; routing test: all 3 IPv4 bypass addresses `in_kernel_direct_set: true`, routed via wlan0 |
| Package upgrade 0.1.0-4 → 0.1.0-5 while connected | PASS | GUI (0.1.0-4) logged *Reconnecting the previous profile after the service restart* within 1 s |

### 7.7 UI fixes verified on screen (`0.1.0-5`)

| Test | Result | Evidence |
|---|---|---|
| Paste dialog: example cannot be mistaken for input | PASS | screenshot: Configuration field first with a one-line italic instruction (no config-like placeholder); example in a separate collapsed, dashed, read-only panel labelled **EXAMPLE ONLY** |
| Paste dialog: config typed into Name is caught | PASS | typing `[Interface]` in *Name (optional)* shows *"This looks like configuration text. Paste the configuration into the Configuration box above; this field is only a name."* |
| Split badge distinguishes firewall vs traffic (connected) | PASS | screenshot: **Installed in firewall** + **Active · bypassing the VPN**, note *"3 address ranges currently bypass the VPN"*; matches kernel via routing test (IPv4 in set, IPv6 not installed because IPv6 is disabled) |
| Split badge, disconnected states ("Not installed", "Inactive · VPN disconnected", "Active · allowed through kill switch") | NOT TESTED on screen | logic shared with the Active Rules tab (`src/screens/split/splitState.ts`); reviewed, type-checked |

## 8. Security review

An independent adversarial review of the daemon/IPC/parsers was performed (read-only, by a
separate reviewer). **No path to command execution or injection** (nft script, `ip`/`wg`/
`resolvectl`/`resolvconf` argv, `wg setconf` stdin, `/etc/resolv.conf`) was found: every
value reaching those sinks is a typed `IpAddr`/`SocketAddr`/validated hostname or a fixed
string, and nothing runs through a shell. 15 weaknesses were confirmed and **all fixed**
before the real-system runs:

| # | Severity | Finding | Fix | Verified by |
|---|---|---|---|---|
| F1 | high | Hostile DNS reply could cost ~150 MB in the root daemon (no name-length cap) | 255-octet name cap, ≤64 answers parsed, ≤32 addresses kept | unit test `hostile_answers_are_bounded` |
| F2 | medium | Hostile DNS could accumulate unlimited bypass addresses (unclamped TTL) | TTL ≤ 1 day; special ranges dropped; per-name 64 and global 8192 caps | unit tests |
| F3 | medium | Slow/hostile DNS could stall firewall re-verification (refresh ran inside the supervisor tick) | split DNS on its own loop with deadlines; tick never waits on DNS | namespace suite |
| F4 | medium | "firewall verified" was a substring check; an inserted `accept` kept it true | verification = exact normalised kernel table vs snapshot taken right after Alizy's own atomic apply | new real-kernel test: inserted accept detected & reverted |
| F5 | medium | Unbounded IPC connections / no read timeout / lock starvation | 64 global / 16 per-uid clients, 60 s read timeout, verify rate-limited, probe cached, `LimitNOFILE=4096` | build + suites |
| F6 | low-med | `TestRoute` needed no polkit; amplification | requires polkit; ≤16 addresses; ≤2 concurrent | §2 "test_route also requires authorization" |
| F7 | medium | pid-reuse race in polkit subject; authorisation cached per connection | start time captured at accept and re-checked; polkit asked on every privileged request | §2 polkit checks |
| F8 | low-med | Endpoint resolution serial under the engine lock | concurrent with deadlines (+ later endpoint cache, §3) | §3 |
| F9 | low | `ip route replace` could clobber foreign main-table routes | `ip route add`; an existing route is left in place with a warning | code + suites |
| F10 | low | `ip rule del priority N` could delete foreign rules | full-selector deletion | unit test |
| F11 | low | DHCP exception allowed any destination | broadcast/LAN destinations only | unit test + nft accepted by kernel |
| F12 | low | `.conf` `ListenPort` could bind privileged ports as root | ports < 1024 ignored with a warning | unit tests |
| F13 | low | split input stored un-normalised; app rules unvalidated | normalised; app rules rejected (not implemented); ids/notes validated | code |
| F14 | low | key export temp file could be pre-planted | random name, `O_EXCL` + `O_NOFOLLOW` | store tests |
| F15 | info | core dumps / extra capabilities | `PR_SET_DUMPABLE=0`, `LimitCORE=0`, bounding set reduced to `CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN` | §2 unit check |

Also found during this validation and fixed: **private keys silently fell back to 0600
files** on this machine (see §9), and a key-loss risk if the keyring became available
later (no migration). Fixed: keyring-first with automatic migration from the file store,
and the reason is written to the Logs screen.

Remaining (accepted) risks: `src_valid_mark` sysctl is set and not reverted (same as
wg-quick); non-polkit group members over SSH can *read* status, profile names, split rules
and events; Direct-domain answers are trusted (inherent to domain-based split tunnelling;
IP rules always outrank them); firewalld's IPv6 rpfilter may drop replies for IPv6 Direct
rules (documented in ROUTING_SECURITY.md).

## 9. Private-key storage on this machine

| Test | Result | Evidence |
|---|---|---|
| Keys stored in the real system keyring | **BLOCKED (environment)** | gnome-keyring owns `org.freedesktop.secrets`, but the Secret Service has **no `default` collection alias** (`ReadAlias default → /`) and both persistent keyrings are locked; `keyring` returns `NoStorageAccess`. Alizy therefore used its 0600-file fallback (`~/.local/share/io.alizy.app/secrets/`, dir 0700). |
| Fallback is restrictive and reported | PASS | files 0600 in 0700 dir; reason logged to the Logs screen (after fix) |
| Keys never in SQLite (DB + WAL) | PASS | store integration test + `secret-check` |
| Migration to keyring when it becomes available | NOT TESTED on this machine | requires the user to set a default keyring (Seahorse) and unlock it |

## 10. DEB / RPM packaging (inspection only)

| Package | Result | Notes |
|---|---|---|
| `packaging/deb/build-alizyd-deb.sh` | NOT TESTED (no Debian system) | Depends `wireguard-tools, nftables, iproute2, polkitd \| policykit-1, systemd`; installs unit to `/lib/systemd/system`, sysusers + polkit; `postinst` creates the group, `prerm` disables the service and runs `alizyd --remove-firewall`. Gap: no `postrm` purge of `/var/lib/alizy`; upgrade restarts are not wired (`deb-systemd-invoke` not used). |
| `packaging/rpm/alizyd.spec` | NOT TESTED (no Fedora/openSUSE system) | Uses `%systemd_post/preun/postun_with_restart` (upgrade restart OK), `%sysusers_create_compat`; conditional `iproute` vs `iproute2`. Bug found in review and fixed: `%sysusers_create_compat` referenced the source tree; now uses `Source1: alizy.sysusers`. Still unbuilt. |
| Tauri GUI `.deb` / `.rpm` / AppImage | NOT TESTED | config present (`tauri.conf.json`), depends on `alizyd`; not built here. |

No DEB or RPM package is claimed to work until installed and exercised on its distribution.

## 11. Not supported / not claimed

Windows and macOS: **not implemented**, not validated, no support claimed. Application-based
split tunnelling: not implemented on any platform.

## 12. Final repository audit

| Check | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | clean |
| `cargo check --workspace --all-targets` | PASS | 0 warnings |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | exit 0 |
| `cargo test --workspace` | PASS | 77 tests (core 64, store 6, daemon 7) |
| `tsc --noEmit`, `vite build` | PASS | clean build |
| Real-kernel suites (`tests/leak/run.sh`, `dns_backends.sh file`) | PASS | 55/55, 21/21 |
| Git state | — | no commits, nothing staged; all files untracked (nothing was committed) |
| `.gitignore` covers build output | **FAIL → fixed** | makepkg `src/`, `pkg/` and `*.pkg.tar.zst` (~7 000 files) were not ignored; added. Local validation results (`target/system-validation/`) are ignored too, as they can hold host network details. 174 files remain as commit candidates (source, docs, tests, packaging, icons, lockfiles). |
| No keys / credentials in commit candidates | PASS | no 32-byte base64 key strings except the public RFC 7748 / unit-test vectors; no passwords, tokens or API keys |
| No sensitive network information | PASS after fixes | removed from this report: the user's tunnel address and username; the user's profile names replaced by "profile A/B"; test scripts no longer hard-code profile or NetworkManager connection names (environment variables, see `tests/system/README.md`). The only public IPs in source are the published CDN ranges used for shared-address warnings. |
| No platform/package over-claims | PASS after fix | README and milestone log now state that only the Arch package was installed and validated; DEB/RPM/AppImage untested; Windows/macOS not implemented (README, docs/PLATFORMS.md) |

## 13. AUR package (`packaging/aur`), 2026-11-26

**Build.** `packaging/aur-release.sh 0.1.0 11 --build` on a throwaway git repository holding a
snapshot of the working tree (tracked + untracked, minus `opencode/`), tagged `v0.1.0`. This is
the real AUR code path (`git+…#tag=` source, sha256 of `git archive <tag>` validated by
makepkg, `prepare`/`build`/`check`/`package`), only fetched from `file://` instead of GitHub.
Result: built; `check()` 217 tests passed, 0 failed (2 ignored). `namcap PKGBUILD`: clean.
`namcap` on the packages: only expected warnings (runtime-executed tools reported as "may not
be needed"; the deliberate `systemd-sysusers` call in `post_upgrade`). Every dependency
resolves from `core`/`extra` (`pacman -Sp`); `badvpn` is in `extra` (1.999.130-11).
The test packages were built before `gcc-libs` was replaced by `libgcc` in `depends`
(metadata only; both installed here).

**Upgrade `0.1.0-10` (local build) → `0.1.0-11` (AUR build), connected, kill switch on**
(`tests/system/60-aur-package.sh upgrade`): 28 PASS, 1 FAIL (test-script bug: systemctl prints
properties in another order; the values were `active`/`enabled`/`Type=notify`; check fixed).
Kill-switch table present in all 52 samples (every 0.1 s) during the upgrade; daemon restarted
onto the new binary with readiness after protection; no "unit changed on disk" warning; policy,
profiles, settings, key files, key backends, service state unchanged (digests); history kept;
GUI reconnected the previous profile by itself; installed files, `pacman -Qkk`, permissions
(`alizyd` 0755 root, socket 0660 root:alizy, `/var/lib/alizy` 0700), socket access for the
group and refusal for `nobody`; new GUI launched and logged its connection to the service.

**Removal and reinstall** (`… remove`): 39 PASS, 2 FAIL. Removing `alizy` left the service
running (same PID, still connected, kill switch in the kernel). Removing `alizyd` stopped and
removed the unit, the `inet alizy` table, `alizy0` and the routing rules; `/etc/resolv.conf`
unchanged; network worked without Alizy; `/var/lib/alizy`, the group, the user and all user
data were kept; the post-remove message was shown. Reinstall printed the post-install message
and started nothing (service disabled, no firewall table, network unchanged). Enabling the
service restored the saved policy (protected, verified). The 2 FAILs were the harness: the
previous profile was an SSH profile, which `alizyctl connect` cannot connect (it needs a typed
password), so "reconnect" and the following internet check failed; the GUI's auto-connect then
connected a WireGuard profile with the kill switch verified (observed in the daemon's events).
The script now starts the GUI and checks its auto-connect instead.

**Not tested:** `yay`/`paru` (the package is not on the AUR yet; their behaviour for split
packages is standard makepkg), a clean-chroot build (`devtools` not installed), the real
GitHub tag (does not exist yet), aarch64, re-login group activation (this account has
`Linger=yes`, so only the reboot path applies here), the `pre_remove` resolv.conf restore
(this machine uses systemd-resolved), bit-for-bit reproducibility.
