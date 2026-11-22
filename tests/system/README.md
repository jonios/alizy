# Real-system validation scripts

These run against an **installed** Alizy (`alizyd` service + `alizy` GUI) on a real
machine and send real traffic. They run as the normal user and call `sudo` only for
root-only probes (`nft list`, `SO_BINDTODEVICE` leak probes, `rtcwake`, `systemctl`).
Every script restores connectivity on exit (trap): Alizy disconnected, kill switch
off, and the optional `ALIZY_KEEP_CONN` NetworkManager connection brought back up.

| Variable | Meaning |
|---|---|
| `ALIZY_TEST_PROFILE_A` | name of an imported Alizy profile (required) |
| `ALIZY_TEST_PROFILE_B` | a second profile, for switching tests (`20-network.sh`) |
| `ALIZY_KEEP_CONN` | NetworkManager connection to take down during tests and always restore (e.g. another VPN you depend on) |
| `PHYS`, `ROUTER_DNS` | physical interface (default `wlan0`) and LAN DNS server (default `192.168.0.1`) used for leak probes |

| Script | What it checks |
|---|---|
| `10-install-checks.sh` | service, socket permissions, group/polkit authorisation, GUI root refusal (non-disruptive) |
| `20-network.sh` | tunnel, kill switch, TCP/DNS leaks (with controls), split tunnelling, profile switch under leak probing, GUI kill, Wi-Fi off/on, IPv4/IPv6 off, DNS failure, daemon SIGKILL/restart, cleanup to baseline |
| `30-suspend.sh` | suspend/resume (~25 s, RTC wake) with the kill switch on |
| `40-tray-notify.sh` | tray menu actions via `com.canonical.dbusmenu`, desktop notifications (GUI must be running) |
| `50-upgrade-restart.sh` | package upgrade while connected; GUI reconnect after a service restart |

Results go to `target/system-validation/results.tsv` (git-ignored: it can contain
host network details).

Example:

```bash
ALIZY_TEST_PROFILE_A=Home ALIZY_TEST_PROFILE_B=Office sudo -E -u "$USER" -g alizy bash tests/system/20-network.sh
```
