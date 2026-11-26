# Troubleshooting

Start here, it answers most questions in one go:

```bash
/usr/local/lib/alizy/alizy-installer status
```

It shows the installed version, whether the service runs, whether your user is in the
`alizy` group and where the app is. In the app, **Settings → General → System Check**
lists anything missing on this machine with the exact command to fix it.

## The app says the service isn't reachable

The message under the red banner says which case it is:

**"The Alizy service (alizyd) is not installed"**: run the installer from the
[latest release](https://github.com/jonios/alizy/releases/latest), see
[INSTALLATION.md](INSTALLATION.md).

**"…is not running"**: start it and look at its log:

```bash
sudo systemctl enable --now alizyd
```

```bash
journalctl -u alizyd -b
```

**"Permission denied on /run/alizy/alizyd.sock"**: your session is not in the `alizy`
group yet. `id -nG` must list `alizy`. If it doesn't:

```bash
sudo usermod -aG alizy "$USER"
```

then log out completely and back in. Still missing? Reboot once: a systemd user
manager that outlives the logout (lingering, uwsm, another open session) keeps the old
group list.

## No internet, and the kill switch is on

That's the kill switch working: with it on and no VPN connected, nothing may leave the
computer outside the tunnel. Either connect a profile, or turn the kill switch off in
**Network Settings**.

If the app can't be used, remove Alizy's firewall rules from a terminal:

```bash
sudo /usr/local/bin/alizyd --remove-firewall
```

This only removes Alizy's own table, routing rules and interface. Stopping the service
(`systemctl stop alizyd`) deliberately keeps the rules: a crash or stop must never open
a leak.

## Connecting fails

- **"resolving the endpoint(s) timed out"**: the profile uses a host name and DNS is
  blocked (kill switch on, no tunnel). Alizy uses the last address it resolved for that
  name; for a profile that never connected before, turn the kill switch off once, or use
  an IP address as `Endpoint`.
- **Connected but no traffic / "No handshake for over 3 minutes"**: the server is not
  answering. Check the profile's `Endpoint`, port and keys with the server operator.
  A firewall on the way may block UDP.
- **"this does not look like a WireGuard configuration"**: the file must start with an
  `[Interface]` section. Alizy imports standard WireGuard `.conf` files; `PostUp`,
  `PreDown` and similar script lines are removed (never run).

## DNS doesn't work while connected

```bash
resolvectl status
```

The `alizy0` link should list your VPN's DNS servers and `DNS Domain: ~.`. Without
systemd-resolved, `/etc/resolv.conf` should contain the VPN's DNS servers while
connected. The service log usually says why not:

```bash
journalctl -u alizyd --since "10 min ago"
```

## Split tunnelling rule doesn't apply

Open **Split Tunneling → Routing test**, enter the address or domain and run it. It reads
the kernel's actual state and tells you whether that destination goes through the VPN
or directly, and which rule decided. Domain rules apply to the addresses the domain
resolves to; shared CDN addresses (marked "Shared IP") affect every site on them.

## LAN proxy

Other devices can't connect: your distribution's firewall probably blocks incoming
connections. Allow the proxy ports from your local network:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8080,1080 proto tcp
```

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=1080/tcp && sudo firewall-cmd --reload
```

Replace the subnet with yours (the app shows the address it listens on). The proxy has
**no password**: anyone on your network can use it while it's on.

## The AppImage doesn't start

- **"AppImages require FUSE to run"**: install FUSE 2 or run it with
  `--appimage-extract-and-run`, see [APPIMAGE.md](APPIMAGE.md#fuse).
- **"version `GLIBC_2.xx' not found"**: your distribution is older than the supported
  baseline (glibc 2.35, e.g. Ubuntu 22.04).
- **"Alizy must not run as root"**: start it as your normal user. Privileged work is
  done by the service.
- Blank or flickering window on unusual GPU setups: start it with
  `WEBKIT_DISABLE_DMABUF_RENDERER=1 ./Alizy-x86_64.AppImage`.
- Run it from a terminal to see its messages: `./Alizy-x86_64.AppImage`.

## No tray icon

Your desktop needs a StatusNotifier host: Waybar's `tray` module (Hyprland, Sway), KDE
Plasma's system tray, the *AppIndicator and KStatusNotifierItem Support* extension on
GNOME. Without a tray, closing the window quits the app; the service and VPN keep
running.

## Keys are stored in files, not the keyring

The Logs screen says why. Usually no Secret Service is running, or it has no default
keyring, or the keyring is locked. Start one (GNOME Keyring, KWallet, KeePassXC with
Secret Service enabled) and unlock it; Alizy moves the keys into it the next time it
starts.

## The installer stops

- **"already installed by package …"**: the service came from a package. Update or
  remove it with that package manager; the installer never overwrites package files.
- **"required components are missing"**: install the packages it lists (or rerun with
  `--install-deps`).
- **"systemd is not running as the init system"**: Alizy's service needs systemd.
- **"upgrade failed; version … was restored"**: the new service didn't start, so the
  previous version was put back and is running. Look at `journalctl -u alizyd -b` and
  report it.

## Reporting a bug

Include `alizy-installer status`, `journalctl -u alizyd -b` and the System Check
output. **Check them for anything private first** (server addresses, profile names).
Security problems: see [SECURITY.md](../SECURITY.md), don't open a public issue.
