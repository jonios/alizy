# Alizy on Arch Linux

Alizy is in the AUR as one source package that builds two installable packages:

| Package | What it is | Runs as |
|---|---|---|
| `alizyd` | The system service: WireGuard tunnels, the kill switch (nftables), DNS, split tunnelling, LAN proxy | root, under systemd |
| `alizy` | The desktop app you click on | your normal user |

Installing `alizy` always installs `alizyd` too. You can install `alizyd` alone on a
machine without a desktop.

Every dependency comes from the official Arch repositories (`core` and `extra`).
Nothing comes from other AUR packages.

## 1. Install

### With yay

```bash
yay -S alizy
```

### With paru

```bash
paru -S alizy
```

### Without an AUR helper (makepkg)

```bash
sudo pacman -S --needed base-devel git
```

```bash
git clone https://aur.archlinux.org/alizy.git
cd alizy
makepkg -si
```

`makepkg -si` installs the build tools it needs (Rust, Node.js, WebKitGTK), builds both
packages and asks pacman to install them. The first build takes several minutes:
Alizy is compiled from source (Rust + a web UI).

> `makepkg` builds two packages from this one directory. If you only want the
> service (headless machine), install just that file afterwards:
> `sudo pacman -U alizyd-*.pkg.tar.zst`.

## 2. First-time setup (once)

Installing the package does **not** start anything, turn on the kill switch or touch
your network. Three steps finish the setup:

**Start the service** (now, and automatically at every boot):

```bash
sudo systemctl enable --now alizyd
```

**Allow your account to use it.** Only members of the `alizy` group can talk to the
service:

```bash
sudo usermod -aG alizy "$USER"
```

**Log out completely and log back in.** Then open a terminal and check:

```bash
id -nG | grep -w alizy
```

If it prints a line containing `alizy`, you are done. If it prints nothing, reboot once
instead. That happens when your systemd user manager outlived the logout and kept the
old group list: lingering is enabled (`loginctl show-user "$USER" -p Linger` says
`yes`), another session was still open (a TTY or SSH login), or your desktop is started
through uwsm.

Now start **Alizy** from your application menu, or run `alizy`. It refuses to run as
root; start it as yourself.

### What the package sets up for you

You don't have to create or edit any of these by hand:

| Item | How |
|---|---|
| Group `alizy` (may control the service) | `/usr/lib/sysusers.d/alizy.conf`, applied by pacman's sysusers hook |
| System user `alizy-ssh` (runs `ssh` for SSH profiles, never root) | same sysusers file |
| `alizyd.service` | `/usr/lib/systemd/system/alizyd.service` (not enabled automatically) |
| Socket `/run/alizy/alizyd.sock`, mode `0660 root:alizy` | created by the service when it starts |
| State directory `/var/lib/alizy`, mode `0700 root` | created by systemd (`StateDirectory=`) |
| Authorization (polkit action `io.alizy.daemon.control`) | `/usr/share/polkit-1/actions/io.alizy.policy`: group members in an active local session are allowed without a password prompt; anyone else is refused |
| Menu entry and icons | `/usr/share/applications/io.alizy.app.desktop`, `/usr/share/icons/hicolor/*/apps/io.alizy.app.*` |

## 3. Using it

1. **Import a profile:** Configurations → Import (a `.conf` file, several files, a
   folder, drag-and-drop, or paste the text). `PostUp`/`PreDown` scripts in imported
   files are removed, never run.
2. **Connect:** pick the profile, press Connect.
3. **Optional, recommended: turn on the kill switch** in Network Settings. With it on,
   nothing leaves your computer outside the VPN, not even when the VPN drops, the app
   crashes or the computer reboots.

Closing the window hides Alizy to the tray; **Quit** closes the app only. Neither
disconnects the VPN or turns off the kill switch: those belong to the service.

## 4. Optional dependencies

pacman lists these after installing. Add the ones you want:

| Package | Repo | What it adds |
|---|---|---|
| `libayatana-appindicator` | extra | The tray icon. Without it, closing the window quits the app (the VPN keeps running). |
| A Secret Service keyring: `gnome-keyring`, `kwallet` or `keepassxc` | extra | Keeps private keys in your desktop keyring. Without one, keys are stored in files only you can read (`0600`), and the Logs screen says so. |
| `openssh` | core | SSH tunnel profiles (VPN over an SSH server) |
| `badvpn` | extra | SSH tunnel profiles (`badvpn-tun2socks`) |
| `openresolv` | extra | Only if your system already manages DNS through `resolvconf`. Not needed with systemd-resolved, and not needed when `/etc/resolv.conf` is a plain file (Alizy then manages it directly and restores it on disconnect). |

```bash
sudo pacman -S --needed libayatana-appindicator openssh badvpn
```

## 5. Desktop environments

| Desktop | Status | Notes |
|---|---|---|
| Hyprland | **Tested** (Omarchy/Ryoku, Hyprland 0.57) | Tray needs a StatusNotifier host in your bar (e.g. Waybar's `tray` module). |
| KDE Plasma | Expected to work, not tested | Tray works out of the box; KWallet provides the keyring. |
| GNOME | Expected to work, not tested | The tray needs the *AppIndicator and KStatusNotifierItem Support* extension. |
| Sway, Xfce, Cinnamon, MATE, others | Expected to work, not tested | Tray needs a StatusNotifier host. |

The app needs a running desktop session (Wayland or X11). The service needs neither:
it runs at boot, before anyone logs in.

## 6. Updating

Updates arrive like any other AUR package:

```bash
yay -Syu
```

```bash
paru -Syu
```

Without a helper: `cd` into your clone, `git pull`, then `makepkg -si`.

What happens during an update:

- Profiles, settings, history, private keys and split-tunnel rules are **kept**. They
  live outside the package (`~/.local/share/io.alizy.app`, your keyring,
  `/var/lib/alizy`) and pacman never touches them.
- The service restarts onto the new version. A running VPN connection is interrupted
  for about a second. With the kill switch on, nothing leaks during that second (the
  firewall rules stay in the kernel); the app then reconnects your previous profile
  by itself.
- With the kill switch **off**, traffic flows over your normal connection for that
  second, exactly as when the VPN drops.
- If the service fails to come back after an update, the update removes Alizy's
  firewall rules so you are not left offline, and prints how to start it again.
- Restart the app (Quit from the tray, then open it again) to run the new GUI.

## 7. Uninstalling

**Remove only the app, keep the service running** (e.g. it now runs headless):

```bash
sudo pacman -R alizy
```

**Remove everything** (app and service):

```bash
sudo pacman -Rs alizy
```

(or `sudo pacman -R alizy alizyd`). Removing the service stops it, takes the VPN down,
deletes Alizy's firewall table, routing rules and network interface, and restores DNS.
Your normal network works immediately, even if the kill switch was on.

Your data is **kept**, so a reinstall picks up where you left off. For a complete
removal, delete it yourself:

```bash
sudo rm -rf /var/lib/alizy
```

```bash
sudo userdel alizy-ssh
```

```bash
sudo groupdel alizy
```

```bash
rm -rf ~/.local/share/io.alizy.app ~/.config/autostart/Alizy.desktop
```

Private keys stored in a desktop keyring are under the name `io.alizy.app`. Delete them
with Seahorse (GNOME), KWalletManager or KeePassXC. Deleting a profile inside Alizy
before uninstalling removes its keys too.

## 8. Troubleshooting

**"Permission denied on /run/alizy/alizyd.sock"**: your session is not in the `alizy`
group yet. Run `id -nG`. If `alizy` is missing, do the group step above and log out
fully (or reboot).

**"The Alizy service (alizyd) is not running"**:

```bash
sudo systemctl enable --now alizyd
```

```bash
systemctl status alizyd
```

```bash
journalctl -u alizyd -b
```

**No internet and the kill switch is on.** This is the kill switch doing its job while
no VPN is connected. Connect a profile, or turn the kill switch off in Network
Settings. If the app isn't available:

```bash
sudo alizyd --remove-firewall
```

(Stopping the service alone keeps the rules in place on purpose, so a crash can never
open a leak.)

**Check what's missing on this machine.** It prints each problem with the exact
`pacman` command to fix it, and installs nothing:

```bash
alizyd --probe
```

It is also in the app under Settings → System Check.

**No tray icon**: install `libayatana-appindicator` and make sure your desktop has a
StatusNotifier host (see the desktop table above).

**Keys stored in files instead of the keyring**: the Logs screen shows why. Usually
there is no keyring daemon, or no default keyring exists or it is locked. Create or
unlock one (e.g. in Seahorse); Alizy moves the keys into it automatically next time.

**Building fails in `npm ci` or `cargo fetch`**: both download dependencies, so the
build needs internet access. With the kill switch on and no VPN connected, the build
can't download anything. Connect first, or build before turning the kill switch on.

**"Installed but nothing happens in yay"**: if you previously built Alizy yourself from
a checkout with a higher `pkgrel`, the AUR version looks older to pacman. Reinstall from
the AUR once: `yay -S alizy`.

Something else? Collect `journalctl -u alizyd -b` and `alizyd --probe`, check them for
anything private, and open an issue.
