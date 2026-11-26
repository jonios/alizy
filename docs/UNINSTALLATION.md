# Uninstalling Alizy

There are two separate things to remove, and you can remove either one alone:

| | Removes | Keeps | Needs root |
|---|---|---|---|
| **The system service** (`uninstall`) | `alizyd`, its unit, the polkit rule; Alizy's firewall table, routing rules and network interface; restores DNS | your profiles, keys, settings; `/var/lib/alizy` unless `--purge` | yes |
| **The app** (`remove-app`) | `~/Applications/Alizy.AppImage`, its menu entry and icons, and the app's "launch at startup" entry | everything else, including the service | no |

**Your VPN profiles, private keys, settings and history are never deleted** by either
command. They're listed at the end if you want to delete them yourself.

## Remove the system service

```bash
sudo /usr/local/lib/alizy/alizy-installer uninstall
```

(or `./alizy-installer-x86_64 uninstall` with the installer you downloaded.)

Before it changes anything, it shows the current state (service running? kill switch
active? tunnel up?) and explains the consequence, then asks you to type `remove`:

> The VPN disconnects and the kill switch is turned off: from that moment your traffic
> uses your normal internet connection, unprotected.

Then it:

1. stops and disables the service. A clean stop takes the tunnel down and restores DNS;
2. removes **only Alizy's own** nftables table (`inet alizy`), routing rules and the
   `alizy0` interface. ufw, firewalld and other rules are not touched;
3. restores `/etc/resolv.conf` if Alizy had replaced it and the service could not
   restore it itself (for example after a crash);
4. **checks** that no Alizy firewall table, interface or routing rule is left. If one
   is, it stops with an error and removes nothing else, so you can run it again;
5. removes the files it installed (listed in `/usr/local/lib/alizy/manifest`).

It works when the service has crashed or isn't running: the firewall table and routes
are removed either way.

### `--purge`

```bash
sudo /usr/local/lib/alizy/alizy-installer uninstall --purge
```

Also deletes `/var/lib/alizy` (the saved kill-switch setting, split-tunnel rules, LAN
proxy setting, DNS cache) and the `alizy` group and `alizy-ssh` user. Still doesn't touch
your profiles.

Without `--purge`, reinstalling later brings back your saved kill-switch setting and
split-tunnel rules. If the kill switch was on, the reinstall warns you that traffic is
blocked until you connect.

## Remove the app

As your normal user (no sudo):

```bash
/usr/local/lib/alizy/alizy-installer remove-app
```

or delete `~/Applications/Alizy.AppImage` and
`~/.local/share/applications/io.alizy.app.desktop` by hand.

Removing only the app leaves the service running: an active VPN connection and the kill
switch stay in effect. Use the service uninstall above to stop protection.

## Delete your data too (complete removal)

After removing the service and the app:

```bash
rm -rf ~/.local/share/io.alizy.app
```

Private keys stored in a desktop keyring are under the name `io.alizy.app`. Delete them
with Seahorse (GNOME), KWalletManager or KeePassXC. Deleting a profile inside Alizy
before uninstalling removes its key too.

## Package installs

If the service came from a pacman package ([ARCH_LINUX.md](ARCH_LINUX.md)), remove it
with `sudo pacman -R alizy alizyd`; the package's own scripts do the same network
cleanup. The installer refuses to remove files it did not install.
