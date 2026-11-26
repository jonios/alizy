# Alizy on Arch Linux and Omarchy

## Recommended: AppImage + installer

Use the same release files as every other distribution. See
[INSTALLATION.md](INSTALLATION.md):

```bash
sha256sum -c SHA256SUMS
```

```bash
chmod +x alizy-installer-x86_64 Alizy-x86_64.AppImage && ./alizy-installer-x86_64
```

When required packages are missing, the installer shows and (after asking) runs:

```bash
sudo pacman -S --needed wireguard-tools nftables iproute2 polkit
```

Optional extras, all from the official repositories:

```bash
sudo pacman -S --needed openssh badvpn libayatana-appindicator
```

(`openssh` + `badvpn`: SSH tunnel profiles; `libayatana-appindicator`: tray icon;
`badvpn` is in `extra`.) For keys in a keyring, any Secret Service provider works:
`gnome-keyring`, `kwallet` or `keepassxc`.

The installer puts the service under `/usr/local` and records every file in
`/usr/local/lib/alizy/manifest`; pacman doesn't track it. Update and remove it with the
installer ([UPDATING.md](UPDATING.md), [UNINSTALLATION.md](UNINSTALLATION.md)).

### Coming from the pacman packages

If you built and installed the `alizy`/`alizyd` packages earlier, the installer refuses
to overwrite them. Remove them first; your profiles, keys and settings, including
`/var/lib/alizy`, are kept:

```bash
sudo pacman -R alizy alizyd
```

Removing the package turns the kill switch off and disconnects the VPN until the new
service runs. If your saved kill-switch setting is on, the installer tells you that
traffic is blocked as soon as the new service starts, until you connect.

### Omarchy / Hyprland notes

- Tray icon: Waybar needs its `tray` module, which Omarchy enables by default.
- On the tested Omarchy machine the user session lingers (uwsm), so after the installer
  added the user to the `alizy` group, only a reboot applied it; a logout was not
  enough. Check with `id -nG | grep -w alizy` after logging back in.
- ufw is supported: Alizy adds its own nftables table and leaves ufw's rules alone. For
  the LAN proxy, open its ports in ufw ([TROUBLESHOOTING.md](TROUBLESHOOTING.md#lan-proxy)).

## Optional: build a pacman package

For people who prefer pacman to track every file. Two PKGBUILDs ship with the source:

| PKGBUILD | Builds from | Use |
|---|---|---|
| `packaging/aur/PKGBUILD` | a release tag on GitHub (checksum-verified) | AUR-style package of an official release |
| `packaging/arch/PKGBUILD` | your local checkout, including uncommitted changes | development |

```bash
git clone https://github.com/jonios/alizy.git && cd alizy/packaging/aur && makepkg -si
```

Both produce two packages, `alizyd` (service) and `alizy` (app, as a normal binary, not
an AppImage), with all dependencies from the official repositories. After installing:

```bash
sudo systemctl enable --now alizyd
```

```bash
sudo usermod -aG alizy "$USER"
```

then log out and back in (or reboot, see above). The package scripts never start the
service or change your network by themselves. Updating rebuilds the package; upgrades
restart the service and fall back safely if it doesn't come back. `pacman -R alizy`
removes only the app, and `pacman -Rs alizy` removes both, including Alizy's
firewall/routing state. Data is kept either way.

**AUR:** `packaging/aur/` is ready to be published as the AUR package `alizy` (the name
is free), but AUR account registration was closed when it was prepared, so
`yay -S alizy` / `paru -S alizy` **do not work yet**. Use the AppImage + installer.
Publishing steps: [RELEASING.md](RELEASING.md#optional-the-aur-package).

Don't mix the two methods: use either the installer or the pacman packages.
