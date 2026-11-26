# Installing Alizy

Alizy has two parts, and you need both:

| Part | File | What it is | Runs as |
|---|---|---|---|
| **The app** | `Alizy-x86_64.AppImage` | The window you click on: profiles, connect button, settings. Portable; nothing to install. | you |
| **The system service** (`alizyd`) | installed by `alizy-installer-x86_64` | Does the privileged work: WireGuard and SSH tunnels, the nftables kill switch, DNS, routing, split tunnelling, LAN proxy. Starts at boot, before the network. | root, under systemd |

An AppImage can't install a system service, and a kill switch can't live in a user
app: it has to keep working when the app is closed, crashed or not yet started. So the
service comes from a small installer that you run once (and again for each update).

## Requirements

- **x86_64** Linux with **systemd** and **glibc 2.35 or newer**: Ubuntu 22.04+,
  Debian 12+, Fedora 36+, Linux Mint 21+, Pop!_OS 22.04+, Arch, Omarchy, Manjaro,
  EndeavourOS, openSUSE Tumbleweed. See [the support table](#supported-distributions).
- A kernel with WireGuard (Linux 5.6 or newer; every current distribution has it).
- These packages. **The installer checks for them and offers to install missing ones**
  with your distribution's package manager:

| Needed for | Arch / Omarchy | Ubuntu / Debian | Fedora | openSUSE |
|---|---|---|---|---|
| WireGuard (`wg`) | `wireguard-tools` | `wireguard-tools` | `wireguard-tools` | `wireguard-tools` |
| Kill switch (`nft`) | `nftables` | `nftables` | `nftables` | `nftables` |
| Routing (`ip`) | `iproute2` | `iproute2` | `iproute` | `iproute2` |
| Authorisation (`pkcheck`) | `polkit` | `polkitd` | `polkit` | `polkit` |

Optional, for extra features (the installer lists them too):

| Feature | Arch / Omarchy | Ubuntu / Debian | Fedora | openSUSE |
|---|---|---|---|---|
| SSH tunnel profiles | `openssh` `badvpn` | `openssh-client` `badvpn` ¹ | `openssh-clients` `badvpn` ¹ | `openssh-clients` `badvpn` ¹ |
| DNS without systemd-resolved, if you use `resolvconf` | `openresolv` | `resolvconf` | `openresolv` | `openresolv` |
| Tray icon | `libayatana-appindicator` | `libayatana-appindicator3-1` | `libayatana-appindicator-gtk3` | `libayatana-appindicator3-1` |
| Keys in the desktop keyring | `gnome-keyring` or KWallet or KeePassXC | same | same | same |

¹ `badvpn` is in Arch's official `extra` repository. On other distributions it may not
be packaged; SSH profiles need it, WireGuard profiles do not.

The app itself (WebKitGTK, GTK and their libraries) is bundled inside the AppImage. It
takes only the graphics-related libraries every desktop already has from your system
(Mesa EGL/GBM, Wayland client, HarfBuzz, FriBidi; see [APPIMAGE.md](APPIMAGE.md#compatibility)).

## Install

1. Download these three files from the
   [latest release](https://github.com/jonios/alizy/releases/latest) into one folder
   (e.g. `~/Downloads`):
   - `Alizy-x86_64.AppImage`
   - `alizy-installer-x86_64`
   - `SHA256SUMS`

2. Open a terminal in that folder and check the downloads:

   ```bash
   sha256sum -c SHA256SUMS
   ```

   Both lines must say `OK`.

3. Run the installer:

   ```bash
   chmod +x alizy-installer-x86_64 Alizy-x86_64.AppImage
   ```

   ```bash
   ./alizy-installer-x86_64
   ```

   It asks for your password (through `sudo`, or `pkexec` if `sudo` isn't set up),
   checks the system, shows what it will do and waits for your OK. Then it:
   - installs `alizyd`, its systemd unit, the `alizy` group and the `alizy-ssh` user,
     and the polkit rule, under `/usr/local` (`/usr/share/polkit-1` for the rule);
   - enables and starts the service. **The kill switch stays off** until you turn it on;
   - adds your account to the `alizy` group (only members may control the VPN);
   - copies the AppImage to `~/Applications/Alizy.AppImage` and adds **Alizy** to your
     application menu.

4. **Log out completely and log back in**, so your session joins the `alizy` group.
   Check in a terminal:

   ```bash
   id -nG | grep -w alizy
   ```

   No output? Your user session outlived the logout (lingering is enabled, you use
   uwsm, or another session is still open): reboot once.

5. Start **Alizy** from your application menu, import a WireGuard configuration and
   connect. See the [README](../README.md#first-steps).

You can read the installer before running it: everything up to the line
`__ALIZY_PAYLOAD_BELOW__` is a plain bash script (`less alizy-installer-x86_64`), and
the archive after it is checked against a SHA-256 stored in the script before anything
is used.

### Distribution notes

**Arch Linux / Omarchy / Manjaro / EndeavourOS**: the steps above work as-is. If you
installed Alizy earlier from a PKGBUILD (the `alizy`/`alizyd` pacman packages), remove
those first; your profiles and settings are kept:

```bash
sudo pacman -R alizy alizyd
```

Building a pacman package yourself is still possible, see [ARCH_LINUX.md](ARCH_LINUX.md).

**Ubuntu / Debian / Linux Mint / Pop!_OS**: when the installer offers to install the
missing packages it runs `apt-get update` and `apt-get install` for you. GNOME's top bar
shows no tray icons without the *AppIndicator and KStatusNotifierItem Support* extension
(Ubuntu ships it enabled).

**Fedora**: packages come from `dnf`. firewalld can stay enabled: Alizy uses its own
nftables table next to it. For the LAN proxy you have to open its ports in firewalld
yourself (see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#lan-proxy)).

**openSUSE**: packages come from `zypper`. Not tested.

### Without the installer's AppImage step

Run the AppImage from anywhere: double-click it in your file manager, or
`./Alizy-x86_64.AppImage`. To skip the menu entry, pass `--no-appimage` to the
installer. Details: [APPIMAGE.md](APPIMAGE.md).

### Non-interactive install

```bash
sudo ./alizy-installer-x86_64 --yes --install-deps
```

`--yes` accepts every question, `--install-deps` allows installing missing packages.
Without `--install-deps`, missing packages stop the installation instead.

## Supported distributions

Tested means the full installer lifecycle ran in that distribution (fresh install with
dependency installation, a real WireGuard tunnel, kill switch, upgrade while connected,
failed-upgrade rollback, uninstall with DNS restore, reinstall, purge): see
[TESTING.md](TESTING.md).

| Distribution | Installer | App (AppImage) |
|---|---|---|
| Arch Linux / Omarchy | tested (container + real machine) | tested (container + real machine) |
| Ubuntu 22.04 / 24.04 | tested (containers) | tested (containers, virtual display) |
| Debian 12 | tested (container) | tested (container, virtual display) |
| Fedora 45 | tested (container) | tested (container, virtual display) |
| openSUSE, Linux Mint, Pop!_OS, Manjaro, EndeavourOS | expected to work, not tested | expected to work, not tested |

**Not supported:**
- distributions without systemd (Alpine, Void, Devuan, Gentoo with OpenRC): the kill
  switch's boot-time protection depends on systemd;
- glibc older than 2.35 (Ubuntu 20.04, Debian 11, RHEL/Alma/Rocky 8 and 9);
- aarch64/ARM (not built yet, see [RELEASING.md](RELEASING.md#aarch64));
- Windows and macOS.

## Next steps

- Updating: [UPDATING.md](UPDATING.md)
- Removing: [UNINSTALLATION.md](UNINSTALLATION.md)
- Problems: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
