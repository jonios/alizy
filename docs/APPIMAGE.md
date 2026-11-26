# The Alizy AppImage

`Alizy-x86_64.AppImage` is the desktop app as one portable file. It contains the app
binary and the libraries it needs (WebKitGTK, GTK, GLib and friends), so it does not
depend on your distribution's versions of them.

## What it is, and what it is not

- It **is** the user interface: profiles, connect/disconnect, kill-switch and split
  tunnelling settings, logs. It runs as your user and never as root (it refuses to
  start as root).
- It is **not** the VPN service. Connections, the kill switch, DNS and routing are done
  by `alizyd`, a system service installed by `alizy-installer-x86_64`
  ([INSTALLATION.md](INSTALLATION.md)). The app talks to it through
  `/run/alizy/alizyd.sock`.
- Without the service the app still opens and manages your profiles, but shows
  **"The Alizy background service isn't reachable"** with what to do: *not installed*
  (run the installer), *not running* (`sudo systemctl enable --now alizyd`), or
  *permission denied* (your session is not in the `alizy` group yet).

## Running it

The installer copies it to `~/Applications/Alizy.AppImage` and creates the menu entry
**Alizy**. You can also run it from anywhere:

```bash
chmod +x Alizy-x86_64.AppImage
```

```bash
./Alizy-x86_64.AppImage
```

or double-click it in your file manager (some file managers ask whether to run or
display executable files; choose *Run*).

To add a copy you placed yourself to the menu, run the installer with
`--appimage /path/to/Alizy-x86_64.AppImage`.

**Launch at startup** (Settings → General) writes `~/.config/autostart/Alizy.desktop`
pointing at the AppImage file itself, so it keeps working across updates as long as
the file stays at the same path.

## FUSE

AppImages mount themselves with FUSE 2 (`libfuse.so.2`). Most desktops have it.
If the AppImage fails with *"AppImages require FUSE to run"*:

| Distribution | Package |
|---|---|
| Ubuntu 24.04+ | `libfuse2t64` |
| Ubuntu 22.04, Debian | `libfuse2` |
| Fedora | `fuse-libs` |
| Arch / Omarchy | `fuse2` |

Or run it without FUSE (it unpacks to a temporary folder each time):

```bash
./Alizy-x86_64.AppImage --appimage-extract-and-run
```

## Compatibility

- **glibc 2.35 or newer.** The release is built on Ubuntu 22.04, so it runs on that and
  anything newer: Debian 12+, Fedora 36+, current Arch, Mint 21+, Pop!_OS 22.04+.
- **x86_64 only** for now.
- **A normal graphical desktop.** Like all AppImages, it uses a few libraries from your
  system because they must match your graphics stack: Mesa's EGL and GBM, the Wayland
  client library, HarfBuzz and FriBidi (`libEGL.so.1`, `libgbm.so.1`,
  `libwayland-client.so.0`, `libharfbuzz.so.0`, `libfribidi.so.0`). Every desktop
  installation of the supported distributions has them; minimal server or container
  images may not.
- Wayland and X11 both work.
- Tray icon: needs a StatusNotifier host (Waybar's `tray`, KDE, the GNOME AppIndicator
  extension, most others). Without one, closing the window quits the app; the service
  and the VPN keep running.
- Private keys: kept in your desktop keyring (Secret Service: GNOME Keyring, KWallet,
  KeePassXC) when one is running and unlocked; otherwise in files only your user can
  read (`0600`), and the app's Logs screen says so.

Which distributions were actually tested: [TESTING.md](TESTING.md).

## Updating

Download the new AppImage *and* run the installer from the same release; see
[UPDATING.md](UPDATING.md). The app does not update itself and never downloads
anything; **Check for updates** in Settings only tells you whether a newer release
exists.

## Verifying a download

Each release has a `SHA256SUMS` file:

```bash
sha256sum -c SHA256SUMS
```

## Extracting

```bash
./Alizy-x86_64.AppImage --appimage-extract
```

creates `squashfs-root/` with the app (`usr/bin/alizy`), its libraries and the desktop
file, if you want to inspect it.
