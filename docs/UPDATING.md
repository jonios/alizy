# Updating Alizy

The app and the system service are released together and must stay on the same
version. One step updates both: download the new release and run its installer.

## How to find out about updates

- **In the app:** Settings → General → About → **Check for updates**. It asks GitHub
  for the newest release when you press the button and shows the version and a link
  to the release page. It never downloads or runs anything, and it sends no request on
  its own.
- Watch the repository's releases on GitHub (*Watch → Custom → Releases*).

## Update

1. Download the new `Alizy-x86_64.AppImage`, `alizy-installer-x86_64` and `SHA256SUMS`
   from the [latest release](https://github.com/jonios/alizy/releases/latest) into one
   folder.
2. Verify and run:

   ```bash
   sha256sum -c SHA256SUMS
   ```

   ```bash
   chmod +x alizy-installer-x86_64 Alizy-x86_64.AppImage && ./alizy-installer-x86_64
   ```

3. Quit Alizy (tray → **Quit**) and start it again from the menu, so the new app runs.

### What happens during the update

- **Your data is kept.** Profiles, private keys, settings and history live in your home
  folder and keyring; service settings (kill switch on/off, split-tunnel rules, LAN
  proxy) in `/var/lib/alizy`. The installer never touches them.
- **The service restarts** onto the new version. A connected VPN drops for about a
  second:
  - with the **kill switch on**, its nftables rules stay in the kernel during the
    restart, so nothing leaks; the service comes back in protected mode and the app
    reconnects your previous profile by itself;
  - with the **kill switch off**, traffic uses your normal connection for that second,
    as when a VPN connection drops.
- **If the new service fails to start, the installer restores the previous version**
  and starts it again, and tells you so. Your protection settings are unchanged.
- The AppImage in `~/Applications` is replaced atomically (written next to the old
  file, then renamed), so a running Alizy keeps working until you restart it.
- Version checks: the installer refuses to install an older version over a newer one
  unless you pass `--allow-downgrade`.

## Mismatched versions

If you start a newer AppImage without running its installer (or the other way round),
the app shows **"App and service versions differ"** on the dashboard and in
Settings → About. Run the installer from the same release as your AppImage.

## Rolling back

Download the older release's files and run its installer with `--allow-downgrade`.
Service settings are kept in a format older versions read; if that ever changes, the
release notes say so.

## Packages instead of the AppImage

If you installed Alizy from a pacman package you built yourself
([ARCH_LINUX.md](ARCH_LINUX.md)), update it the same way you installed it. The
installer refuses to manage a package-installed service.
