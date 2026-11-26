# Releasing Alizy

GitHub Releases is the release channel. Each release has exactly these assets:

| Asset | Built by | Contents |
|---|---|---|
| `Alizy-x86_64.AppImage` | `tauri build --bundles appimage` | the desktop app with its GUI libraries |
| `alizy-installer-x86_64` | `scripts/release/build.sh` | bash installer + tar payload: `alizyd`, systemd unit, sysusers file, polkit action, icons, LICENSE |
| `SHA256SUMS` | `scripts/release/build.sh` | SHA-256 of both files |

The asset names carry no version, so `https://github.com/jonios/alizy/releases/latest/download/<asset>`
always points at the newest release. The version is inside: `alizyd --version`, the
installer's `--help`, the app's About card, and the release tag.

**Versions must match** across `Cargo.toml` (`[workspace.package] version`),
`package.json` and `src-tauri/tauri.conf.json`. The build and the release workflow
refuse to run otherwise, and the workflow also refuses a tag that isn't `v<version>`.

## Build baseline

Everything is built on **Ubuntu 22.04** (glibc 2.35, WebKitGTK 4.1), so the binaries
run on that and every newer distribution. `scripts/release/build.sh` fails if any
binary needs a newer glibc. The toolchain is pinned in two places, which must agree:
`scripts/release/Containerfile` (local builds) and `.github/workflows/release.yml` (CI):
Rust 1.100.0, Node.js 24.22.3.

## Build locally

```bash
scripts/release/build-in-container.sh
```

Builds the **current working tree** in the Ubuntu 22.04 container (podman or docker)
and writes `dist-release/`. It runs the whole test suite first, then builds the daemon
and the AppImage, assembles the installer, verifies the glibc floor, the AppImage
contents and the installer's self-check, and writes and verifies `SHA256SUMS`.

Then test the result:

```bash
tests/installer/run.sh ubuntu22
```

```bash
tests/installer/run.sh fedora
```

(and `ubuntu24`, `debian12`). Each run boots that distribution with systemd in a
container, without Alizy's dependencies, and goes through install, a real WireGuard
tunnel, kill switch, upgrade while connected, failed-upgrade rollback, uninstall with
DNS restore, reinstall and purge. Build the images once with:

```bash
for d in "ubuntu22 ubuntu:22.04" "ubuntu24 ubuntu:24.04" "debian12 debian:12" "fedora fedora:latest"; do set -- $d; podman build --build-arg BASE=docker.io/library/$2 -t localhost/alizy-itest:$1 tests/installer; done
```

## Release checklist

1. **Bump the version** in `Cargo.toml`, `package.json`, `src-tauri/tauri.conf.json`,
   then `cargo update -w` and `npm install --package-lock-only`.
2. **Checks** pass: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`,
   `npm run build` (the `ci` workflow runs the same on every push).
3. **Local release build and installer tests** (above), at least one distribution.
4. **Commit, then tag** (annotated, `v` prefix) and push the tag:

   ```bash
   git tag -a v0.2.0 -m "Alizy 0.2.0"
   ```

   ```bash
   git push origin main v0.2.0
   ```

5. The **release workflow** (`.github/workflows/release.yml`) runs on the tag: same
   build script on an `ubuntu-22.04` runner, then it creates a **draft** release with
   the three assets and install notes containing the checksums.
6. **Review the draft** on GitHub: download the assets, `sha256sum -c SHA256SUMS`, try
   the installer. Write the release notes (what changed, anything users must know).
7. **Publish** the draft. Only now is the release public.

A tag can also be (re)built by hand: *Actions → release → Run workflow* with the tag
name; it uploads to the existing draft.

### Never move a published tag

Users and the optional AUR package verify what they download. If a release is broken,
publish a new patch version.

## Signing

Releases are currently protected by HTTPS from GitHub and `SHA256SUMS`. There is no
cryptographic signature yet. Adding one (e.g. minisign or GPG over `SHA256SUMS`) needs
a long-lived key held by the maintainer; when added, document the public key in the
README and verify it in the install instructions.

## aarch64

Not built yet. Tauri and every dependency support aarch64 Linux, and GitHub offers
`ubuntu-22.04-arm` runners, so a second job in `release.yml` with `runs-on:
ubuntu-22.04-arm` (and `uname -m` checks in `build.sh` and the installer relaxed to
`aarch64`) should work. It has not been built or tested; don't ship it untested.

## Optional: the AUR package

`packaging/aur/` holds a ready AUR package (split `alizyd` + `alizy`, built from the git
tag). It is optional and not required for releases. AUR account registration was closed
when it was prepared. To publish a release there:

```bash
packaging/aur-release.sh 0.2.0 --build
```

This writes `pkgver`, `pkgrel=1` and the tag's checksum
(`git archive --format tar <tag> | sha256sum`, the same thing makepkg verifies) into
`packaging/aur/PKGBUILD`, regenerates `.SRCINFO` and test-builds the tag locally. Commit
that, then push `PKGBUILD`, `.SRCINFO` and `alizyd.install` to
`ssh://aur@aur.archlinux.org/alizy.git`. Packaging-only fixes keep `pkgver` and bump
`pkgrel`: `packaging/aur-release.sh 0.2.0 2`.

`packaging/arch/PKGBUILD` packages your local working tree (`makepkg -si`) for
development; keep its dependency lists in sync with the AUR one.
