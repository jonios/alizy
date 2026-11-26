# Releasing Alizy (GitHub tag + AUR)

The AUR package builds from a **git tag** of the GitHub repository:

```
source=("alizy::git+https://github.com/jonios/alizy.git#tag=v$pkgver")
sha256sums=('<sha256 of the tagged tree>')
```

makepkg verifies a git tag source by computing
`git -c core.abbrev=no archive --format tar <tag> | sha256sum` over the cloned
repository (pacman ≥ 6.1). The checksum therefore depends only on the tagged
commit's content, never on GitHub's tarball compression, and you can compute it
locally **before** pushing. Moving a tag after release changes the checksum, so
users' builds fail loudly instead of silently building different code.

`packaging/aur-release.sh` does all the PKGBUILD edits for you.

## Files

| Path | Purpose |
|---|---|
| `packaging/aur/PKGBUILD` | AUR package (split: `alizyd` + `alizy`) |
| `packaging/aur/.SRCINFO` | Generated; must always match the PKGBUILD |
| `packaging/aur/alizyd.install` | pacman scriptlets (install/upgrade/remove) |
| `packaging/aur-release.sh` | Sets version + checksum, regenerates `.SRCINFO`, optional test build |
| `packaging/arch/PKGBUILD` | Development only: packages the local working tree (`makepkg -si`). Keep its dependencies and `package_*()` steps in sync with the AUR one. |

## Release checklist

1. **Bump the version** in all three places (they must agree; the script checks):
   `Cargo.toml` (`[workspace.package] version`), `package.json`,
   `src-tauri/tauri.conf.json`. Then run `cargo update -w` so `Cargo.lock` follows,
   and `npm install --package-lock-only` so `package-lock.json` follows.

2. **Verify** on the release commit:

   ```bash
   cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
   ```

   ```bash
   cargo test --workspace && npm run build
   ```

3. **Commit and tag** (annotated tag, `v` prefix):

   ```bash
   git tag -a v0.2.0 -m "Alizy 0.2.0"
   ```

4. **Prepare the PKGBUILD and test-build the tag locally**, before pushing:

   ```bash
   packaging/aur-release.sh 0.2.0 --build
   ```

   This writes `pkgver`, `pkgrel=1` and the checksum into `packaging/aur/PKGBUILD`,
   regenerates `.SRCINFO`, then builds the tag from this local clone in a temporary
   directory (with `check()`) and copies the packages to `target/aur-test/`. Install
   them (`sudo pacman -U target/aur-test/*.pkg.tar.zst`) to try the release on your
   machine.

5. **Commit the packaging change** (`packaging/aur/PKGBUILD`, `.SRCINFO`) and push
   the branch **and the tag**:

   ```bash
   git push origin main v0.2.0
   ```

6. **Optional: create a GitHub release** from the tag (release notes). The AUR package
   doesn't need release assets.

7. **Publish to the AUR** (next section).

### Packaging-only fix (same version)

When only the PKGBUILD or `alizyd.install` changes, keep `pkgver` and bump `pkgrel`:

```bash
packaging/aur-release.sh 0.2.0 2
```

### Install-script changes need a GitHub release too?

No. `alizyd.install` lives in the AUR repository next to the PKGBUILD, not in the
tag. The files under `packaging/linux/` (unit, sysusers, polkit policy, desktop file)
**are** taken from the tag, so changing those needs a new tag.

## Publishing to the AUR

One-time setup:

1. Create an account at <https://aur.archlinux.org/register>.
2. Add your SSH **public** key under *My Account → SSH Public Key*.
3. Add this to `~/.ssh/config`:

   ```
   Host aur.archlinux.org
     IdentityFile ~/.ssh/aur
     User aur
   ```

4. Fill in the `# Maintainer:` line of `packaging/aur/PKGBUILD` with your name and
   an email address (an obfuscated form like `name at example dot com` is common).

First publication (the AUR creates the package when you push to a new name):

```bash
git clone ssh://aur@aur.archlinux.org/alizy.git ~/aur/alizy
```

```bash
cp packaging/aur/{PKGBUILD,.SRCINFO,alizyd.install} ~/aur/alizy/
```

```bash
cd ~/aur/alizy && git add PKGBUILD .SRCINFO alizyd.install && git commit -m "Initial import: alizy 0.1.0-1" && git push
```

Every later release: same `cp`, then `git commit -m "Update to 0.2.0-1"` and
`git push`.

The AUR repository must contain only `PKGBUILD`, `.SRCINFO` and `alizyd.install`, on
branch `master`. It must not contain built packages or the `src/`/`pkg/` folders.
The pkgbase `alizy` publishes both package names, `alizy` and `alizyd`, from one
repository.

### Pre-push checks

Run these in `packaging/aur/`:

```bash
makepkg --printsrcinfo | diff - .SRCINFO && echo ".SRCINFO matches"
```

```bash
namcap PKGBUILD
```

Optional, the strongest check, which catches undeclared build dependencies: build in
a clean chroot (`sudo pacman -S devtools`, then `pkgctl build` or
`extra-x86_64-build` inside `packaging/aur/`).
