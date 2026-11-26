#!/usr/bin/env bash
# Prepare packaging/aur for a release tag.
#
#   packaging/aur-release.sh VERSION [PKGREL] [--build]
#
# Requires a local git tag vVERSION. Sets pkgver/pkgrel, writes the sha256 that
# makepkg verifies for the git tag (`git archive --format tar <tag> | sha256sum`,
# the same computation makepkg uses for git sources), and regenerates .SRCINFO.
# --build also builds the tag from this local repository in a temporary
# directory (nothing is pushed or installed), so a broken tag is caught before
# it is published. Run it before `git push --tags`.
set -euo pipefail

usage() { sed -n '2,12s/^# \{0,1\}//p' "$0"; exit 2; }
[[ $# -ge 1 ]] || usage
VER=$1; shift
REL=1
BUILD=0
for a in "$@"; do
  case $a in
    --build) BUILD=1 ;;
    ''|*[!0-9]*) usage ;;
    *) REL=$a ;;
  esac
done
[[ $VER =~ ^[0-9]+\.[0-9]+\.[0-9]+([._+][0-9A-Za-z]+)*$ ]] || { echo "invalid version: $VER"; exit 2; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
AUR="$ROOT/packaging/aur"
TAG="v$VER"

git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  || { echo "tag $TAG does not exist. Commit the release, then: git tag -a $TAG -m 'Alizy $VER'"; exit 1; }

# The versions inside the tagged tree must match, or the binaries report another version.
mismatch=0
check_ver() { # file pattern
  local got
  got=$(git -C "$ROOT" show "$TAG:$1" | grep -m1 -oE "$2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^"]*' || true)
  if [[ $got != "$VER" ]]; then echo "  $1 at $TAG has version '${got:-?}', expected $VER"; mismatch=1; fi
}
check_ver Cargo.toml '^version = "[^"]+"'
check_ver package.json '"version": "[^"]+"'
check_ver src-tauri/tauri.conf.json '"version": "[^"]+"'
[[ $mismatch -eq 0 ]] || { echo "Bump the versions above, commit, and move the tag before releasing."; exit 1; }

SUM=$(git -C "$ROOT" -c core.abbrev=no archive --format tar "$TAG" | sha256sum | cut -d' ' -f1)

sed -i -E \
  -e "s/^pkgver=.*/pkgver=$VER/" \
  -e "s/^pkgrel=.*/pkgrel=$REL/" \
  -e "s/^sha256sums=.*/sha256sums=('$SUM')/" \
  "$AUR/PKGBUILD"
(cd "$AUR" && makepkg --printsrcinfo > .SRCINFO)
echo "PKGBUILD: pkgver=$VER pkgrel=$REL sha256=$SUM"
echo ".SRCINFO regenerated."

if [[ $BUILD -eq 1 ]]; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  cp "$AUR/PKGBUILD" "$AUR/alizyd.install" "$TMP/"
  # Same tag, same git objects, so the same checksum - only fetched locally.
  sed -i -E "s|^source=.*|source=(\"\$pkgbase::git+file://$ROOT#tag=v\$pkgver\")|" "$TMP/PKGBUILD"
  (cd "$TMP" && makepkg --cleanbuild --noconfirm)
  mkdir -p "$ROOT/target/aur-test"
  cp "$TMP"/*.pkg.tar.zst "$ROOT/target/aur-test/"
  echo "Test packages: $ROOT/target/aur-test/"
fi
