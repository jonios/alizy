#!/usr/bin/env bash
# Builds the Linux release assets. Runs on Ubuntu 22.04 (the release baseline):
# inside the container from build-in-container.sh, or directly on a GitHub
# Actions ubuntu-22.04 runner (.github/workflows/release.yml).
#
#   OUT=dist-release scripts/release/build.sh
#
# Produces in $OUT:
#   Alizy-x86_64.AppImage      the desktop app (portable, unprivileged)
#   alizy-installer-x86_64     installs/upgrades/removes the system service
#   SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
OUT=$(realpath -m "${OUT:-$ROOT/dist-release}")
GLIBC_MAX=2.35
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
export APPIMAGE_EXTRACT_AND_RUN=1   # linuxdeploy runs without FUSE (containers, CI)

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\nrelease build failed: %s\n' "$*" >&2; exit 1; }

[[ $(uname -m) == x86_64 ]] || fail "x86_64 only (aarch64: see docs/RELEASING.md)"
glibc=$(ldd --version 2>&1 | sed -n '1s/.* //p')
[[ $glibc == "$GLIBC_MAX" ]] || echo "warning: building on glibc $glibc, the release baseline is $GLIBC_MAX" >&2

step "versions"
VER=$(grep -m1 -E '^version = "' Cargo.toml | cut -d'"' -f2)
for f in package.json src-tauri/tauri.conf.json; do
  v=$(grep -m1 -oE '"version": "[^"]+"' "$f" | cut -d'"' -f4)
  [[ $v == "$VER" ]] || fail "$f has version $v, Cargo.toml has $VER"
done
echo "Alizy $VER"

step "dependencies (locked)"
npm ci --no-audit --no-fund
cargo fetch --locked

step "tests"
cargo test --locked --workspace
npm run build   # type-check + UI bundle (tauri build runs it again for the app)

step "daemon"
cargo build --locked --release -p alizyd
ALIZYD="$CARGO_TARGET_DIR/release/alizyd"

step "AppImage"
./node_modules/.bin/tauri build --bundles appimage -- --locked
APPIMAGE=$(ls -1t "$CARGO_TARGET_DIR"/release/bundle/appimage/*.AppImage | sed -n 1p)
[[ -f $APPIMAGE ]] || fail "no AppImage produced"

step "installer"
rm -rf "$OUT"; mkdir -p "$OUT"
P=$(mktemp -d)
trap 'rm -rf "$P"' EXIT
install -Dm755 "$ALIZYD" "$P/bin/alizyd"
mkdir -p "$P/systemd" "$P/sysusers" "$P/polkit" "$P/share"
sed 's#^ExecStart=/usr/bin/alizyd$#ExecStart=/usr/local/bin/alizyd#' packaging/linux/alizyd.service > "$P/systemd/alizyd.service"
grep -qx 'ExecStart=/usr/local/bin/alizyd' "$P/systemd/alizyd.service" || fail "unit ExecStart was not rewritten"
install -m644 packaging/linux/alizy.sysusers "$P/sysusers/alizy.conf"
install -m644 packaging/linux/io.alizy.policy "$P/polkit/io.alizy.policy"
install -m644 src-tauri/icons/128x128@2x.png "$P/share/io.alizy.app.png"
install -m644 src-tauri/icons/alizy.svg "$P/share/io.alizy.app.svg"
install -m644 LICENSE "$P/LICENSE"
echo "$VER" > "$P/VERSION"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$P" -cf - . | gzip -n -9 > "$P.payload"
PSUM=$(sha256sum "$P.payload" | cut -d' ' -f1)
INST="$OUT/alizy-installer-x86_64"
sed -e "s/@VERSION@/$VER/g" -e "s/@PAYLOAD_SHA256@/$PSUM/" packaging/installer/alizy-installer.sh > "$INST"
printf '%s\n' "__ALIZY_PAYLOAD_""BELOW__" >> "$INST"
cat "$P.payload" >> "$INST"
rm -f "$P.payload"
chmod 0755 "$INST"
install -m0755 "$APPIMAGE" "$OUT/Alizy-x86_64.AppImage"

step "verify"
max_glibc() { objdump -T "$1" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1; }
check_glibc() { # file label
  local m; m=$(max_glibc "$1")
  [[ -n $m ]] || fail "$2: no glibc symbols found"
  [[ $(printf '%s\n%s\n' "$m" "$GLIBC_MAX" | sort -V | tail -1) == "$GLIBC_MAX" ]] || fail "$2 needs glibc $m (> $GLIBC_MAX)"
  echo "$2: needs glibc <= $m"
}
check_glibc "$ALIZYD" alizyd
X=$(mktemp -d)
(cd "$X" && "$OUT/Alizy-x86_64.AppImage" --appimage-extract >/dev/null)
check_glibc "$X/squashfs-root/usr/bin/alizy" "AppImage alizy"
[[ -f $X/squashfs-root/AppRun && -f $X/squashfs-root/alizy.desktop || -n $(ls "$X"/squashfs-root/*.desktop 2>/dev/null) ]] || fail "AppImage has no AppRun/desktop file"
rm -rf "$X"
awk '$0 == "__ALIZY_PAYLOAD_BELOW__" { exit } { print }' "$INST" > "$P.header"
bash -n "$P.header" || fail "installer header has a syntax error"
rm -f "$P.header"
help_out=$("$INST" --help)
grep -q "Alizy system installer $VER" <<< "$help_out" || fail "installer --help does not report $VER"
grep -q '^__ALIZY_PAYLOAD_BELOW__$' "$INST" || fail "installer payload marker missing"
[[ $("$ALIZYD" --version) == "alizyd $VER" ]] || fail "alizyd reports another version"

(cd "$OUT" && sha256sum Alizy-x86_64.AppImage alizy-installer-x86_64 > SHA256SUMS && sha256sum -c SHA256SUMS)
step "done"
ls -la "$OUT"
