#!/usr/bin/env bash
# Builds the release assets locally in the Ubuntu 22.04 release container
# (podman, or docker). Uses the current working tree, including uncommitted
# changes; official releases are built by .github/workflows/release.yml from a tag.
#
#   scripts/release/build-in-container.sh            -> dist-release/
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
OUT=$ROOT/dist-release
IMAGE=localhost/alizy-build:ubuntu22.04
ENGINE=$(command -v podman || command -v docker || true)
[[ -n $ENGINE ]] || { echo "podman or docker is required"; exit 1; }

"$ENGINE" build -t "$IMAGE" -f scripts/release/Containerfile scripts/release
mkdir -p "$OUT"
# Source snapshot: tracked + untracked-but-not-ignored files (no target/, node_modules/).
SNAP=$(mktemp "${TMPDIR:-/tmp}/alizy-src.XXXXXX.tar")
git ls-files -co --exclude-standard -z | tar --null -T - -cf "$SNAP"
chmod 0644 "$SNAP"
# Runs as an unprivileged user inside the container (the test suite needs a
# non-root uid and unprivileged ICMP sockets); outputs are copied out afterwards.
NAME=alizy-release-build-$$
trap 'rm -f "$SNAP"; "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
"$ENGINE" run --name "$NAME" --user 1000:1000 --sysctl net.ipv4.ping_group_range="0 65534" \
  -e HOME=/tmp/home \
  -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -v alizy-cargo-registry:/opt/cargo/registry:U \
  -v alizy-npm-cache:/tmp/home/.npm:U \
  -v alizy-tauri-cache:/tmp/home/.cache/tauri:U \
  -v alizy-build-target:/build-target:U \
  -v "$SNAP":/src.tar:ro \
  "$IMAGE" bash -c 'mkdir -p /tmp/src && tar -xf /src.tar -C /tmp/src && cd /tmp/src && git init -q && CARGO_TARGET_DIR=/build-target OUT=/tmp/out scripts/release/build.sh'
rm -rf "$OUT" && mkdir -p "$OUT"
"$ENGINE" cp "$NAME":/tmp/out/. "$OUT/"
(cd "$OUT" && sha256sum -c SHA256SUMS)
echo "Release assets: $OUT"
