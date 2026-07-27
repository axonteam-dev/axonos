#!/usr/bin/env bash
# Convert an initramfs cpio (newc) into a SquashFS 4.0 image (gzip), Linux-style.
set -euo pipefail

SRC="${1:-}"
DST="${2:-}"
if [[ -z "$SRC" || -z "$DST" ]]; then
  echo "usage: $0 <initfs.cpio> <initfs.squashfs>" >&2
  exit 2
fi
if [[ ! -f "$SRC" ]]; then
  echo "mkinitfs-squashfs: missing $SRC" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$ROOT/build/initfs-root.$$"
mkdir -p "$(dirname "$DST")"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

if command -v podman >/dev/null 2>&1; then
  CTR=podman
elif command -v docker >/dev/null 2>&1; then
  CTR=docker
else
  echo "mkinitfs-squashfs: need podman or docker (host mksquashfs musl binary not used)" >&2
  exit 1
fi

# Absolute paths for bind mounts
SRC_ABS="$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")"
DST_ABS="$(cd "$(dirname "$DST")" && pwd)/$(basename "$DST")"
WORKDIR_ABS="$(cd "$WORKDIR" && pwd)"

"$CTR" run --rm \
  -v "$SRC_ABS:/in.cpio:ro" \
  -v "$WORKDIR_ABS:/rootfs:z" \
  -v "$(dirname "$DST_ABS"):/out:z" \
  docker.io/library/alpine:3.20 \
  sh -c '
    set -e
    apk add --no-cache squashfs-tools cpio >/dev/null
    cd /rootfs
    cpio -idm < /in.cpio
    mksquashfs /rootfs "/out/'"$(basename "$DST_ABS")"'" \
      -comp gzip -b 131072 -noappend -processors '"$(nproc 2>/dev/null || echo 2)"'
  '

echo "mkinitfs-squashfs: wrote $DST_ABS"
