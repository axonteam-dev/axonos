#!/usr/bin/env bash
# Repack iso/boot/initfs.sfs after tools/populate-apt-rootfs.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SFS="${1:-$ROOT/iso/boot/initfs.sfs}"
if [[ ! -f "$SFS" ]]; then
    echo "inject-apt-rootfs: missing $SFS" >&2
    exit 1
fi
WORKDIR="$ROOT/build/initfs-apt-root.$$"
mkdir -p "$ROOT/build"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
echo "inject-apt-rootfs: unsquashing $SFS"
unsquashfs -d "$WORKDIR/root" "$SFS" >/dev/null
"$ROOT/tools/populate-apt-rootfs.sh" "$WORKDIR/root"
echo "inject-apt-rootfs: packing squashfs"
rm -f "$SFS"
mksquashfs "$WORKDIR/root" "$SFS" -comp gzip -b 131072 -noappend -processors "$(nproc 2>/dev/null || echo 2)" >/dev/null
echo "inject-apt-rootfs: wrote $SFS ($(du -h "$SFS" | awk '{print $1}'))"
