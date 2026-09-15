#!/usr/bin/env bash
# Extract a Debian UTF-8 console font (psf.gz) as console.psf, place it in
# ~/rootfs/usr/share/fonts/ and inject it into iso/boot/initfs.sfs so the boot
# console fonts render UTF-8 (tmux panes, cyrillic) with a real glyph map.
# Default source: Uni2-Terminus16.psf.gz (8x16, box drawing + full Latin-1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SFS="${1:-$ROOT/iso/boot/initfs.sfs}"
SRC_ROOTFS="${2:-${HOME}/rootfs}"
SRC_GZ="${3:-/usr/share/consolefonts/Uni2-Terminus16.psf.gz}"

if [[ ! -f "$SRC_GZ" ]]; then
    echo "inject-console-font: missing $SRC_GZ" >&2
    exit 1
fi
if [[ ! -f "$SFS" ]]; then
    echo "inject-console-font: missing $SFS" >&2
    exit 1
fi

# --- decompressed console.psf lives in the shared rootfs tree ---
DST_FR="$SRC_ROOTFS/usr/share/fonts/console.psf"
mkdir -p "$SRC_ROOTFS/usr/share/fonts"
gzip -dc "$SRC_GZ" > "$DST_FR"
cp "$DST_FR" "$SRC_ROOTFS/usr/share/fonts/console.psf" 2>/dev/null || true
sz=$(stat -c %s "$DST_FR")
echo "inject-console-font: wrote $DST_FR ($sz bytes)"

# --- inject into the live ISO squashfs ---
WORKDIR="$ROOT/build/initfs-font.$$"
mkdir -p "$ROOT/build"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
echo "inject-console-font: unsquashing $SFS"
unsquashfs -d "$WORKDIR/root" "$SFS" >/dev/null
mkdir -p "$WORKDIR/root/usr/share/fonts"
cp "$DST_FR" "$WORKDIR/root/usr/share/fonts/console.psf"
NEW="$SFS.new.$$"
rm -f "$NEW"
echo "inject-console-font: packing squashfs"
mksquashfs "$WORKDIR/root" "$NEW" -comp gzip -b 131072 -noappend -processors "$(nproc 2>/dev/null || echo 2)" >/dev/null
mv -f "$NEW" "$SFS"
echo "inject-console-font: wrote $SFS"