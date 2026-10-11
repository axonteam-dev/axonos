#!/usr/bin/env bash
# Copy ~/rootfs X11 tree into iso/boot/initfs.sfs so startx works on a live ISO.
#
# GNU cp follows destination symlinks. Initfs has BusyBox applet links
# (usr/bin/resize -> busybox). Debian xterm ships a real /usr/bin/resize;
# a plain `cp -a` therefore overwrites PID1 busybox with xterm resize.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SFS="${1:-$ROOT/iso/boot/initfs.sfs}"
SRC="${2:-${HOME}/rootfs}"
if [[ ! -f "$SFS" ]]; then
    echo "inject-x11-rootfs: missing $SFS" >&2
    exit 1
fi
if [[ ! -x "$SRC/usr/lib/xorg/Xorg" ]]; then
    echo "inject-x11-rootfs: run tools/install-x11-rootfs.sh $SRC first" >&2
    exit 1
fi
WORKDIR="$ROOT/build/initfs-x11.$$"
mkdir -p "$ROOT/build"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
echo "inject-x11-rootfs: unsquashing $SFS"
unsquashfs -d "$WORKDIR/root" "$SFS" >/dev/null

BB=""
for cand in "$WORKDIR/root/usr/bin/busybox" "$WORKDIR/root/bin/busybox"; do
    if [[ -f "$cand" && ! -L "$cand" ]]; then
        sz=$(stat -c %s "$cand")
        if [[ "$sz" -gt 100000 ]]; then
            BB="$WORKDIR/busybox.pid1"
            cp -a "$cand" "$BB"
            echo "inject-x11-rootfs: saved PID1 busybox (${sz} bytes)"
            break
        fi
    fi
done

echo "inject-x11-rootfs: copy $SRC -> initfs"
# Unlink dest first so applet symlinks are replaced, not followed.
cp -a --remove-destination "$SRC"/. "$WORKDIR/root/"

if [[ -n "$BB" && -f "$BB" ]]; then
    mkdir -p "$WORKDIR/root/usr/bin"
    cp -a "$BB" "$WORKDIR/root/usr/bin/busybox"
    echo "inject-x11-rootfs: restored PID1 busybox"
fi
# xserver-xorg-core ships modesetting; it claims the VGA PCI slot, then
# dies on stub /dev/dri/card0 — Xorg reports "no screens found".
rm -f "$WORKDIR/root/usr/lib/xorg/modules/drivers/modesetting_drv.so"
FBDEV_SO="$WORKDIR/root/usr/lib/xorg/modules/drivers/fbdev_drv.so"
if [[ -f "$FBDEV_SO" ]]; then
    python3 "$ROOT/tools/patch-fbdev-drv.py" "$FBDEV_SO"
fi
# Keep AxonOS PID1 as the busybox linuxrc applet, not Debian's linuxrc link
# if it somehow became a regular file (resize, etc.).
if [[ -e "$WORKDIR/root/usr/bin/busybox" ]]; then
    ln -sfn bin/busybox "$WORKDIR/root/linuxrc"
fi

rm -rf "$WORKDIR/root/var/cache/apt/archives" \
       "$WORKDIR/root/var/tmp" \
       "$WORKDIR/root/root/.cache"
mkdir -p "$WORKDIR/root/tmp/.X11-unix" "$WORKDIR/root/tmp/.ICE-unix" \
         "$WORKDIR/root/var/cache/apt/archives/partial"
chmod 1777 "$WORKDIR/root/tmp/.X11-unix" "$WORKDIR/root/tmp/.ICE-unix" || true

bbsz=$(stat -c %s "$WORKDIR/root/usr/bin/busybox" 2>/dev/null || echo 0)
if [[ "$bbsz" -lt 100000 ]]; then
    echo "inject-x11-rootfs: FATAL: busybox is ${bbsz} bytes (clobbered)" >&2
    exit 1
fi

echo "inject-x11-rootfs: packing squashfs"
NEW="$SFS.new.$$"
rm -f "$NEW"
mksquashfs "$WORKDIR/root" "$NEW" -comp gzip -b 131072 -noappend -processors "$(nproc 2>/dev/null || echo 2)" >/dev/null
mv -f "$NEW" "$SFS"
echo "inject-x11-rootfs: wrote $SFS ($(du -h "$SFS" | awk '{print $1}'))"
