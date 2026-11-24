#!/bin/sh
# Destructive BIOS installer: wipe one whole disk and install the running
# AxonOS live image there as a persistent ext2 root.
#
#   axon-install --disk /dev/sda --yes-wipe
#
# Nothing is touched without --yes-wipe. Run it from the live ISO, not from the
# system being replaced.
set -eu

DISK=
CONFIRM=0

usage() {
    echo "usage: $0 --disk /dev/sdX --yes-wipe" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --disk) [ "$#" -ge 2 ] || usage; DISK=$2; shift 2 ;;
        --yes-wipe) CONFIRM=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[ -n "$DISK" ] || usage
[ "$CONFIRM" -eq 1 ] || {
    echo "Refusing to touch $DISK without --yes-wipe" >&2
    exit 2
}
case "$DISK" in
    /dev/sd[a-z]|/dev/vd[a-z]) ;;
    *) echo "expected a whole disk such as /dev/sda, got: $DISK" >&2; exit 2 ;;
esac
[ -e "$DISK" ] || { echo "no such disk: $DISK" >&2; exit 1; }
[ ! -e "${DISK}1" ] || {
    echo "refusing to reuse an already partitioned disk ($DISK has a first partition)" >&2
    exit 1
}

# This implementation has not yet passed an end-to-end installation and
# reboot test. In particular, a successful mount does not prove durability.
echo "Installer disabled: persistent disk installation is not yet verified." >&2
exit 1

for tool in sfdisk mkfs.ext2 mount umount cp mkdir chmod grub-install blockdev mountpoint; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

PART=${DISK}1
MNT=/mnt/axon-target
MEDIA=/mnt/axon-install-media
[ ! -L "$MNT" ] || { echo "refusing symlink target: $MNT" >&2; exit 1; }
[ ! -L "$MEDIA" ] || { echo "refusing symlink media path: $MEDIA" >&2; exit 1; }
mkdir -p "$MNT" "$MEDIA"
if mountpoint -q "$MNT"; then
    echo "refusing mounted target: $MNT" >&2
    exit 1
fi
if mountpoint -q "$MEDIA"; then
    echo "refusing mounted media path: $MEDIA" >&2
    exit 1
fi

# Verify the boot medium before partitioning. Only unmount a mount made here.
MEDIA_MOUNTED=0
cleanup_media() {
    if [ "$MEDIA_MOUNTED" -eq 1 ]; then
        umount "$MEDIA" || echo "warning: could not unmount $MEDIA" >&2
    fi
}
trap cleanup_media EXIT
mount -t iso9660 /dev/sr0 "$MEDIA" || mount -t iso9660 /dev/sr1 "$MEDIA" || {
    echo "cannot mount AxonOS boot media" >&2
    exit 1
}
MEDIA_MOUNTED=1
[ -f "$MEDIA/boot/axonos.elf" ] || {
    echo "boot media does not contain /boot/axonos.elf" >&2
    exit 1
}

echo "Wiping partition table on $DISK and creating one ext2 root partition"
sfdisk --wipe always "$DISK" <<EOF
label: dos
unit: sectors

start=2048, type=83, bootable
EOF
blockdev --rereadpt "$DISK" || {
    echo "partition table reread failed; installation stopped" >&2
    exit 1
}
[ -e "$PART" ] || { echo "kernel did not publish $PART; reboot and retry" >&2; exit 1; }

mkfs.ext2 -F -b 4096 -L AXONROOT "$PART"
mount -t ext2 "$PART" "$MNT"

echo "Copying running root filesystem (pseudo filesystems excluded)"
for dir in dev proc run sys tmp mnt media cdrom; do
    mkdir -p "$MNT/$dir"
    chmod 0755 "$MNT/$dir"
done
chmod 1777 "$MNT/tmp"
for dir in bin boot etc home lib lib64 opt root sbin srv usr var; do
    [ -e "/$dir" ] || continue
    cp -a "/$dir" "$MNT"/
done

echo "Installing kernel from the boot media"
mkdir -p "$MNT/boot"
cp "$MEDIA/boot/axonos.elf" "$MNT/boot/axonos.elf"

cat > "$MNT/etc/fstab" <<EOF
# <file system>	<mount point>	<type>	<options>	<dump>	<pass>
$PART	/	ext2	defaults	0	1
proc	/proc	proc	defaults	0	0
sysfs	/sys	sysfs	defaults	0	0
tmpfs	/run	tmpfs	mode=0755,nosuid,nodev	0	0
tmpfs	/tmp	tmpfs	mode=1777,nosuid,nodev	0	0
EOF

mkdir -p "$MNT/boot/grub"
cat > "$MNT/boot/grub/grub.cfg" <<EOF
set default=0
set timeout=5
insmod ext2
insmod multiboot2
menuentry "AxonOS (persistent root)" {
    multiboot2 /boot/axonos.elf root=$PART axon.init=systemd systemd.log_target=null systemd.log_level=emerg systemd.log_color=true systemd.show_status=true
    echo "Booting AxonOS from $PART..."
    boot
}
EOF

echo "Installing GRUB for BIOS on $DISK"
grub-install --target=i386-pc --boot-directory="$MNT/boot" "$DISK"

sync
umount "$MNT"
rmdir "$MNT" 2>/dev/null || true
echo "Done. Remove the ISO and boot from $DISK."
