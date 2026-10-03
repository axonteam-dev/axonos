#!/usr/bin/env bash
# Copy the OpenRC runtime from a working AxonOS initfs tree into a rootfs,
# then configure BusyBox PID 1 to start OpenRC before the login consoles.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${1:?usage: install-openrc-rootfs.sh <extracted-initfs> <rootfs>}"
rootfs="${2:?usage: install-openrc-rootfs.sh <extracted-initfs> <rootfs>}"

if [[ ! -f "$source_root/lib/librc.so.1" || ! -x "$source_root/usr/sbin/openrc" ||
      ! -x "$source_root/usr/bin/busybox" || ! -e "$source_root/etc/init.d/local" ]]; then
    echo "install-openrc-rootfs: source is not a working AxonOS initfs" >&2
    exit 1
fi
if [[ ! -d "$rootfs/etc" || ! -d "$rootfs/usr" ]]; then
    echo "install-openrc-rootfs: destination rootfs does not exist" >&2
    exit 1
fi

if [[ "$(realpath "$source_root")" != "$(realpath "$rootfs")" ]]; then
    mkdir -p "$rootfs/usr/bin" "$rootfs/usr/sbin" "$rootfs/lib"
    for name in init.d conf.d local.d runlevels; do
        mkdir -p "$rootfs/etc/$name"
        cp -a -n "$source_root/etc/$name/." "$rootfs/etc/$name/"
    done
    for name in rc.conf hostname passwd group shadow; do
        if [[ -e "$source_root/etc/$name" && ! -e "$rootfs/etc/$name" ]]; then
            cp -a "$source_root/etc/$name" "$rootfs/etc/$name"
        fi
    done
    mkdir -p "$rootfs/lib/rc"
    cp -a -n "$source_root/lib/rc/." "$rootfs/lib/rc/"
    cp -a -n "$source_root/lib/librc.so.1" "$source_root/lib/libeinfo.so.1" "$rootfs/lib/"
    for name in mkmntdirs openrc openrc-run rc-service rc-sstat rc-update service start-stop-daemon supervise-daemon; do
        cp -a -n "$source_root/usr/sbin/$name" "$rootfs/usr/sbin/$name"
    done
    cp -a -n "$source_root/usr/bin/rc-status" "$rootfs/usr/bin/rc-status"
    cp -a -n "$source_root/usr/bin/busybox" "$rootfs/usr/bin/busybox"
    if [[ ! -e "$rootfs/usr/bin/sh" && ! -L "$rootfs/usr/bin/sh" ]]; then
        ln -s busybox "$rootfs/usr/bin/sh"
    fi
    if [[ ! -e "$rootfs/usr/sbin/init" && ! -L "$rootfs/usr/sbin/init" ]]; then
        ln -s ../bin/busybox "$rootfs/usr/sbin/init"
    fi
fi

mkdir -p "$rootfs/run" "$rootfs/etc/runlevels/sysinit" \
         "$rootfs/etc/runlevels/boot" "$rootfs/etc/runlevels/default"
for entry in sysinit:dmesg boot:hostname default:local; do
    level="${entry%%:*}"
    service="${entry#*:}"
    if [[ ! -e "$rootfs/etc/init.d/$service" ]]; then
        echo "install-openrc-rootfs: missing service $service" >&2
        exit 1
    fi
    link="$rootfs/etc/runlevels/$level/$service"
    if [[ ! -e "$link" && ! -L "$link" ]]; then
        ln -s "/etc/init.d/$service" "$link"
    fi
done
cp "$repo/tools/openrc-inittab" "$rootfs/etc/inittab"
echo "install-openrc-rootfs: configured $rootfs"
