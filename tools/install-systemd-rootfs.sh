#!/usr/bin/env bash
# Stage Debian's systemd PID 1 and its ELF dependencies into an AxonOS rootfs.
# This does not replace /sbin/init: select the systemd boot entry for testing.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rootfs="${1:?usage: install-systemd-rootfs.sh ROOTFS SYSTEMD_DEB SHARED_DEB}"
systemd_deb="${2:?missing systemd .deb}"
shared_deb="${3:?missing libsystemd-shared .deb}"
if [[ ! -d "$rootfs/etc" || ! -d "$rootfs/usr" ]]; then
    echo "install-systemd-rootfs: invalid rootfs: $rootfs" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dpkg-deb -x "$systemd_deb" "$tmp/systemd"
dpkg-deb -x "$shared_deb" "$tmp/shared"
for pkg in systemd shared; do
    for dir in etc usr var; do
        if [[ -d "$tmp/$pkg/$dir" ]]; then
            mkdir -p "$rootfs/$dir"
            cp -a -n "$tmp/$pkg/$dir/." "$rootfs/$dir/"
        fi
    done
done

# The Debian package depends on these runtime libraries. Existing rootfs
# libraries take precedence; copy each missing SONAME and its real target.
mkdir -p "$rootfs/lib/x86_64-linux-gnu"
for soname in libapparmor.so.1 libblkid.so.1 libmount.so.1 libpam.so.0; do
    from="/lib/x86_64-linux-gnu/$soname"
    real="$(realpath "$from")"
    if [[ ! -e "$rootfs/lib/x86_64-linux-gnu/$soname" ]]; then
        cp -a -n "$real" "$rootfs/lib/x86_64-linux-gnu/"
        cp -a -n "$from" "$rootfs/lib/x86_64-linux-gnu/"
    fi
done

mkdir -p "$rootfs/etc/systemd/system" "$rootfs/run/systemd"
cp "$repo/tools/axon-systemd.target" "$rootfs/etc/systemd/system/axon-systemd.target"
cp "$repo/tools/axon-getty.service" "$rootfs/etc/systemd/system/axon-getty.service"
ln -sfn axon-systemd.target "$rootfs/etc/systemd/system/default.target"
# The shared image also contains OpenRC's SysV scripts. They remain available
# to OpenRC, but must not be turned into dozens of generated systemd units.
mkdir -p "$rootfs/etc/systemd/system-generators"
ln -sfn /dev/null "$rootfs/etc/systemd/system-generators/systemd-sysv-generator"
echo "install-systemd-rootfs: staged systemd in $rootfs"
