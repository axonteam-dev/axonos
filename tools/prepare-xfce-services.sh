#!/usr/bin/env bash
# Install missing XFCE runtime services in fresh and cached Debian roots.
set -euo pipefail
root="${1:?usage: bash tools/prepare-xfce-services.sh ROOTFS}"
[[ -f "$root/etc/debian_version" ]] || { echo "not a Debian root: $root" >&2; exit 1; }
policy="$root/usr/sbin/policy-rc.d"
created_policy=0
cleanup() { if [[ "$created_policy" == 1 ]]; then rm -f "$policy"; fi; }
trap cleanup EXIT

packages_ok() {
    local package status
    for package in pm-utils at-spi2-core; do
        status=$(unshare -Ur chroot "$root" /usr/bin/dpkg-query -W -f='${Status}' "$package" 2>/dev/null) || return 1
        [[ "$status" == 'install ok installed' ]] || return 1
    done
}
files_ok() {
    [[ -x "$root/usr/bin/pm-is-supported" && -x "$root/usr/libexec/at-spi-bus-launcher" ]] &&
        [[ -f "$root/usr/share/dbus-1/services/org.a11y.Bus.service" ]] &&
        grep -Fxq 'Name=org.a11y.Bus' "$root/usr/share/dbus-1/services/org.a11y.Bus.service" &&
        grep -Fxq 'Exec=/usr/libexec/at-spi-bus-launcher' "$root/usr/share/dbus-1/services/org.a11y.Bus.service"
}

if ! packages_ok || ! files_ok; then
    if [[ ! -e "$policy" && ! -L "$policy" ]]; then
        printf '#!/bin/sh\nexit 101\n' > "$policy"
        chmod 755 "$policy"
        created_policy=1
    fi
    # Reinstall also repairs missing files in a root whose dpkg status is stale.
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$root" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false \
        -y --no-install-recommends install --reinstall pm-utils at-spi2-core
fi
packages_ok && files_ok || {
    echo 'XFCE pm-utils or AT-SPI package/service validation failed' >&2; exit 1;
}
