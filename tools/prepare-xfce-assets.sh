#!/usr/bin/env bash
# Repair the Debian staging root before packing it; run on fresh and cached roots.
set -euo pipefail
root="${1:?usage: bash tools/prepare-xfce-assets.sh ROOTFS}"
[[ -f "$root/etc/debian_version" ]] || { echo "not a Debian root: $root" >&2; exit 1; }
cache=usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache
loader=/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader_svg.so
policy="$root/usr/sbin/policy-rc.d"
created_policy=0
cleanup() { if [[ "$created_policy" == 1 ]]; then rm -f "$policy"; fi; }
trap cleanup EXIT

if [[ ! -f "$root$loader" ]] || ! grep -Fxq "\"$loader\"" "$root/$cache" 2>/dev/null; then
    if [[ ! -e "$policy" && ! -L "$policy" ]]; then
        printf '#!/bin/sh\nexit 101\n' > "$policy"
        chmod 755 "$policy"
        created_policy=1
    fi
    # Package postinst/trigger generates the cache using guest-absolute paths.
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$root" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false \
        -y --no-install-recommends install --reinstall librsvg2-common
fi
[[ -f "$root$loader" ]] && grep -Fxq "\"$loader\"" "$root/$cache" || {
    echo 'XFCE SVG loader or its cache entry is missing' >&2; exit 1;
}
[[ -s "$root/usr/share/mime/mime.cache" ]] || {
    echo 'shared MIME database is missing; install/configure shared-mime-info' >&2; exit 1;
}
[[ -f "$root/usr/share/backgrounds/xfce/xfce-blue.jpg" ]] || {
    echo 'XFCE backgrounds missing; install xfdesktop4-data' >&2; exit 1;
}
