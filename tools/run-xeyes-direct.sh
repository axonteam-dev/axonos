#!/bin/sh
# Diagnostic only: run xeyes with Xorg drawing directly to fbdev.
set -eu
BASE=/opt/axonos-xeyes
DISPLAY_NUMBER=${1:-:1}
CONF=$(mktemp /tmp/axonos-xeyes-direct.XXXXXX)
trap 'rm -f "$CONF"' EXIT HUP INT TERM
sed 's/Option "ShadowFB" "true"/Option "ShadowFB" "false"/' /etc/X11/xorg.conf > "$CONF"
if ! grep -q 'Option "ShadowFB" "false"' "$CONF"; then
    echo 'Cannot prepare direct framebuffer configuration' >&2
    exit 1
fi
export LD_LIBRARY_PATH="$BASE/lib"
printf 'Starting xeyes with direct fbdev on %s (X11 authorization disabled).\n' "$DISPLAY_NUMBER"
/opt/axonos-x11/bin/xinit "$BASE/bin/xeyes" -geometry 200x100+100+100 -- \
    /usr/lib/xorg/Xorg "$DISPLAY_NUMBER" -config "$CONF" -nolisten tcp -ac
