#!/bin/sh
# Run within the xterm started by ax-xcheck, without starting a second Xorg.
if [ "$#" -ne 0 ] || [ -z "${DISPLAY:-}" ]; then
    echo 'Run ax-xfce-check inside the xterm started by ax-xcheck.' >&2
    exit 2
fi
log="${TMPDIR:-/tmp}/ax-xfce-check.log"
echo "Starting XFCE on the existing Xorg; output: $log"
exec dbus-launch --exit-with-session startxfce4 > "$log" 2>&1
