#!/bin/sh
# Isolated-VM diagnostic only: -ac disables X11 authentication.
set -eu
BASE=/opt/axonos-xeyes
rm -f /tmp/xeyes-trace.log
exec /opt/axonos-x11/bin/xinit "$BASE/run-trace-client.sh" -- \
    /usr/lib/xorg/Xorg "${1:-:1}" -nolisten tcp -ac
