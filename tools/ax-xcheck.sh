#!/bin/sh
# Start a minimal X session first; launch XFCE explicitly from its xterm.
if [ "$#" -ne 0 ]; then
    echo "Usage: ax-xcheck" >&2
    exit 2
fi
echo 'Starting Xorg with bundled xterm. In xterm run: /usr/local/bin/ax-xfce-check'
exec /opt/axonos-x11/run-xterm.sh
