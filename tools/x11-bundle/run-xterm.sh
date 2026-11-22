#!/bin/sh
# Minimal isolated X11 smoke test. -ac is for a disposable trusted VM only.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DISPLAY_NUMBER=${1:-:1}
XORG=${XORG:-/usr/lib/xorg/Xorg}
if [ ! -x "$XORG" ]; then
    printf 'Xorg not found: %s\n' "$XORG" >&2
    exit 1
fi
if [ ! -e /dev/ptmx ]; then
    printf 'Warning: /dev/ptmx is missing; xterm may not start a shell.\n' >&2
fi
export XAPPLRESDIR="$BASE/share/X11/app-defaults"
export TERMINFO="$BASE/share/terminfo"
export TERM=xterm
printf 'Starting %s with xterm on %s (X access control disabled for this test).\n' "$XORG" "$DISPLAY_NUMBER"

# --library-path applies only to the program started by this loader. Do not
# export LD_LIBRARY_PATH: Xorg, /bin/sh and their children must see the
# caller's original environment, including an unset or empty variable.
LOADER="$BASE/lib/ld-linux-x86-64.so.2"
exec "$LOADER" --library-path "$BASE/lib" "$BASE/bin/xinit" \
    "$LOADER" --library-path "$BASE/lib" "$BASE/bin/xterm" \
    -ut -geometry 80x24 -e /bin/sh -- \
    "$XORG" "$DISPLAY_NUMBER" -nolisten tcp -ac
