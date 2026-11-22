#!/bin/sh
# Use an already running X server and its existing authorization.
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "${DISPLAY:-}" ]; then
    printf 'DISPLAY is not set; run this inside an existing X session.\n' >&2
    exit 1
fi
export XAPPLRESDIR="$BASE/share/X11/app-defaults"
export TERMINFO="$BASE/share/terminfo"
# Do not change LD_LIBRARY_PATH: the shell and its children need the caller's
# original environment, not the bundled libraries used by xterm itself.
exec "$BASE/lib/ld-linux-x86-64.so.2" --library-path "$BASE/lib" \
    "$BASE/bin/xterm" -ut -geometry 80x24 -e /bin/sh
