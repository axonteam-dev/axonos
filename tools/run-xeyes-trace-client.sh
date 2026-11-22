#!/bin/sh
set -eu
BASE=/opt/axonos-xeyes
export LD_LIBRARY_PATH="$BASE/lib"
export LD_PRELOAD="$BASE/xeyes-trace.so"
exec "$BASE/bin/xeyes" -geometry 200x100+100+100
