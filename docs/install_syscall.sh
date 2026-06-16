#!/bin/bash
# Finalize syscall/ layout: drop legacy syscall64* trees and fix ownership.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

USER_NAME="${SUDO_USER:-miha}"
GROUP_ID="${SUDO_GID:-$(id -g "$USER_NAME")}"

chown -R "$USER_NAME:$GROUP_ID" \
    "$ROOT/syscall" "$ROOT/makefile" "$ROOT/build" "$ROOT/inc" 2>/dev/null || true

rm -rf "$ROOT/syscall64" "$ROOT/syscall64_split" "$ROOT/syscall64.monolith.bak"
rm -rf "$ROOT/build"

chown -R "$USER_NAME:$GROUP_ID" "$ROOT/syscall" "$ROOT/makefile" "$ROOT/inc"

echo "syscall/ ready; removed syscall64 and syscall64_split."
