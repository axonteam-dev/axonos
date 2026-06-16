#!/bin/bash
# Delete root-owned syscall64/ left over from "sudo make".
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then exec sudo "$0" "$@"; fi
rm -rf syscall64 syscall64_split syscall64.monolith.bak
chown -R "${SUDO_USER:-miha}:${SUDO_GID:-$(id -g "${SUDO_USER:-miha}")}" syscall makefile build inc 2>/dev/null || true
echo "syscall64 removed."
