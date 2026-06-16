#!/bin/bash
# Fix root-owned tree after "sudo make". Run once.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $EUID -ne 0 ]]; then exec sudo "$0" "$@"; fi
U="${SUDO_USER:-miha}"
G="${SUDO_GID:-$(id -g "$U")}"
chown -R "$U:$G" "$ROOT"
rm -rf "$ROOT/syscall64" "$ROOT/build"
echo "Ownership fixed for $U. Run: python3 scripts/cleanup_style.py && make clean && make iso"