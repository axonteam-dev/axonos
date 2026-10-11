#!/usr/bin/env bash
# Generate configuration with stable timestamps for unchanged contents.
set -euo pipefail
exec python3 "$(dirname "$0")/genconfig.py" "$@"
