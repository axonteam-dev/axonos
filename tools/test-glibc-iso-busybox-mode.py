#!/usr/bin/env python3
"""The extracted rescue BusyBox and its applet links must be executable."""
from pathlib import Path
import re

script = (Path(__file__).resolve().parents[1] / "tools/build-glibc-iso.sh").read_text()
extract = script.index('unsquashfs -cat "$SOURCE_SFS" usr/bin/busybox > "$ROOTFS/usr/bin/busybox"')
tail = script[extract:script.index("# apk and opkg", extract)]
assert re.search(r'(?m)^chmod\s+0?755\s+"\$ROOTFS/usr/bin/busybox"\s*$', tail)
print("PASS: Debian ISO restores executable permissions on extracted BusyBox")
