#!/usr/bin/env python3
"""Check the built image's APT sandbox and debconf frontend prerequisites."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
image = root / "build/axonos.sfs"


def unsquash(option, *paths):
    return subprocess.check_output(["unsquashfs", option, str(image), *paths], text=True)


passwd = unsquash("-cat", "etc/passwd")
entry = next(line.split(":") for line in passwd.splitlines()
             if line.startswith("_apt:"))
uid, gid = int(entry[2]), int(entry[3])
for directory in ("var/lib/apt/lists/partial", "var/cache/apt/archives/partial"):
    listing = unsquash("-lln", directory)
    line = next(line for line in listing.splitlines()
                if line.endswith("squashfs-root/" + directory))
    assert line.startswith("drwx------"), line
    assert re.search(rf"\b{uid}/{gid}\b", line), line

listing = unsquash("-ll", "usr/bin/dialog", "usr/share/perl")
assert "squashfs-root/usr/bin/dialog" in listing
assert re.search(r"squashfs-root/usr/share/perl/[^/]+/Term/ReadLine\.pm$", listing, re.M)
listing = unsquash("-ll", "usr/lib/apk/db/installed", "usr/lib/apk/db/scripts.tar.gz",
                   "etc/apk/world")
for path in ("usr/lib/apk/db/installed", "usr/lib/apk/db/scripts.tar.gz", "etc/apk/world"):
    assert "squashfs-root/" + path in listing, path
print("PASS: APT sandbox directories and debconf frontends in image")
