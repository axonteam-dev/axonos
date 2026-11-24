#!/usr/bin/env python3
"""Check the installer's real sfdisk input against a disposable image."""
from pathlib import Path
import shutil
import subprocess
import tempfile

script = (Path(__file__).resolve().parents[1] / "tools/axon-install-disk.sh").read_text()
assert 'sfdisk --wipe always "$DISK" <<EOF\n' in script
assert script.index('[ -f "$MEDIA/boot/axonos.elf" ]') < script.index('sfdisk --wipe always "$DISK"')
assert 'multiboot2 /boot/axonos.elf root=$PART ' in script
layout = script.split('sfdisk --wipe always "$DISK" <<EOF\n', 1)[1].split("\nEOF", 1)[0] + "\n"
if not shutil.which("sfdisk"):
    raise SystemExit("sfdisk required for installer partition test")
with tempfile.TemporaryDirectory(prefix="axon-installer-partition-") as tmp:
    disk = Path(tmp) / "disk.img"
    with disk.open("wb") as image:
        image.truncate(64 * 1024 * 1024)
    subprocess.run(["sfdisk", "--wipe", "always", str(disk)], input=layout,
                   text=True, check=True, capture_output=True)
    result = subprocess.run(["sfdisk", "--json", str(disk)], text=True,
                            check=True, capture_output=True)
    import json
    table = json.loads(result.stdout)["partitiontable"]
    assert table["label"] == "dos"
    assert len(table["partitions"]) == 1
    part = table["partitions"][0]
    assert part["start"] == 2048 and part["type"].lower() == "83"
    assert part["bootable"] is True
print("PASS: installer creates one bootable MBR partition on a disposable image")
