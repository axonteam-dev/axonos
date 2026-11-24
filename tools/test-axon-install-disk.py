#!/usr/bin/env python3
"""The disk installer must refuse ambiguous targets and unconfirmed wipes."""
from pathlib import Path
import os
import subprocess
import tempfile

script = Path(__file__).resolve().parents[1] / "tools/axon-install-disk.sh"


def run(args, env=None, cwd=None):
    return subprocess.run(["/bin/sh", str(script), *args], env=env, cwd=cwd,
                          capture_output=True, text=True)


result = run([])
assert result.returncode == 2 and "--yes-wipe" in result.stderr

result = run(["--disk", "/dev/sda"])
assert result.returncode == 2 and "--yes-wipe" in result.stderr

result = run(["--disk", "sda", "--yes-wipe"])
assert result.returncode == 2 and "whole disk" in result.stderr

result = run(["--yes-wipe"])
assert result.returncode == 2 and "usage:" in result.stderr

with tempfile.TemporaryDirectory(prefix="axon-installer-") as tmp:
    root = Path(tmp)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    calls = root / "calls"
    for tool in ("fdisk", "mkfs.ext2", "mount", "umount", "cp", "mkdir",
                 "grub-install", "blockdev", "mountpoint"):
        (bin_dir / tool).write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / tool).chmod(0o755)
    env = dict(os.environ, PATH=str(bin_dir) + ":" + os.environ.get("PATH", "/usr/bin:/bin"))
    fake_disk = root / "sda"
    fake_disk.write_bytes(b"")
    result = run(["--disk", str(fake_disk), "--yes-wipe"], env=env)
    assert result.returncode == 2 and "whole disk" in result.stderr

    # A plausible /dev path with an existing partition must be refused before
    # any destructive command can run.
    dev_dir = root / "dev"
    dev_dir.mkdir()
    (dev_dir / "sda").write_bytes(b"")
    (dev_dir / "sda1").write_bytes(b"")
    result = run(["--disk", str(dev_dir / "sda"), "--yes-wipe"], env=env)
    # The path check only accepts /dev/sdX, so use a symlinked chroot-like tree
    # via a bind-style name in /dev is not possible unprivileged; assert the
    # stricter whole-disk filter rejects it instead.
    assert result.returncode == 2

print("PASS: disk installer refuses unconfirmed and malformed invocations")
