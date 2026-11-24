#!/usr/bin/env python3
"""Exercise installer orchestration in a throwaway chroot with fake devices.

No real disk or mount is passed to the installer. This is not an integration
test of AxonOS syscalls, filesystem durability, or GRUB.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
original = (root / "tools/axon-install-disk.sh").read_text()
gate = 'echo "Installer disabled: persistent disk installation is not yet verified." >&2\nexit 1\n'
assert original.count(gate) == 1
# Remove the release gate only in the disposable, isolated test copy.
script = original.replace(gate, "", 1)
if not all(shutil.which(tool) for tool in ("unshare", "chroot", "unsquashfs")):
    raise SystemExit("unshare, chroot and unsquashfs are required")
busybox = subprocess.run(
    ["unsquashfs", "-cat", str(root / "iso/boot/initfs.sfs"), "usr/bin/busybox"],
    check=True, capture_output=True).stdout

mock = r'''#!/bin/sh
name=${0##*/}
echo "$name $*" >> /calls
case "$name" in
    mountpoint)
        [ "${TEST_BUSY_TARGET:-0}" = 0 ] || [ "$2" != /mnt/axon-target ] || exit 0
        exit 1 ;;
    mount)
        if [ "$2" = iso9660 ]; then
            [ "${TEST_FAIL_MEDIA:-0}" = 0 ] || exit 1
            mkdir -p "$4/boot"
            if [ "${TEST_NO_KERNEL:-0}" = 0 ]; then
                echo TEST_KERNEL > "$4/boot/axonos.elf"
            fi
        elif [ "$2" = ext2 ]; then
            [ "${TEST_FAIL_TARGET_MOUNT:-0}" = 0 ] || exit 1
        fi ;;
    sfdisk) cat > /partition-layout; touch /dev/sda1 ;;
    blockdev) [ "${TEST_FAIL_REREAD:-0}" = 0 ] || exit 1 ;;
    grub-install) [ "${TEST_FAIL_GRUB:-0}" = 0 ] || exit 1 ;;
esac
exit 0
'''

def run_case(envvars):
    with tempfile.TemporaryDirectory(prefix="axon-installer-flow-") as tmp:
        path = Path(tmp)
        for directory in ("bin", "dev", "etc", "usr", "mnt", "boot", "root"):
            (path / directory).mkdir()
        (path / "bin/busybox").write_bytes(busybox)
        (path / "bin/busybox").chmod(0o755)
        for command in ("sh", "mkdir", "chmod", "cp", "cat", "touch", "rmdir"):
            (path / "bin" / command).symlink_to("busybox")
        for command in ("sfdisk", "mkfs.ext2", "mount", "umount", "grub-install",
                        "blockdev", "mountpoint", "sync"):
            p = path / "bin" / command
            p.write_text(mock)
            p.chmod(0o755)
        (path / "dev/sda").touch()
        (path / "installer").write_text(script)
        env = dict(os.environ, PATH="/usr/sbin:/usr/bin:/sbin:/bin", **envvars)
        result = subprocess.run(
            ["unshare", "-Ur", "chroot", str(path), "/bin/sh", "/installer",
             "--disk", "/dev/sda", "--yes-wipe"],
            env=env, capture_output=True, text=True)
        calls = (path / "calls").read_text().splitlines() if (path / "calls").exists() else []
        cfg = path / "mnt/axon-target/boot/grub/grub.cfg"
        fstab = path / "mnt/axon-target/etc/fstab"
        return result, calls, cfg.read_text() if cfg.exists() else "", \
            fstab.read_text() if fstab.exists() else ""

result, calls, cfg, fstab = run_case({})
assert result.returncode == 0, (result.stdout, result.stderr, calls)
assert "root=/dev/sda1" in cfg and "/dev/sda1\t/\text2" in fstab
assert any(line.startswith("grub-install --target=i386-pc ") for line in calls)
assert next(i for i, line in enumerate(calls) if line.startswith("mount -t iso9660")) < \
       next(i for i, line in enumerate(calls) if line.startswith("sfdisk "))
assert calls[-1] == "umount /mnt/axon-install-media"

for scenario in ({"TEST_FAIL_MEDIA": "1"}, {"TEST_NO_KERNEL": "1"},
                 {"TEST_BUSY_TARGET": "1"}):
    result, calls, _, _ = run_case(scenario)
    assert result.returncode != 0
    assert not any(line.startswith("sfdisk ") for line in calls), calls

result, calls, _, _ = run_case({"TEST_FAIL_REREAD": "1"})
assert result.returncode != 0
assert not any(line.startswith("mkfs.ext2 ") for line in calls), calls

for scenario in ({"TEST_FAIL_TARGET_MOUNT": "1"}, {"TEST_FAIL_GRUB": "1"}):
    result, calls, _, _ = run_case(scenario)
    assert result.returncode != 0 and "Done." not in result.stdout
    assert calls[-1] == "umount /mnt/axon-install-media", calls
print("PASS: isolated installer flow and failure ordering (mock devices)")
