#!/usr/bin/env python3
"""Exercise fbdev sysfs publication and the legacy Xorg readlink path."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "drv/video/fbdev.c").read_text()
start = source.index("static void fbdev_sysfs_attr_devname(")
end = source.index("\nvoid fbdev_sysfs_publish(", start)
implementation = source[start:end]

fixture = r'''
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
typedef ssize_t (*show_t)(char *, size_t, void *);
struct sysfs_attr { show_t show; void *store; void *priv; };
static ssize_t sysfs_show_const(char *buf, size_t size, void *priv) {
    (void)buf; (void)size; (void)priv; return 0;
}
static int sysfs_mkdir(const char *path) { printf("D %s\n", path); return 0; }
static int sysfs_create_file(const char *path, const struct sysfs_attr *attr) {
    (void)attr; printf("F %s\n", path); return 0;
}
static int sysfs_create_symlink(const char *path, const char *target) {
    printf("L %s %s\n", path, target); return 0;
}
''' + implementation + r'''
int main(void) { return fbdev_sysfs_publish_now(0, 0x15, 0); }
'''

with tempfile.TemporaryDirectory(prefix="axon-fbdev-sysfs-") as tmp:
    base = Path(tmp)
    c = base / "fixture.c"
    binary = base / "fixture"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    events = subprocess.check_output([str(binary)], text=True).splitlines()
    for event in events:
        parts = event.split(" ")
        path = base / parts[1].lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        if parts[0] == "D":
            path.mkdir(exist_ok=True)
        elif parts[0] == "F":
            path.touch()
        elif parts[0] == "L":
            path.symlink_to(parts[2])
    fb = base / "sys/class/graphics/fb0"
    subsystem = fb / "device/subsystem"
    target = os.readlink(subsystem)
    assert "bus/pci" not in target
    assert subsystem.resolve(strict=True) == base / "sys/bus/platform"
    assert (fb / "dev").is_file() and (fb / "name").is_file()
    assert (base / "sys/bus/platform/devices/axonfb.0").resolve(strict=True) == (
        base / "sys/devices/platform/axonfb.0")

print("PASS: fbdev class resolves through device to platform subsystem")
