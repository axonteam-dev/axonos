#!/usr/bin/env python3
"""Test disk/partition names used to build /sys/block."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "core/entry/init.c").read_text()
start = source.index("static unsigned sysfs_parse_partition_name(")
function = source[start:source.index("\n}\n", start) + 3]
fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
'''
tests = r'''
int main(void) {
    char parent[64];
    assert(sysfs_parse_partition_name("sda", parent, sizeof(parent)) == 0);
    assert(strcmp(parent, "sda") == 0);
    assert(sysfs_parse_partition_name("sda12", parent, sizeof(parent)) == 12);
    assert(strcmp(parent, "sda") == 0);
    assert(sysfs_parse_partition_name("nvme0n1", parent, sizeof(parent)) == 0);
    assert(strcmp(parent, "nvme0n1") == 0);
    assert(sysfs_parse_partition_name("nvme0n1p3", parent, sizeof(parent)) == 3);
    assert(strcmp(parent, "nvme0n1") == 0);
    assert(sysfs_parse_partition_name("sr0", parent, sizeof(parent)) == 0);
    assert(strcmp(parent, "sr0") == 0);
    puts("PASS: sysfs block disk and partition names");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-sysfs-block-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + function + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
