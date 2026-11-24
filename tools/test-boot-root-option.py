#!/usr/bin/env python3
"""Exercise the actual bounded boot command line root parser."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/entry/init.c").read_text()
start = source.index("static void boot_parse_root_option(")
parser = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <string.h>
#include <stddef.h>
static char axon_root_dev[64];
''' + parser + r'''
static void check(const char *s, size_t n, const char *expected) {
    memset(axon_root_dev, 0, sizeof(axon_root_dev));
    boot_parse_root_option(s, n);
    assert(strcmp(axon_root_dev, expected) == 0);
}
int main(void) {
    const char *s = "quiet\taxon.root=/dev/sda1\nother=1";
    check(s, strlen(s), "/dev/sda1");
    s = "quiet root=/dev/nvme0n1p1 ro";
    check(s, strlen(s), "/dev/nvme0n1p1");
    s = "root=/dev/sda1 axon.root=/dev/sdb2";
    check(s, strlen(s), "/dev/sdb2");
    s = "axon.root=/dev/sdb2 root=/dev/sda1";
    check(s, strlen(s), "/dev/sda1");
    s = "notroot=/dev/sda1";
    check(s, strlen(s), "");
    s = "notaxon.root=/dev/sda2";
    check(s, strlen(s), "");
    s = "axon.root=/dev/sda1 trailing";
    check(s, strlen("axon.root=/dev/sda1"), "/dev/sda1");
    check("axon.root=", strlen("axon.root="), "");
    char long_arg[120] = "axon.root=";
    memset(long_arg + 10, 'a', 100);
    long_arg[110] = 0;
    check(long_arg, 110, "");
    check(NULL, 0, "");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-root-parser-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: boot root option respects token and buffer boundaries")
