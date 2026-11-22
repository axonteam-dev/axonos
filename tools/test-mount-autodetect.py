#!/usr/bin/env python3
"""Check NULL/empty mount fstype is normalized to auto."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static char *mount_type_or_auto(")
function = source[start:source.index("\n}\n", start) + 3]
fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define kmalloc malloc
#define kfree free
'''
tests = r'''
int main(void) {
    char *type = mount_type_or_auto(NULL);
    assert(type && strcmp(type, "auto") == 0);
    free(type);

    type = malloc(1);
    assert(type);
    type[0] = '\0';
    type = mount_type_or_auto(type);
    assert(type && strcmp(type, "auto") == 0);
    free(type);

    type = malloc(5);
    assert(type);
    memcpy(type, "ext4", 5);
    char *same = mount_type_or_auto(type);
    assert(same == type && strcmp(same, "ext4") == 0);
    free(same);
    puts("PASS: omitted mount fstype selects auto; explicit fstype is preserved");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-mount-auto-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + function + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
