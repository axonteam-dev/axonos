#!/usr/bin/env python3
"""Test the actual open-directory guard and both dispatcher integrations."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int syscall_open_directory_error(")
end = source.index("\n}", start) + 2
helper = source[start:end]
open_case = source[source.index("case SYS_open: {"):source.index("case SYS_openat: {")]
openat_case = source[source.index("case SYS_openat: {"):source.index("case SYS_close:", source.index("case SYS_openat: {"))]
assert "syscall_open_directory_error(flags, f->type)" in open_case
assert "!otmp && syscall_open_directory_error(flags, f->type)" in openat_case
assert "(flags & 0x10000) && (flags & O_CREAT_MASK)" in open_case
assert "(flags & 0x10000) && (flags & O_CREAT_MASK)" in openat_case
program = r'''
#include <assert.h>
#include <stdio.h>
#define ENOTDIR 20
#define FS_TYPE_DIR 2
''' + helper + r'''
int main(void) {
    assert(syscall_open_directory_error(0x10000, 1) == ENOTDIR);
    assert(syscall_open_directory_error(0x210000, 1) == ENOTDIR);
    assert(syscall_open_directory_error(0x10000, FS_TYPE_DIR) == 0);
    assert(syscall_open_directory_error(0, 1) == 0);
    puts("PASS: O_DIRECTORY rejects non-directories in open and openat");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-open-directory-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
