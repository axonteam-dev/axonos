#!/usr/bin/env python3
"""Do not treat systemd .socket symlinks as shared libraries in lstat."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int path_is_shared_library(")
fn = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <string.h>
#include <stdio.h>
''' + fn + r'''
int main(void) {
    assert(path_is_shared_library("/usr/lib/libfoo.so"));
    assert(path_is_shared_library("/usr/lib/libfoo.so.1"));
    assert(!path_is_shared_library("/usr/lib/systemd/system/sockets.target.wants/foo.socket"));
    assert(!path_is_shared_library("/usr/lib/systemd/system/foo.service"));
    assert(!path_is_shared_library("/path.so/sockets.target.wants/foo.socket"));
    puts("PASS: shared-library lookup keeps .socket symlink metadata");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-soname-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(program)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
