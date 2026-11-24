#!/usr/bin/env python3
"""An ext2 mounted at / must keep its internal paths absolute."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static int e2_relpath(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
static const char *prefix;
static int fs_get_matching_mount_prefix(const char *path, char *out, size_t cap) {
    (void)path;
    if (strlen(prefix) >= cap) return -1;
    strcpy(out, prefix); return 0;
}
''' + source[start:end] + r'''
int main(void) {
    char out[32]; prefix = "/";
    assert(e2_relpath("/usr", out, sizeof out) == 0 && !strcmp(out, "/usr"));
    assert(e2_relpath("/", out, sizeof out) == 0 && !strcmp(out, "/"));
    assert(e2_relpath("/usr", out, 4) != 0);
    prefix = "/mnt";
    assert(e2_relpath("/mnt/usr", out, sizeof out) == 0 && !strcmp(out, "/usr"));
    assert(e2_relpath("/mnt", out, sizeof out) == 0 && !strcmp(out, "/"));
    puts("PASS: ext2 preserves absolute paths when mounted at root");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-root-path-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
