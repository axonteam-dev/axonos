#!/usr/bin/env python3
"""Exercise the page-cache fill loop against short reads, EOF and errors."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/pagecache.c").read_text()
start = source.index("static int pc_read_exact(")
end = source.index("\n}\n", start) + 2
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
struct fs_file { int unused; };
static int mode, calls;
static ssize_t fs_read(struct fs_file *f, void *buf, size_t n, size_t offset) {
    (void)f;
    calls++;
    if (mode == 1 && calls == 2) return 0;
    if (mode == 2 && calls == 2) return -1;
    if (mode == 3) return (ssize_t)n + 1;
    if (n > 7) n = 7;
    for (size_t i = 0; i < n; i++) ((unsigned char *)buf)[i] = (offset + i) & 255;
    return (ssize_t)n;
}
''' + source[start:end] + r'''
int main(void) {
    struct fs_file file = {0};
    unsigned char b[4096];
    calls = mode = 0;
    assert(pc_read_exact(&file, b, sizeof b, 23) == 0 && calls > 1);
    for (size_t i = 0; i < sizeof b; i++) assert(b[i] == ((i + 23) & 255));
    for (mode = 1; mode <= 3; mode++) {
        calls = 0;
        assert(pc_read_exact(&file, b, sizeof b, 23) == -1);
    }
    calls = 0;
    assert(pc_read_exact(&file, b, 0, 23) == 0 && calls == 0);
    puts("PASS: page-cache fill handles partial reads and rejects premature EOF/errors");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-pagecache-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
