#!/usr/bin/env python3
"""Block sorting used to detect duplicate pointers must handle odd sizes."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/ext2.c").read_text()
start = source.index("static void e2_sort_truncate_blocks(")
end = source.index("\n}\n", start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
''' + source[start:end] + r'''
static int cmp(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}
int main(void) {
    uint32_t seed = 7, a[1024], b[1024];
    for (size_t n = 0; n <= 1024; n++) {
        for (size_t i = 0; i < n; i++) {
            seed = seed * 1664525u + 1013904223u;
            a[i] = b[i] = seed % 97;
        }
        e2_sort_truncate_blocks(a, n);
        qsort(b, n, sizeof(*b), cmp);
        for (size_t i = 0; i < n; i++) assert(a[i] == b[i]);
    }
    puts("PASS: truncate block sorting matches qsort for lengths 0..1024");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ext2-sort-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
