#!/usr/bin/env python3
"""Global VMA storage is initialized after the heap and handles allocation failure."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_vma.c").read_text()
init = (root / "core/entry/init.c").read_text()
header = (root / "inc/user_vma.h").read_text()
assert "#define USER_VMA_MAX 8192" in header
assert init.index("if (user_vma_init() != 0)") > init.index("heap_init(heap_start, heap_size)")
start = source.index("int user_vma_init(void) {")
end = source.index("\n}\n", start) + 3
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define USER_VMA_MAX 8192
typedef struct { int used; } user_vma_t;
static user_vma_t *g_user_vmas;
static user_vma_t storage[USER_VMA_MAX];
static int fail=1, allocations;
static void *kmalloc(size_t n) { assert(n==sizeof(storage)); allocations++; return fail ? NULL : storage; }
''' + source[start:end] + r'''
int main(void) {
    memset(storage, 0xff, sizeof(storage));
    assert(user_vma_init()==-1 && !g_user_vmas);
    fail=0; assert(user_vma_init()==0 && g_user_vmas==storage);
    for (int i=0; i<USER_VMA_MAX; i++) assert(!storage[i].used);
    assert(user_vma_init()==0 && allocations==2);
    puts("PASS: larger heap-backed VMA table initializes once and handles OOM");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-init-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
