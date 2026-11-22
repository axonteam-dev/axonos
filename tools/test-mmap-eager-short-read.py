#!/usr/bin/env python3
"""Exercise the kernel's eager mmap copy helper with partial file reads."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_mmap.c").read_text()
helper = source[source.index("static int user_mmap_copyin_file("):
                source.index("uint64_t user_syscall_mmap(")]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
typedef struct mm { void *pml4; } mm_t;
typedef struct thread { mm_t *mm, *mm_ptemplate; } thread_t;
struct fs_file { unsigned char data[9000]; int stop; };
static mm_t kernel = { (void *)1 };
static mm_t *mm_kernel(void) { return &kernel; }
static ssize_t fs_read(struct fs_file *f, void *p, size_t n, size_t off) {
    if (f->stop && off >= 500) return 0;
    if (n > 137) n = 137;
    memcpy(p, f->data + off, n);
    return (ssize_t)n;
}
static int mm_copy_to_user(mm_t *mm, mm_t *share, uint64_t dest,
                           const void *src, size_t n) {
    (void)mm; (void)share; memcpy((void *)(uintptr_t)dest, src, n); return 0;
}
''' + helper + r'''
int main(void) {
    struct fs_file f = {0};
    unsigned char out[8000];
    for (size_t i = 0; i < sizeof(f.data); ++i) f.data[i] = (unsigned char)(i * 17);
    thread_t thread = { .mm = &kernel };
    memset(out, 0, sizeof(out));
    assert(user_mmap_copyin_file(&thread, &f, (uintptr_t)out, sizeof(out), 23) == 0);
    assert(memcmp(out, f.data + 23, sizeof(out)) == 0);
    f.stop = 1;
    assert(user_mmap_copyin_file(&thread, &f, (uintptr_t)out, sizeof(out), 23) == -1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mmap-short-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: eager mmap handles short reads and rejects premature EOF")
