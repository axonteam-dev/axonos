#!/usr/bin/env python3
"""Host-only gate test: high user frames stay opt-in and single CPU."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static void *mm_user_frame_alloc(")
end = mm.index("\n/* The kernel mapping", start)
source = r'''
#include <assert.h>
#include <stdint.h>
struct frame_page { uint64_t pa; void *kva; };
static int cpus = 1, low_ok, high_calls, high_zero;
static void *frame_alloc(void) { return low_ok ? (void *)0x1000 : 0; }
static void *frame_alloc_zero(void) { return low_ok ? (void *)0x2000 : 0; }
static int smp_cpu_count(void) { return cpus; }
static int frame_alloc_high(struct frame_page *p, int zero) {
    high_calls++; high_zero = zero;
    p->pa = 0x100001000ULL; p->kva = (void *)0x3000; return 0;
}
''' + mm[start:end] + r'''
int main(void) {
    low_ok = 1;
    assert(mm_user_frame_alloc(1) == (void *)0x2000 && high_calls == 0);
    low_ok = 0;
    cpus = 4;
    assert(mm_user_frame_alloc(1) == 0 && high_calls == 0);
    cpus = 1;
    assert(mm_user_frame_alloc(1) == (void *)0x3000);
    assert(high_calls == 1 && high_zero == 1);
    assert(mm_user_frame_alloc(0) == (void *)0x3000);
    assert(high_calls == 2 && high_zero == 0);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-DAXON_EXPERIMENTAL_HIGH_USER_FRAMES=1",
                    str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: high user frames require opt-in and a single CPU")
