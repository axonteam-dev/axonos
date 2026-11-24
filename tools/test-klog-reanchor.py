#!/usr/bin/env python3
"""Exercise the real TSC reanchor code with an independently controlled clock."""
from pathlib import Path
import subprocess
import tempfile

src = (Path(__file__).resolve().parents[1] / "core/klog.c").read_text()
start = src.index("void klog_reanchor_tsc(void)")
body = src[start:src.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
static uint64_t klog_tsc_per_us, klog_tsc_base, klog_time_base_usec, tsc;
static uint64_t klog_rdtsc(void) { return tsc; }
''' + body + r'''
int main(void) {
    klog_tsc_per_us = 10;
    klog_tsc_base = 1000;
    klog_time_base_usec = 100;
    tsc = 6000;
    klog_reanchor_tsc();
    assert(klog_tsc_base == 6000 && klog_time_base_usec == 600);
    tsc = 8000;
    klog_reanchor_tsc();
    assert(klog_tsc_base == 8000 && klog_time_base_usec == 800);
    klog_tsc_per_us = 0;
    tsc = 9000;
    klog_reanchor_tsc();
    assert(klog_tsc_base == 8000 && klog_time_base_usec == 800);
}
'''
with tempfile.TemporaryDirectory(prefix="axon-tsc-reanchor-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: reanchoring preserves elapsed TSC time")
