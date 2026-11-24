#!/usr/bin/env python3
"""Test actual syslog ring formatting, including wrap and short buffers."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/klog.c").read_text()
start = source.index("long klog_syslog_read_all(")
body = source[start:source.index("\n}\n", start) + 3]
start = source.index("static void klog_ring_append(")
append = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KLOG_RING_SZ 128
enum klog_level { KLOG_EMERG, KLOG_ALERT, KLOG_CRIT, KLOG_ERR,
                  KLOG_WARNING, KLOG_NOTICE, KLOG_INFO, KLOG_DEBUG };
static char klog_ring[KLOG_RING_SZ];
static uint8_t klog_ring_levels[3][(KLOG_RING_SZ + 7) / 8];
static size_t klog_ring_len, klog_ring_pos;
static int klog_lock;
static void acquire_irqsave(int *p, unsigned long *f) { (void)p; *f = 0; }
static void release_irqrestore(int *p, unsigned long f) { (void)p; (void)f; }
''' + append + body + r'''
int main(void) {
    const char *first = "[    1.000000] alpha\n";
    const char *second = "[    2.000000] beta\n";
    char out[256];
    klog_ring_append(first, strlen(first), KLOG_ERR);
    klog_ring_append(second, strlen(second), KLOG_WARNING);
    long n = klog_syslog_read_all(out, sizeof(out));
    const char *want = "<3>[    1.000000] alpha\n<4>[    2.000000] beta\n";
    assert(n == (long)strlen(want) && !memcmp(out, want, (size_t)n));
    assert(klog_syslog_read_all(out, 3) == 0);
    assert(klog_syslog_read_all(out, 4) == 4 && !memcmp(out, "<3>[", 4));
    klog_ring_len = 0;
    klog_ring_pos = 124;
    char wrapped[KLOG_RING_SZ];
    memset(wrapped, 'x', sizeof(wrapped));
    memcpy(wrapped, "a\nbc", 4);
    klog_ring_append(wrapped, sizeof(wrapped), KLOG_DEBUG);
    n = klog_syslog_read_all(out, sizeof(out));
    assert(n == KLOG_RING_SZ + 6 && !memcmp(out, "<7>a\n<7>bc", 10));
    klog_ring_append("z", 1, (enum klog_level)99);
    assert((klog_ring_levels[0][124 / 8] & (1u << (124 % 8))) == 0);
    assert((klog_ring_levels[1][124 / 8] & (1u << (124 % 8))) != 0);
    assert((klog_ring_levels[2][124 / 8] & (1u << (124 % 8))) != 0);
    puts("PASS: syslog prefixes each ring line and handles wrap and short buffers");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-klog-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
