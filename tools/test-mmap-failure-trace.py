#!/usr/bin/env python3
"""Exercise the actual dispatch trace helper with host stubs; no guest needed."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static void trace_mmap_failure(')
end = source.index('\nstatic struct fs_file *socket_file_get', start)
helper = source[start:end]
assert 'sizeof("mmap.trace=1")' in source
assert 'trace_mmap_failure(cur, a1, a2, a3, a4, a5, a6, mr);' in source
program = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#define THREAD_MAX_FD 8
typedef struct { uint64_t tid; char name[16]; } thread_t;
struct fs_file { const char *path; };
static int mmap_failure_trace;
static unsigned mmap_failure_trace_count;
static struct fs_file file = {"/lib/test so"};
static int lookups, logs;
static char line[512];
static struct fs_file *syscall_fd_get(thread_t *t, int fd) {
    (void)t; lookups++; return fd == 3 ? &file : 0;
}
static void qemu_debug_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap); logs++;
}
''' + helper + r'''
int main(void) {
    thread_t t = {42, "loader"};
    trace_mmap_failure(&t, 1, 2, 3, 4, 3, 5, (uint64_t)-12);
    assert(!logs && !lookups);
    mmap_failure_trace = 1;
    trace_mmap_failure(&t, 1, 2, 3, 4, 3, 5, 0x1000);
    assert(!logs && !lookups);
    trace_mmap_failure(&t, 1, 2, 3, 4, 3, 5, (uint64_t)-12);
    assert(logs == 1 && lookups == 1);
    assert(strstr(line, "path=/lib/test?so errno=12"));
    assert(strstr(line, "len=0x2 prot=0x3 flags=0x4 fd=3 off=0x5"));
    trace_mmap_failure(&t, 1, 2, 3, 0x20, 3, 5, (uint64_t)-22);
    assert(lookups == 1 && strstr(line, "path=? errno=22"));
    for (int i = 0; i < 100; i++)
        trace_mmap_failure(&t, 1, 2, 3, 4, 3, 5, (uint64_t)-9);
    assert(logs == 64 && mmap_failure_trace_count == 64);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mmap-trace-') as tmp:
    c = Path(tmp) / 'test.c'
    binary = Path(tmp) / 'test'
    c.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: mmap failure trace opt-in, details, anonymous fd, and budget')
