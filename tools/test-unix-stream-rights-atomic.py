#!/usr/bin/env python3
"""Check that failed UNIX stream sends cannot attach rights to later data."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static ssize_t unix_stream_write_from_user_ex(')
write = source[start:source.index('\nstatic ssize_t unix_stream_write_from_user(', start)]
start = source.index('static ssize_t unix_stream_read_to_kernel_ex(')
read = source[start:source.index('\nstatic ssize_t unix_stream_read_to_kernel(', start)]
program = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
struct fs_file { int unused; };
typedef struct { int used, nfds; size_t pos; struct fs_file *fds[4]; } unix_fdpass_t;
typedef struct {
    int lock, closed[2]; uint8_t q01[8], q10[8];
    size_t q01_head, q01_tail, q01_count, q10_head, q10_tail, q10_count;
    size_t written_bytes[2], read_bytes[2]; unix_fdpass_t fdpass[2][8];
} unix_stream_conn_t;
typedef struct { unix_stream_conn_t *unix_conn; int unix_end, nonblock; } ksock_net_t;
static int freed, fail_copy;
static void fs_file_free(struct fs_file *f) { (void)f; freed++; }
static int user_range_ok(const void *p, size_t n) { (void)p; (void)n; return 1; }
static int copy_from_user_raw(void *d, const void *s, size_t n) {
    if (fail_copy) return -1;
    memcpy(d, s, n); return 0;
}
static void acquire_irqsave(int *l, unsigned long *f) { (void)l; (void)f; }
static void release_irqrestore(int *l, unsigned long f) { (void)l; (void)f; }
static void thread_sleep(int n) { (void)n; assert(!"unexpected sleep"); }
static int unix_stream_interrupted(void) { return 0; }
''' + write + read + r'''
int main(void) {
    unix_stream_conn_t c = {0};
    ksock_net_t a = {&c, 0, 1}, b = {&c, 1, 1};
    struct fs_file file = {0}, *rights[] = {&file}, *received[4] = {0};
    char buf[16]; int nr = 0;
    assert(unix_stream_write_from_user_ex(&a, "12345678", 8, NULL, 0, 0) == 8);
    assert(unix_stream_write_from_user_ex(&a, "x", 1, rights, 1, 0) == -EAGAIN);
    assert(freed == 1 && !c.fdpass[0][0].used);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 8, 0, received, &nr, 0) == 8);
    assert(unix_stream_write_from_user_ex(&a, "y", 1, NULL, 0, 0) == 1);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 1, 0, received, &nr, 0) == 1);
    assert(nr == 0 && buf[0] == 'y');
    fail_copy = 1;
    assert(unix_stream_write_from_user_ex(&a, "x", 1, rights, 1, 0) == -EFAULT);
    assert(freed == 2 && !c.fdpass[0][0].used);
    fail_copy = 0;
    c.closed[1] = 1;
    assert(unix_stream_write_from_user_ex(&a, "x", 1, rights, 1, 0) == -EPIPE);
    assert(freed == 3 && !c.fdpass[0][0].used);
    c.closed[1] = 0;
    assert(unix_stream_write_from_user_ex(&a, "xy", 2, rights, 1, 0) == 2);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 2, 0, received, &nr, 0) == 2);
    assert(nr == 1 && received[0] == &file);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-rights-atomic-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: UNIX stream rights are committed only with data')
