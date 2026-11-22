#!/usr/bin/env python3
"""Exercise UNIX stream message helpers with a per-call nonblocking flag."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static ssize_t unix_stream_write_from_user_ex(')
write = source[start:source.index('\nstatic ssize_t unix_stream_write_from_user(', start)]
start = source.index('static ssize_t unix_stream_read_to_kernel_ex(')
read = source[start:source.index('\nstatic ssize_t unix_stream_read_to_kernel(', start)]
start = source.index('static ssize_t unix_stream_read_to_user(')
user_read = source[start:source.index('\nstatic void unix_socket_cleanup(', start)]
assert '((int)a3 & 0x40) != 0' in source
assert 'got_fds, &got_n, (flags & 0x40) != 0' in source
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
static int freed;
static void fs_file_free(struct fs_file *f) { (void)f; freed++; }
static int user_range_ok(const void *p, size_t n) { (void)p; (void)n; return 1; }
static int copy_from_user_raw(void *d, const void *s, size_t n) { memcpy(d,s,n); return 0; }
static int copy_to_user_safe(void *d, const void *s, size_t n) { memcpy(d,s,n); return 0; }
static void acquire_irqsave(int *l, unsigned long *f) { (void)l; (void)f; }
static void release_irqrestore(int *l, unsigned long f) { (void)l; (void)f; }
static void thread_sleep(int n) { (void)n; assert(!"unexpected blocking sleep"); }
static int interrupted;
static int unix_stream_interrupted(void) { return interrupted; }
''' + write + read + user_read + r'''
int main(void) {
    unix_stream_conn_t c = {0};
    ksock_net_t a = {&c, 0, 0}, b = {&c, 1, 0};
    char buf[16] = "abcdefghijk";
    assert(unix_stream_read_to_kernel_ex(&b, buf, 1, 0, NULL, NULL, 1) == -EAGAIN);
    assert(unix_stream_write_from_user_ex(&a, buf, 11, NULL, 0, 1) == 8);
    assert(unix_stream_write_from_user_ex(&a, buf, 1, NULL, 0, 1) == -EAGAIN);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 8, 0, NULL, NULL, 1) == 8);
    interrupted = 1;
    assert(unix_stream_read_to_kernel_ex(&b, buf, 1, 0, NULL, NULL, 0) == -EINTR);
    interrupted = 0;
    assert(unix_stream_write_from_user_ex(&a, buf, 8, NULL, 0, 1) == 8);
    interrupted = 1;
    assert(unix_stream_write_from_user_ex(&a, buf, 1, NULL, 0, 0) == -EINTR);
    assert(!a.nonblock && !b.nonblock);
    /* A plain read must advance the same stream position as recvmsg. */
    memset(&c, 0, sizeof(c)); interrupted = 0;
    struct fs_file file = {0}, *rights[] = {&file}, *received[4] = {0};
    int nr = 0;
    assert(unix_stream_write_from_user_ex(&a, "a", 1, NULL, 0, 0) == 1);
    assert(unix_stream_read_to_user(&b, buf, 1, 0) == 1);
    assert(unix_stream_write_from_user_ex(&a, "b", 1, rights, 1, 0) == 1);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 1, 0, received, &nr, 0) == 1);
    assert(nr == 1 && received[0] == &file);
    assert(unix_stream_write_from_user_ex(&a, "c", 1, rights, 1, 0) == 1);
    assert(unix_stream_read_to_user(&b, buf, 1, 1) == 1 && freed == 0);
    assert(unix_stream_read_to_user(&b, buf, 1, 0) == 1 && freed == 1);
    assert(unix_stream_write_from_user_ex(&a, "d", 1, rights, 1, 0) == 1);
    assert(unix_stream_read_to_kernel_ex(&b, buf, 1, 0, NULL, NULL, 0) == 1);
    assert(freed == 2);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-msg-dontwait-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: UNIX stream message helpers respect MSG_DONTWAIT')
