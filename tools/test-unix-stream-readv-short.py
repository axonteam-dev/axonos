#!/usr/bin/env python3
"""Verify the syscall's stream readv returns after obtaining a prefix."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {', source.index('case SYS_readv:'))
end = source.index('\n            uint64_t total = 0;', start)
snippet = source[start:end]
program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#define SYSCALL_FTYPE_SOCKET 1
#define SOCK_STREAM_LOCAL 1
typedef struct { void *unix_conn; int type_base; } ksock_net_t;
struct fs_file { int type; void *driver_private; };
struct iovec_k { uint64_t base, len; };
static int calls; static size_t available;
static int user_range_ok(void *p, size_t n) { (void)n; return p != 0; }
static uint64_t ret_err(int e) { return (uint64_t)-e; }
static uint64_t ret_read_err(ssize_t e) { return (uint64_t)e; }
static ssize_t net_sock_read_userspace(void *cur, ksock_net_t *s, void *p, size_t n) {
    (void)cur; (void)s; assert(++calls == 1); if (n > available) n = available;
    memset(p, 'x', n); return (ssize_t)n;
}
static uint64_t run(struct iovec_k *iov, int iovcnt) {
    ksock_net_t s = {(void *)1, SOCK_STREAM_LOCAL};
    struct fs_file file = {SYSCALL_FTYPE_SOCKET, &s}, *f = &file; void *cur = 0;
''' + snippet + r'''
    return 999;
}
int main(void) {
    char a[8192], b[4];
    struct iovec_k v[] = {{(uintptr_t)a, sizeof(a)}, {(uintptr_t)b, sizeof(b)}};
    available = 3; calls = 0; assert(run(v, 2) == 3 && calls == 1);
    available = 4096; calls = 0; assert(run(v, 2) == 4096 && calls == 1);
    v[0].len = 4; available = 4; calls = 0; assert(run(v, 2) == 4 && calls == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-unix-readv-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: UNIX stream readv returns available bytes without a second blocking read')
