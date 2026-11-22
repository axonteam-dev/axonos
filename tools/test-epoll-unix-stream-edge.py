#!/usr/bin/env python3
"""Exercise the actual epoll edge scan when a stream refills between waits."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static size_t epoll_stream_read_seq(')
helper = source[start:source.index('\n}', start) + 2]
start = source.index('size_t stream_seq = epoll_stream_read_seq(it->file);')
scan = source[start:source.index('it->et_stream_write_seq = stream_seq;', start) + len('it->et_stream_write_seq = stream_seq;')]
assert '__atomic_add_fetch(&c->written_bytes[dir], n, __ATOMIC_RELEASE)' in source
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#define SYSCALL_FTYPE_SOCKET 7
#define FS_TYPE_INOTIFY 8
#define EPOLLIN_K 1
#define EPOLLONESHOT_K (1u << 30)
#define EPOLLET_K (1u << 31)
struct conn { size_t written_bytes[2]; };
typedef struct { struct conn *unix_conn; int unix_dgram, unix_end; } ksock_net_t;
typedef struct { size_t sequence; } inotify_state_k;
struct fs_file { int type; void *driver_private; };
typedef struct { struct fs_file *file; uint32_t events; uint64_t data;
    int fd; uint8_t et_delivered; size_t et_stream_write_seq; } item;
typedef struct { uint32_t events; uint64_t data; } event;
static int available;
static short fd_file_poll_revents(void *t, struct fs_file *f, short want)
{ (void)t; (void)f; return available ? want : 0; }
static uint32_t poll_to_epoll_revents(short rev, uint32_t events)
{ return rev & events; }
''' + helper + r'''
static int wait_once(item *it) {
    event outbuf[1]; int nout = 0; void *wait_thr = 0; short want = 1;
    for (int i = 0; i < 1; i++) {
''' + scan + r'''
    }
    (void)outbuf; return nout;
}
int main(void) {
    struct conn conn = {{0, 0}};
    ksock_net_t socket = {&conn, 0, 0};
    struct fs_file file = {SYSCALL_FTYPE_SOCKET, &socket};
    item watch = {&file, EPOLLIN_K | EPOLLET_K, 0, 0, 0, 0};
    conn.written_bytes[1] = 20; available = 1; assert(wait_once(&watch) == 1);
    assert(wait_once(&watch) == 0); /* still ready, no new write */
    /* Consumer drains and producer refills before the next wait. */
    available = 0; conn.written_bytes[1] += 10; available = 1;
    assert(wait_once(&watch) == 1);
    assert(wait_once(&watch) == 0);
    available = 0; assert(wait_once(&watch) == 0);
    conn.written_bytes[1]++; available = 1; assert(wait_once(&watch) == 1);
    inotify_state_k ino = {1};
    struct fs_file inotify_file = {FS_TYPE_INOTIFY, &ino};
    item inotify_watch = {&inotify_file, EPOLLIN_K | EPOLLET_K, 0, 0, 0, 0};
    assert(wait_once(&inotify_watch) == 1);
    assert(wait_once(&inotify_watch) == 0);
    ino.sequence++;
    assert(wait_once(&inotify_watch) == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-epoll-edge-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: epoll sees Unix stream and inotify refills between edge-triggered waits')
