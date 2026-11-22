#!/usr/bin/env python3
"""Exercise the actual stream cleanup after queued SCM_RIGHTS transfers."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static void unix_socket_cleanup(')
cleanup = source[start:source.index('\n/* ---------- SysV SHM', start)]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
struct fs_file { int freed; };
typedef struct { int used, nfds; struct fs_file *fds[4]; } unix_fdpass_t;
typedef struct { int lock, closed[2], refs; unix_fdpass_t fdpass[2][8]; } unix_stream_conn_t;
typedef struct { int closed[2], lock; } unix_dgram_pair_t;
typedef struct { int unix_listening, unix_end; unix_stream_conn_t *unix_conn;
    unix_dgram_pair_t *unix_dgram; unsigned long owner_pid, peer_cred_pid; } ksock_net_t;
typedef struct { char *name; } thread_t;
static int locked, freed_conn;
static void acquire_irqsave(int *l, unsigned long *f) { (void)l; (void)f; assert(!locked); locked=1; }
static void release_irqrestore(int *l, unsigned long f) { (void)l; (void)f; assert(locked); locked=0; }
static void fs_file_free(struct fs_file *f) { assert(!locked); f->freed++; }
static void kfree(void *p) { (void)p; freed_conn++; }
static thread_t *thread_get_current_user(void) { return NULL; }
static unsigned long process_pid(thread_t *t) { (void)t; return 0; }
#define klogprintf_logonly(...) ((void)0)
static struct fs_file *unix_acceptq_pop(ksock_net_t *s) { (void)s; return NULL; }
static void net_fs_file_destroy(struct fs_file *f) { (void)f; }
static void unix_dgram_pair_put(unix_dgram_pair_t *p) { (void)p; }
''' + cleanup + r'''
int main(void) {
    unix_stream_conn_t c = {.refs=2};
    ksock_net_t a = {.unix_conn=&c, .unix_end=0};
    ksock_net_t b = {.unix_conn=&c, .unix_end=1};
    struct fs_file to_peer = {0}, to_closed = {0};
    c.fdpass[0][0] = (unix_fdpass_t){.used=1,.nfds=1,.fds={&to_peer}};
    c.fdpass[1][0] = (unix_fdpass_t){.used=1,.nfds=1,.fds={&to_closed}};
    unix_socket_cleanup(&a);
    assert(c.closed[0] && c.refs == 1 && !a.unix_conn);
    assert(c.fdpass[0][0].used && !to_peer.freed);
    assert(!c.fdpass[1][0].used && to_closed.freed == 1);
    unix_socket_cleanup(&b);
    assert(to_peer.freed == 1 && freed_conn == 1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-unix-close-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-function', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: UNIX stream close preserves outgoing rights and releases outside lock')
