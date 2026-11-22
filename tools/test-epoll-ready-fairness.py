#!/usr/bin/env python3
"""Run the kernel's epoll scan against continuously readable Unix clients."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('int scan_count = ep->nitems;')
end = source.index('\n                if (nout > 0)', start)
scan = source[start:end]
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#define EPOLLIN_K 1
#define EPOLLET_K (1u << 31)
#define EPOLLONESHOT_K (1u << 30)
typedef struct { int ready; size_t seq; } file;
typedef struct { int fd; file *file; uint32_t events; uint64_t data;
    int et_delivered; size_t et_stream_write_seq; } epoll_item_t;
typedef struct { int nitems, next_scan; epoll_item_t items[4]; } kepoll_t;
typedef struct { uint32_t events; uint64_t data; } event;
static int epoll_interest_to_poll(uint32_t e) { return e & EPOLLIN_K; }
static size_t epoll_stream_read_seq(file *f) { return f->seq; }
static short fd_file_poll_revents(void *t, file *f, short want)
{ (void)t; return f->ready ? want : 0; }
static uint32_t poll_to_epoll_revents(short r, uint32_t e) { return r & e; }
static int wait_once(kepoll_t *ep, event *outbuf, int maxevents) {
    int nout = 0; void *wait_thr = 0;
''' + scan + r'''
    return nout;
}
int main(void) {
    file clients[3] = {{1, 1}, {1, 1}, {1, 1}};
    kepoll_t ep = {0}; event out[3]; ep.nitems = 3;
    for (int i = 0; i < 3; i++) {
        ep.items[i].fd = i; ep.items[i].file = &clients[i];
        ep.items[i].events = EPOLLIN_K; ep.items[i].data = (uint64_t)i;
    }
    /* No client is drained: each must still get a turn. */
    for (int i = 0; i < 9; i++) {
        assert(wait_once(&ep, out, 1) == 1);
        assert(out[0].data == (uint64_t)(i % 3));
    }
    assert(wait_once(&ep, out, 2) == 2);
    assert(out[0].data == 0 && out[1].data == 1);
    assert(wait_once(&ep, out, 2) == 2);
    assert(out[0].data == 2 && out[1].data == 0);
    /* A removed last item must not leave the cursor out of range. */
    ep.next_scan = 2; ep.nitems = 2;
    assert(wait_once(&ep, out, 1) == 1 && out[0].data == 0);
    clients[0].ready = clients[1].ready = 0;
    assert(wait_once(&ep, out, 1) == 0);
    ep.nitems = 0; assert(wait_once(&ep, out, 1) == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-epoll-fair-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: epoll rotates across continuously ready clients')
