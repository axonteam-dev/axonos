#!/usr/bin/env python3
"""Compare the actual epoll scan with its former modulo-based indexing."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('int scan_count = ep->nitems;')
end = source.index('\n                if (nout > 0)', start)
scan = source[start:end]
new_loop = '''for (int scanned = 0, i = scan_start;
                     scanned < scan_count && nout < maxevents;
                     scanned++, i = (i + 1 == scan_count ? 0 : i + 1)) {'''
old_loop = '''for (int scanned = 0; scanned < scan_count && nout < maxevents; scanned++) {
                    int i = (scan_start + scanned) % scan_count;'''
assert new_loop in scan
old = scan.replace(new_loop, old_loop).replace(
    'ep->next_scan = (i + 1 == scan_count ? 0 : i + 1);',
    'ep->next_scan = (i + 1) % scan_count;')
prefix = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#define EPOLLIN_K 1
#define EPOLLET_K (1u << 31)
#define EPOLLONESHOT_K (1u << 30)
typedef struct { int ready; size_t seq; } file;
typedef struct { int fd; file *file; uint32_t events; uint64_t data;
    int et_delivered; size_t et_stream_write_seq; } epoll_item_t;
typedef struct { int nitems, next_scan; epoll_item_t items[256]; } kepoll_t;
typedef struct { uint32_t events; uint64_t data; } event;
static int epoll_interest_to_poll(uint32_t e) { return e & 1; }
static size_t epoll_stream_read_seq(file *f) { return f->seq; }
static short fd_file_poll_revents(void *t, file *f, short want)
{ (void)t; return f->ready ? want : 0; }
static uint32_t poll_to_epoll_revents(short r, uint32_t e) { return r & e; }
'''
def function(name, body):
    return f'static int {name}(kepoll_t *ep, event *outbuf, int maxevents) {{\n' + \
        'int nout = 0; void *wait_thr = 0;\n' + body + '\nreturn nout;\n}\n'

main = r'''
static uint64_t ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec; }
int main(void) {
    kepoll_t a = {0}, b; file clients[127] = {{0}}; event out[128];
    a.nitems = 127;
    for (int i = 0; i < a.nitems; ++i) {
        a.items[i].fd = i; a.items[i].file = &clients[i];
        a.items[i].events = EPOLLIN_K; a.items[i].data = i;
    }
    b = a;
    uint64_t times[2], sums[2] = {0, 0};
    for (int mode = 0; mode < 2; ++mode) {
        kepoll_t *ep = mode ? &b : &a;
        uint64_t start = ns();
        for (int j = 0; j < 200000; ++j) {
            clients[j % 127].ready = 1;
            int n = mode ? optimized(ep, out, 4) : baseline(ep, out, 4);
            for (int k = 0; k < n; ++k) sums[mode] += out[k].data + 1;
            clients[j % 127].ready = 0;
        }
        times[mode] = ns() - start;
    }
    if (sums[0] != sums[1] || a.next_scan != b.next_scan) return 1;
    printf("PASS: matching results; baseline %.1f ns/scan, optimized %.1f ns/scan\n",
           times[0] / 200000.0, times[1] / 200000.0);
}
'''
with tempfile.TemporaryDirectory(prefix='axon-epoll-bench-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'bench.c', Path(tmp) / 'bench'
    src.write_text(prefix + function('baseline', old) + function('optimized', scan) + main)
    subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
