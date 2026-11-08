#!/usr/bin/env python3
"""Exercise the kernel PTY read with a wake immediately after block arming."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'fs/virt/pty.c').read_text()
def extract(start, end):
    return source[source.index(start):source.index(end, source.index(start))]
ring_read = extract('static ssize_t pty_ring_read(', 'static size_t pty_ring_avail(')
avail = extract('static size_t pty_ring_avail(', 'static void pty_ring_flush(')
read = extract('ssize_t pty_read(', 'ssize_t pty_write(')
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define PTY_BUF_CAP 16
typedef int spinlock_t;
struct pty_ring { char buf[PTY_BUF_CAP]; size_t head, tail, count;
                  spinlock_t lock; int waiters[8], waiters_count; };
struct pty_pair { int master_opens, slave_opens; struct pty_ring m2s, s2m; };
struct pty_handle { struct pty_pair *pair; int is_master; };
struct fs_file { struct pty_handle *h; int flags; };
typedef struct { int tid; uint64_t pending_signals, saved_sig_mask; } thread_t;
static thread_t thread = {1, 0, 0};
static struct pty_pair *pair;
static int blocked, inject;
static struct pty_handle *pty_handle_of(struct fs_file *f) { return f->h; }
static thread_t *thread_current(void) { return &thread; }
static thread_t *thread_get_current_user(void) { return &thread; }
static void acquire_irqsave(spinlock_t *l, unsigned long *flags)
{ assert(!*l); *l = 1; *flags = 0; }
static void release_irqrestore(spinlock_t *l, unsigned long flags) {
    (void)flags; assert(*l); *l = 0;
    if (blocked && inject) {
        if (inject == 1) { pair->s2m.buf[0] = 'X'; pair->s2m.count = 1; }
        else if (inject == 2) pair->slave_opens = 0;
        else thread.pending_signals = 1;
        blocked = 0; inject = 0;
    }
}
static void thread_block(int tid) { assert(tid == 1); blocked = 1; }
static void thread_yield(void) { assert(!blocked); }
static void thread_sleep(unsigned ms) {
    assert(ms == 1 && !blocked);
    pair->s2m.buf[pair->s2m.head] = 'Y'; pair->s2m.count = 1;
}
''' + ring_read + avail + read + r'''
int main(void) {
    struct pty_pair p = {0}; p.master_opens = p.slave_opens = 1; pair = &p;
    struct pty_handle h = {&p, 1}; struct fs_file f = {&h, 0}; char c;
    inject = 1; assert(pty_read(&f, &c, 1) == 1 && c == 'X');
    inject = 2; assert(pty_read(&f, &c, 1) == 0);
    p.slave_opens = 1; f.flags = 0x800; assert(pty_read(&f, &c, 1) == -11);
    f.flags = 0; p.s2m.waiters_count = 8;
    assert(pty_read(&f, &c, 1) == 1 && c == 'Y');
    p.s2m.waiters_count = 0; inject = 3;
    assert(pty_read(&f, &c, 1) == -4 && p.s2m.waiters_count == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-pty-read-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: PTY data and peer-close wakeups cannot be lost')
