#!/usr/bin/env python3
"""Test the actual PTY claim and syscall open eligibility helpers on the host."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
pty = (root / 'fs/virt/pty.c').read_text()
syscall = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
claim = pty[pty.index('int pty_try_acquire_ctty('):pty.index('int pty_get_controlling_sid(')]
helper = syscall[syscall.index('static int thread_has_ctty('):syscall.index('/* Readiness for an open file')]
assert syscall.count('syscall_pty_maybe_acquire_ctty(cur, f, flags);') == 2
program = r'''
#include <assert.h>
#include <stddef.h>
typedef struct { int pid, sid, pgid; } process_t;
typedef struct { int attached_tty, attached_pty, tid, sid, pgid; process_t *process; } thread_t;
struct pty_pair { int controlling_sid, fg_pgrp; };
struct pty_handle { int is_master; struct pty_pair *pair; };
struct fs_file { struct pty_handle *h; };
static int g_pty_table_lock;
static struct pty_handle *pty_handle_of(struct fs_file *f) { return f ? f->h : NULL; }
static int pty_get_index(struct fs_file *f) { (void)f; return 3; }
static void acquire_irqsave(int *l, unsigned long *f) { assert(!*l); *l = 1; *f = 0; }
static void release_irqrestore(int *l, unsigned long f) { (void)f; assert(*l); *l = 0; }
''' + claim + helper + r'''
int main(void) {
    struct pty_pair pair = {-1, -1};
    struct pty_handle h = {0, &pair}; struct fs_file f = {&h};
    process_t p = {42, 42, 42}; thread_t t = {-1, -1, 42, 42, 42, &p};
    syscall_pty_maybe_acquire_ctty(&t, &f, 0x100); assert(pair.controlling_sid == -1);
    syscall_pty_maybe_acquire_ctty(&t, &f, 0x200000); assert(pair.controlling_sid == -1);
    h.is_master = 1; syscall_pty_maybe_acquire_ctty(&t, &f, 0); assert(pair.controlling_sid == -1);
    h.is_master = 0; p.sid = 7; syscall_pty_maybe_acquire_ctty(&t, &f, 0); assert(pair.controlling_sid == -1);
    p.sid = 42; syscall_pty_maybe_acquire_ctty(&t, &f, 0);
    assert(pair.controlling_sid == 42 && pair.fg_pgrp == 42 && t.attached_pty == 3);
    t.attached_pty = -1; p.pid = p.sid = 43;
    syscall_pty_maybe_acquire_ctty(&t, &f, 0); assert(t.attached_pty == -1 && pair.controlling_sid == 42);
    return 0;
}
'''
with tempfile.TemporaryDirectory(dir='/tmp/opencode', prefix='pty-ctty-') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: PTY automatic controlling-terminal eligibility and ownership')
