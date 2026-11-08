#!/usr/bin/env python3
"""Check ioctl's FD lookup against shared-table reuse and close."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'syscall/dispatch/syscall_dispatch.c').read_text()
ioctl = source[source.index('case SYS_ioctl:'):]
start = ioctl.index('struct fs_file *f = cur->process ? cur->process->fds[fd] : cur->fds[fd];')
lookup = ioctl[start:ioctl.index('\n', start)]
program = r'''
#include <assert.h>
#include <stddef.h>
struct fs_file { int id; };
struct process { struct fs_file *fds[4]; };
struct thread { struct process *process; struct fs_file *fds[4]; };
static struct fs_file *lookup(struct thread *cur, int fd) {
''' + lookup + r'''
    return f;
}
int main(void) {
    struct fs_file old = {1}, pty = {2};
    struct process p = {0}; struct thread t = {0};
    t.process = &p; t.fds[2] = &old; p.fds[2] = &pty;
    assert(lookup(&t, 2) == &pty);
    p.fds[2] = NULL; assert(lookup(&t, 2) == NULL);
    t.process = NULL; assert(lookup(&t, 2) == &old);
}
'''
with tempfile.TemporaryDirectory(prefix='axon-ioctl-fd-', dir='/tmp/opencode') as tmp:
    c, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    c.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: ioctl uses the shared descriptor table, including closed slots')
