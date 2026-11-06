#!/usr/bin/env python3
"""Fork/clone must never inherit stale slots from a thread fd mirror."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void fork_inherit_fd_table(thread_t *child, thread_t *parent) {")
end = source.index("\n}\n", start) + 3
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#define THREAD_MAX_FD 8
#define PROCESS_MAX_FD 8
struct fs_file { int refcount, fds, type; void *driver_private; };
typedef struct process { struct fs_file *fds[8]; int fd_cloexec[8]; } process_t;
typedef struct thread { process_t *process; struct fs_file *fds[8]; } thread_t;
typedef struct { int unused; } ksock_net_t;
#define SYSCALL_FTYPE_SOCKET 123
static __attribute__((unused)) int fork_socket_should_share_ksock(ksock_net_t *s) { (void)s; return 0; }
static __attribute__((unused)) struct fs_file *fork_child_socket_file(struct fs_file *f) { (void)f; return NULL; }
static __attribute__((unused)) void fs_file_get(struct fs_file *f) { assert(f->refcount > 0); f->refcount++; }
static __attribute__((unused)) void fs_file_fd_open(struct fs_file *f) { f->fds++; }
''' + source[start:end] + r'''
int main(void) {
    struct fs_file current={.refcount=1,.fds=1}, stale={0}, local={.refcount=1,.fds=1};
    process_t parent_proc={0}, child_proc={0};
    thread_t parent={.process=&parent_proc}, forked={.process=&child_proc},
             worker={.process=&parent_proc}, no_proc={0}, independent={0};
    parent_proc.fds[1]=&current; parent.fds[1]=&stale;
    parent.fds[2]=&stale; /* shared slot was closed */
    fork_inherit_fd_table(&forked,&parent);
    assert(forked.fds[1]==&current && !forked.fds[2]);
    assert(current.refcount==2);
    fork_inherit_fd_table(&worker,&parent);
    assert(worker.fds[1]==&current && !worker.fds[2]);
    assert(current.refcount==3);
    no_proc.fds[0]=&local;
    fork_inherit_fd_table(&independent,&no_proc);
    assert(independent.fds[0]==&local && local.refcount==2);
    puts("PASS: fork and clone use shared fd table including closed slots");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-fork-fd-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
