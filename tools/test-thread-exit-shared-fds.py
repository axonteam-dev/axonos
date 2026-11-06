#!/usr/bin/env python3
"""A CLONE_THREAD worker exit must not close process-owned descriptors."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("                    for (int fd = 0; fd < THREAD_MAX_FD; ++fd) {", source.index("case SYS_exit: {"))
end = source.index("                    if (cur->mm_ptemplate)", start)
loop = source[start:end]
program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#define THREAD_MAX_FD 8
struct fs_file { int refs, fds; };
typedef struct thread thread_t;
typedef struct process { struct fs_file *fds[8]; int fd_cloexec[8]; thread_t *leader; } process_t;
struct thread { process_t *process; struct fs_file *fds[8]; };
static void fs_file_free(struct fs_file *f) { assert(f->refs > 0); --f->refs; }
static __attribute__((unused)) int fs_file_fd_close(struct fs_file *f) { assert(f->fds > 0); return --f->fds; }
static void worker_exit(thread_t *cur) {
''' + loop + r'''
}
int main(void) {
    process_t p={0}; thread_t leader={.process=&p}, worker={.process=&p}; p.leader=&leader;
    struct fs_file inherited={2,1}, worker_opened={1,1};
    p.fds[1]=leader.fds[1]=worker.fds[1]=&inherited;
    p.fds[2]=worker.fds[2]=&worker_opened;
    worker_exit(&worker);
    assert(p.fds[1]==&inherited && inherited.refs==1 && inherited.fds==1);
    assert(p.fds[2]==&worker_opened && worker_opened.refs==1 && worker_opened.fds==1);
    assert(!worker.fds[1] && !worker.fds[2]);
    puts("PASS: worker exit leaves worker-opened shared fd installed");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-thread-fds-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
