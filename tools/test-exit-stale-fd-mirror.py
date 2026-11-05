#!/usr/bin/env python3
"""Exiting a process must not release closed entries from its tid mirror."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void thread_close_all_fds(thread_t *cur) {")
end = source.index("\n}\n", start) + 3
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define PROCESS_MAX_FD 8
#define THREAD_MAX_FD 8
struct fs_file { int refs, fds; };
typedef struct process { struct fs_file *fds[8]; int fd_cloexec[8]; } process_t;
typedef struct thread { process_t *process; struct fs_file *fds[8]; } thread_t;
static thread_t *threads[3];
static int thread_get_count(void) { return 3; }
static thread_t *thread_get_by_index(int i) { return threads[i]; }
static __attribute__((unused)) int fs_file_fd_close(struct fs_file *f) { assert(f->fds>0); return --f->fds; }
static void fs_file_free(struct fs_file *f) { assert(f->refs>0); --f->refs; }
''' + source[start:end] + r'''
int main(void) {
    process_t p={0}, other={0};
    thread_t leader={.process=&p}, worker={.process=&p}, outsider={.process=&other};
    struct fs_file live={2,2}, stale={0,0}, orphan={1,1};
    threads[0]=&leader; threads[1]=&worker; threads[2]=&outsider;
    p.fds[1]=p.fds[2]=&live;
    leader.fds[1]=leader.fds[2]=&live;
    worker.fds[1]=&live;
    leader.fds[3]=&stale; /* sibling closed and freed shared fd 3 */
    outsider.fds[1]=&live;
    thread_close_all_fds(&leader);
    assert(live.refs==0 && !p.fds[1] && !p.fds[2]);
    assert(!leader.fds[1] && !leader.fds[2] && !leader.fds[3] && !worker.fds[1]);
    assert(outsider.fds[1]==&live && stale.refs==0);
    thread_t no_process={0}; no_process.fds[0]=&orphan;
    thread_close_all_fds(&no_process);
    assert(orphan.refs==0 && !no_process.fds[0]);
    puts("PASS: process exit ignores stale fd mirrors and closes shared descriptors once");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-exit-fd-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
