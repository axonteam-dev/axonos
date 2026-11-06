#!/usr/bin/env python3
"""exec metadata synchronization must not republish stale fd mirrors."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "core/process.c").read_text()
elf = (root / "core/elf.c").read_text()
start = source.index("static void process_sync_thread_state(")
end = source.index("process_t *process_find(", start)
assert "process_sync_from_thread(cur_user->process, cur_user)" not in elf
assert "ut->fds[fd] = ut->process->fds[fd];" in elf
program = r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define PROCESS_MAX_FD 4
#define AXON_NGROUPS_MAX 4
typedef int gid_t;
typedef struct { void *mm; int pgid,sid,uid,euid,suid,gid,egid,sgid,ngroups;
    int groups[4],umask; char cwd[16],fs_root[16]; void *fds[4]; } process_t;
typedef struct { void *mm; int pgid,sid,uid,euid,suid,gid,egid,sgid,ngroups;
    int groups[4],umask; char cwd[16],fs_root[16]; void *fds[4]; } thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t process_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->held); l->held=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->held); l->held=0; }
''' + source[start:end] + r'''
int main(void) {
    int stale, live, newly_opened, new_mm;
    process_t p={0}; thread_t t={0};
    t.mm=&new_mm; t.fds[1]=&stale; t.fds[2]=NULL;
    p.fds[1]=NULL; p.fds[2]=&live; p.fds[3]=&newly_opened;
    process_sync_exec_from_thread(&p,&t);
    assert(p.mm==&new_mm && !p.fds[1] && p.fds[2]==&live && p.fds[3]==&newly_opened);
    process_t child={0}; t.fds[0]=&live;
    process_sync_from_thread(&child,&t);
    assert(child.fds[0]==&live && child.fds[1]==&stale);
    puts("PASS: exec keeps shared fds; fork initialization still publishes child fds");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-exec-fds-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
