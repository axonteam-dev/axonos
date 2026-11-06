#!/usr/bin/env python3
"""A signal arriving before sigsuspend blocks must not leave the task blocked."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
case = source.index("case SYS_rt_sigsuspend: {")
start = source.index("                thread_block(wait_tid);", case)
end = source.index("                syscall_restore_live_frame_from_snapshot", start)
snippet = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define THREAD_BLOCKED 1
#define THREAD_READY 2
typedef struct { uint64_t pending_signals; int state; } thread_t;
static thread_t task;
static int inject, yielded;
static void thread_block(int tid) { (void)tid; task.state=THREAD_BLOCKED; if (inject) task.pending_signals=1; }
static void thread_unblock(int tid) { (void)tid; task.state=THREAD_READY; }
static void thread_yield(void) { yielded++; }
static void wait_once(void) {
    thread_t *tcur=&task; int wait_tid=1; uint64_t new_mask=0;
''' + snippet + r'''
}
int main(void) {
    inject=1; wait_once(); assert(task.state==THREAD_READY && yielded==0);
    inject=0; task.pending_signals=0; wait_once(); assert(task.state==THREAD_BLOCKED && yielded==1);
    puts("PASS: sigsuspend restores runnable state after signal/block race");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sigsuspend-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
