#!/usr/bin/env python3
"""Exercise real waitid dispatch, EOF-style WNOHANG output and exit/block ordering."""
from pathlib import Path
import subprocess
import tempfile

source=(Path(__file__).resolve().parents[1]/"syscall/dispatch/syscall_dispatch.c").read_text()
start=source.index("        case SYS_waitid: {")
body=source[start:source.index("        case SYS_ioctl:",start)]
assert "wait4_block_recheck(waiter, pid_arg)" in body
assert "thread_block(" not in body
helper_start=source.index("static void wait4_block_recheck(")
helper=source[helper_start:source.index("\n}\n",helper_start)+3]
program=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SIGCHLD 17
enum { SYS_waitid=247 };
enum { THREAD_READY=0, THREAD_BLOCKED=2, THREAD_TERMINATED=3 };
typedef struct process process_t;
typedef struct thread {
    uint64_t tid, pending_signals;
    int state, wait_upid, wait_options;
    process_t *process;
} thread_t;
struct process { int pgid, exit_status; uint64_t pid; uint32_t uid; thread_t *leader; };
static process_t owner={.pgid=1}, child_process={.pid=99,.uid=123,.exit_status=7<<8};
static thread_t child={.tid=8}, parent={.tid=4,.process=&owner};
static int dead, has_children=1, race_exit, blocks, yields, reaps;
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int user_range_ok(const void *p,size_t n) { (void)n; return p!=NULL; }
static int copy_to_user_safe(void *p,const void *s,size_t n) { memcpy(p,s,n);return 0; }
static process_t *process_find_child(process_t *p,int pid,int pgid,int zombies,int *has) {
    (void)pid;assert(p==&owner&&pgid==1&&zombies==1);*has=has_children;return dead?&child_process:NULL;
}
static thread_t *wait4_find_thread_zombie(thread_t *t,int pid) {
    (void)pid;assert(t==&parent);return dead&&child.state==THREAD_TERMINATED?&child:NULL;
}
static int process_reap(process_t *p,process_t *c) { assert(p==&owner&&c==&child_process);reaps++;dead=0;return 0; }
static int thread_reap(int tid) { assert(tid==8);return 0; }
static thread_t *find_terminated_child(thread_t *t) { (void)t;return NULL; }
static int wait4_eintr_pending(thread_t *t) { (void)t;return 0; }
static void thread_block(int tid) { assert(tid==4);blocks++;parent.state=THREAD_BLOCKED; }
static void thread_unblock(int tid) { assert(tid==4);parent.state=THREAD_READY; }
static void wait4_arm_children(thread_t *t,int pid) {
    (void)pid;assert(t==&parent);
    if(race_exit) { dead=1;child.state=THREAD_TERMINATED;child_process.leader=&child;thread_unblock(4); }
}
static void thread_yield(void) { yields++;assert(!"lost wakeup caused an unexpected yield"); }
static void syscall_restore_live_frame_from_snapshot(thread_t *t,const char *label) { (void)t;(void)label; }
'''+helper+r'''
static uint64_t run(thread_t *cur,uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4) {
    switch(SYS_waitid) {
'''+body+r'''
    }
    return ret_err(ENOSYS);
}
int main(void) {
    uint8_t info[128];memset(info,0xa5,sizeof(info));
    assert(run(&parent,0,0,(uintptr_t)info,4|1)==0);
    for(unsigned i=0;i<sizeof(info);i++)assert(info[i]==0);
    assert(parent.wait_upid==-1&&!blocks&&!yields);
    assert((int64_t)run(&parent,1,0,(uintptr_t)info,4)==-EINVAL);
    assert((int64_t)run(&parent,2,(uint64_t)-1,(uintptr_t)info,4)==-EINVAL);
    race_exit=1;
    assert(run(&parent,0,0,(uintptr_t)info,4)==0);
    assert(blocks==1&&!yields&&reaps==1);
    assert(*(int32_t*)(info+0)==SIGCHLD&&*(int32_t*)(info+8)==1);
    assert(*(int32_t*)(info+16)==99&&*(uint32_t*)(info+20)==123&&*(int32_t*)(info+24)==7);
    race_exit=0;dead=1;child.state=THREAD_TERMINATED;child_process.leader=&child;
    assert(run(&parent,1,99,(uintptr_t)info,4|0x01000000)==0&&reaps==1); /* WNOWAIT */
    puts("PASS: waitid exit/block race, WNOHANG zero siginfo, uid/status, WNOWAIT and invalid IDs");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-waitid-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                    "-fsanitize=undefined",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
