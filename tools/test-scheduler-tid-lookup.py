#!/usr/bin/env python3
"""Verify bounded direct TID lookup and wakeups, including AP-origin fork wakes."""
from pathlib import Path
import subprocess
import tempfile

source=(Path(__file__).resolve().parents[1]/"cpu/thread/thread.c").read_text()


def function(signature):
    start=source.index(signature)
    while source.index(";",start)<source.index("{",start):
        start=source.index(signature,start+len(signature))
    opening=source.index("{",start);end=opening+1;depth=1
    while depth:
        depth+=(source[end]=="{")-(source[end]=="}");end+=1
    return source[start:end]


lookup=function("thread_t* thread_get(")
unblock=function("void thread_unblock(")
fork=function("void thread_unblock_fork_child(")
assert "for (" not in lookup+unblock+fork
program=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define MAX_THREADS 512
#define SMP_MAX_CPUS 2
enum { THREAD_READY,THREAD_RUNNING,THREAD_BLOCKED,THREAD_TERMINATED,THREAD_SLEEPING };
typedef struct {
    uint64_t tid,sched_vruntime;
    uint32_t sleep_until,sched_fifo_seq;
    int state,ring,bound_cpu,vfork_waiting;
} thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t sched_lock;
static thread_t *threads[512],*current_cpu[2];
static int reschedules;
static void acquire_irqsave(spinlock_t *l,unsigned long *f) { assert(!l->held);l->held=1;*f=0; }
static void release_irqrestore(spinlock_t *l,unsigned long f) { (void)f;assert(l->held);l->held=0; }
static void thread_note_ready_nolock(thread_t *t) { if(!t->vfork_waiting) t->state=THREAD_READY; }
static void thread_request_resched(void) { reschedules++; }
static int smp_sched_cpu_id(void) { return 1; }
'''+lookup+unblock+fork+r'''
int main(void) {
    thread_t last={.tid=511,.state=THREAD_BLOCKED,.ring=3,.sleep_until=123};
    threads[511]=&last;
    assert(thread_get(511)==&last&&thread_get(-1)==NULL&&thread_get(512)==NULL&&thread_get(0)==NULL);
    thread_unblock(511);assert(last.state==THREAD_READY&&!last.sleep_until&&reschedules==1);
    thread_unblock(511);assert(reschedules==1);
    last.state=THREAD_TERMINATED;thread_unblock(511);assert(last.state==THREAD_TERMINATED);
    last.state=THREAD_BLOCKED;last.vfork_waiting=1;thread_unblock(511);
    assert(last.state==THREAD_BLOCKED&&reschedules==1);
    last.vfork_waiting=0;
    thread_t parent={.sched_vruntime=100};current_cpu[1]=&parent;
    thread_unblock_fork_child(511);
    assert(last.state==THREAD_READY&&last.bound_cpu==0&&last.sched_vruntime==99);
    last.tid=510;assert(thread_get(511)==NULL); /* verify slot identity, not just address */
    puts("PASS: O(1) TID lookup/wake preserves lifecycle and binds ring3 fork children to their executable CPU");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-tid-lookup-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
