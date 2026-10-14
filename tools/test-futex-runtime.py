#!/usr/bin/env python3
"""Run the actual futex backend with deterministic scheduler/clock interleavings."""
from pathlib import Path
import subprocess
import tempfile

source=(Path(__file__).resolve().parents[1]/"syscall/futex/futex.c").read_text()
body="\n".join(line for line in source.splitlines() if not line.startswith("#include "))
program=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define MMIO_IDENTITY_LIMIT UINTPTR_MAX
enum { THREAD_READY=0, THREAD_RUNNING=1, THREAD_BLOCKED=2, THREAD_TERMINATED=3 };
typedef struct { int id; } mm_t;
typedef struct {
    uint64_t tid,pending_signals,saved_sig_mask;
    int state;
    mm_t *mm;
    void *active_futex_waiter;
} thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t futex_lock;
static mm_t a_mm={1},b_mm={2};
static thread_t a={.tid=5,.mm=&a_mm,.state=THREAD_RUNNING}, b={.tid=6,.mm=&b_mm,.state=THREAD_RUNNING};
static thread_t *current=&a;
static uint32_t word=1,second=1,alias=1;
static int change_on_lock, live_allocs, blocks, yields, mode;
static uint64_t now_ns;
static uint32_t delay_ms;
enum { TIMEOUT, WAKE, SIGNAL, BITSET, REQUEUE, SHARED };
static thread_t *thread_current(void) { return current; }
static thread_t *thread_get(int tid) { return tid==5?&a:tid==6?&b:NULL; }
static void acquire_irqsave(spinlock_t *l,unsigned long *f) {
    assert(!l->held);l->held=1;*f=0;
    if(l==&futex_lock&&change_on_lock) { word=7;change_on_lock=0; }
}
static void release_irqrestore(spinlock_t *l,unsigned long f) { (void)f;assert(l->held);l->held=0; }
static void *kmalloc(size_t n) { void *p=malloc(n);assert(p);live_allocs++;return p; }
static void kfree(void *p) { if(p) { live_allocs--;free(p); } }
static int mm_copy_from_user(mm_t *m,void *dst,uint64_t address,size_t n) {
    if(!m||address<=0x1000)return -1;
    memcpy(dst,(void*)(uintptr_t)address,n);return 0;
}
static int mm_user_leaf_pa(mm_t *m,uint64_t address,int write,uint64_t *pa) {
    (void)m;(void)write;
    if(address==(uintptr_t)&word||address==(uintptr_t)&alias) { *pa=0x10000;return 0; }
    if(address==(uintptr_t)&second) { *pa=0x20000;return 0; }
    return -1;
}
static uint64_t time_monotonic_us(void) { return now_ns/1000; }
static void ktime_get_real_ts64(int64_t *sec,int64_t *ns) {
    *sec=100+(int64_t)(now_ns/1000000000ULL);*ns=now_ns%1000000000ULL;
}
static void thread_block(int tid) { assert(tid==5);a.state=THREAD_BLOCKED;blocks++; }
static void thread_block_with_timeout(int tid,uint32_t ms) { thread_block(tid);delay_ms=ms; }
static void thread_unblock(int tid) { thread_t *t=thread_get(tid);assert(t);t->state=THREAD_READY; }
static void thread_yield(void);
'''+body+r'''
static void thread_yield(void) {
    assert(current==&a&&a.state==THREAD_BLOCKED&&!futex_lock.held);yields++;
    if(mode==TIMEOUT) { now_ns+=(uint64_t)delay_ms*1000000ULL;thread_unblock(5); }
    else if(mode==SIGNAL) { a.pending_signals=2;thread_unblock(5); }
    else {
        current=&b;
        if(mode==WAKE) {
            b.mm=&b_mm;
            assert(futex_syscall((uintptr_t)&word,129,1,NULL,0,0)==0); /* wrong private mm */
            b.mm=&a_mm;
            assert(futex_syscall((uintptr_t)&word,129,1,NULL,0,0)==1);
        } else if(mode==BITSET) {
            b.mm=&a_mm;
            assert(futex_syscall((uintptr_t)&word,138,1,NULL,0,1)==0);
            assert(futex_syscall((uintptr_t)&word,138,1,NULL,0,2)==1);
        } else if(mode==REQUEUE) {
            b.mm=&a_mm;
            assert(futex_syscall((uintptr_t)&word,132,0,(void*)1,(uintptr_t)&second,2)==-11);
            assert(futex_syscall((uintptr_t)&word,131,0,(void*)1,(uintptr_t)&second,0)==1);
            assert(futex_syscall((uintptr_t)&word,129,1,NULL,0,0)==0);
            assert(futex_syscall((uintptr_t)&second,129,1,NULL,0,0)==1);
        } else if(mode==SHARED) {
            b.mm=&b_mm;
            assert(futex_syscall((uintptr_t)&alias,1,1,NULL,0,0)==1);
        }
        current=&a;
    }
    a.state=THREAD_RUNNING;
}
static void reset(void) {
    assert(!live_allocs&&!a.active_futex_waiter&&!futex_lock.held);
    a.state=THREAD_RUNNING;a.pending_signals=0;word=1;now_ns=0;blocks=0;yields=0;
}
int main(void) {
    struct { int64_t sec,ns; } ts={0,5000000};
    mode=TIMEOUT;
    assert(futex_syscall((uintptr_t)&word,128,1,&ts,0,0)==-110);
    assert(delay_ms==5&&yields==1);reset();
    ts.ns=10;
    assert(futex_syscall((uintptr_t)&word,128,1,&ts,0,0)==-110&&delay_ms==1);reset();
    ts.ns=1000000000;
    assert(futex_syscall((uintptr_t)&word,128,1,&ts,0,0)==-22);reset();
    change_on_lock=1;
    assert(futex_syscall((uintptr_t)&word,128,1,NULL,0,0)==-11&&!blocks);reset();
    mode=WAKE;
    assert(futex_syscall((uintptr_t)&word,128,1,NULL,0,0)==0);reset();
    mode=SIGNAL;
    assert(futex_syscall((uintptr_t)&word,128,1,NULL,0,0)==-4);reset();
    mode=BITSET;
    assert(futex_syscall((uintptr_t)&word,137,1,NULL,0,2)==0);reset();
    mode=REQUEUE;
    assert(futex_syscall((uintptr_t)&word,128,1,NULL,0,0)==0);reset();
    mode=SHARED;
    assert(futex_syscall((uintptr_t)&word,0,1,NULL,0,0)==0);reset();
    mode=TIMEOUT;ts.sec=100;ts.ns=5000000;
    assert(futex_syscall((uintptr_t)&word,137|256,1,&ts,0,1)==-110&&delay_ms==5);reset();
    ts.sec=30*24*60*60;ts.ns=0;
    assert(futex_syscall((uintptr_t)&word,128,1,&ts,0,0)==-110&&yields==2);reset();
    assert(futex_syscall((uintptr_t)&word+1,128,1,NULL,0,0)==-22);
    assert(futex_syscall((uintptr_t)&word,137,1,NULL,0,0)==-22);
    assert(futex_syscall(0x1000,128,1,NULL,0,0)==-14);reset();
    /* Reaping a killed waiter must remove its registration before slot reuse. */
    unsigned long flags;acquire_irqsave(&futex_lock,&flags);
    futex_node_t *node=futex_find_node((uintptr_t)&word,&a_mm,1);
    futex_waiter_t *w=kmalloc(sizeof(*w));memset(w,0,sizeof(*w));
    w->tid=5;w->bitset=UINT32_MAX;w->node=node;node->waiters=w;a.active_futex_waiter=w;
    release_irqrestore(&futex_lock,flags);
    a.state=THREAD_TERMINATED;futex_cancel_thread(&a);reset();
    assert(futex_syscall((uintptr_t)&word,129,1,NULL,0,0)==0);
    puts("PASS: actual futex relative/absolute timeout, bitsets, private/shared keys, atomic recheck, EINTR, requeue and reap cleanup");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-futex-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                    "-fsanitize=address,undefined",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
