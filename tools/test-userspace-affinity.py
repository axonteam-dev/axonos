#!/usr/bin/env python3
"""Run actual affinity dispatch against the scheduler's current BSP-only policy."""
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[1]
source=(root/"syscall/dispatch/syscall_dispatch.c").read_text()
start=source.index("        case SYS_sched_getaffinity:")
body=source[start:source.index("        case SYS_sched_setscheduler:",start)]
assert "smp_default_affinity_mask" not in body
program=r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
enum { SYS_sched_getaffinity=204, SYS_sched_setaffinity=203 };
typedef struct { uint64_t tid, linux_tid; } thread_t;
static int copies;
static uint64_t linux_task_tid(thread_t *t) { return t->linux_tid; }
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int user_range_ok(const void *p,size_t n) { (void)n;return p!=NULL; }
static int copy_to_user_safe(void *to,const void *from,size_t n) { copies++;memcpy(to,from,n);return 0; }
static int copy_from_user_raw(void *to,const void *from,size_t n) { if(!from)return -1;memcpy(to,from,n);return 0; }
static uint64_t run(thread_t *cur,uint64_t num,uint64_t a1,uint64_t a2,uint64_t a3) {
    switch(num) {
'''+body+r'''
    }
    return ret_err(ENOSYS);
}
int main(void) {
    thread_t task={.tid=4,.linux_tid=313};_Alignas(8) uint8_t mask[128];memset(mask,0xa5,sizeof(mask));
    assert(run(&task,SYS_sched_getaffinity,0,sizeof(mask),(uintptr_t)mask)==8);
    assert(*(uint64_t*)mask==1&&copies==1);
    for(unsigned i=8;i<sizeof(mask);i++)assert(mask[i]==0xa5); /* only returned bytes are written */
    assert(run(&task,SYS_sched_getaffinity,313,8,(uintptr_t)mask)==8);
    assert((int64_t)run(&task,SYS_sched_getaffinity,4,8,(uintptr_t)mask)==-ESRCH);
    assert((int64_t)run(&task,SYS_sched_getaffinity,0,1,(uintptr_t)mask)==-EINVAL);
    assert((int64_t)run(&task,SYS_sched_getaffinity,0,8,0)==-EFAULT);
    mask[0]=2;
    assert((int64_t)run(&task,SYS_sched_setaffinity,0,1,(uintptr_t)mask)==-EINVAL);
    mask[0]=3;
    assert(run(&task,SYS_sched_setaffinity,0,1,(uintptr_t)mask)==0);
    assert(run(&task,SYS_sched_getaffinity,0,sizeof(mask),(uintptr_t)mask)==8&&*(uint64_t*)mask==1);
    puts("PASS: raw affinity byte count, real BSP mask, Linux TID, EINVAL and one bounded copy (not per-byte clearing)");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-affinity-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                    "-fsanitize=undefined",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
