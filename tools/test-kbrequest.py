#!/usr/bin/env python3
"""Exercise actual KDSIGACCEPT registration and Alt-Up signal dispatch."""
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parents[1]
source=(root/"syscall/dispatch/syscall_dispatch.c").read_text()
keyboard=(root/"drv/input/keyboard.c").read_text()
assert "if (alt_pressed) syscall_kbrequest_event();" in keyboard


def function(signature):
    start=source.index(signature)
    return source[start:source.index("\n}\n",start)+3]


program=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define SIGKILL 9
#define THREAD_TERMINATED 3
typedef struct { int euid, state; uint64_t tid, pid, pending_signals; } thread_t;
typedef struct { thread_t *leader; } process_t;
typedef struct { int held; } spinlock_t;
static spinlock_t kbrequest_lock;
static uint64_t kbrequest_pid;
static int kbrequest_signal;
static thread_t target={.tid=5,.pid=1};
static process_t process={&target};
static uint64_t process_pid(thread_t *t) { return t->pid; }
static process_t *process_find(uint64_t pid) { return pid==target.pid ? &process : NULL; }
static void acquire_irqsave(spinlock_t *l,unsigned long *f) { assert(!l->held);l->held=1;*f=0; }
static void release_irqrestore(spinlock_t *l,unsigned long f) { (void)f;assert(l->held);l->held=0; }
static void thread_set_pending_signal(thread_t *t,int sig) { t->pending_signals|=1ULL<<(sig-1); }
'''+function("static int kbrequest_register(")+function("void syscall_kbrequest_event(")+r'''
int main(void) {
    syscall_kbrequest_event(); assert(!target.pending_signals);
    thread_t unpriv={.euid=1000,.pid=2};
    assert(kbrequest_register(&unpriv,28)==-1);
    assert(kbrequest_register(&target,0)==-22 && kbrequest_register(&target,9)==-22);
    assert(kbrequest_register(&target,65)==-22);
    assert(kbrequest_register(&target,28)==0);
    syscall_kbrequest_event();assert(target.pending_signals==(1ULL<<27));
    target.pending_signals=0;target.state=THREAD_TERMINATED;
    syscall_kbrequest_event();assert(!target.pending_signals);
    target.state=0;target.pid=3;
    syscall_kbrequest_event();assert(!target.pending_signals); /* dead PID registration must not target a reused slot */
    puts("PASS: KDSIGACCEPT permissions/range and actual kbrequest signal delivery, no dead/reused target");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-kbrequest-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
