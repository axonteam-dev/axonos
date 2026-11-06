#!/usr/bin/env python3
"""Reap thread-keyed VMA mirrors without touching the shared mm's entries."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_vma.c").read_text()
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("void user_vma_remove_all_for_tid(")
end = source.index("\n}\n", start) + 3
worker = dispatch[dispatch.index("case SYS_exit: {"):]
assert "user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));" in worker[:worker.index("int ignore_sigchld")]
peer = dispatch[dispatch.index("static void exit_group_reap_peer_threads(thread_t *cur) {"):]
assert "user_vma_remove_all_for_tid((uint64_t)(t->tid ? t->tid : 1));" in peer[:peer.index("static int force_fatal_signal_thread_group")]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define USER_VMA_MAX 4
typedef struct { int used; uint64_t tid; int *refs; } user_vma_t;
typedef struct { int locked; } spinlock_t;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->locked); l->locked=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; assert(l->locked); l->locked=0; }
static void user_vma_clear_nolock(user_vma_t *v) { if (v->refs) --*v->refs; v->used=0; }
''' + source[start:end] + r'''
int main(void) {
    int refs=3;
    g_user_vmas[0]=(user_vma_t){1,1,&refs};
    g_user_vmas[1]=(user_vma_t){1,2,&refs};
    g_user_vmas[2]=(user_vma_t){1,2,&refs};
    user_vma_remove_all_for_tid(2);
    assert(g_user_vmas[0].used && !g_user_vmas[1].used && !g_user_vmas[2].used && refs==1);
    puts("PASS: exiting worker releases only its tid VMA records");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vma-exit-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
