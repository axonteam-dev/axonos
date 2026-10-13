#!/usr/bin/env python3
"""Host regressions for init handoff, fork VMAs and pipe wakeup ordering.

Compile the actual kernel helpers with deterministic scheduler/MM fixtures;
no VM is started and no root filesystem is modified.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
syscalls = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
elf = (root / "core/elf.c").read_text()
vma = (root / "mm/user_vma.c").read_text()
mm = (root / "core/mm.c").read_text()


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


pipe_type = syscalls[syscalls.index("typedef struct pipe {"):
                     syscalls.index("} pipe_t;") + len("} pipe_t;")]
pipe_read = function(syscalls, "static ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur, int nonblock) {")
pipe_write = function(syscalls, "static ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur, int nonblock) {")
pipe_test = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef struct { int locked; } spinlock_t;
typedef struct { uint64_t tid; } thread_t;
''' + pipe_type + r'''
static void syscall_trace_init_spawn(thread_t *t, const char *event, uint64_t a, uint64_t b) {
    (void)t; (void)event; (void)a; (void)b;
}
static void openrc_pipe_wait_owners(pipe_t *p, thread_t *t) { (void)p; (void)t; }
static int pipe_trace_left = -1;
#define devel_printf(...) printf(__VA_ARGS__)
static pipe_t *active;
static int blocked, yields, inject;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(!lock->locked); lock->locked = 1; *flags = 0;
}
static void thread_block(int tid) {
    assert(tid == 7 && active->lock.locked);
    blocked = 1;
}
static void thread_unblock(int tid) {
    assert(tid == 7); blocked = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags;
    assert(lock->locked); lock->locked = 0;
    /* Force the exact formerly racy window: peer acts immediately at unlock. */
    if (inject && (active->reader_waiter_tid >= 0 || active->writer_waiter_tid >= 0)) {
        int event = inject; inject = 0;
        if (event == 1) { active->buf[0] = 'x'; active->head = 1; }
        if (event == 2 || event == 4) active->refcount = 1;
        if (event == 3) active->tail = active->head;
        if (active->reader_waiter_tid >= 0) {
            thread_unblock(active->reader_waiter_tid); active->reader_waiter_tid = -1;
        }
        if (active->writer_waiter_tid >= 0) {
            thread_unblock(active->writer_waiter_tid); active->writer_waiter_tid = -1;
        }
    }
}
static void thread_yield(void) {
    assert(!active->lock.locked && !blocked); yields++;
}
''' + pipe_read + "\n" + pipe_write + r'''
static void reset(pipe_t *p, uint8_t *buf) {
    memset(p, 0, sizeof(*p)); memset(buf, 0, 8);
    p->buf = buf; p->size = 8; p->refcount = 2;
    p->reader_waiter_tid = p->writer_waiter_tid = -1;
    active = p; blocked = yields = inject = 0;
}
int main(void) {
    pipe_t p; uint8_t data[8]; char out; thread_t self = {.tid = 7};
    reset(&p, data); inject = 1;
    assert(pipe_read_bytes(&p, &out, 1, &self, 0) == 1 && out == 'x');
    assert(yields == 1);
    reset(&p, data); inject = 2;
    assert(pipe_read_bytes(&p, &out, 1, &self, 0) == 0 && yields == 1);
    reset(&p, data); p.head = 7; inject = 3;
    assert(pipe_write_bytes(&p, "y", 1, &self, 0) == 1 && yields == 1);
    reset(&p, data); p.head = 7; inject = 4;
    assert(pipe_write_bytes(&p, "y", 1, &self, 0) == -EPIPE && yields == 1);
    reset(&p, data); p.refcount = 1;
    assert(pipe_write_bytes(&p, "y", 1, &self, 0) == -EPIPE && p.head == 0);
    reset(&p, data);
    assert(pipe_read_bytes(&p, &out, 1, &self, 1) == -EAGAIN);
    assert(!blocked && p.reader_waiter_tid == -1);
    p.head = 7;
    assert(pipe_write_bytes(&p, "y", 1, &self, 1) == -EAGAIN);
    assert(!blocked && p.writer_waiter_tid == -1);
    puts("PASS: pipe data/EOF/space/close wakeups cannot be lost; EPIPE/nonblocking");
}
'''

pid_start = elf.index("int is_pid1_path =") + len("int is_pid1_path =")
pid_expression = elf[pid_start:elf.index(";", pid_start)]
handoff_start = elf.index("        if (caller && resume_mm) {")
handoff = elf[handoff_start:elf.index("\n        }", handoff_start) + len("\n        }")]
mm_exit = function(mm, "int mm_switch_away_from(mm_t *dead) {")
handoff_test = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct { int identity; } mm_t;
typedef struct { mm_t *mm; } thread_t;
static mm_t g_kernel_mm = {1}, user_mm = {2}, other_mm = {3};
static mm_t *active;
static int g_mm_ready = 1;
static void mm_init(void) { g_mm_ready = 1; }
static int mm_switch(mm_t *mm) { active = mm; return 0; }
''' + mm_exit + r'''
static int is_init(const char *path) { return ''' + pid_expression + r'''; }
static void handoff(thread_t *caller, mm_t *resume_mm) {
''' + handoff + r'''
}
int main(void) {
    thread_t loader = {.mm = &user_mm}, init = {.mm = &user_mm};
    active = &user_mm;
    handoff(&loader, &g_kernel_mm);
    assert(loader.mm == &g_kernel_mm && active == &g_kernel_mm);
    assert(init.mm == &user_mm);
    handoff(&loader, NULL); assert(loader.mm == &g_kernel_mm);
    active = &other_mm;
    assert(mm_switch_away_from(&user_mm) == 0 && active == &g_kernel_mm);
    assert(mm_switch_away_from(&g_kernel_mm) == -1);
    assert(is_init("/usr/lib/systemd/systemd") && is_init("/lib/systemd/systemd"));
    assert(is_init("/sbin/init") && !is_init("/usr/bin/systemctl"));
    puts("PASS: init loader keeps kernel mm; fatal exit uses kernel root; systemd PID1");
}
'''
assert "kernel_execve_into_mm(k_interp, nargv, envp, resume_mm)" in elf
assert elf.index("if (caller && resume_mm)") < elf.index("/* Now make the new user thread runnable. */")

find_vma = function(vma, "static user_vma_t *user_vma_find_fault_nolock(thread_t *runner, uintptr_t va) {")
vma_test = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define USER_VMA_MAX 4
typedef struct { int used; uint64_t tid; uintptr_t addr, len; int prot; } user_vma_t;
typedef struct { user_vma_t vmas[USER_VMA_MAX]; } mm_t;
typedef struct { uint64_t tid; mm_t *mm; } thread_t;
static user_vma_t g_user_vmas[USER_VMA_MAX];
static user_vma_t *user_vma_mm_storage(mm_t *mm, int create) {
    (void)create; return mm ? mm->vmas : NULL;
}
static int user_vma_tid_matches_runner_mm_nolock(thread_t *runner, uint64_t tid) {
    return runner && runner->tid == tid;
}
''' + find_vma + r'''
int main(void) {
    mm_t child = {0}, unrelated = {0};
    thread_t runner = {.tid = 9, .mm = &child};
    child.vmas[0] = (user_vma_t){1, 0, 0x8000000, 4096, 5};
    g_user_vmas[0] = (user_vma_t){1, 88, 0x8000000, 4096, 0};
    assert(user_vma_find_fault_nolock(&runner, 0x8000fff) == &child.vmas[0]);
    assert(!user_vma_find_fault_nolock(&runner, 0x8001000));
    g_user_vmas[1] = (user_vma_t){1, 9, 0x8000000, 4096, 0};
    assert(user_vma_find_fault_nolock(&runner, 0x8000000) == &g_user_vmas[1]);
    memset(g_user_vmas, 0, sizeof(g_user_vmas)); runner.mm = &unrelated;
    assert(!user_vma_find_fault_nolock(&runner, 0x8000000));
    puts("PASS: fault lookup finds inherited mm-only VMAs and isolates processes");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-init-runtime-") as tmp:
    for name, program in (("pipe", pipe_test), ("handoff", handoff_test), ("vma", vma_test)):
        source = Path(tmp) / f"{name}.c"
        binary = Path(tmp) / name
        source.write_text(program)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
