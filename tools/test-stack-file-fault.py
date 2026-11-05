#!/usr/bin/env python3
"""A spawn stack's TLS allowance must not shadow a file-backed code VMA."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
def function(path, start):
    source = (root / path).read_text()
    i = source.index(start)
    return source[i:source.index("\n}\n", i) + 3]

lookup = function("mm/user_vma.c", "int user_vma_is_lazy_file_page_for(")
stack = function("cpu/ints/idt.c", "static int fault_try_user_stack_page(")
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_TLS_SIZE (2u * 1024u * 1024u)
typedef struct { int lock; } spinlock_t;
typedef struct mm { int dummy; } mm_t;
typedef struct thread {
    int ring; uintptr_t user_stack_base, user_stack_limit; mm_t *mm, *mm_ptemplate;
} thread_t;
#define USER_VMA_MAX 4
typedef struct { int used, file; uint64_t tid; uintptr_t addr; size_t len; } user_vma_t;
static user_vma_t g_user_vmas[USER_VMA_MAX], mm_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;
static mm_t mm;
static thread_t child = {3, 0x8389000, 0x8392000, &mm, NULL};
static int allocations, leaf_present;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { assert(!l->lock); l->lock=1; *f=0; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; l->lock=0; }
static int user_vma_tid_matches_runner_mm_nolock(thread_t *t, uint64_t tid) {
    assert(t == &child); return tid == 1;
}
static user_vma_t *user_vma_mm_storage(mm_t *m, int create) {
    (void)create; return m ? mm_vmas : NULL;
}
static int user_vma_is_filemap(const user_vma_t *v) { return v && v->file; }
static thread_t *thread_current(void) { return &child; }
static thread_t *thread_get_current_user(void) { return &child; }
static int mm_va_leaf_pa(mm_t *m, uint64_t va, uint64_t *pa) {
    (void)m; (void)va; *pa=0; return leaf_present ? 0 : -1;
}
static void invlpg(void *p) { (void)p; }
static mm_t *mm_kernel(void) { return &mm; }
static int mm_make_private_range_noyield(mm_t *m, uint64_t lo, uint64_t hi,
                                         int copy, mm_t *share) {
    (void)m; (void)lo; (void)hi; (void)copy; (void)share; allocations++; return 0;
}
''' + lookup + stack + r'''
int main(void) {
    mm_vmas[0] = (user_vma_t){.used=1, .file=1, .addr=0x8235000, .len=0x1000};
    /* libc execve page is within 2 MiB below the spawn stack. */
    assert(fault_try_user_stack_page(0x8235000, 0x14) == 0);
    assert(allocations == 0);
    mm_vmas[0].used=0;
    g_user_vmas[0] = (user_vma_t){.used=1, .file=1, .tid=1,
                                  .addr=0x8235000, .len=0x1000};
    assert(fault_try_user_stack_page(0x8235000, 0x14) == 0);
    assert(allocations == 0);
    /* Ordinary not-present stack page remains demand-zero. */
    assert(fault_try_user_stack_page(0x8390000, 0x6) == 1);
    assert(allocations == 1);
    /* Present faults and addresses outside the stack do not allocate. */
    assert(fault_try_user_stack_page(0x8390000, 0x7) == 0);
    assert(fault_try_user_stack_page(0x8000000, 0x6) == 0);
    assert(allocations == 1);
    puts("PASS: file-backed fault wins over overlapping spawn stack allowance");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-stack-file-fault-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
