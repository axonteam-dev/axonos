#!/usr/bin/env python3
"""Exercise real VMA classification/clone and futex key selection together."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
vma = (root / "mm/user_vma.c").read_text()
futex = (root / "syscall/futex/futex.c").read_text()
mm = (root / "core/mm.c").read_text()
dup = mm[mm.index("mm_t *mm_dup_user("):]
assert dup.index("user_vma_clone_mm(child, parent)") < dup.index(
    "mm_cow_mark_all_user_writable_walk(")

vma_functions = vma[vma.index("static user_vma_t *user_vma_mm_storage("):
                    vma.index("static int user_vma_kind_is_mmap_like(")]
key_function = futex[futex.index("static int futex_key("):
                     futex.index("\nstatic int futex_wake_locked(")]

program = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define EINVAL 22
#define EFAULT 14
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_VMA_MM_MAX 8
#define USER_VMA_KIND_SHM 1
#define USER_VMA_KIND_ELF_LOAD 2
typedef struct { int refs; } file_t;
typedef struct {
    int used, tid, prot, kind;
    uintptr_t addr;
    size_t len;
    file_t *file;
    uint64_t file_off;
} user_vma_t;
typedef struct { void *vma_storage; } mm_t;
typedef struct { mm_t *mm; } thread_t;
typedef struct { int held; } spinlock_t;
static spinlock_t g_user_vma_lock;
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
static void acquire_irqsave(spinlock_t *l, unsigned long *f) {
    assert(!l->held); l->held = 1; *f = 0;
}
static void release_irqrestore(spinlock_t *l, unsigned long f) {
    (void)f; assert(l->held); l->held = 0;
}
static void fs_file_get(file_t *f) { f->refs++; }
static uint64_t frame = 0x90000;
static int mm_user_leaf_pa(mm_t *mm, uint64_t addr, int write, uint64_t *out) {
    (void)mm; (void)write; *out = frame + (addr & 4095); return 0;
}
""" + vma_functions + key_function + r"""
int main(void) {
    mm_t parent = {0}, child = {0}, empty = {0};
    thread_t p = {&parent}, c = {&child};
    uintptr_t pk, ck, before, after;
    mm_t *po, *co, *owner;
    const uintptr_t stack = 0x70000, elf = 0x400000, shared = 0x800000;

    /* No VMA storage at all: primary stack and ELF are private fallbacks. */
    assert(!user_vma_is_shared_page_mm(&parent, stack));
    assert(!user_vma_is_shared_page_mm(&parent, elf));
    assert(futex_key(&p, stack, 0, &before, &owner) == 0 && owner == &parent);
    frame = 0xa0000;
    assert(futex_key(&p, stack, 0, &after, &owner) == 0 && before == after);
    assert(futex_key(&p, elf, 0, &before, &owner) == 0 && owner == &parent);
    frame = 0xb0000;
    assert(futex_key(&p, elf, 0, &after, &owner) == 0 && before == after);

    assert(user_vma_add_mm(&parent, elf, 0x1000, 0, USER_VMA_KIND_ELF_LOAD) == 0);
    assert(user_vma_add_mm(&parent, shared, 0x1000, 0, USER_VMA_KIND_SHM) == 0);
    assert(!user_vma_is_shared_page_mm(&parent, stack));
    assert(!user_vma_is_shared_page_mm(&parent, elf));
    assert(user_vma_is_shared_page_mm(&parent, shared));
    assert(!user_vma_is_shared_page_mm(&parent, shared + 0x1000));

    /* mm_dup_user clones the parent's per-mm VMA metadata before its COW walk. */
    assert(user_vma_clone_mm(&child, &parent) == 0);
    assert(user_vma_clone_mm(&empty, &(mm_t){0}) == 0 && !empty.vma_storage);
    assert(user_vma_is_shared_page_mm(&child, shared));
    assert(!user_vma_is_shared_page_mm(&child, stack));
    assert(!user_vma_is_shared_page_mm(&child, elf));
    assert(futex_key(&p, shared, 0, &pk, &po) == 0);
    assert(futex_key(&c, shared, 0, &ck, &co) == 0);
    assert(!po && !co && pk == ck);
    assert(futex_key(&p, stack, 0, &pk, &po) == 0);
    assert(futex_key(&c, stack, 0, &ck, &co) == 0);
    assert(po == &parent && co == &child);
    free(parent.vma_storage);
    free(child.vma_storage);
    puts("PASS: real VMA fallback and shared clone/futex keys after fork");
}
"""

with tempfile.TemporaryDirectory(prefix="axon-futex-vma-") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
