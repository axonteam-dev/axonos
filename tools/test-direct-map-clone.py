#!/usr/bin/env python3
"""Exercise the actual mm_clone_from implementation with a supervisor slot."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "core/mm.c").read_text()
begin = source.index("mm_t *mm_clone_from(mm_t *src) {")
end = source.index("\n/*", begin)
clone = source[begin:end]
program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#define PAGE_SIZE_4K 4096ULL
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define PG_PRESENT 1ULL
#define PG_RW 2ULL
#define PG_US 4ULL
#define PG_NX (1ULL << 63)
typedef struct { uint64_t *pml4; uint64_t cr3; void *pml4_alloc_raw; int refcount; } mm_t;
typedef int mm_dm_ctx_t;
static int g_mm_ready = 1;
static void mm_init(void) { g_mm_ready = 1; }
static mm_t *mm_clone_current(void) { abort(); }
static void *kmalloc(size_t size) { return malloc(size); }
static void kfree(void *p) { free(p); }
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t ctx) { (void)ctx; }
''' + clone + r'''
int main(void) {
    uint64_t *root = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(root != MAP_FAILED && (uintptr_t)root < MMIO_IDENTITY_LIMIT);
    uint64_t supervisor = 0x12345000ULL | PG_PRESENT | PG_RW | PG_NX;
    root[256] = supervisor;
    mm_t source = {.pml4 = root, .cr3 = (uintptr_t)root};
    mm_t *exec_root = mm_clone_from(&source);
    assert(exec_root && exec_root->pml4[256] == supervisor);
    /* The second source CR3 must also be below 4GiB, like kernel heap pages. */
    uint64_t *parent = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(parent != MAP_FAILED);
    memcpy(parent, exec_root->pml4, 4096);
    mm_t parent_mm = {.pml4 = parent, .cr3 = (uintptr_t)parent};
    mm_t *fork_root = mm_clone_from(&parent_mm);
    assert(fork_root && fork_root->pml4[256] == supervisor);
    assert(!(fork_root->pml4[256] & PG_US));
    kfree(exec_root->pml4_alloc_raw); kfree(exec_root);
    kfree(fork_root->pml4_alloc_raw); kfree(fork_root);
    assert(munmap(root, 4096) == 0 && munmap(parent, 4096) == 0);
    puts("PASS: actual mm_clone_from preserves supervisor direct-map slot");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-dm-clone-", dir="/tmp/opencode") as tmp:
    test_c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    test_c.write_text(program)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    str(test_c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
