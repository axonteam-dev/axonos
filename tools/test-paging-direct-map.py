#!/usr/bin/env python3
"""Ensure 2MiB map/unmap edits page tables through the kernel direct map."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mem/paging.c").read_text()


def extract(start, end):
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


allocator = extract("static uint64_t* next_free_table(void) {", "\n}\n") + "\n}\n"
entry_lookup = extract(
    "static uint64_t *page_table_from_entry(uint64_t entry) {", "\n}\n"
) + "\n}\n"
map_impl = extract("static int map_page_2m_on_l4(", "\nint map_page_2m(uint64_t va")
wrappers = source[source.index("int map_page_2m(uint64_t va"):]
assert "static spinlock_t g_page_table_map_lock;" in source
assert wrappers.count("acquire_irqsave(&g_page_table_map_lock, &irqf);") == 2
assert wrappers.count("release_irqrestore(&g_page_table_map_lock, irqf);") == 2

fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PT_ENTRIES 512
#define PAGE_SIZE_2M 0x200000ULL
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define PG_PRESENT (1ULL << 0)
#define PG_RW (1ULL << 1)
#define PG_US (1ULL << 2)
#define PG_PWT (1ULL << 3)
#define PG_PCD (1ULL << 4)
#define PG_GLOBAL (1ULL << 8)
#define PG_PS_2M (1ULL << 7)
#define PG_NX (1ULL << 63)
#define PG_PAT (1ULL << 12)
#define PG_SOFT_COW (1ULL << 10)
#define PG_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define PG_ADDR_MASK_2M (PG_ADDR_MASK & ~(PAGE_SIZE_2M - 1ULL))
#define PG_ADDR_MASK_1G (PG_ADDR_MASK & ~((1ULL << 30) - 1ULL))

typedef struct { uint64_t *pml4; } mm_t;
typedef struct { uint64_t cr3; unsigned long irqf; } mm_dm_ctx_t;
typedef struct { uint32_t lock; } spinlock_t;
static spinlock_t g_page_table_map_lock;
static uint64_t *active_root;
static uint64_t *kernel_root;
static mm_t kernel_mm;
static unsigned direct_map_enters;
static unsigned direct_map_leaves;
static unsigned lock_acquires;
static unsigned lock_releases;
static int lock_held;
static int in_direct_map;

static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(lock == &g_page_table_map_lock && !lock_held);
    *flags = 0;
    lock_held = 1;
    lock_acquires++;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags;
    assert(lock == &g_page_table_map_lock && lock_held && !in_direct_map);
    lock_held = 0;
    lock_releases++;
}

static uint64_t paging_read_cr3(void) {
    return (uint64_t)(uintptr_t)active_root;
}
static mm_dm_ctx_t mm_enter_direct_map(void) {
    assert(lock_held);
    mm_dm_ctx_t ctx = {.cr3 = paging_read_cr3(), .irqf = 0};
    active_root = kernel_root;
    in_direct_map = 1;
    direct_map_enters++;
    return ctx;
}
static void mm_leave_direct_map(mm_dm_ctx_t ctx) {
    active_root = (uint64_t *)(uintptr_t)(ctx.cr3 & ~0xFFFULL);
    in_direct_map = 0;
    direct_map_leaves++;
}
static mm_t *mm_kernel(void) { return &kernel_mm; }
static int mm_dbg_ash_overlaps(uint64_t lo, uint64_t hi) {
    (void)lo; (void)hi; return 0;
}
static void devel_printf(const char *fmt, ...) { (void)fmt; }
static void invlpg(void *va) {
    (void)va;
    assert(lock_held && in_direct_map);
}
''' + allocator + entry_lookup + map_impl + wrappers + r'''
static uint64_t *mapped_l2(uint64_t *root, uint64_t va) {
    uint64_t e4 = root[(va >> 39) & 0x1ff];
    assert(e4 & PG_PRESENT);
    uint64_t *l3 = (uint64_t *)(uintptr_t)(e4 & PG_ADDR_MASK);
    uint64_t e3 = l3[(va >> 30) & 0x1ff];
    assert((e3 & PG_PRESENT) && !(e3 & PG_PS_2M));
    return (uint64_t *)(uintptr_t)(e3 & PG_ADDR_MASK);
}

int main(void) {
    static uint64_t private_root[PT_ENTRIES] __attribute__((aligned(4096)));
    static uint64_t swapper_root[PT_ENTRIES] __attribute__((aligned(4096)));
    const uint64_t va = 0x400000ULL;
    active_root = private_root;
    kernel_root = swapper_root;
    kernel_mm.pml4 = swapper_root;

    assert(map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) == 0);
    assert(direct_map_enters == 1 && direct_map_leaves == 1);
    assert(lock_acquires == 1 && lock_releases == 1 && !lock_held);
    assert(!in_direct_map && active_root == private_root);
    uint64_t *private_l2 = mapped_l2(private_root, va);
    uint64_t *kernel_l2 = mapped_l2(swapper_root, va);
    assert(private_l2[(va >> 21) & 0x1ff] & PG_PRESENT);
    assert(kernel_l2[(va >> 21) & 0x1ff] & PG_PRESENT);

    assert(unmap_page_2m(va) == 0);
    assert(direct_map_enters == 2 && direct_map_leaves == 2);
    assert(lock_acquires == 2 && lock_releases == 2 && !lock_held);
    assert(!in_direct_map && active_root == private_root);
    assert(private_l2[(va >> 21) & 0x1ff] == 0);
    assert(kernel_l2[(va >> 21) & 0x1ff] == 0);
    puts("PASS: page-table map/unmap runs under kernel direct-map CR3");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-paging-direct-") as tmp:
    source_path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source_path.write_text(fixture)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-no-pie", str(source_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
