#!/usr/bin/env python3
"""Regression-test page-table walks when non-leaf entries carry NX."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mem/paging.c").read_text()


def extract(start, end):
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


allocator = extract("static uint64_t* next_free_table(void) {", "\n}\n") + "\n}\n"
entry_ptr = extract(
    "static uint64_t *page_table_from_entry(uint64_t entry) {", "\n}\n"
) + "\n}\n"
walker = extract(
    "static int map_page_2m_on_l4(", "\nint map_page_2m(uint64_t va"
)
assert "entry & PG_ADDR_MASK" in entry_ptr
assert "entry & ~0xFFFULL" not in entry_ptr
assert "leaf & PG_ADDR_MASK_1G" in walker

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <paging.h>
#include <mmio.h>

void invlpg(void *va) { (void)va; }
''' + allocator + entry_ptr + walker + r'''
static uint64_t root[PT_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l3[PT_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l2[PT_ENTRIES] __attribute__((aligned(4096)));
static uint64_t l1[PT_ENTRIES] __attribute__((aligned(4096)));
static uint64_t split_root[PT_ENTRIES] __attribute__((aligned(4096)));
static uint64_t split_l3[PT_ENTRIES] __attribute__((aligned(4096)));

static uint64_t table_entry(const uint64_t *table, uint64_t flags) {
    uint64_t pa = (uint64_t)(uintptr_t)table;
    assert(pa < MMIO_IDENTITY_LIMIT);
    assert((pa & 0xFFFu) == 0);
    return (pa & PG_ADDR_MASK) | flags;
}

int main(void) {
    const uint64_t nx = PG_NX;
    const uint64_t va = 0x400000ULL; /* L4[0], L3[0], L2[2], L1[0] */

    root[0] = table_entry(l3, PG_PRESENT | PG_RW | nx);
    l3[0] = table_entry(l2, PG_PRESENT | PG_RW | nx);
    l2[2] = table_entry(l1, PG_PRESENT | PG_RW | nx);
    l1[0] = 0x900000ULL | PG_PRESENT | PG_RW;
    assert(map_page_2m_on_l4(root, va, 0xA00000ULL,
                             PG_PRESENT | PG_RW | PG_US) == 0);
    assert((l1[0] & PG_ADDR_MASK) == 0x900000ULL);
    assert(l1[0] & PG_US);

    /* Invalid table addresses are rejected before a dereference. */
    root[0] = 0x100000000ULL | PG_PRESENT | PG_RW;
    assert(map_page_2m_on_l4(root, va, 0xA00000ULL,
                             PG_PRESENT | PG_RW) == -3);
    root[0] = table_entry(l3, PG_PRESENT | PG_RW);
    l3[0] = 0x100000000ULL | PG_PRESENT | PG_RW;
    assert(map_page_2m_on_l4(root, va, 0xA00000ULL,
                             PG_PRESENT | PG_RW) == -3);

    /* Splitting an NX 1GiB leaf must retain only its physical address bits. */
    split_root[0] = table_entry(split_l3, PG_PRESENT | PG_RW | nx);
    split_l3[0] = 0x40000000ULL | PG_PRESENT | PG_RW | PG_PS_2M | nx;
    assert(map_page_2m_on_l4(split_root, va, 0xA00000ULL,
                             PG_PRESENT | PG_RW) == 0);
    uint64_t *split_l2 = (uint64_t *)(uintptr_t)(split_l3[0] & PG_ADDR_MASK);
    assert((split_l2[0] & PG_ADDR_MASK_2M) == 0x40000000ULL);
    assert((split_l2[1] & PG_ADDR_MASK_2M) == 0x40200000ULL);
    assert((split_l2[0] & (PG_PRESENT | PG_RW | PG_PS_2M | PG_NX)) ==
           (PG_PRESENT | PG_RW | PG_PS_2M | PG_NX));
    assert((split_l2[1] & (PG_PRESENT | PG_RW | PG_PS_2M | PG_NX)) ==
           (PG_PRESENT | PG_RW | PG_PS_2M | PG_NX));
    assert(split_l2[2] == (0xA00000ULL | PG_PRESENT | PG_RW | PG_PS_2M));
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="axon-paging-mask-") as tmp:
    c_file = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c_file.write_text(fixture)
    subprocess.run(
        ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-no-pie",
         "-I", str(root / "inc"), str(c_file), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("PASS: NX-safe page-table extraction, low-4GiB validation, and 1GiB splitting")
