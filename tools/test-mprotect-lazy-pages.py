#!/usr/bin/env python3
"""mprotect's page-table walk must accept holes in a lazy VMA."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_map.c").read_text()
start = source.index("int user_map_mprotect_range(")
end = source.index("\n}\n", start) + 3
function = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
#define USER_DATA_REGION_LO 0x200000ULL
#define USER_DATA_REGION_HI 0x10000000ULL
#define PAGE_SIZE_2M 0x200000ULL
#define PG_PRESENT 1ULL
#define PG_RW 2ULL
#define PG_US 4ULL
#define PG_PS_2M 0x80ULL
#define PG_SOFT_COW 0x400ULL
#define PG_SOFT_OWNED 0x800ULL
#define PG_NX (1ULL << 63)
#define PG_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define PG_ADDR_MASK_2M (PG_ADDR_MASK & ~(PAGE_SIZE_2M - 1ULL))
typedef struct { uint64_t *pml4; } mm_t;
typedef struct { mm_t *mm; } thread_t;
static uint64_t l4[512] __attribute__((aligned(4096)));
static uint64_t l3[512] __attribute__((aligned(4096)));
static uint64_t l2[512] __attribute__((aligned(4096)));
static uint64_t l1[512] __attribute__((aligned(4096)));
static mm_t kernel, mm = { l4 };
static thread_t thread = { &mm };
static thread_t *thread_get_current_user(void) { return &thread; }
static thread_t *thread_current(void) { return &thread; }
static mm_t *mm_kernel(void) { return &kernel; }
static uint64_t paging_read_cr3(void) { return 0; }
static void invlpg(void *p) { (void)p; }
''' + function + r'''
int main(void) {
    const uint64_t start = 0x40000000ULL;
    kernel.pml4 = l2;
    assert(user_map_mprotect_range(start, start + 0x400000, 3) == 0);
    l4[0] = (uintptr_t)l3 | PG_PRESENT;
    assert(user_map_mprotect_range(start, start + 0x400000, 3) == 0);
    l3[1] = (uintptr_t)l2 | PG_PRESENT;
    assert(user_map_mprotect_range(start, start + 0x400000, 3) == 0);
    l2[0] = (uintptr_t)l1 | PG_PRESENT;
    l1[0] = 0x12345000ULL | PG_PRESENT | PG_US | PG_SOFT_COW | PG_SOFT_OWNED;
    l1[1] = 0x23456000ULL | PG_PRESENT | PG_US;
    assert(user_map_mprotect_range(start, start + 0x400000, 3) == 0);
    assert((l1[0] & PG_SOFT_COW) && !(l1[0] & PG_RW) && (l1[0] & PG_NX));
    assert((l1[1] & PG_RW) && (l1[1] & PG_NX));
    assert(l1[2] == 0 && l2[1] == 0);
    assert(user_map_mprotect_range(start + 4, start, 3) == -1);
    assert(user_map_mprotect_range(MMIO_IDENTITY_LIMIT, MMIO_IDENTITY_LIMIT, 3) == -1);
    puts("PASS: lazy mprotect skips absent tables and updates present COW pages");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mprotect-lazy-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
