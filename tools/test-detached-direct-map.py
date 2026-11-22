#!/usr/bin/env python3
"""Host test of the unpublished supervisor-only direct-map page tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
program = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <direct_map.h>
#include <paging.h>

struct arena { uint64_t *tables[32]; unsigned n, fail_at; };
static uint64_t *alloc_table(void *ctx, uint64_t *pa) {
    struct arena *a = ctx;
    if (a->n == a->fail_at || a->n == 32) return NULL;
    uint64_t *p = aligned_alloc(4096, 4096);
    assert(p);
    memset(p, 0xff, 4096); /* builder must clear all entries itself */
    a->tables[a->n] = p;
    *pa = ((uint64_t)++a->n) * 4096;
    return p;
}
static uint64_t *resolve(void *ctx, uint64_t pa) {
    struct arena *a = ctx;
    if (!pa || (pa & 4095) || pa / 4096 > a->n) return NULL;
    return a->tables[pa / 4096 - 1];
}
static void cleanup(struct arena *a) {
    for (unsigned i = 0; i < a->n; i++) free(a->tables[i]);
}
static int walk(struct arena *a, uint64_t root, uint64_t pa) {
    uint64_t e = root;
    assert((e & (PG_PRESENT | PG_RW | PG_NX)) == (PG_PRESENT | PG_RW | PG_NX));
    assert(!(e & PG_US));
    uint64_t *l3 = resolve(a, e & PG_ADDR_MASK);
    e = l3[(pa >> 30) & 511];
    if (!(e & PG_PRESENT)) return 0;
    assert(!(e & PG_US) && (e & PG_NX) && (e & PG_RW));
    uint64_t *l2 = resolve(a, e & PG_ADDR_MASK);
    e = l2[(pa >> 21) & 511];
    if (!(e & PG_PRESENT)) return 0;
    assert(!(e & PG_US) && (e & PG_NX) && (e & PG_RW));
    if (e & PG_PS_2M) {
        assert((e & PG_ADDR_MASK_2M) == (pa & ~(PAGE_SIZE_2M - 1)));
        return 2;
    }
    uint64_t *l1 = resolve(a, e & PG_ADDR_MASK);
    e = l1[(pa >> 12) & 511];
    if (!(e & PG_PRESENT)) return 0;
    assert(!(e & PG_US) && (e & PG_NX) && (e & PG_RW));
    assert((e & PG_ADDR_MASK) == (pa & ~(PAGE_SIZE_4K - 1)));
    return 1;
}
int main(void) {
    struct bootmem map = {.count = 3, .limit = DIRECT_MAP_SIZE,
        .ranges = {{0x1000, 0x3000}, {0x200000, 0x400000},
                   {0x100001000ULL, 0x100003000ULL}}};
    struct arena a = {.fail_at = 32};
    struct direct_map_allocator ops = {&a, alloc_table, resolve};
    uint64_t entry = 99;
    assert(((DIRECT_MAP_BASE >> 39) & 511) == 256);
    assert(direct_map_build(&map, &ops, &entry) == 0);
    assert(!walk(&a, entry, 0));
    assert(walk(&a, entry, 0x1000) == 1);
    assert(!walk(&a, entry, 0x3000));
    assert(walk(&a, entry, 0x3ff000) == 2);
    assert(!walk(&a, entry, 0x400000));
    assert(!walk(&a, entry, 0x100000000ULL));
    assert(walk(&a, entry, 0x100002000ULL) == 1);
    assert(!walk(&a, entry, 0x100003000ULL));
    uint64_t kernel[512] = {0}, exec_root[512], fork_root[512];
    assert(direct_map_publish(kernel, entry | PG_US) != 0);
    assert(kernel[256] == 0);
    assert(direct_map_publish(kernel, entry & ~PG_NX) != 0);
    assert(kernel[256] == 0);
    assert(direct_map_publish(kernel, entry) == 0);
    assert(direct_map_publish(kernel, entry) != 0);
    /* Model the full PML4 copies used for exec and fork. */
    memcpy(exec_root, kernel, sizeof(kernel));
    memcpy(fork_root, exec_root, sizeof(exec_root));
    assert(exec_root[256] == entry && fork_root[256] == entry);
    assert(!(fork_root[256] & PG_US));
    assert(walk(&a, fork_root[256], 0x100002000ULL) == 1);
    unsigned needed = a.n;
    cleanup(&a);
    for (unsigned fail = 0; fail < needed; fail++) {
        struct arena b = {.fail_at = fail};
        struct direct_map_allocator bops = {&b, alloc_table, resolve};
        entry = 99;
        assert(direct_map_build(&map, &bops, &entry) != 0 && entry == 0);
        cleanup(&b);
    }
    struct arena b = {.fail_at = 32};
    struct direct_map_allocator bops = {&b, alloc_table, resolve};
    map.ranges[1].start = 0x2000; /* overlap */
    entry = 99;
    assert(direct_map_build(&map, &bops, &entry) != 0 && !entry && !b.n);
    map.ranges[1].start = 0x200000;
    map.ranges[2].end = DIRECT_MAP_SIZE + 4096;
    assert(direct_map_build(&map, &bops, &entry) != 0 && !entry && !b.n);
    puts("PASS: detached supervisor/NX direct map, holes, >4GiB and failure");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-direct-map-", dir="/tmp/opencode") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "inc"), str(source),
                    str(root / "mem/direct_map.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
