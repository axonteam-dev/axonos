#!/usr/bin/env python3
"""Host-only Multiboot memory-map and disjoint PMM regressions."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]

program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <bootmem.h>
#include <pmm.h>
#include <spinlock.h>

#define P 4096ULL
#define M (1024ULL * 1024ULL)
#define LIMIT (4ULL * 1024ULL * M)
#define HIGH 0x61000000ULL
#define LOW_END 0x5f500000ULL

void acquire_irqsave(spinlock_t *l, unsigned long *f) { (void)l; *f = 0; }
void release_irqrestore(spinlock_t *l, unsigned long f) { (void)l; (void)f; }
void kprintf(const char *fmt, ...) { (void)fmt; }

struct builder { uint8_t bytes[32768]; uint32_t pos, mmap, n; };
static void w32(uint8_t *p, uint32_t n) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(n >> (i * 8));
}
static void w64(uint8_t *p, uint64_t n) { w32(p, (uint32_t)n); w32(p + 4, (uint32_t)(n >> 32)); }
static void begin(struct builder *b) {
    memset(b, 0, sizeof(*b)); b->pos = 8; b->mmap = 8; b->pos += 16;
    w32(b->bytes + b->mmap, 6); w32(b->bytes + b->mmap + 8, 24);
}
static void entry(struct builder *b, uint64_t base, uint64_t len, uint32_t type) {
    assert(b->pos + 24 < sizeof(b->bytes));
    w64(b->bytes + b->pos, base); w64(b->bytes + b->pos + 8, len);
    w32(b->bytes + b->pos + 16, type); b->pos += 24; b->n++;
}
static void close_mmap(struct builder *b) { w32(b->bytes + b->mmap + 4, 16 + 24 * b->n); }
static void module(struct builder *b, uint32_t lo, uint32_t hi) {
    w32(b->bytes + b->pos, 3); w32(b->bytes + b->pos + 4, 16);
    w32(b->bytes + b->pos + 8, lo); w32(b->bytes + b->pos + 12, hi); b->pos += 16;
}
static void fb(struct builder *b, uint64_t addr, uint32_t pitch, uint32_t height) {
    w32(b->bytes + b->pos, 8); w32(b->bytes + b->pos + 4, 32);
    w64(b->bytes + b->pos + 8, addr); w32(b->bytes + b->pos + 16, pitch);
    w32(b->bytes + b->pos + 24, height); b->pos += 32;
}
static void finish(struct builder *b) {
    w32(b->bytes + b->pos, 0); w32(b->bytes + b->pos + 4, 8); b->pos += 8;
    w32(b->bytes, b->pos);
}
static int parse(struct bootmem *map, struct builder *b) {
    return bootmem_from_multiboot(map, 0x36d76289u, b->bytes, LIMIT);
}
static uint64_t high_total(const struct bootmem *m) {
    uint64_t result = 0;
    for (size_t i = 0; i < m->count; i++) {
        uint64_t lo = m->ranges[i].start < HIGH ? HIGH : m->ranges[i].start;
        if (lo < m->ranges[i].end) result += m->ranges[i].end - lo;
    }
    return result;
}
static void map_tests(void) {
    struct bootmem map;
    struct builder b;
    uint64_t lo, hi;
    begin(&b);
    entry(&b, 2ULL * 1024 * M, 1024 * M, 1); /* intentionally unsorted */
    entry(&b, 256 * M, 6 * M, 2);            /* reserved within usable */
    entry(&b, M, 2200 * M, 1);              /* overlaps previous usable */
    entry(&b, LIMIT, 2ULL * 1024 * M, 1);  /* not identity-mapped */
    close_mmap(&b);
    module(&b, (uint32_t)(1700 * M + 1), (uint32_t)(1702 * M + 9));
    fb(&b, 1750 * M + 3, 4096, 600);
    finish(&b);
    assert(parse(&map, &b) == 0);
    assert(bootmem_is_free(&map, 100 * M, 200 * M));
    assert(!bootmem_is_free(&map, 255 * M, 263 * M));
    assert(!bootmem_is_free(&map, 256 * M, 257 * M));
    assert(!bootmem_is_free(&map, 1700 * M, 1700 * M + P));
    assert(!bootmem_is_free(&map, 1702 * M, 1702 * M + P));
    assert(!bootmem_is_free(&map, 1750 * M, 1750 * M + P));
    assert(!bootmem_is_free(&map, LIMIT, LIMIT + P));
    assert(bootmem_free_bytes(&map, 256 * M - P, 262 * M + P) == 2 * P);
    assert(bootmem_free_bytes(&map, 262 * M, 262 * M) == 0);
    assert(bootmem_free_bytes(NULL, 0, LIMIT) == 0);
    assert(bootmem_from_multiboot(&map, 0x36d76289u, b.bytes, 1ULL << 52) == 0);
    assert(bootmem_free_bytes(&map, LIMIT, 1ULL << 52) == 2ULL * 1024 * M);
    assert(bootmem_free_bytes(&map, LIMIT - P, LIMIT + P) == P);
    assert(parse(&map, &b) == 0);
    assert(bootmem_reserve(&map, 1800 * M + 1, 1800 * M + P + 1) == 0);
    assert(!bootmem_is_free(&map, 1800 * M, 1800 * M + 2 * P));

    /* The half split grows with RAM instead of stopping at 256 MiB. */
    begin(&b); entry(&b, M, 3071 * M, 1); close_mmap(&b); finish(&b);
    assert(parse(&map, &b) == 0);
    assert(bootmem_find_heap(&map, HIGH, 64 * M, LOW_END, HIGH, &lo, &hi) == 0);
    assert(lo == HIGH && hi == 3072 * M);
    size_t heap = bootmem_heap_size(lo, (size_t)(hi - lo), HIGH, 1024 * M);
    assert(heap >= 128 * M && heap <= 1024 * M);
    assert(bootmem_reserve(&map, lo, lo + heap) == 0);
    assert(high_total(&map) > 256 * M);

    /* Low-memory fallback keeps its object heap and does not claim low frames. */
    begin(&b); entry(&b, M, 1023 * M, 1); close_mmap(&b); finish(&b);
    assert(parse(&map, &b) == 0);
    assert(bootmem_find_heap(&map, 64 * M, 64 * M, LOW_END, HIGH, &lo, &hi) == 0);
    assert(lo == 64 * M && hi == 1024 * M);
    assert(bootmem_heap_size(lo, (size_t)(hi - lo), HIGH, 1024 * M) == hi - lo);
    assert(high_total(&map) == 0);

    /* A small high fragment must not replace a much larger low heap. */
    begin(&b); entry(&b, M, 1023 * M, 1); entry(&b, HIGH, 32 * M, 1);
    close_mmap(&b); finish(&b);
    assert(parse(&map, &b) == 0);
    assert(bootmem_find_heap(&map, HIGH, 64 * M, LOW_END, HIGH, &lo, &hi) == 0);
    assert(lo == 64 * M && hi == 1024 * M);
    assert(high_total(&map) == 32 * M);

    /* Reject missing, truncated, inconsistent and overflowing maps/tags. */
    begin(&b); entry(&b, M, 1024 * M, 1); close_mmap(&b); finish(&b);
    assert(bootmem_from_multiboot(&map, 0, b.bytes, LIMIT) != 0);
    w32(b.bytes + b.mmap + 8, 23); assert(parse(&map, &b) != 0);
    w32(b.bytes + b.mmap + 8, 24);
    w32(b.bytes + b.mmap + 12, 1); assert(parse(&map, &b) != 0);
    w32(b.bytes + b.mmap + 12, 0);
    w64(b.bytes + b.mmap + 16, ~(uint64_t)0 - 3); assert(parse(&map, &b) != 0);
    w64(b.bytes + b.mmap + 16, M);
    w32(b.bytes + b.pos - 4, 9); assert(parse(&map, &b) != 0);
    w32(b.bytes + b.pos - 4, 8);
    w32(b.bytes + b.mmap + 4, 39); assert(parse(&map, &b) != 0);
    begin(&b); entry(&b, M, 1024 * M, 1); close_mmap(&b);
    module(&b, 0x200000, 0x100000); finish(&b); assert(parse(&map, &b) != 0);
    begin(&b); entry(&b, M, 1024 * M, 1); close_mmap(&b);
    fb(&b, ~(uint64_t)0 - 1, 4096, 2); finish(&b); assert(parse(&map, &b) != 0);
    begin(&b);
    for (unsigned i = 0; i < BOOTMEM_MAX_RANGES + 1; i++)
        entry(&b, M + i * 2 * P, P, 1);
    close_mmap(&b); finish(&b); assert(parse(&map, &b) != 0);
}

static void pmm_tests(void) {
    const size_t pages = 64, size = pages * P;
    uint8_t *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(mem != MAP_FAILED && (uintptr_t)mem + size < LIMIT);
    uintptr_t base = (uintptr_t)mem;
    memset(mem, 0xa5, size);
    struct builder b; struct bootmem map; int expected[64]; void *got[64]; size_t count = 0;
    begin(&b);
    entry(&b, base, size, 1);
    entry(&b, base + 15 * P + 1, 2 * P - 2, 2);
    close_mmap(&b);
    module(&b, (uint32_t)(base + 8 * P + 1), (uint32_t)(base + 10 * P + 1));
    fb(&b, base + 25 * P + 1, 4096, 2);
    finish(&b);
    memcpy(mem + 128, b.bytes, b.pos);
    assert(bootmem_from_multiboot(&map, 0x36d76289u, mem + 128, LIMIT) == 0);
    assert(bootmem_reserve(&map, base + 40 * P, base + 41 * P) == 0);
    for (size_t i = 0; i < pages; i++) {
        expected[i] = bootmem_is_free(&map, base + i * P, base + (i + 1) * P);
        count += (size_t)expected[i];
    }
    assert(!expected[0] && !expected[8] && !expected[9] && !expected[10]);
    assert(!expected[15] && !expected[16] && !expected[25] && !expected[27] && !expected[40]);
    pmm_init(0, 0);
    for (size_t i = 0; i < map.count; i++)
        assert(pmm_add_range(map.ranges[i].start, map.ranges[i].end) == 0);
    assert(pmm_ready() && pmm_total_pages() == count && pmm_free_pages() == count);
    assert(pmm_add_range(map.ranges[0].start, map.ranges[0].end) != 0);
    uint8_t before = mem[8 * P];
    pmm_free_page(mem + 8 * P); /* hole inside the overall address span */
    pmm_free_page(mem + P + 1); /* unaligned */
    assert(mem[8 * P] == before && pmm_free_pages() == count);
    for (size_t i = 0; i < count; i++) {
        got[i] = pmm_alloc_page(); assert(got[i]);
        size_t index = ((uintptr_t)got[i] - base) / P;
        assert(index < pages && expected[index]); expected[index] = 0;
    }
    assert(!pmm_alloc_page() && pmm_free_pages() == 0);
    for (size_t i = 0; i < count; i++) pmm_free_page(got[i]);
    assert(pmm_free_pages() == count);
    assert(munmap(mem, size) == 0);
}
int main(void) {
    map_tests(); pmm_tests();
    puts("PASS: Multiboot reservations, RAM sizing and disjoint PMM ranges");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="axon-bootmem-", dir="/tmp/opencode") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text(program)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "inc"), str(source),
                    str(root / "mem/bootmem.c"), str(root / "mem/pmm.c"),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
