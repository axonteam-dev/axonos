#!/usr/bin/env python3
"""Host-only experimental high-RAM pool tests; does not install page tables."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
program = r'''
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ram_page_pool.h>
#include <paging.h>

#define BASE 0x100000000ULL
#define N 32
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    (void)lock; *flags = 0; assert(!pthread_mutex_lock(&mutex));
}
void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)lock; (void)flags; assert(!pthread_mutex_unlock(&mutex));
}
struct mapping { unsigned char *data; int missing; };
static int fail_metadata, metadata_allocs, metadata_frees;
static void *metadata_alloc(size_t n) {
    metadata_allocs++;
    return fail_metadata ? NULL : malloc(n);
}
static void metadata_free(void *p) { metadata_frees++; free(p); }
static void *resolve(void *ctx, uint64_t pa) {
    struct mapping *m = ctx;
    if (pa < BASE || pa >= BASE + N * PAGE_SIZE_4K || (pa & 4095)) return NULL;
    unsigned n = (unsigned)((pa - BASE) / PAGE_SIZE_4K);
    if ((int)n == m->missing) return NULL;
    return m->data + n * PAGE_SIZE_4K;
}
static uint32_t active[N];
static void *worker(void *v) {
    struct ram_page_pool *p = v;
    for (unsigned i = 0; i < 5000; i++) {
        struct ram_page page;
        assert(ram_page_pool_alloc(p, &page) == 0);
        size_t n = (size_t)((page.pa - BASE) / PAGE_SIZE_4K);
        assert(__atomic_exchange_n(&active[n], 1, __ATOMIC_SEQ_CST) == 0);
        assert(__atomic_exchange_n(&active[n], 0, __ATOMIC_SEQ_CST) == 1);
        assert(ram_page_pool_free(p, page) == 0);
    }
    return NULL;
}
int main(void) {
    struct mapping m = {aligned_alloc(4096, N * 4096), -1};
    assert(m.data); memset(m.data, 0xcc, N * 4096);
    struct bootmem map = {.count = 3, .limit = BASE + N * 4096,
        .ranges = {{0x1000, 0x9000}, {BASE, BASE + 8 * 4096},
                   {BASE + 12 * 4096, BASE + N * 4096}}};
    struct bootmem original = map;
    struct ram_page_pool *p = calloc(1, sizeof(*p)); assert(p);
    uint64_t state[N];
    assert(ram_page_pool_init(p, &map, state, 27, &m, resolve) != 0);
    assert(!memcmp(&map, &original, sizeof map));
    m.missing = 5;
    assert(ram_page_pool_init(p, &map, state, N, &m, resolve) != 0);
    assert(!memcmp(&map, &original, sizeof map));
    m.missing = -1;
    assert(ram_page_pool_init(p, &map, state, N, &m, resolve) == 0);
    /* Bootstrap must not touch the contents of any free high page. */
    for (size_t i = 0; i < N * 4096; i++) assert(m.data[i] == 0xcc);
    assert(map.count == 1 && bootmem_is_free(&map, 0x1000, 0x9000));
    assert(!bootmem_is_free(&map, BASE, BASE + 4096));
    assert(ram_page_pool_free_pages(p) == 28);
    assert(ram_page_pool_init(p, &map, state, N, &m, resolve) != 0);
    struct ram_page pages[N], unused = {0};
    /* A corrupt recycled link must not pull a never-allocated page out of
     * the virgin sequence a second time. */
    assert(ram_page_pool_alloc(p, &unused) == 0);
    assert(ram_page_pool_free(p, unused) == 0);
    uint64_t *first_link = resolve(&m, unused.pa);
    *first_link = BASE + 4096;
    assert(ram_page_pool_alloc(p, &unused) != 0);
    *first_link = 0;
    for (size_t i = 0; i < 28; i++) {
        assert(ram_page_pool_alloc(p, &pages[i]) == 0);
        assert(pages[i].pa >= BASE && resolve(&m, pages[i].pa) == pages[i].va);
        assert(pages[i].pa < BASE + 8 * 4096 || pages[i].pa >= BASE + 12 * 4096);
        for (size_t j = 0; j < i; j++) assert(pages[i].pa != pages[j].pa);
    }
    assert(ram_page_pool_alloc(p, &unused) != 0);
    struct ram_page stale = pages[0], bad = pages[0];
    bad.va = (char *)bad.va + 1;
    assert(ram_page_pool_free(p, bad) != 0);
    bad = pages[0]; bad.pa = BASE + 9 * 4096;
    assert(ram_page_pool_free(p, bad) != 0);
    assert(ram_page_pool_free(p, pages[0]) == 0);
    assert(ram_page_pool_free(p, pages[0]) != 0);
    assert(ram_page_pool_alloc(p, &pages[0]) == 0);
    assert(pages[0].pa == stale.pa && pages[0].generation != stale.generation);
    assert(ram_page_pool_free(p, stale) != 0);
    for (size_t i = 0; i < 28; i++) assert(ram_page_pool_free(p, pages[i]) == 0);
    pthread_t threads[4];
    for (size_t i = 0; i < 4; i++) assert(!pthread_create(&threads[i], NULL, worker, p));
    for (size_t i = 0; i < 4; i++) assert(!pthread_join(threads[i], NULL));
    assert(ram_page_pool_free_pages(p) == 28);
    /* A corrupted intrusive link is rejected without giving the page away. */
    void *head = resolve(&m, p->head);
    uint64_t saved = *(uint64_t *)head;
    *(uint64_t *)head = BASE + 9 * 4096;
    assert(ram_page_pool_alloc(p, &unused) != 0);
    assert(ram_page_pool_free_pages(p) == 28);
    *(uint64_t *)head = saved;
    /* Boot integration is transactional across allocation and resolver errors. */
    struct ram_page_pool *boot = calloc(1, sizeof(*boot)); assert(boot);
    struct bootmem available = original;
    struct bootmem invalid = original;
    invalid.ranges[1].start++;
    assert(ram_page_pool_bootstrap(boot, &invalid, &m, resolve,
                                   metadata_alloc, metadata_free) != 0);
    assert(metadata_allocs == 0 && !boot->ready);
    invalid = original; invalid.count = 1;
    assert(ram_page_pool_bootstrap(boot, &invalid, &m, resolve,
                                   metadata_alloc, metadata_free) != 0);
    assert(metadata_allocs == 0 && !boot->ready);
    fail_metadata = 1;
    assert(ram_page_pool_bootstrap(boot, &available, &m, resolve,
                                   metadata_alloc, metadata_free) != 0);
    assert(!memcmp(&available, &original, sizeof available) && !boot->ready);
    fail_metadata = 0; m.missing = 5;
    assert(ram_page_pool_bootstrap(boot, &available, &m, resolve,
                                   metadata_alloc, metadata_free) != 0);
    assert(!memcmp(&available, &original, sizeof available) && !boot->ready);
    assert(metadata_frees == 1);
    m.missing = -1;
    assert(ram_page_pool_bootstrap(boot, &available, &m, resolve,
                                   metadata_alloc, metadata_free) == 0);
    assert(metadata_allocs == 3 && boot->total == 28);
    assert(available.count == 1 && bootmem_is_free(&available, 0x1000, 0x9000));
    assert(ram_page_pool_bootstrap(boot, &available, &m, resolve,
                                   metadata_alloc, metadata_free) != 0);
    struct ram_page high;
    assert(ram_page_pool_alloc(boot, &high) == 0);
    memset(high.va, 0, PAGE_SIZE_4K);
    assert(ram_page_pool_free(boot, high) == 0);
    free(boot->state); free(boot);
    free(p); free(m.data);
    puts("PASS: high-RAM pool reservations, stale frees, holes, SMP and corruption");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-ram-page-pool-", dir="/tmp/opencode") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text(program)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-DAXON_EXPERIMENTAL_DIRECT_MAP=1", "-I", str(root / "inc"),
                    str(source), str(root / "mem/ram_page_pool.c"),
                    str(root / "mem/bootmem.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
