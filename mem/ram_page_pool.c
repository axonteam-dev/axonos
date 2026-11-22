#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
#include <ram_page_pool.h>
#include <direct_map.h>
#include <paging.h>

#define HIGH_RAM_START (1ULL << 32)

static int index_of(const struct ram_page_pool *p, uint64_t pa, size_t *index)
{
    if (pa & (PAGE_SIZE_4K - 1)) return -1;
    for (size_t i = 0; i < p->count; i++) {
        const struct ram_page_range *r = &p->ranges[i];
        if (pa >= r->start && pa < r->end) {
            *index = r->first + (size_t)((pa - r->start) / PAGE_SIZE_4K);
            return 0;
        }
    }
    return -1;
}

static void *mapped(struct ram_page_pool *p, uint64_t pa)
{
    void *va = p->resolve(p->ctx, pa);
    return va && !((uintptr_t)va & (PAGE_SIZE_4K - 1)) ? va : NULL;
}

int ram_page_pool_init(struct ram_page_pool *p, struct bootmem *free_map,
                       uint64_t *state, size_t state_count,
                       void *ctx, void *(*resolve)(void *, uint64_t))
{
    struct bootmem remaining;
    size_t total = 0;
    if (!p || p->ready || !free_map || !state || !resolve ||
        ((uintptr_t)state & (sizeof(*state) - 1)) ||
        free_map->count > BOOTMEM_MAX_RANGES || free_map->limit > DIRECT_MAP_SIZE)
        return -1;
    p->count = 0;
    p->head = 0;
    p->virgin_range = 0;
    p->virgin_next = 0;
    p->resolve = resolve;
    p->ctx = ctx;
    remaining = *free_map;
    for (size_t i = 0; i < free_map->count; i++) {
        uint64_t lo = free_map->ranges[i].start, hi = free_map->ranges[i].end;
        if (lo >= hi || hi > free_map->limit ||
            ((lo | hi) & (PAGE_SIZE_4K - 1)) ||
            (i && lo < free_map->ranges[i - 1].end))
            goto fail;
        if (hi <= HIGH_RAM_START) continue;
        if (lo < HIGH_RAM_START) lo = HIGH_RAM_START;
        size_t pages = (size_t)((hi - lo) / PAGE_SIZE_4K);
        if (pages > state_count - total) goto fail;
        p->ranges[p->count++] = (struct ram_page_range){lo, hi, total};
        total += pages;
        if (bootmem_reserve(&remaining, lo, hi) != 0) goto fail;
    }
    if (!total) goto fail;
    /* Check every page before touching any. Resolver must remain stable. */
    for (size_t i = 0; i < p->count; i++)
        for (uint64_t pa = p->ranges[i].start; pa < p->ranges[i].end; pa += PAGE_SIZE_4K)
            if (!mapped(p, pa)) goto fail;
    for (size_t i = 0; i < total; i++) state[i] = 0;
    /* Untouched free pages need no intrusive link. In particular, do not
     * dirty every gigabyte of guest RAM merely to initialize the pool. */
    p->virgin_next = p->ranges[0].start;
    p->lock.lock = 0;
    p->state = state;
    p->total = p->free_pages = total;
    *free_map = remaining;
    p->ready = 1;
    return 0;
fail:
    p->count = 0;
    p->head = 0;
    return -1;
}

int ram_page_pool_alloc(struct ram_page_pool *p, struct ram_page *out)
{
    unsigned long flags;
    size_t index, next_index;
    if (!p || !out || !p->ready) return -1;
    acquire_irqsave(&p->lock, &flags);
    int recycled = p->head != 0;
    uint64_t pa = recycled ? p->head : p->virgin_next;
    void *va = pa ? mapped(p, pa) : NULL;
    if (!va || index_of(p, pa, &index) || (p->state[index] & 1) ||
        p->state[index] >= UINT64_MAX - 1 || !p->free_pages) {
        release_irqrestore(&p->lock, flags);
        return -1;
    }
    if (recycled) {
        uint64_t next = *(uint64_t *)va;
        if (!p->state[index] || (next &&
            (next == pa || index_of(p, next, &next_index) ||
             !p->state[next_index] || (p->state[next_index] & 1)))) {
            release_irqrestore(&p->lock, flags);
            return -1;
        }
        p->head = next;
    } else {
        if (p->state[index] != 0 || p->virgin_range >= p->count) {
            release_irqrestore(&p->lock, flags);
            return -1;
        }
        p->virgin_next += PAGE_SIZE_4K;
        if (p->virgin_next == p->ranges[p->virgin_range].end) {
            p->virgin_range++;
            p->virgin_next = p->virgin_range < p->count
                ? p->ranges[p->virgin_range].start : 0;
        }
    }
    p->free_pages--;
    p->state[index]++; /* free even generation -> next allocated odd */
    *out = (struct ram_page){pa, va, p->state[index]};
    release_irqrestore(&p->lock, flags);
    return 0;
}

int ram_page_pool_free(struct ram_page_pool *p, struct ram_page page)
{
    unsigned long flags;
    size_t index;
    if (!p || !p->ready) return -1;
    acquire_irqsave(&p->lock, &flags);
    if (index_of(p, page.pa, &index) || !page.generation ||
        !(page.generation & 1) || p->state[index] != page.generation ||
        !page.va || mapped(p, page.pa) != page.va || p->free_pages >= p->total) {
        release_irqrestore(&p->lock, flags);
        return -1;
    }
    *(uint64_t *)page.va = p->head;
    p->head = page.pa;
    p->state[index]++; /* allocated odd -> free even */
    p->free_pages++;
    release_irqrestore(&p->lock, flags);
    return 0;
}

size_t ram_page_pool_free_pages(struct ram_page_pool *p)
{
    unsigned long flags;
    if (!p || !p->ready) return 0;
    acquire_irqsave(&p->lock, &flags);
    size_t n = p->free_pages;
    release_irqrestore(&p->lock, flags);
    return n;
}

int ram_page_pool_bootstrap(struct ram_page_pool *p, struct bootmem *map,
                            void *ctx, void *(*resolve)(void *, uint64_t),
                            void *(*alloc_metadata)(size_t),
                            void (*free_metadata)(void *))
{
    uint64_t pages = 0;
    if (!p || p->ready || !map || map->count > BOOTMEM_MAX_RANGES ||
        map->limit > DIRECT_MAP_SIZE || !resolve || !alloc_metadata || !free_metadata)
        return -1;
    for (size_t i = 0; i < map->count; i++) {
        uint64_t lo = map->ranges[i].start, hi = map->ranges[i].end;
        if (lo >= hi || hi > map->limit || ((lo | hi) & (PAGE_SIZE_4K - 1)) ||
            (i && lo < map->ranges[i - 1].end))
            return -1;
        if (hi <= HIGH_RAM_START) continue;
        if (lo < HIGH_RAM_START) lo = HIGH_RAM_START;
        pages += (hi - lo) / PAGE_SIZE_4K;
    }
    if (!pages || pages > (size_t)-1 / sizeof(uint64_t)) return -1;
    uint64_t *state = alloc_metadata((size_t)pages * sizeof(*state));
    if (!state) return -1;
    if (ram_page_pool_init(p, map, state, (size_t)pages, ctx, resolve) != 0) {
        free_metadata(state);
        return -1;
    }
    return 0;
}
#endif
