#include <direct_map.h>
#include <paging.h>

static uint64_t *new_table(const struct direct_map_allocator *a, uint64_t *pa)
{
    uint64_t *table = a->alloc(a->ctx, pa);
    if (!table || ((uintptr_t)table & (PAGE_SIZE_4K - 1)) ||
        (*pa & ~PG_ADDR_MASK) || !*pa)
        return NULL;
    /* Do not trust an allocator to have cleared inherited permissions. */
    for (size_t i = 0; i < PT_ENTRIES; i++) table[i] = 0;
    return table;
}

static uint64_t *child(uint64_t *entry, const struct direct_map_allocator *a)
{
    if (!(*entry & PG_PRESENT)) {
        uint64_t pa = 0;
        uint64_t *table = new_table(a, &pa);
        if (!table) return NULL;
        *entry = pa | PG_PRESENT | PG_RW | PG_NX;
        return table;
    }
    if (*entry & PG_PS_2M) return NULL;
    return a->resolve(a->ctx, *entry & PG_ADDR_MASK);
}

int direct_map_build(const struct bootmem *map,
                     const struct direct_map_allocator *a, uint64_t *entry_out)
{
    uint64_t root_pa = 0;
    uint64_t *l3;
    if (!entry_out) return -1;
    *entry_out = 0;
    if (!map || !a || !a->alloc || !a->resolve ||
        map->count > BOOTMEM_MAX_RANGES)
        return -1;
    /* Validate before allocating: no wrap, out-of-window range, or overlap. */
    for (size_t i = 0; i < map->count; i++) {
        uint64_t lo = map->ranges[i].start, hi = map->ranges[i].end;
        if (lo >= hi || hi > DIRECT_MAP_SIZE || hi > map->limit ||
            ((lo | hi) & (PAGE_SIZE_4K - 1)) ||
            (i && lo < map->ranges[i - 1].end))
            return -1;
    }
    l3 = new_table(a, &root_pa);
    if (!l3) return -1;
    for (size_t i = 0; i < map->count; i++) {
        uint64_t pa = map->ranges[i].start, end = map->ranges[i].end;
        while (pa < end) {
            uint64_t *l2 = child(&l3[(pa >> 30) & 511], a);
            if (!l2) return -1;
            uint64_t *e2 = &l2[(pa >> 21) & 511];
            if (!(pa & (PAGE_SIZE_2M - 1)) && end - pa >= PAGE_SIZE_2M) {
                if (*e2) return -1;
                *e2 = pa | PG_PRESENT | PG_RW | PG_PS_2M | PG_NX;
                pa += PAGE_SIZE_2M;
            } else {
                uint64_t *l1 = child(e2, a);
                if (!l1) return -1;
                uint64_t *e1 = &l1[(pa >> 12) & 511];
                if (*e1) return -1;
                *e1 = pa | PG_PRESENT | PG_RW | PG_NX;
                pa += PAGE_SIZE_4K;
            }
        }
    }
    *entry_out = root_pa | PG_PRESENT | PG_RW | PG_NX;
    return 0;
}

int direct_map_publish(uint64_t *pml4, uint64_t entry)
{
    const size_t index = (DIRECT_MAP_BASE >> 39) & 511u;
    const uint64_t required = PG_PRESENT | PG_RW | PG_NX;
    if (!pml4 || pml4[index] || (entry & ~PG_ADDR_MASK) != required ||
        !(entry & PG_ADDR_MASK))
        return -1;
    pml4[index] = entry;
    return 0;
}
