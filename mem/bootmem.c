#include <bootmem.h>
#include <paging.h>

#define MB2_MAGIC 0x36d76289u
#define MB2_MAX_SIZE (64u * 1024u * 1024u)

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read64(const uint8_t *p)
{
    return (uint64_t)read32(p) | ((uint64_t)read32(p + 4) << 32);
}

/* Insert usable RAM, merging overlapping or adjacent entries. */
static int add_usable(struct bootmem *map, uint64_t start, uint64_t end)
{
    size_t i, j;
    if (start >= map->limit || end <= start)
        return 0;
    if (end > map->limit)
        end = map->limit;
    start = (start + PAGE_SIZE_4K - 1u) & ~(PAGE_SIZE_4K - 1u);
    end &= ~(PAGE_SIZE_4K - 1u);
    if (start >= end)
        return 0;
    for (i = 0; i < map->count && map->ranges[i].end < start; i++) {}
    j = i;
    while (j < map->count && map->ranges[j].start <= end) {
        if (map->ranges[j].start < start) start = map->ranges[j].start;
        if (map->ranges[j].end > end) end = map->ranges[j].end;
        j++;
    }
    if (i == j) {
        if (map->count == BOOTMEM_MAX_RANGES) return -1;
        for (size_t k = map->count; k > i; k--)
            map->ranges[k] = map->ranges[k - 1];
        map->count++;
    } else {
        size_t removed = j - i - 1;
        for (size_t k = i + 1; k + removed < map->count; k++)
            map->ranges[k] = map->ranges[k + removed];
        map->count -= removed;
    }
    map->ranges[i].start = start;
    map->ranges[i].end = end;
    return 0;
}

int bootmem_reserve(struct bootmem *map, uint64_t start, uint64_t end)
{
    if (!map || end < start) return -1;
    if (end == start || start >= map->limit) return 0;
    if (end > map->limit) end = map->limit;
    start &= ~(PAGE_SIZE_4K - 1u);
    end = (end + PAGE_SIZE_4K - 1u) & ~(PAGE_SIZE_4K - 1u);
    for (size_t i = 0; i < map->count;) {
        struct bootmem_range *r = &map->ranges[i];
        if (r->end <= start || r->start >= end) {
            i++;
        } else if (start <= r->start && end >= r->end) {
            for (size_t j = i + 1; j < map->count; j++)
                map->ranges[j - 1] = map->ranges[j];
            map->count--;
        } else if (start <= r->start) {
            r->start = end;
            i++;
        } else if (end >= r->end) {
            r->end = start;
            i++;
        } else {
            if (map->count == BOOTMEM_MAX_RANGES) return -1;
            for (size_t j = map->count; j > i + 1; j--)
                map->ranges[j] = map->ranges[j - 1];
            map->ranges[i + 1].start = end;
            map->ranges[i + 1].end = r->end;
            r->end = start;
            map->count++;
            break;
        }
    }
    return 0;
}

int bootmem_is_free(const struct bootmem *map, uint64_t start, uint64_t end)
{
    if (!map || end <= start) return 0;
    for (size_t i = 0; i < map->count; i++)
        if (start >= map->ranges[i].start && end <= map->ranges[i].end)
            return 1;
    return 0;
}

uint64_t bootmem_free_bytes(const struct bootmem *map, uint64_t start, uint64_t end)
{
    uint64_t total = 0;
    if (!map || end <= start) return 0;
    for (size_t i = 0; i < map->count; i++) {
        uint64_t lo = map->ranges[i].start > start ? map->ranges[i].start : start;
        uint64_t hi = map->ranges[i].end < end ? map->ranges[i].end : end;
        if (hi > lo) total += hi - lo;
    }
    return total;
}

static int from_multiboot(struct bootmem *map, uint32_t magic, const void *info,
                          uint64_t limit, uint32_t except_module)
{
    const uint8_t *p = (const uint8_t *)info;
    uint32_t total, mmap_off = 0, mmap_size = 0, entry_size = 0;
    int ended = 0;

    if (!map || !p || magic != MB2_MAGIC || !limit ||
        (limit & (PAGE_SIZE_4K - 1u)) || limit > UINT64_MAX - PAGE_SIZE_4K)
        return -1;
    map->count = 0;
    map->limit = limit;
    total = read32(p);
    if (total < 16 || total > MB2_MAX_SIZE || (total & 7u)) return -1;

    /* Validate the entire tag stream before trusting any of its reservations. */
    for (uint32_t off = 8; off <= total - 8;) {
        uint32_t type = read32(p + off), size = read32(p + off + 4);
        if (size < 8 || size > total - off) return -1;
        if (type == 0) {
            if (size != 8 || off + 8 != total) return -1;
            ended = 1;
            break;
        }
        if (type == 6) {
            if (mmap_off || size < 16) return -1;
            entry_size = read32(p + off + 8);
            if (entry_size < 24 || read32(p + off + 12) != 0 ||
                (size - 16u) % entry_size) return -1;
            mmap_off = off;
            mmap_size = size;
        } else if (type == 3) {
            if (size < 16 || read32(p + off + 12) <= read32(p + off + 8))
                return -1;
        } else if (type == 8 && size < 32) {
            return -1;
        } else if (type == 18) {
            /* EFI boot services still own memory: an E820 map is not enough. */
            return -1;
        }
        off += (size + 7u) & ~7u;
    }
    if (!ended || !mmap_off) return -1;

    /* First union all type-1 ranges, then subtract every non-type-1 entry.
     * Firmware maps are not required to be sorted or free of overlaps. */
    for (uint32_t e = mmap_off + 16; e < mmap_off + mmap_size; e += entry_size) {
        uint64_t base = read64(p + e), len = read64(p + e + 8);
        if (len > UINT64_MAX - base) return -1;
        if (read32(p + e + 16) == 1 && add_usable(map, base, base + len) != 0)
            return -1;
    }
    for (uint32_t e = mmap_off + 16; e < mmap_off + mmap_size; e += entry_size) {
        uint64_t base = read64(p + e), len = read64(p + e + 8);
        if (read32(p + e + 16) != 1 && bootmem_reserve(map, base, base + len) != 0)
            return -1;
    }
    for (uint32_t off = 8; off < total - 8;) {
        uint32_t type = read32(p + off), size = read32(p + off + 4);
        if (type == 3 && off != except_module) {
            if (bootmem_reserve(map, read32(p + off + 8), read32(p + off + 12)) != 0)
                return -1;
        } else if (type == 8) {
            uint64_t base = read64(p + off + 8);
            uint64_t bytes = (uint64_t)read32(p + off + 16) * read32(p + off + 24);
            if (bytes > UINT64_MAX - base || bootmem_reserve(map, base, base + bytes) != 0)
                return -1;
        }
        off += (size + 7u) & ~7u;
    }
    if ((uintptr_t)p > ~(uintptr_t)0 - total ||
        bootmem_reserve(map, (uintptr_t)p, (uintptr_t)p + total) != 0)
        return -1;
    return map->count ? 0 : -1;
}

int bootmem_from_multiboot(struct bootmem *map, uint32_t magic,
                           const void *info, uint64_t limit)
{
    return from_multiboot(map, magic, info, limit, UINT32_MAX);
}

int bootmem_from_multiboot_except_module(struct bootmem *map, uint32_t magic,
                                         const void *info, uint64_t limit,
                                         uint32_t module_offset)
{
    return from_multiboot(map, magic, info, limit, module_offset);
}

int bootmem_find_topdown(const struct bootmem *map, uint64_t size,
                         uint64_t alignment, uint64_t floor, uint64_t ceiling,
                         uint64_t guard, uint64_t *start)
{
    if (!map || !start || !size || !alignment ||
        (alignment & (alignment - 1u))) return -1;
    if (ceiling > map->limit) ceiling = map->limit;
    for (size_t i = map->count; i > 0; i--) {
        uint64_t lo = map->ranges[i - 1].start, hi = map->ranges[i - 1].end;
        if (lo < floor) lo = floor;
        if (hi > ceiling) hi = ceiling;
        if (hi <= lo || guard > hi - lo || size > hi - lo - guard) continue;
        uint64_t candidate = (hi - guard - size) & ~(alignment - 1u);
        if (candidate >= lo) {
            *start = candidate;
            return 0;
        }
    }
    return -1;
}

/* Prefer the existing boot layout, then a high range, then a low range.
 * The excluded middle is the user stack/TLS boundary. */
int bootmem_find_heap(const struct bootmem *map, uint64_t preferred,
                      uint64_t floor, uint64_t low_end, uint64_t high_start,
                      uint64_t *start, uint64_t *end)
{
    uint64_t best_lo = 0, best_hi = 0;
    const uint64_t minimum = 16u * 1024u * 1024u;
    if (!map || !start || !end || low_end > high_start) return -1;
    for (int pass = 0; pass < 4; pass++) {
        for (size_t i = 0; i < map->count; i++) {
            uint64_t lo = map->ranges[i].start, hi = map->ranges[i].end;
            int low = pass == 1 || pass == 2;
            uint64_t zone_lo = low ? floor : high_start;
            uint64_t zone_hi = low ? low_end : map->limit;
            uint64_t want = pass < 2 ? 128u * 1024u * 1024u : minimum;
            if (lo < floor) lo = floor;
            if (lo < zone_lo) lo = zone_lo;
            if (hi > zone_hi) hi = zone_hi;
            if (hi <= lo || hi - lo < want) continue;
            if (preferred >= lo && preferred < hi && hi - preferred >= want) {
                *start = preferred;
                *end = hi;
                return 0;
            }
            if (hi - lo > best_hi - best_lo) {
                best_lo = lo;
                best_hi = hi;
            }
        }
        if (best_hi > best_lo) break;
    }
    if (best_hi <= best_lo) return -1;
    *start = best_lo;
    *end = best_hi;
    return 0;
}

size_t bootmem_heap_size(uint64_t start, size_t available,
                         uint64_t high_start, size_t object_max)
{
    const size_t minimum = 128ULL * 1024ULL * 1024ULL;
    if (start < high_start || available <= minimum)
        return available;
    size_t object_heap = (available / 2u) & ~(size_t)(PAGE_SIZE_4K - 1u);
    if (object_heap < minimum) object_heap = minimum;
    if (object_heap > object_max) object_heap = object_max;
    return object_heap;
}
