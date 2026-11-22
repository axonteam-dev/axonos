/*
 * mem/pmm.c — physical page pool for Soft_OWNED frames.
 *
 * Linux: buddy/memblock owns pages; slab is a client. AxonOS previously
 * allocated every user frame via kmalloc(8KiB), exhausting the object heap.
 * This PMM hands out 4KiB identity pages from reserved RAM ranges.
 */
#include <pmm.h>
#include <bootmem.h>
#include <paging.h>
#include <mmio.h>
#include <spinlock.h>
#include <vga.h>

static spinlock_t pmm_lock;
static struct bootmem_range pmm_ranges[BOOTMEM_MAX_RANGES];
static size_t pmm_range_count;
static uintptr_t pmm_free_head; /* intrusive freelist: page stores next PA */
static size_t pmm_total;
static size_t pmm_free;
static int pmm_inited;

void pmm_init(uintptr_t lo, uintptr_t hi)
{
    unsigned long irqf;
    acquire_irqsave(&pmm_lock, &irqf);
    pmm_range_count = 0;
    pmm_free_head = 0;
    pmm_total = 0;
    pmm_free = 0;
    pmm_inited = 0;
    release_irqrestore(&pmm_lock, irqf);
    if (hi > lo && pmm_add_range(lo, hi) != 0)
        kprintf("pmm: invalid initial range [0x%llx..0x%llx)\n",
                (unsigned long long)lo, (unsigned long long)hi);
}

int pmm_add_range(uintptr_t lo, uintptr_t hi)
{
    unsigned long irqf;
    size_t n = 0;
    if (lo >= (uintptr_t)MMIO_IDENTITY_LIMIT || hi <= lo)
        return -1;
    if (hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
        hi = (uintptr_t)MMIO_IDENTITY_LIMIT;
    lo = (lo + (uintptr_t)PAGE_SIZE_4K - 1u) & ~((uintptr_t)PAGE_SIZE_4K - 1u);
    hi &= ~((uintptr_t)PAGE_SIZE_4K - 1u);
    /* Zero is the freelist sentinel. */
    if (!lo) lo = (uintptr_t)PAGE_SIZE_4K;
    if (hi <= lo) return -1;

    acquire_irqsave(&pmm_lock, &irqf);
    if (pmm_range_count == BOOTMEM_MAX_RANGES || pmm_free != pmm_total) {
        release_irqrestore(&pmm_lock, irqf);
        return -1;
    }
    for (size_t i = 0; i < pmm_range_count; i++) {
        if (lo < pmm_ranges[i].end && pmm_ranges[i].start < hi) {
            release_irqrestore(&pmm_lock, irqf);
            return -1;
        }
    }
    pmm_ranges[pmm_range_count].start = lo;
    pmm_ranges[pmm_range_count].end = hi;
    pmm_range_count++;
    for (uintptr_t p = lo; p < hi; p += (uintptr_t)PAGE_SIZE_4K) {
        *(uintptr_t *)(void *)p = pmm_free_head;
        pmm_free_head = p;
        n++;
    }
    pmm_total += n;
    pmm_free += n;
    pmm_inited = 1;
    release_irqrestore(&pmm_lock, irqf);

    kprintf("pmm: range [0x%llx..0x%llx) pages=%llu (%llu MiB)\n",
            (unsigned long long)lo, (unsigned long long)hi,
            (unsigned long long)n,
            (unsigned long long)((n * (size_t)PAGE_SIZE_4K) / (1024ull * 1024ull)));
    return 0;
}

int pmm_ready(void)
{
    return pmm_inited;
}

void *pmm_alloc_page(void)
{
    unsigned long irqf;
    uintptr_t page;

    if (!pmm_inited)
        return NULL;
    acquire_irqsave(&pmm_lock, &irqf);
    page = pmm_free_head;
    if (!page) {
        static int oom_once;
        size_t total = pmm_total;
        release_irqrestore(&pmm_lock, irqf);
        if (!oom_once) {
            oom_once = 1;
            kprintf("pmm: out of pages (managed %llu MiB) -- user mmap/fork/xz will ENOMEM\n",
                    (unsigned long long)((total * (size_t)PAGE_SIZE_4K) / (1024ull * 1024ull)));
        }
        return NULL;
    }
    pmm_free_head = *(uintptr_t *)(void *)page;
    if (pmm_free > 0)
        pmm_free--;
    release_irqrestore(&pmm_lock, irqf);
    return (void *)page;
}

void pmm_free_page(void *page)
{
    unsigned long irqf;
    uintptr_t pa = (uintptr_t)page;

    if (!pmm_inited || !page)
        return;
    if (pa & ((uintptr_t)PAGE_SIZE_4K - 1u))
        return;
    int managed = 0;
    for (size_t i = 0; i < pmm_range_count; i++) {
        if (pa >= pmm_ranges[i].start && pa < pmm_ranges[i].end) {
            managed = 1;
            break;
        }
    }
    if (!managed)
        return;
    acquire_irqsave(&pmm_lock, &irqf);
    *(uintptr_t *)(void *)pa = pmm_free_head;
    pmm_free_head = pa;
    pmm_free++;
    release_irqrestore(&pmm_lock, irqf);
}

size_t pmm_total_pages(void)
{
    return pmm_total;
}

size_t pmm_free_pages(void)
{
    return pmm_free;
}
