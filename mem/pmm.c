/*
 * mem/pmm.c — contiguous physical page pool for Soft_OWNED frames.
 *
 * Linux: buddy/memblock owns pages; slab is a client. AxonOS previously
 * allocated every user frame via kmalloc(8KiB), exhausting the object heap.
 * This PMM hands out 4KiB identity pages from a reserved arena.
 */
#include <pmm.h>
#include <paging.h>
#include <mmio.h>
#include <spinlock.h>
#include <vga.h>

static spinlock_t pmm_lock;
static uintptr_t pmm_base;
static uintptr_t pmm_end;
static uintptr_t pmm_free_head; /* intrusive freelist: page stores next PA */
static size_t pmm_total;
static size_t pmm_free;
static int pmm_inited;

static uintptr_t pmm_align_up(uintptr_t v, uintptr_t a)
{
    return (v + (a - 1u)) & ~(a - 1u);
}

static uintptr_t pmm_align_down(uintptr_t v, uintptr_t a)
{
    return v & ~(a - 1u);
}

void pmm_init(uintptr_t lo, uintptr_t hi)
{
    unsigned long irqf;
    uintptr_t p;
    size_t n = 0;

    lo = pmm_align_up(lo, (uintptr_t)PAGE_SIZE_4K);
    hi = pmm_align_down(hi, (uintptr_t)PAGE_SIZE_4K);
    if (hi <= lo + (uintptr_t)PAGE_SIZE_4K) {
        kprintf("pmm: arena too small lo=0x%llx hi=0x%llx\n",
                (unsigned long long)lo, (unsigned long long)hi);
        return;
    }
    if (hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
        hi = pmm_align_down((uintptr_t)MMIO_IDENTITY_LIMIT, (uintptr_t)PAGE_SIZE_4K);

    acquire_irqsave(&pmm_lock, &irqf);
    pmm_base = lo;
    pmm_end = hi;
    pmm_free_head = 0;
    pmm_total = 0;
    pmm_free = 0;
    for (p = lo; p + (uintptr_t)PAGE_SIZE_4K <= hi; p += (uintptr_t)PAGE_SIZE_4K) {
        *(uintptr_t *)(void *)p = pmm_free_head;
        pmm_free_head = p;
        n++;
    }
    pmm_total = n;
    pmm_free = n;
    pmm_inited = (n > 0) ? 1 : 0;
    release_irqrestore(&pmm_lock, irqf);

    kprintf("pmm: arena [0x%llx..0x%llx) pages=%llu (%llu MiB)\n",
            (unsigned long long)lo, (unsigned long long)hi,
            (unsigned long long)n,
            (unsigned long long)((n * (size_t)PAGE_SIZE_4K) / (1024ull * 1024ull)));
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
            kprintf("pmm: out of pages (arena %llu MiB) -- user mmap/fork/xz will ENOMEM\n",
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
    if (pa < pmm_base || pa >= pmm_end)
        return;
    if (pa & ((uintptr_t)PAGE_SIZE_4K - 1u))
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
