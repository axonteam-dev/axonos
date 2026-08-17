/*
 * Shared file page cache for MAP_PRIVATE / ELF demand paging.
 * Key: (backing_id, generation, page_index). SquashFS gen is always 0.
 */
#include <pagecache.h>
#include <frame.h>
#include <paging.h>
#include <spinlock.h>
#include <heap.h>
#include <string.h>

#define PAGECACHE_BUCKETS 512
#define PAGECACHE_MAX     2048

struct pagecache_ent {
    uint64_t backing_id;
    uint64_t generation;
    uint64_t page_index;
    uint64_t pa;
    uint64_t last_used;
    struct pagecache_ent *next;
};

static spinlock_t g_pc_lock;
static struct pagecache_ent *g_pc_bucket[PAGECACHE_BUCKETS];
static int g_pc_count;
static uint64_t g_pc_tick;

static unsigned pc_hash(uint64_t backing_id, uint64_t generation, uint64_t page_index)
{
    uint64_t h = backing_id ^ (generation * 0x9E3779B97F4A7C15ULL) ^
                 (page_index * 0xBF58476D1CE4E5B9ULL);
    return (unsigned)(h & (PAGECACHE_BUCKETS - 1u));
}

static struct pagecache_ent *pc_find_locked(uint64_t backing_id, uint64_t generation,
                                            uint64_t page_index)
{
    unsigned b = pc_hash(backing_id, generation, page_index);
    struct pagecache_ent *e;
    for (e = g_pc_bucket[b]; e; e = e->next) {
        if (e->backing_id == backing_id && e->generation == generation &&
            e->page_index == page_index)
            return e;
    }
    return NULL;
}

static int pc_evict_one_locked(void)
{
    struct pagecache_ent *best = NULL;
    struct pagecache_ent **best_pp = NULL;
    uint64_t best_tick = UINT64_MAX;
    int i;

    for (i = 0; i < PAGECACHE_BUCKETS; i++) {
        struct pagecache_ent **pp = &g_pc_bucket[i];
        while (*pp) {
            struct pagecache_ent *e = *pp;
            if (frame_refcount(e->pa) == 1u && e->last_used <= best_tick) {
                best = e;
                best_pp = pp;
                best_tick = e->last_used;
            }
            pp = &e->next;
        }
    }
    if (!best || !best_pp)
        return -1;
    *best_pp = best->next;
    g_pc_count--;
    frame_release(best->pa);
    kfree(best);
    return 0;
}

int pagecache_get(struct fs_file *file, uint64_t file_off, uint64_t *pa_out)
{
    uint64_t backing_id;
    uint64_t generation;
    uint64_t page_index;
    uint64_t aligned;
    unsigned long irqf;
    struct pagecache_ent *hit;
    void *page;
    uint64_t pa;
    ssize_t nr;
    size_t n;

    if (!file || !pa_out || file->backing_id == 0)
        return -1;
    aligned = file_off & ~0xFFFULL;
    backing_id = file->backing_id;
    generation = file->backing_gen;
    page_index = aligned >> 12;

    acquire_irqsave(&g_pc_lock, &irqf);
    hit = pc_find_locked(backing_id, generation, page_index);
    if (hit) {
        if (frame_retain(hit->pa) != 0) {
            release_irqrestore(&g_pc_lock, irqf);
            return -1;
        }
        hit->last_used = ++g_pc_tick;
        *pa_out = hit->pa;
        release_irqrestore(&g_pc_lock, irqf);
        return 0;
    }
    release_irqrestore(&g_pc_lock, irqf);

    page = frame_alloc_zero();
    if (!page)
        return -1;
    pa = (uint64_t)(uintptr_t)page;
    n = (size_t)PAGE_SIZE_4K;
    if (aligned >= (uint64_t)file->size)
        n = 0;
    else if ((uint64_t)n > (uint64_t)file->size - aligned)
        n = (size_t)((uint64_t)file->size - aligned);
    if (n > 0) {
        nr = fs_read(file, page, n, (size_t)aligned);
        if (nr < 0 || (size_t)nr != n) {
            frame_release(pa);
            return -1;
        }
    }

    acquire_irqsave(&g_pc_lock, &irqf);
    hit = pc_find_locked(backing_id, generation, page_index);
    if (hit) {
        if (frame_retain(hit->pa) != 0) {
            release_irqrestore(&g_pc_lock, irqf);
            frame_release(pa);
            return -1;
        }
        hit->last_used = ++g_pc_tick;
        *pa_out = hit->pa;
        release_irqrestore(&g_pc_lock, irqf);
        frame_release(pa);
        return 0;
    }
    while (g_pc_count >= PAGECACHE_MAX) {
        if (pc_evict_one_locked() != 0)
            break;
    }
    if (g_pc_count < PAGECACHE_MAX) {
        struct pagecache_ent *ent = (struct pagecache_ent *)kmalloc(sizeof(*ent));
        if (ent) {
            unsigned b = pc_hash(backing_id, generation, page_index);
            ent->backing_id = backing_id;
            ent->generation = generation;
            ent->page_index = page_index;
            ent->pa = pa;
            ent->last_used = ++g_pc_tick;
            ent->next = g_pc_bucket[b];
            g_pc_bucket[b] = ent;
            g_pc_count++;
            if (frame_retain(pa) != 0) {
                release_irqrestore(&g_pc_lock, irqf);
                frame_release(pa);
                return -1;
            }
            *pa_out = pa;
            release_irqrestore(&g_pc_lock, irqf);
            return 0;
        }
    }
    /* Cache is full of busy pages: hand the private frame to the caller. */
    *pa_out = pa;
    release_irqrestore(&g_pc_lock, irqf);
    return 0;
}

void pagecache_invalidate(uint64_t backing_id)
{
    unsigned long irqf;
    int i;

    if (!backing_id)
        return;
    acquire_irqsave(&g_pc_lock, &irqf);
    for (i = 0; i < PAGECACHE_BUCKETS; i++) {
        struct pagecache_ent **pp = &g_pc_bucket[i];
        while (*pp) {
            struct pagecache_ent *e = *pp;
            if (e->backing_id == backing_id) {
                *pp = e->next;
                g_pc_count--;
                frame_release(e->pa);
                kfree(e);
            } else {
                pp = &e->next;
            }
        }
    }
    release_irqrestore(&g_pc_lock, irqf);
}
