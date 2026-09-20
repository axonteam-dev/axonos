#include <pagecache.h>
#include <frame.h>
#include <paging.h>
#include <spinlock.h>
#include <heap.h>
#include <string.h>
#include <mm.h>
#include <thread.h>
#include <debug.h>
#include <klog.h>

#define PAGECACHE_BUCKETS 512
#define PAGECACHE_MAX     32768

struct pagecache_ent {
    uint64_t backing_id;
    uint64_t generation;
    uint64_t page_index;
    uint64_t pa;
    uint64_t last_used;
    int dsm;                   
    struct pagecache_ent *next;
};

static spinlock_t g_pc_lock;
static struct pagecache_ent *g_pc_bucket[PAGECACHE_BUCKETS];
static int g_pc_count;
static uint64_t g_pc_tick;

static int g_pc_trace;
#define PC_TRACE_MAX 1500
static int g_pc_inv_left = 800;
static void pc_trace_one(const char *tag, unsigned long pid, uint64_t bid,
                         uint64_t gen, uint64_t pg, uint64_t extra1,
                         uint64_t extra2)
{
    if (g_pc_trace < PC_TRACE_MAX)
        klogprintf_logonly("pc[%s] pid=%lu bid=0x%llx gen=%llu pg=0x%llx a=0x%llx b=0x%llx\n",
                tag, pid, (unsigned long long)bid, (unsigned long long)gen,
                (unsigned long long)pg, (unsigned long long)extra1,
                (unsigned long long)extra2);
    g_pc_trace++;
}

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
            if (e->dsm) {
                pp = &e->next;
                continue;
            }
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
    int rc = -1;
    mm_dm_ctx_t dm;
    int shmfile;
    unsigned long tr_pid;
    uint64_t tr_page_off;
    uint64_t tr_size, tr_n;
    unsigned long long tr_a8;
    int tr_miss;

    if (!file || !pa_out || file->backing_id == 0)
        return -1;
    {
        static int pcget_dbg_left = 120;
        if (pcget_dbg_left-- > 0)
            klogprintf_logonly("pcget pid=%lu bid=0x%llx off=0x%llx path=%s\n",
                (unsigned long)(thread_current() ? thread_current()->linux_tgid : 0),
                (unsigned long long)file->backing_id,
                (unsigned long long)file_off,
                file->path ? file->path : "?");
    }
    shmfile = (file->path && (strstr(file->path, "/PostgreSQL.") != NULL));
    aligned = file_off & ~0xFFFULL;
    backing_id = file->backing_id;
    /*
     * Resolve the LIVE inode generation through the fs driver, not the
     * handle snapshot: after a write(2)/ftruncate bumps the generation the
     * cache entries are re-stamped, and a stale backing_gen lookup would
     * MISS and re-read the file (zeros for a posix_fallocate'd MAP_SHARED
     * file) instead of the coherent frame.
     */
    generation = fs_current_generation(file);
    if (shmfile && generation != file->backing_gen) {
        static int pc_stale_left = 512;
        if (pc_stale_left-- > 0)
            klogprintf_logonly("pc[STALE] pid=%lu bid=0x%llx filegen=%llu livegen=%llu pg=0x%llx\n",
                    thread_current() ?
                        (unsigned long)thread_current()->linux_tgid : 0UL,
                    (unsigned long long)backing_id,
                    (unsigned long long)file->backing_gen,
                    (unsigned long long)generation,
                    (unsigned long long)(aligned >> 12));
    }
    page_index = aligned >> 12;
    tr_pid = 0;
    tr_page_off = aligned;
    tr_size = file ? file->size : 0;
    tr_n = 0;
    tr_a8 = 0;
    tr_miss = 0;
    if (shmfile && thread_current())
        tr_pid = (unsigned long)thread_current()->linux_tgid;

    /*
     * MAP_SHARED mmap unmaps the process identity window first. PMM frames
     * and the object heap live in that VA==PA range, so fill must run under
     * swapper CR3 (same rule as mm_map_user_page).
     */
    dm = mm_enter_direct_map();

    acquire_irqsave(&g_pc_lock, &irqf);
    hit = pc_find_locked(backing_id, generation, page_index);
    if (hit) {
        if (frame_retain(hit->pa) != 0) {
            release_irqrestore(&g_pc_lock, irqf);
            goto out;
        }
        hit->last_used = ++g_pc_tick;
        *pa_out = hit->pa;
        release_irqrestore(&g_pc_lock, irqf);
        if (shmfile) {
            pc_trace_one("HIT", tr_pid, backing_id, generation, page_index,
                         (uint64_t)hit->pa, (uint64_t)frame_refcount(hit->pa));
            const uint64_t *w = (const uint64_t *)(uintptr_t)hit->pa;
            pc_trace_one("HIT a8", 0, w[0],
                         ((uint64_t)frame_refcount(hit->pa) << 32) |
                             (generation & 0xffffffffULL),
                         page_index, backing_id, w[1]);
        }
        rc = 0;
        goto out;
    }
    release_irqrestore(&g_pc_lock, irqf);

    page = frame_alloc_zero();
    if (!page)
        goto out;
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
            goto out;
        }
    }
    if (shmfile) {
        tr_miss = 1;
        memcpy(&tr_a8, page, sizeof(tr_a8));
        tr_n = n;
    }

    acquire_irqsave(&g_pc_lock, &irqf);
    hit = pc_find_locked(backing_id, generation, page_index);
    if (hit) {
        if (frame_retain(hit->pa) != 0) {
            release_irqrestore(&g_pc_lock, irqf);
            frame_release(pa);
            goto out;
        }
        hit->last_used = ++g_pc_tick;
        *pa_out = hit->pa;
        release_irqrestore(&g_pc_lock, irqf);
        frame_release(pa);
        rc = 0;
        goto out;
    }
    while (g_pc_count >= PAGECACHE_MAX) {
        if (pc_evict_one_locked() != 0)
            break; /* all entries busy: grow the cache instead */
    }
    {
        struct pagecache_ent *ent = (struct pagecache_ent *)kmalloc(sizeof(*ent));
        if (ent) {
            unsigned b = pc_hash(backing_id, generation, page_index);
            ent->backing_id = backing_id;
            ent->generation = generation;
            ent->page_index = page_index;
            ent->pa = pa;
            ent->last_used = ++g_pc_tick;
            ent->dsm = shmfile ? 1 : 0;
            ent->next = g_pc_bucket[b];
            g_pc_bucket[b] = ent;
            g_pc_count++;
            if (frame_retain(pa) != 0) {
                release_irqrestore(&g_pc_lock, irqf);
                frame_release(pa);
                goto out;
            }
            *pa_out = pa;
            release_irqrestore(&g_pc_lock, irqf);
            rc = 0;
            goto out;
        }
    }
    /*
     * Heap exhausted for a cache entry: a MAP_SHARED caller MUST NOT get a
     * private frame (the next attach would read divergent data), so fail the
     * fault instead of corrupting shared memory.
     */
    release_irqrestore(&g_pc_lock, irqf);
    frame_release(pa);
    rc = -1;
out:
    if (shmfile && tr_miss)
        pc_trace_one("MISS pid", tr_pid, backing_id, generation, page_index,
                     tr_page_off, ((uint64_t)tr_n << 32) | (tr_size & 0xffffffffULL));
    if (shmfile && tr_miss) {
        const uint64_t *w = (const uint64_t *)(uintptr_t)pa;
        pc_trace_one("MISS a8", 0, tr_a8, ((uint64_t)tr_n << 32) | (tr_size & 0xffffffffULL),
                     backing_id, generation, w[1]);
        pc_trace_one("MISS pa", tr_pid, backing_id, generation, page_index,
                     (uint64_t)(uintptr_t)pa, frame_refcount(pa));
    }
    mm_leave_direct_map(dm);
    return rc;
}

void pagecache_invalidate(uint64_t backing_id, uint64_t new_generation)
{
    unsigned long irqf;
    int i;
    int n_dsm = 0, n_drop = 0, n_keep = 0, n_restamp = 0;

    if (!backing_id)
        return;
    acquire_irqsave(&g_pc_lock, &irqf);
    for (i = 0; i < PAGECACHE_BUCKETS; i++) {
        struct pagecache_ent **pp = &g_pc_bucket[i];
        while (*pp) {
            struct pagecache_ent *e = *pp;
            if (e->backing_id == backing_id) {
                if (e->dsm) {
                    n_dsm++;
                    if (new_generation) {
                        e->generation = new_generation;
                        n_restamp++;
                    }
                    pp = &e->next;
                } else if (frame_refcount(e->pa) == 1u) {
                    n_drop++;
                    *pp = e->next;
                    g_pc_count--;
                    frame_release(e->pa);
                    kfree(e);
                } else {
                    n_keep++;
                    if (new_generation) {
                        e->generation = new_generation;
                        n_restamp++;
                    }
                    pp = &e->next;
                }
            } else {
                pp = &e->next;
            }
        }
    }
    release_irqrestore(&g_pc_lock, irqf);
    /*
     * pc[INV] is capped so boot noise (pid 0 churning /dev/shm/proc ino 0xe,
     * invalidating absent entries) can no longer exhaust the budget and hide
     * real per-segment invalidations.  Only log when the invalidate actually
     * touched pagecache entries (dsm keep, drop, or restamp), and dump the
     * control-frame qwords when a DSM entry was involved so we can correlate
     * whether segment_handles[] content survives.
     */
    if (g_pc_inv_left > 0 && (n_dsm || n_drop || n_keep || n_restamp)) {
        g_pc_inv_left--;
        if (n_dsm) {
            const uint64_t *w = NULL;
            unsigned long fl2;
            acquire_irqsave(&g_pc_lock, &fl2);
            for (i = 0; i < PAGECACHE_BUCKETS && !w; i++) {
                struct pagecache_ent *e = g_pc_bucket[i];
                while (e) {
                    if (e->backing_id == backing_id && e->dsm) {
                        w = (const uint64_t *)(uintptr_t)e->pa;
                        break;
                    }
                    e = e->next;
                }
            }
            if (w) {
                klogprintf_logonly("pc[INV] pid=%lu bid=0x%llx newgen=%llu dsm=%d drop=%d keep=%d restamp=%d count=%d q0=0x%llx q1=0x%llx q2=0x%llx q3=0x%llx\n",
                        thread_current() ?
                            (unsigned long)thread_current()->linux_tgid : 0UL,
                        (unsigned long long)backing_id,
                        (unsigned long long)new_generation,
                        n_dsm, n_drop, n_keep, n_restamp, g_pc_count,
                        (unsigned long long)w[0], (unsigned long long)w[1],
                        (unsigned long long)w[2], (unsigned long long)w[3]);
                release_irqrestore(&g_pc_lock, fl2);
            } else {
                release_irqrestore(&g_pc_lock, fl2);
                klogprintf_logonly("pc[INV] pid=%lu bid=0x%llx newgen=%llu dsm=%d drop=%d keep=%d restamp=%d count=%d\n",
                        thread_current() ?
                            (unsigned long)thread_current()->linux_tgid : 0UL,
                        (unsigned long long)backing_id,
                        (unsigned long long)new_generation,
                        n_dsm, n_drop, n_keep, n_restamp, g_pc_count);
            }
        } else {
            klogprintf_logonly("pc[INV] pid=%lu bid=0x%llx newgen=%llu dsm=%d drop=%d keep=%d restamp=%d count=%d\n",
                    thread_current() ?
                        (unsigned long)thread_current()->linux_tgid : 0UL,
                    (unsigned long long)backing_id,
                    (unsigned long long)new_generation,
                    n_dsm, n_drop, n_keep, n_restamp, g_pc_count);
        }
    }
}
