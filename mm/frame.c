#include <frame.h>
#include <heap.h>
#include <paging.h>
#include <pmm.h>
#include <spinlock.h>
#include <string.h>

/* 256K slots × 4KiB = 1GiB of Soft_OWNED user pages. 64K (256MiB) was
 * smaller than the PMM arena; apt's 128MiB cache plus lists exhausted
 * it while fork still memcpy'd every private leaf into dpkg-deb/xz. */
#define FRAME_META_MAX 262144
#define FRAME_HASH_SIZE 8192

typedef struct frame_meta {
    uint64_t pa;
    void *raw; /* non-NULL only for legacy kmalloc-backed frames */
    unsigned refs;
    /* Freelist link when refs==0; PA hash chain when refs>0. */
    int link;
} frame_meta_t;

/* Heap-allocated: a static frames[] BSS blows past 0x400000 (user ET_EXEC). */
static frame_meta_t *frames;
static int frames_cap;
static int *frame_hash; /* FRAME_HASH_SIZE entries, heap-allocated */
static int frame_free_head = -1;
static spinlock_t frame_lock = { 0 };

static unsigned frame_hash_pa(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    return (unsigned)((pa >> 12) & (FRAME_HASH_SIZE - 1u));
}

void frame_init(void) {
    unsigned long flags;
    frames_cap = FRAME_META_MAX;
    frames = (frame_meta_t *)kmalloc(sizeof(frame_meta_t) * (size_t)frames_cap);
    if (!frames) {
        frames_cap = 4096;
        frames = (frame_meta_t *)kmalloc(sizeof(frame_meta_t) * (size_t)frames_cap);
    }
    acquire_irqsave(&frame_lock, &flags);
    if (frames)
        memset(frames, 0, sizeof(frame_meta_t) * (size_t)frames_cap);
    frame_hash = (int *)kmalloc(sizeof(int) * FRAME_HASH_SIZE);
    if (frame_hash) {
        for (int i = 0; i < FRAME_HASH_SIZE; i++)
            frame_hash[i] = -1;
    }
    frame_free_head = -1;
    if (frames) {
        for (int i = frames_cap - 1; i >= 0; --i) {
            frames[i].link = frame_free_head;
            frame_free_head = i;
        }
    }
    release_irqrestore(&frame_lock, flags);
}

static int frame_slot_locked(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    if (!frames)
        return -1;
    if (!frame_hash) {
        for (int i = 0; i < frames_cap; ++i)
            if (frames[i].refs && frames[i].pa == pa)
                return i;
        return -1;
    }
    unsigned h = frame_hash_pa(pa);
    for (int i = frame_hash[h]; i >= 0; i = frames[i].link) {
        if (frames[i].refs && frames[i].pa == pa)
            return i;
    }
    return -1;
}

static int frame_take_free_locked(void) {
    if (!frames)
        return -1;
    int slot = frame_free_head;
    if (slot < 0)
        return -1;
    frame_free_head = frames[slot].link;
    frames[slot].link = -1;
    return slot;
}

static void frame_return_free_locked(int slot) {
    if (!frames || slot < 0 || slot >= frames_cap)
        return;
    frames[slot].pa = 0;
    frames[slot].raw = NULL;
    frames[slot].refs = 0;
    frames[slot].link = frame_free_head;
    frame_free_head = slot;
}

static void frame_hash_insert_locked(int slot) {
    if (!frames || !frame_hash || slot < 0)
        return;
    unsigned h = frame_hash_pa(frames[slot].pa);
    frames[slot].link = frame_hash[h];
    frame_hash[h] = slot;
}

static void frame_hash_remove_locked(int slot) {
    if (!frames || !frame_hash || slot < 0)
        return;
    unsigned h = frame_hash_pa(frames[slot].pa);
    int *pp = &frame_hash[h];
    while (*pp >= 0) {
        if (*pp == slot) {
            *pp = frames[slot].link;
            frames[slot].link = -1;
            return;
        }
        pp = &frames[*pp].link;
    }
}

void *frame_alloc(void) {
    if (!frames)
        return NULL;

    void *page = NULL;
    void *raw = NULL;

    /* Prefer PMM (4KiB from reserved arena). Fall back to kmalloc only if
     * pmm was not carved at boot — never the steady-state path. */
    if (pmm_ready()) {
        page = pmm_alloc_page();
        if (!page)
            return NULL;
    } else {
        raw = kmalloc((size_t)PAGE_SIZE_4K * 2u);
        if (!raw)
            return NULL;
        page = (void *)(((uintptr_t)raw + PAGE_SIZE_4K - 1u) &
                        ~((uintptr_t)PAGE_SIZE_4K - 1u));
    }

    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_take_free_locked();
    if (slot >= 0) {
        frames[slot].pa = (uint64_t)(uintptr_t)page;
        frames[slot].raw = raw;
        frames[slot].refs = 1;
        frame_hash_insert_locked(slot);
    }
    release_irqrestore(&frame_lock, flags);
    if (slot < 0) {
        if (raw)
            kfree(raw);
        else
            pmm_free_page(page);
        return NULL;
    }
    return page;
}

void *frame_alloc_zero(void) {
    void *frame = frame_alloc();
    if (frame)
        memset(frame, 0, (size_t)PAGE_SIZE_4K);
    return frame;
}

int frame_adopt(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    if (!pa || !frames)
        return -1;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot < 0) {
        slot = frame_take_free_locked();
        if (slot >= 0) {
            frames[slot].pa = pa;
            frames[slot].raw = NULL;
            frames[slot].refs = 1;
            frame_hash_insert_locked(slot);
        }
    }
    release_irqrestore(&frame_lock, flags);
    return slot < 0 ? -1 : 0;
}

int frame_retain(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0)
        frames[slot].refs++;
    release_irqrestore(&frame_lock, flags);
    return slot < 0 ? -1 : 0;
}

void frame_release(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    void *raw = NULL;
    int free_pmm = 0;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0 && --frames[slot].refs == 0) {
        raw = frames[slot].raw;
        free_pmm = (raw == NULL);
        frame_hash_remove_locked(slot);
        frame_return_free_locked(slot);
    }
    release_irqrestore(&frame_lock, flags);
    if (raw)
        kfree(raw);
    else if (free_pmm)
        pmm_free_page((void *)(uintptr_t)pa);
}

unsigned frame_refcount(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    unsigned long flags;
    unsigned refs = 0;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0)
        refs = frames[slot].refs;
    release_irqrestore(&frame_lock, flags);
    return refs;
}
