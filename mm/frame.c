#include <frame.h>
#include <heap.h>
#include <paging.h>
#include <pmm.h>
#include <mmio.h>
#include <spinlock.h>
#include <string.h>
#include <vga.h>
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
#include <ram_page_pool.h>
#endif

/* Default capacity for the legacy heap-backed allocator. A PMM arena may be
 * larger than this, and needs one metadata slot for every physical page. */
#define FRAME_META_MAX 262144
#define FRAME_HASH_SIZE 8192
#define FRAME_META_CHUNK 64
#define FRAME_META_DIR_ENTRIES 512
#define FRAME_META_DIR_MAX 2048

typedef struct frame_meta {
    uint64_t pa;
    void *raw; /* non-NULL only for legacy kmalloc-backed frames */
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    struct ram_page high;
#endif
    unsigned refs;
    /* Freelist link when refs==0; PA hash chain when refs>0. */
    int link;
} frame_meta_t;

/* Heap-allocated: a static frames[] BSS blows past 0x400000 (user ET_EXEC). */
static frame_meta_t *frames;
static int frames_cap;
static int frames_base_cap;
static frame_meta_t **frame_extra[FRAME_META_DIR_MAX];
static size_t frame_extra_count;
static size_t frame_free_count;
static int *frame_hash; /* FRAME_HASH_SIZE entries, heap-allocated */
static size_t frame_hash_count = FRAME_HASH_SIZE;
static int frame_free_head = -1;
static spinlock_t frame_lock = { 0 };

/* Frame indices stay stable when boot-time metadata is extended. */
static frame_meta_t *frame_entry(int index) {
    if (index < frames_base_cap)
        return &frames[index];
    unsigned extra = (unsigned)(index - frames_base_cap);
    unsigned chunk = extra / FRAME_META_CHUNK;
    return &frame_extra[chunk / FRAME_META_DIR_ENTRIES]
                       [chunk % FRAME_META_DIR_ENTRIES][extra % FRAME_META_CHUNK];
}

static unsigned frame_hash_pa(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    return (unsigned)((pa >> 12) & (frame_hash_count - 1u));
}

void frame_init(void) {
    unsigned long flags;
    size_t capacity = FRAME_META_MAX;
    size_t pmm_pages = pmm_total_pages();
    if (pmm_pages > capacity)
        capacity = pmm_pages;
    /* Slot links are int indices; also avoid overflowing the allocation size. */
    if (capacity > (size_t)0x7fffffff)
        capacity = (size_t)0x7fffffff;
    if (capacity > ~(size_t)0 / sizeof(frame_meta_t))
        capacity = ~(size_t)0 / sizeof(frame_meta_t);
    frames = NULL;
    while (capacity >= 4096) {
        frames_cap = (int)capacity;
        frames = (frame_meta_t *)kmalloc(sizeof(frame_meta_t) * (size_t)frames_cap);
        if (frames)
            break;
        capacity /= 2;
    }
    if (!frames)
        frames_cap = 0;
    frames_base_cap = frames_cap;
    frame_extra_count = 0;
    frame_hash_count = FRAME_HASH_SIZE;
    acquire_irqsave(&frame_lock, &flags);
    if (frames)
        memset(frames, 0, sizeof(frame_meta_t) * (size_t)frames_cap);
    frame_hash = (int *)kmalloc(sizeof(int) * FRAME_HASH_SIZE);
    if (frame_hash) {
        for (int i = 0; i < FRAME_HASH_SIZE; i++)
            frame_hash[i] = -1;
    }
    frame_free_head = -1;
    frame_free_count = (size_t)frames_cap;
    if (frames) {
        for (int i = frames_cap - 1; i >= 0; --i) {
            frames[i].link = frame_free_head;
            frame_free_head = i;
        }
    }
    release_irqrestore(&frame_lock, flags);
    if ((size_t)frames_cap < pmm_pages)
        kprintf("frame: metadata capacity %llu pages below PMM %llu pages\n",
                (unsigned long long)frames_cap,
                (unsigned long long)pmm_pages);
}

/* Boot-only rehash: keep lookups bounded as physical RAM grows. On allocation
 * failure the original, correct (but more collision-prone) hash remains. */
static void frame_rehash_for_capacity(size_t capacity) {
    size_t wanted = FRAME_HASH_SIZE;
    while (wanted < capacity / 4 && wanted < (1u << 20))
        wanted <<= 1;
    if (frame_hash && wanted <= frame_hash_count)
        return;
    int *new_hash = (int *)kmalloc(wanted * sizeof(*new_hash));
    if (!new_hash)
        return;
    for (size_t i = 0; i < wanted; i++)
        new_hash[i] = -1;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    for (int i = 0; i < frames_cap; i++) {
        frame_meta_t *entry = frame_entry(i);
        if (entry->refs) {
            unsigned h = (unsigned)((entry->pa >> 12) & (wanted - 1u));
            entry->link = new_hash[h];
            new_hash[h] = i;
        }
    }
    int *old_hash = frame_hash;
    frame_hash = new_hash;
    frame_hash_count = wanted;
    release_irqrestore(&frame_lock, flags);
    if (old_hash)
        kfree(old_hash);
}

int frame_reserve_capacity(size_t pages) {
    /* Boot-only: metadata growth is not synchronized with frame_init. */
    unsigned long flags;
    if (!frames || pages > (size_t)0x7fffffff ||
        pages > (size_t)frames_base_cap +
                    (size_t)FRAME_META_CHUNK * FRAME_META_DIR_ENTRIES *
                    FRAME_META_DIR_MAX)
        return -1;
    while (pages > (size_t)frames_cap) {
        if (frame_extra_count == (size_t)FRAME_META_DIR_ENTRIES * FRAME_META_DIR_MAX ||
            frames_cap > 0x7fffffff - FRAME_META_CHUNK)
            return -1;
        size_t dir = frame_extra_count / FRAME_META_DIR_ENTRIES;
        size_t index = frame_extra_count % FRAME_META_DIR_ENTRIES;
        if (!frame_extra[dir]) {
            frame_extra[dir] = (frame_meta_t **)kmalloc(
                FRAME_META_DIR_ENTRIES * sizeof(*frame_extra[dir]));
            if (!frame_extra[dir])
                return -1;
            memset(frame_extra[dir], 0,
                   FRAME_META_DIR_ENTRIES * sizeof(*frame_extra[dir]));
        }
        frame_meta_t *chunk = NULL;
#if defined(AXON_EXPERIMENTAL_HIGH_USER_FRAMES) && AXON_EXPERIMENTAL_HIGH_USER_FRAMES
        /* Permanently reserve a high page for metadata itself; no user PTE
         * refers to it. The pool owns it until shutdown, like boot tables. */
        _Static_assert(FRAME_META_CHUNK * sizeof(frame_meta_t) <= PAGE_SIZE_4K,
                       "frame metadata chunk must fit in one high page");
        struct ram_page meta_page;
        if (ramfs_high_page_alloc(&meta_page) == 0)
            chunk = (frame_meta_t *)meta_page.va;
#endif
        if (!chunk)
            chunk = (frame_meta_t *)kmalloc(
                (size_t)FRAME_META_CHUNK * sizeof(*chunk));
        if (!chunk)
            return -1;
        memset(chunk, 0, (size_t)FRAME_META_CHUNK * sizeof(*chunk));
        acquire_irqsave(&frame_lock, &flags);
        int first = frames_cap;
        frame_extra[dir][index] = chunk;
        frame_extra_count++;
        for (int i = FRAME_META_CHUNK - 1; i >= 0; --i) {
            chunk[i].link = frame_free_head;
            frame_free_head = first + i;
        }
        frames_cap += FRAME_META_CHUNK;
        frame_free_count += FRAME_META_CHUNK;
        release_irqrestore(&frame_lock, flags);
    }
    frame_rehash_for_capacity((size_t)frames_cap);
    return 0;
}

size_t frame_capacity_pages(void) {
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    size_t capacity = (size_t)frames_cap;
    release_irqrestore(&frame_lock, flags);
    return capacity;
}

size_t frame_free_slots(void) {
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    size_t available = frame_free_count;
    release_irqrestore(&frame_lock, flags);
    return available;
}

static int frame_slot_locked(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    if (!frames)
        return -1;
    if (!frame_hash) {
        for (int i = 0; i < frames_cap; ++i)
            if (frame_entry(i)->refs && frame_entry(i)->pa == pa)
                return i;
        return -1;
    }
    unsigned h = frame_hash_pa(pa);
    for (int i = frame_hash[h]; i >= 0; i = frame_entry(i)->link) {
        if (frame_entry(i)->refs && frame_entry(i)->pa == pa)
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
    frame_free_head = frame_entry(slot)->link;
    frame_entry(slot)->link = -1;
    frame_free_count--;
    return slot;
}

static void frame_return_free_locked(int slot) {
    if (!frames || slot < 0 || slot >= frames_cap)
        return;
    frame_entry(slot)->pa = 0;
    frame_entry(slot)->raw = NULL;
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    frame_entry(slot)->high = (struct ram_page){0};
#endif
    frame_entry(slot)->refs = 0;
    frame_entry(slot)->link = frame_free_head;
    frame_free_head = slot;
    frame_free_count++;
}

static void frame_hash_insert_locked(int slot) {
    if (!frames || !frame_hash || slot < 0)
        return;
    unsigned h = frame_hash_pa(frame_entry(slot)->pa);
    frame_entry(slot)->link = frame_hash[h];
    frame_hash[h] = slot;
}

static void frame_hash_remove_locked(int slot) {
    if (!frames || !frame_hash || slot < 0)
        return;
    unsigned h = frame_hash_pa(frame_entry(slot)->pa);
    int *pp = &frame_hash[h];
    while (*pp >= 0) {
        if (*pp == slot) {
            *pp = frame_entry(slot)->link;
            frame_entry(slot)->link = -1;
            return;
        }
        pp = &frame_entry(*pp)->link;
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
        frame_entry(slot)->pa = (uint64_t)(uintptr_t)page;
        frame_entry(slot)->raw = raw;
        frame_entry(slot)->refs = 1;
        frame_hash_insert_locked(slot);
    }
    release_irqrestore(&frame_lock, flags);
    if (slot < 0) {
        static int metadata_oom_once;
        if (raw)
            kfree(raw);
        else
            pmm_free_page(page);
        if (!metadata_oom_once) {
            metadata_oom_once = 1;
            kprintf("frame: metadata exhausted (%d slots; PMM free=%llu)\n",
                    frames_cap, (unsigned long long)pmm_free_pages());
        }
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

#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
int frame_alloc_high(struct frame_page *out, int zero) {
    struct ram_page high = {0};
    unsigned long flags;
    if (!out || !frames)
        return -1;
    *out = (struct frame_page){0};
    if (ramfs_high_page_alloc(&high) != 0)
        return -1;
    if (zero)
        memset(high.va, 0, (size_t)PAGE_SIZE_4K);

    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_take_free_locked();
    if (slot >= 0) {
        frame_entry(slot)->pa = high.pa;
        frame_entry(slot)->raw = NULL;
        frame_entry(slot)->high = high;
        frame_entry(slot)->refs = 1;
        frame_hash_insert_locked(slot);
    }
    release_irqrestore(&frame_lock, flags);
    if (slot < 0) {
        (void)ramfs_high_page_free(high);
        return -1;
    }
    out->pa = high.pa;
    out->kva = high.va;
    return 0;
}
#endif

int frame_adopt(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    /* An arbitrary high PA has no retained pool-generation handle or proven
     * kernel mapping. High pages must enter via frame_alloc_high instead. */
    if (!pa || pa >= (uint64_t)MMIO_IDENTITY_LIMIT || !frames)
        return -1;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot < 0) {
        slot = frame_take_free_locked();
        if (slot >= 0) {
            frame_entry(slot)->pa = pa;
            frame_entry(slot)->raw = NULL;
            frame_entry(slot)->refs = 1;
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
        frame_entry(slot)->refs++;
    release_irqrestore(&frame_lock, flags);
    return slot < 0 ? -1 : 0;
}

void frame_release(uint64_t pa) {
    pa &= PG_ADDR_MASK;
    void *raw = NULL;
    int free_pmm = 0;
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    struct ram_page high = {0};
#endif
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0 && --frame_entry(slot)->refs == 0) {
        raw = frame_entry(slot)->raw;
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
        high = frame_entry(slot)->high;
        free_pmm = (raw == NULL && high.generation == 0);
#else
        free_pmm = (raw == NULL);
#endif
        frame_hash_remove_locked(slot);
        frame_return_free_locked(slot);
    }
    release_irqrestore(&frame_lock, flags);
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    if (high.generation)
        (void)ramfs_high_page_free(high);
    else
#endif
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
        refs = frame_entry(slot)->refs;
    release_irqrestore(&frame_lock, flags);
    return refs;
}

void *frame_kva(uint64_t pa) {
    unsigned long flags;
    void *result = NULL;
    uint64_t base = pa & PG_ADDR_MASK;
    uintptr_t offset = (uintptr_t)(pa & (PAGE_SIZE_4K - 1u));
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(base);
    if (slot >= 0) {
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
        if (frame_entry(slot)->high.generation)
            result = (void *)((uintptr_t)frame_entry(slot)->high.va + offset);
        else
#endif
            result = (void *)(uintptr_t)(base + offset);
    }
    release_irqrestore(&frame_lock, flags);
    return result;
}
