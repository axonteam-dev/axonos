#include <frame.h>
#include <heap.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>

#define FRAME_META_MAX 32768

typedef struct frame_meta {
    uint64_t pa;
    void *raw;
    unsigned refs;
} frame_meta_t;

static frame_meta_t frames[FRAME_META_MAX];
static spinlock_t frame_lock = { 0 };

void frame_init(void) {
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    memset(frames, 0, sizeof(frames));
    release_irqrestore(&frame_lock, flags);
}

static int frame_slot_locked(uint64_t pa) {
    for (int i = 0; i < FRAME_META_MAX; ++i)
        if (frames[i].refs && frames[i].pa == pa)
            return i;
    return -1;
}

static int frame_empty_slot_locked(void) {
    for (int i = 0; i < FRAME_META_MAX; ++i)
        if (!frames[i].refs)
            return i;
    return -1;
}

void *frame_alloc(void) {
    void *raw = kmalloc((size_t)PAGE_SIZE_4K * 2u);
    if (!raw)
        return NULL;
    uintptr_t aligned = ((uintptr_t)raw + PAGE_SIZE_4K - 1u) &
                        ~((uintptr_t)PAGE_SIZE_4K - 1u);
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_empty_slot_locked();
    if (slot >= 0) {
        frames[slot].pa = (uint64_t)aligned;
        frames[slot].raw = raw;
        frames[slot].refs = 1;
    }
    release_irqrestore(&frame_lock, flags);
    if (slot < 0) {
        kfree(raw);
        return NULL;
    }
    return (void *)aligned;
}

void *frame_alloc_zero(void) {
    void *frame = frame_alloc();
    if (frame)
        memset(frame, 0, (size_t)PAGE_SIZE_4K);
    return frame;
}

int frame_adopt(uint64_t pa) {
    pa &= ~0xFFFULL;
    if (!pa)
        return -1;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot < 0) {
        slot = frame_empty_slot_locked();
        if (slot >= 0) {
            frames[slot].pa = pa;
            frames[slot].raw = NULL;
            frames[slot].refs = 1;
        }
    }
    release_irqrestore(&frame_lock, flags);
    return slot < 0 ? -1 : 0;
}

int frame_retain(uint64_t pa) {
    pa &= ~0xFFFULL;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    /*
     * Never manufacture ownership for an arbitrary identity/kernel-heap PA.
     * Every COW-capable user leaf must originate in frame_alloc(); otherwise
     * the allocator cannot keep its backing alive after the original mmput.
     */
    if (slot >= 0)
        frames[slot].refs++;
    release_irqrestore(&frame_lock, flags);
    return slot < 0 ? -1 : 0;
}

void frame_release(uint64_t pa) {
    pa &= ~0xFFFULL;
    void *raw = NULL;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0 && --frames[slot].refs == 0) {
        raw = frames[slot].raw;
        memset(&frames[slot], 0, sizeof(frames[slot]));
    }
    release_irqrestore(&frame_lock, flags);
    if (raw)
        kfree(raw);
}

unsigned frame_refcount(uint64_t pa) {
    pa &= ~0xFFFULL;
    unsigned refs = 0;
    unsigned long flags;
    acquire_irqsave(&frame_lock, &flags);
    int slot = frame_slot_locked(pa);
    if (slot >= 0)
        refs = frames[slot].refs;
    release_irqrestore(&frame_lock, flags);
    return refs;
}
