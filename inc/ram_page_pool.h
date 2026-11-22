#pragma once

#include <stddef.h>
#include <stdint.h>
#include <bootmem.h>
#include <spinlock.h>

#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP

/* Independent experimental pool; never pass these handles to PMM or frame.
 * A generation protects against freeing a stale handle after reallocation. */
struct ram_page {
    uint64_t pa;
    void *va;
    uint64_t generation;
};

struct ram_page_range {
    uint64_t start, end;
    size_t first;
};

struct ram_page_pool {
    spinlock_t lock;
    struct ram_page_range ranges[BOOTMEM_MAX_RANGES];
    size_t count, total, free_pages;
    uint64_t head;
    size_t virgin_range;
    uint64_t virgin_next;
    uint64_t *state;
    void *ctx;
    void *(*resolve)(void *ctx, uint64_t pa);
    int ready;
};

/*
 * pool must be zero-initialized. Called once, exclusively, before publication.
 * free_map must be the authoritative bootmem ownership map, already excluding
 * every reservation and allocation, and must not be used concurrently. Only
 * ranges >= 4 GiB are claimed; on success free_map loses those ranges.
 *
 * resolve must be a stable, one-to-one, writable supervisor-only mapping of
 * every claimed PA in EVERY CR3 that may call this API. It must be nonblocking
 * and safe with IRQs disabled; mappings and ctx must outlive the pool. The API
 * cannot validate page-table permissions or cache attributes. Metadata must
 * be permanently mapped, aligned uint64_t storage, private and disjoint from
 * all claimed pages. state_count is the number of uint64_t entries available,
 * one per page. Neither pool nor metadata may be user writable.
 *
 * Failure does not change free_map or publish a pool; it may modify metadata
 * and the contents of still-free pages. No deinit/reinitialization is allowed.
 */
int ram_page_pool_init(struct ram_page_pool *pool, struct bootmem *free_map,
                       uint64_t *state, size_t state_count,
                       void *ctx, void *(*resolve)(void *, uint64_t));
/* Pages are not zeroed; consumers must zero them before exposing contents. */
int ram_page_pool_alloc(struct ram_page_pool *pool, struct ram_page *out);
int ram_page_pool_free(struct ram_page_pool *pool, struct ram_page page);
size_t ram_page_pool_free_pages(struct ram_page_pool *pool);

/* Boot adapter: metadata comes from the caller's permanent low-memory heap.
 * On failure free_map is unchanged and any allocated metadata is released. */
int ram_page_pool_bootstrap(struct ram_page_pool *pool, struct bootmem *free_map,
                            void *ctx, void *(*resolve)(void *, uint64_t),
                            void *(*alloc_metadata)(size_t),
                            void (*free_metadata)(void *));

/* Optional RAMFS backing: retain the entire handle in the chunk until free,
 * zero its page before exposing it, and never pass it to PMM/frame/kfree.
 * Failure includes an unavailable or exhausted pool; the caller may fall
 * back to its normal allocator. Only enabled after boot map publication. */
int ramfs_high_page_alloc(struct ram_page *out);
int ramfs_high_page_free(struct ram_page page);
size_t ramfs_high_page_free_pages(void);
size_t ramfs_high_page_total_pages(void);

#endif
