#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>
#include <stddef.h>

/* Keep the CPU-accessible mapping distinct from the physical PTE address. */
struct frame_page {
    uint64_t pa;
    void *kva;
};

void frame_init(void);
/* Boot-only, before concurrent frame operations: grow without changing indices
 * or references. Must be called with the kernel heap mapping active. */
int frame_reserve_capacity(size_t pages);
size_t frame_capacity_pages(void);
size_t frame_free_slots(void);
void *frame_alloc(void);
void *frame_alloc_zero(void);
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
/* Opt-in only: callers must retain the PA, use kva for kernel accesses, and
 * release through frame_release. Not suitable for legacy identity callers. */
int frame_alloc_high(struct frame_page *page, int zero);
#endif
int frame_adopt(uint64_t pa);
int frame_retain(uint64_t pa);
void frame_release(uint64_t pa);
unsigned frame_refcount(uint64_t pa);
/* Caller must hold a live frame reference for the entire use of the mapping.
 * Return NULL for untracked or already released pages. Accepts a page offset. */
void *frame_kva(uint64_t pa);

#endif
