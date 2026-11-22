#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Physical page allocator for Soft_OWNED user frames (Linux-like buddy role).
 * One or more disjoint identity-mapped RAM ranges outside the kmalloc heap.
 * Ranges may only be added during boot, before any pages are allocated.
 */
void pmm_init(uintptr_t lo, uintptr_t hi);
int pmm_add_range(uintptr_t lo, uintptr_t hi);
int pmm_ready(void);
void *pmm_alloc_page(void);
void pmm_free_page(void *page);
size_t pmm_total_pages(void);
size_t pmm_free_pages(void);
