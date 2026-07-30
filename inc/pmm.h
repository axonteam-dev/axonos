#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Physical page allocator for Soft_OWNED user frames (Linux-like buddy role).
 * Contiguous identity-mapped arena carved from RAM outside the kmalloc heap.
 */
void pmm_init(uintptr_t lo, uintptr_t hi);
int pmm_ready(void);
void *pmm_alloc_page(void);
void pmm_free_page(void *page);
size_t pmm_total_pages(void);
size_t pmm_free_pages(void);
