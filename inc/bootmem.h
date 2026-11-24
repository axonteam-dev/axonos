#pragma once

#include <stddef.h>
#include <stdint.h>

/* Early, allocation-free description of page-aligned usable physical RAM.
 * Ranges are sorted, disjoint and half-open. Overflow of the range table is
 * an error, never a reason to forget a reservation. */
#define BOOTMEM_MAX_RANGES 256

struct bootmem_range {
    uint64_t start;
    uint64_t end;
};

struct bootmem {
    struct bootmem_range ranges[BOOTMEM_MAX_RANGES];
    size_t count;
    uint64_t limit;
};

int bootmem_from_multiboot(struct bootmem *map, uint32_t magic,
                           const void *info, uint64_t limit);
/* Used while moving one module: all other reservations still apply. */
int bootmem_from_multiboot_except_module(struct bootmem *map, uint32_t magic,
                                         const void *info, uint64_t limit,
                                         uint32_t module_offset);
/* Parse only the fixed E820 table in a 4096-byte Linux x86 boot_params.
 * This is not a complete boot memory map: the caller must reserve all live
 * objects (including boot_params, initrd and framebuffer) before allocation.
 * setup_data is rejected because it can contain additional E820 entries. */
int bootmem_from_linux_e820(struct bootmem *map, const void *params,
                            size_t params_size, uint64_t limit);
int bootmem_reserve(struct bootmem *map, uint64_t start, uint64_t end);
int bootmem_is_free(const struct bootmem *map, uint64_t start, uint64_t end);
/* Sum the remaining usable bytes in a half-open physical-address window. */
uint64_t bootmem_free_bytes(const struct bootmem *map, uint64_t start, uint64_t end);
int bootmem_find_topdown(const struct bootmem *map, uint64_t size,
                         uint64_t alignment, uint64_t floor, uint64_t ceiling,
                         uint64_t guard, uint64_t *start);
int bootmem_find_heap(const struct bootmem *map, uint64_t preferred,
                      uint64_t floor, uint64_t low_end, uint64_t high_start,
                      uint64_t *start, uint64_t *end);
size_t bootmem_heap_size(uint64_t start, size_t available,
                         uint64_t high_start, size_t object_max);
