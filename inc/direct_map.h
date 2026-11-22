#pragma once

#include <stdint.h>
#include <bootmem.h>

/*
 * Experimental, detached x86-64 RAM direct-map builder. It never publishes
 * a PML4 entry or changes CR3. The caller owns all allocated tables, including
 * on failure, and must keep them alive for as long as any root references them.
 *
 * One PML4 slot provides 512 GiB at a canonical supervisor-only address.
 * Only RAM described by map is mapped; holes remain non-present. No MMIO,
 * firmware reservations, or unverified physical addresses may be added.
 */
#define DIRECT_MAP_BASE 0xffff800000000000ULL
#define DIRECT_MAP_SIZE (1ULL << 39)

struct direct_map_allocator {
    void *ctx;
    /* Returns a 4K-aligned, zeroed table and its 4K-aligned physical address.
     * The address must be representable in an x86 page-table entry. */
    uint64_t *(*alloc)(void *ctx, uint64_t *pa);
    /* Resolve a table PA previously returned by alloc, not arbitrary RAM. */
    uint64_t *(*resolve)(void *ctx, uint64_t pa);
};

/* On success returns a PML4 entry, not a root table. No partial entry is
 * returned on failure; the caller must reclaim its allocator's tables. */
int direct_map_build(const struct bootmem *map,
                     const struct direct_map_allocator *allocator,
                     uint64_t *entry_out);

/* Install only into an empty PML4 slot. The caller must ensure NXE is enabled,
 * no other CPU can use the root, and no process root has been cloned yet. */
int direct_map_publish(uint64_t *pml4, uint64_t entry);

/* Experimental boot-time installation, before AP startup and task roots. */
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
int direct_map_boot_install(uint32_t magic, const void *info);
#endif
