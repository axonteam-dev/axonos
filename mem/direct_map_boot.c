#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
#include <direct_map.h>
#include <paging.h>
#include <heap.h>
#include <mmio.h>
#include <ram_page_pool.h>

/* Detached construction can fail; retain all table allocations only after
 * publishing. Existing boot heap is identity-addressed below 4 GiB. */
#define DIRECT_MAP_BOOT_TABLES 1024
struct boot_tables {
    void *raw[DIRECT_MAP_BOOT_TABLES];
    uint64_t *table[DIRECT_MAP_BOOT_TABLES];
    size_t count;
};
static struct boot_tables tables;
static struct bootmem ram;
static struct ram_page_pool high_pool;

static void *high_resolve(void *ctx, uint64_t pa)
{
    (void)ctx;
    return (void *)(uintptr_t)(DIRECT_MAP_BASE + pa);
}

int ramfs_high_page_alloc(struct ram_page *out)
{
    return ram_page_pool_alloc(&high_pool, out);
}

int ramfs_high_page_free(struct ram_page page)
{
    return ram_page_pool_free(&high_pool, page);
}

size_t ramfs_high_page_free_pages(void)
{
    return ram_page_pool_free_pages(&high_pool);
}

size_t ramfs_high_page_total_pages(void)
{
    return high_pool.ready ? high_pool.total : 0;
}

static uint64_t *boot_alloc(void *ctx, uint64_t *pa)
{
    struct boot_tables *t = ctx;
    if (t->count == DIRECT_MAP_BOOT_TABLES) return NULL;
    void *raw = kmalloc(2 * PAGE_SIZE_4K);
    if (!raw) return NULL;
    uintptr_t aligned = ((uintptr_t)raw + PAGE_SIZE_4K - 1) & ~(PAGE_SIZE_4K - 1);
    if (!aligned || aligned >= MMIO_IDENTITY_LIMIT ||
        aligned > MMIO_IDENTITY_LIMIT - PAGE_SIZE_4K) {
        kfree(raw);
        return NULL;
    }
    t->raw[t->count] = raw;
    t->table[t->count++] = (uint64_t *)aligned;
    *pa = aligned;
    return (uint64_t *)aligned;
}

static uint64_t *boot_resolve(void *ctx, uint64_t pa)
{
    struct boot_tables *t = ctx;
    for (size_t i = 0; i < t->count; i++)
        if ((uintptr_t)t->table[i] == pa) return t->table[i];
    return NULL;
}

static void boot_free_tables(void)
{
    while (tables.count) kfree(tables.raw[--tables.count]);
}

int direct_map_boot_install(uint32_t magic, const void *info)
{
    uint32_t eax, ebx, ecx, edx, maxleaf;
    uint64_t cr4, efer, limit, entry, cr3;
    struct direct_map_allocator a = {&tables, boot_alloc, boot_resolve};
    if (tables.count) return -1;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    if (cr4 & (1ULL << 12)) return -1; /* This layout assumes four levels. */
    __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0xc0000080u));
    efer = ((uint64_t)edx << 32) | eax;
    if (!(efer & (1ULL << 11))) return -1;
    __asm__ volatile("cpuid" : "=a"(maxleaf), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0x80000000u), "c"(0));
    if (maxleaf < 0x80000008u) return -1;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0x80000008u), "c"(0));
    unsigned bits = eax & 0xffu;
    if (bits < 32 || bits > 52) return -1;
    limit = 1ULL << bits;
    if (limit > DIRECT_MAP_SIZE) limit = DIRECT_MAP_SIZE;
    if (bootmem_from_multiboot(&ram, magic, info, limit) != 0) return -1;
    cr3 = paging_read_cr3() & PG_ADDR_MASK;
    if (!cr3 || cr3 >= MMIO_IDENTITY_LIMIT) return -1;
    if (direct_map_build(&ram, &a, &entry) != 0 ||
        direct_map_publish((uint64_t *)(uintptr_t)cr3, entry) != 0) {
        boot_free_tables();
        return -1;
    }
    paging_flush_tlb();
    /* ram is the same reservation-filtered map used to construct the direct
     * map. PMM only owns physical addresses below 4 GiB. Claim high pages
     * before APs or tasks can run; failure leaves this optional pool absent. */
    (void)ram_page_pool_bootstrap(&high_pool, &ram, NULL, high_resolve,
                                  kmalloc, kfree);
    return 0;
}
#endif
