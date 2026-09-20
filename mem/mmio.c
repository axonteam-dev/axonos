#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <spinlock.h>
#include <mmio.h>
#include <paging.h>
#include <vga.h>
#include <klog.h>

#define MMIO_IDENTITY_LIMIT ((uint64_t)0x100000000ULL) /* 4GiB */
/* Place MMIO pool above user region (user stack at 256 MiB; heap/mmap below).
   Avoid overlap: use 512 MiB. */
#define MMIO_POOL_SLOTS 64 /* 64 * 2MiB = 128MiB virtual pool */
#define MMIO_POOL_BASE_VA ((uintptr_t)0x20000000ULL) /* 512 MiB */

static uint8_t mmio_slot_used[MMIO_POOL_SLOTS];
static uint16_t mmio_alloc_count[MMIO_POOL_SLOTS]; /* non-zero only at allocation start */
static spinlock_t mmio_pool_lock = { 0 };
static int mmio_inited = 0;

/* Early framebuffer maps made WB (because IA32_PAT is not programmed yet) get
 * queued here and upgraded to WC by mmio_pat_apply_wc() once paging_init()
 * programs the MSR — after the IDT exists. Any WRMSR before the IDT is a
 * #GP-on-the-floor = triple fault on real hardware (QEMU accepts it silently). */
#define MMIO_WC_PENDING_MAX 8
typedef struct {
	uint64_t va;      /* 2MiB-aligned VA of the first map page */
	uint16_t pages;   /* number of 2MiB pages to upgrade */
	uint8_t  used;
} mmio_wc_pending_t;
static mmio_wc_pending_t mmio_wc_pending[MMIO_WC_PENDING_MAX];

static void mmio_pat_apply_pde(uint64_t *l4, uint64_t va) {
	uint64_t l4i = (va >> 39) & 0x1FF, l3i = (va >> 30) & 0x1FF, l2i = (va >> 21) & 0x1FF;
	if (!l4 || !(l4[l4i] & PG_PRESENT) || (l4[l4i] & PG_PS_2M))
		return;
	uint64_t *l3 = (uint64_t *)(l4[l4i] & ~0xFFFULL);
	if (!l3 || !(l3[l3i] & PG_PRESENT))
		return;
	if (l3[l3i] & PG_PS_2M)
		return; /* 1GiB leaf: skip (map_page_2m would have split it) */
	uint64_t *l2 = (uint64_t *)(l3[l3i] & ~0xFFFULL);
	if (!l2 || !(l2[l2i] & PG_PRESENT))
		return;
	l2[l2i] |= PG_PAT;
	invlpg((void *)va);
}

/* Upgrade every pre-PAT framebuffer mapping to write-combining. Only ever runs
 * from paging_pat_init() (i.e. after the WRMSR + full TLB flush). */
void mmio_pat_apply_wc(void) {
	uint64_t *l4 = (uint64_t *)(paging_read_cr3() & ~0xFFFULL);
	uint32_t upgraded = 0;
	for (size_t i = 0; i < MMIO_WC_PENDING_MAX; i++) {
		mmio_wc_pending_t *e = &mmio_wc_pending[i];
		if (!e->used)
			continue;
		for (uint16_t p = 0; p < e->pages; p++) {
			uint64_t va = e->va + (uint64_t)p * PAGE_SIZE_2M;
			mmio_pat_apply_pde(l4, va);
			upgraded++;
		}
		e->used = 0;
	}
	if (upgraded)
		klogprintf("MMIO: upgraded %u framebuffer page(s) to WC\n", (unsigned)upgraded);
}

/* Configurable behavior:
   - Define MMIO_CACHE_ENABLED=1 to allow cached mappings (no PAT/PWT/PCD).
     By default MMIO uses uncached (PG_PCD|PG_PWT) for safety.
*/
#ifndef MMIO_CACHE_ENABLED
#define MMIO_CACHE_ENABLED 0
#endif

/* Map one physical address range `pa..pa+len-1` into kernel virtual space.
   Для pa < 4GiB возвращаем (void*)pa. Для >=4GiB выделяем подряд n слотов
   по 2MiB и делаем map_page_2m для каждой страницы.
*/
void *mmio_map_phys(uint64_t pa, size_t len) {
	if (len == 0) return NULL;

	/* For MMIO below 4GiB, keep identity VA==PA but REMAP the affected 2MiB pages
	   as uncached (PCD|PWT). VMware in particular can return garbage if MMIO is
	   accessed through cached mappings. */
	if (pa + (uint64_t)len <= MMIO_IDENTITY_LIMIT) {
		uint64_t pa_page = pa & ~(PAGE_SIZE_2M - 1);
		size_t offset_in_page = (size_t)(pa - pa_page);
		size_t total = offset_in_page + len;
		size_t pages_needed = (total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
#if MMIO_CACHE_ENABLED
		const uint64_t flags = PG_PRESENT | PG_RW;
#else
		const uint64_t flags = PG_PRESENT | PG_RW | PG_PCD | PG_PWT;
#endif
		for (size_t p = 0; p < pages_needed; p++) {
			uint64_t page = pa_page + (uint64_t)p * PAGE_SIZE_2M;
			/* identity VA==PA */
			int r = map_page_2m(page, page, flags);
			if (r != 0) {
				klogprintf("MMIO: identity remap failed pa=0x%llx (page=0x%llx) r=%d\n",
				           (unsigned long long)pa,
				           (unsigned long long)page,
				           r);
				return (void*)(uintptr_t)pa; /* fallback: still return identity */
			}
		}
		return (void*)(uintptr_t)pa;
	}

	/* align physical to 2MiB pages */
	uint64_t pa_page = pa & ~(PAGE_SIZE_2M - 1);
	size_t offset_in_page = (size_t)(pa - pa_page);
	size_t total = offset_in_page + len;
	size_t pages_needed = (total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
	if (pages_needed == 0 || pages_needed > MMIO_POOL_SLOTS) {
		klogprintf("MMIO: request too large pages_needed: %u\n", (unsigned)pages_needed);
		return NULL;
	}

	/* allocate contiguous slots */
	acquire(&mmio_pool_lock);
	int start = -1;
	for (int i = 0; i + (int)pages_needed <= MMIO_POOL_SLOTS; i++) {
		int ok = 1;
		for (size_t j = 0; j < pages_needed; j++) {
			if (mmio_slot_used[i + j]) { ok = 0; break; }
		}
		if (ok) { start = i; break; }
	}
	if (start < 0) {
		release(&mmio_pool_lock);
		//kprintf("mmio: no contiguous virtual slots available\n");
		return NULL;
	}

	/* reserve slots */
	for (size_t j = 0; j < pages_needed; j++) mmio_slot_used[start + j] = 1;
	mmio_alloc_count[start] = (uint16_t)pages_needed;
	release(&mmio_pool_lock);

	/* perform mapping per 2MiB page; rollback on failure */
	/* choose mapping flags based on cache preference */
#if MMIO_CACHE_ENABLED
	const uint64_t flags = PG_PRESENT | PG_RW;
#else
	const uint64_t flags = PG_PRESENT | PG_RW | PG_PCD | PG_PWT;
#endif
	for (size_t p = 0; p < pages_needed; p++) {
		uint64_t va_page = MMIO_POOL_BASE_VA + (uint64_t)(start + p) * PAGE_SIZE_2M;
		uint64_t pa_map = pa_page + p * PAGE_SIZE_2M;
		int r = map_page_2m(va_page, pa_map, flags);
		if (r != 0) {
			/* rollback: unmap previous mapped pages and free slots */
			for (size_t q = 0; q < p; q++) {
				uint64_t vaq = MMIO_POOL_BASE_VA + (uint64_t)(start + q) * PAGE_SIZE_2M;
				(void)unmap_page_2m(vaq);
			}
			acquire(&mmio_pool_lock);
			for (size_t j = 0; j < pages_needed; j++) {
				mmio_slot_used[start + j] = 0;
				mmio_alloc_count[start + j] = 0;
			}
			release(&mmio_pool_lock);
			klogprintf("MMIO: map_page_2m failed for PA: 0x%llx\n", (unsigned long long)pa);
			return NULL;
		}
	}

	/* return pointer with correct offset within first page */
	void *ret = (void*)( (char*)(uintptr_t)(MMIO_POOL_BASE_VA + (uint64_t)start * PAGE_SIZE_2M) + offset_in_page );
	return ret;
}

static void *mmio_map_framebuffer_flags(uint64_t pa, size_t len, uint64_t flags) {
	if (len == 0) return NULL;

	if (pa + (uint64_t)len <= MMIO_IDENTITY_LIMIT) {
		uint64_t pa_page = pa & ~(PAGE_SIZE_2M - 1);
		size_t offset_in_page = (size_t)(pa - pa_page);
		size_t total = offset_in_page + len;
		size_t pages_needed = (total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
		for (size_t p = 0; p < pages_needed; p++) {
			uint64_t page = pa_page + (uint64_t)p * PAGE_SIZE_2M;
			if (map_page_2m(page, page, flags) != 0)
				return (void *)(uintptr_t)pa;
		}
		return (void *)(uintptr_t)pa;
	}

	uint64_t pa_page = pa & ~(PAGE_SIZE_2M - 1);
	size_t offset_in_page = (size_t)(pa - pa_page);
	size_t total = offset_in_page + len;
	size_t pages_needed = (total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
	if (pages_needed == 0 || pages_needed > MMIO_POOL_SLOTS) {
		klogprintf("MMIO: framebuffer request too large pages_needed=%u\n", (unsigned)pages_needed);
		return NULL;
	}

	acquire(&mmio_pool_lock);
	int start = -1;
	for (int i = 0; i + (int)pages_needed <= MMIO_POOL_SLOTS; i++) {
		int ok = 1;
		for (size_t j = 0; j < pages_needed; j++) {
			if (mmio_slot_used[i + j]) { ok = 0; break; }
		}
		if (ok) { start = i; break; }
	}
	if (start < 0) {
		release(&mmio_pool_lock);
		return NULL;
	}
	for (size_t j = 0; j < pages_needed; j++) mmio_slot_used[start + j] = 1;
	mmio_alloc_count[start] = (uint16_t)pages_needed;
	release(&mmio_pool_lock);

	for (size_t p = 0; p < pages_needed; p++) {
		uint64_t va_page = MMIO_POOL_BASE_VA + (uint64_t)(start + p) * PAGE_SIZE_2M;
		uint64_t pa_map = pa_page + p * PAGE_SIZE_2M;
		if (map_page_2m(va_page, pa_map, flags) != 0) {
			for (size_t q = 0; q < p; q++) {
				uint64_t vaq = MMIO_POOL_BASE_VA + (uint64_t)(start + q) * PAGE_SIZE_2M;
				(void)unmap_page_2m(vaq);
			}
			acquire(&mmio_pool_lock);
			for (size_t j = 0; j < pages_needed; j++) {
				mmio_slot_used[start + j] = 0;
				mmio_alloc_count[start + j] = 0;
			}
			release(&mmio_pool_lock);
			return NULL;
		}
	}
	return (void *)((char *)(uintptr_t)(MMIO_POOL_BASE_VA + (uint64_t)start * PAGE_SIZE_2M) + offset_in_page);
}

void *mmio_map_framebuffer(uint64_t pa, size_t len) {
	/* Write-back: stores must reach RAM for the display engine (VMware SVGA, QEMU, …).
	   Uncached MMIO-style maps can leave scanout black or glitched for large VRAM BARs.
	   Kept for emulated VRAM that lives in coherent guest RAM. */
	return mmio_map_framebuffer_flags(pa, len, PG_PRESENT | PG_RW);
}

void *mmio_map_framebuffer_wc(uint64_t pa, size_t len) {
	/* Write-combining (WC) via PAT index 4 (PDE bit 12 = PG_PAT, PCD/PWT clear):
	   stores coalesce and drain to DRAM instead of lingering in write-back cache
	   lines the display engine cannot see. This is the fix for real UEFI/GOP
	   framebuffers in system RAM, where WB-without-clflush made rendering crawl.
	   CRITICAL: never WRMSR here. Early boot calls this before the IDT exists
	   (vbe_init_from_multiboot), and a WRMSR 0x277 that #GPs there is an instant
	   triple fault on real hardware. If IA32_PAT is not programmed yet, map WB
	   and queue the PDE for upgrade by mmio_pat_apply_wc() once the MSR is set
	   (in paging_init, after the IDT). Unsupported CPUs fall back to WB. */
	if (!paging_pat_probe())
		return mmio_map_framebuffer_flags(pa, len, PG_PRESENT | PG_RW);

	if (!paging_pat_configured()) {
		void *ret = mmio_map_framebuffer_flags(pa, len, PG_PRESENT | PG_RW);
		if (!ret)
			return ret;
		for (size_t i = 0; i < MMIO_WC_PENDING_MAX; i++) {
			if (!mmio_wc_pending[i].used) {
				mmio_wc_pending[i].va = (uint64_t)(uintptr_t)ret & ~(uint64_t)(PAGE_SIZE_2M - 1);
				size_t total = (size_t)(((uint64_t)(uintptr_t)ret & (uint64_t)(PAGE_SIZE_2M - 1))) + len;
				uint16_t pages = (uint16_t)((total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M);
				mmio_wc_pending[i].pages = pages;
				mmio_wc_pending[i].used = 1;
				break;
			}
		}
		return ret;
	}

	return mmio_map_framebuffer_flags(pa, len, PG_PRESENT | PG_RW | PG_PAT);
}

/* Unmap area previously returned by mmio_map_phys. For identity-mapped VA do nothing.
   For pooled mappings we unmap whole allocation stored in mmio_alloc_count.
*/
void mmio_unmap(void *va, size_t len) {
	if (!va) return;
	uintptr_t v = (uintptr_t)va;
	if (v + (uintptr_t)len <= MMIO_IDENTITY_LIMIT) return; /* identity region */

	uintptr_t pool_base = (uintptr_t)MMIO_POOL_BASE_VA;
	uintptr_t pool_end = pool_base + MMIO_POOL_SLOTS * PAGE_SIZE_2M;
	uintptr_t va_page = v & ~(PAGE_SIZE_2M - 1);
	if (va_page < pool_base || va_page >= pool_end) {
		/* not from our pool */
		return;
	}

	size_t idx = (va_page - pool_base) / PAGE_SIZE_2M;
	acquire(&mmio_pool_lock);
	uint16_t count = mmio_alloc_count[idx];
	if (count == 0) {
		/* nothing recorded at this slot */
		release(&mmio_pool_lock);
		return;
	}
	/* clear metadata first under lock */
	mmio_alloc_count[idx] = 0;
	for (size_t j = 0; j < count; j++) mmio_slot_used[idx + j] = 0;
	release(&mmio_pool_lock);

	/* unmap pages */
	for (size_t p = 0; p < count; p++) {
		uintptr_t vaq = pool_base + (idx + p) * PAGE_SIZE_2M;
		(void)unmap_page_2m((uint64_t)vaq);
	}
}

/* Initialize mmio subsystem (idempotent). */
void mmio_init(void) {
	if (mmio_inited) return;
	acquire(&mmio_pool_lock);
	for (size_t i = 0; i < MMIO_POOL_SLOTS; i++) {
		mmio_slot_used[i] = 0;
		mmio_alloc_count[i] = 0;
	}
	mmio_inited = 1;
	klogprintf("MMIO initialized with %u slots.\n", (unsigned)MMIO_POOL_SLOTS);
	release(&mmio_pool_lock);
}

/* Return pool usage; 0 on success */
int mmio_pool_get_status(mmio_pool_status_t *out) {
	if (!out) return -1;
	mmio_init();
	acquire(&mmio_pool_lock);
	size_t used = 0;
	size_t best_free = 0;
	size_t cur_free = 0;
	for (size_t i = 0; i < MMIO_POOL_SLOTS; i++) {
		if (mmio_slot_used[i]) { used++; cur_free = 0; }
		else { cur_free++; if (cur_free > best_free) best_free = cur_free; }
	}
	out->slots_total = MMIO_POOL_SLOTS;
	out->slots_used = used;
	out->largest_free_run = best_free;
	release(&mmio_pool_lock);
	return 0;
}

/* используем volatile указатели чтобы избежать оптимизаций */
uint8_t mmio_read8(const volatile void *base, size_t offset) {
	const volatile uint8_t *p = (const volatile uint8_t *)((const char*)base + offset);
	return *p;
}

uint16_t mmio_read16(const volatile void *base, size_t offset) {
	const volatile uint16_t *p = (const volatile uint16_t *)((const char*)base + offset);
	return *p;
}

uint32_t mmio_read32(const volatile void *base, size_t offset) {
	const volatile uint32_t *p = (const volatile uint32_t *)((const char*)base + offset);
	return *p;
}

uint64_t mmio_read64(const volatile void *base, size_t offset) {
	const volatile uint64_t *p = (const volatile uint64_t *)((const char*)base + offset);
	return *p;
}

void mmio_write8(volatile void *base, size_t offset, uint8_t val) {
	volatile uint8_t *p = (volatile uint8_t *)((char*)base + offset);
	*p = val;
}

void mmio_write16(volatile void *base, size_t offset, uint16_t val) {
	volatile uint16_t *p = (volatile uint16_t *)((char*)base + offset);
	*p = val;
}

void mmio_write32(volatile void *base, size_t offset, uint32_t val) {
	volatile uint32_t *p = (volatile uint32_t *)((char*)base + offset);
	*p = val;
}

void mmio_write64(volatile void *base, size_t offset, uint64_t val) {
	volatile uint64_t *p = (volatile uint64_t *)((char*)base + offset);
	*p = val;
}
