#pragma once

#include <stdint.h>
#include <stddef.h>

/* Physical addresses below this value are assumed identity-mapped in the kernel.
   Used by loaders/syscalls that temporarily access user buffers via identity mapping. */
#define MMIO_IDENTITY_LIMIT ((uint64_t)0x100000000ULL) /* 4GiB */

/* Простая библиотека/драйвер для работы с MMIO.
   Поддерживает прямой доступ для физических адресов < 4GiB (identity mapping),
   и предоставляет компактные функции чтения/записи типов 8/16/32/64 бит.

   Замечание: в текущей реализации маппинг физических адресов >= 4GiB не
   реализован — для таких устройств необходимо расширить менеджер виртуальной
   памяти. API спроектировано так, чтобы позже добавить map/unmap.
*/

/* Вернуть виртуальный указатель, соответствующий физическому адресу `pa`.
   Если возвращаемое значение NULL — ошибка (не поддерживается). */
void *mmio_map_phys(uint64_t pa, size_t len);

/* Linear framebuffer / VRAM: cached (WB) PTEs. Use for PCI video RAM scanout; keep mmio_map_phys for device regs. */
void *mmio_map_framebuffer(uint64_t pa, size_t len);

/* Linear framebuffer as write-combining (WC) via PAT. For real UEFI/GOP
 * framebuffers in system RAM and discrete VRAM, where WB stores stay in cache
 * lines the scanout engine cannot see (rendering crawls on bare metal).
 * Never WRMSRs at call time; if IA32_PAT is not programmed yet (early boot,
 * before the IDT), the mapping is made WB and upgraded by mmio_pat_apply_wc(). */
void *mmio_map_framebuffer_wc(uint64_t pa, size_t len);

/* Upgrade early pre-PAT framebuffer mappings to WC. Called from paging_pat_init(). */
void mmio_pat_apply_wc(void);

/* Освободить отображение, если оно было создано (noop для identity-mapped). */
void mmio_unmap(void *va, size_t len);

/* Простые helpers для чтения/записи в MMIO (см. volatile access). */
uint8_t  mmio_read8(const volatile void *base, size_t offset);
uint16_t mmio_read16(const volatile void *base, size_t offset);
uint32_t mmio_read32(const volatile void *base, size_t offset);
uint64_t mmio_read64(const volatile void *base, size_t offset);

void mmio_write8(volatile void *base, size_t offset, uint8_t val);
void mmio_write16(volatile void *base, size_t offset, uint16_t val);
void mmio_write32(volatile void *base, size_t offset, uint32_t val);
void mmio_write64(volatile void *base, size_t offset, uint64_t val);


/* Introspection: report pool usage */
typedef struct {
    size_t slots_total;
    size_t slots_used;
    /* largest contiguous free run in slots */
    size_t largest_free_run;
} mmio_pool_status_t;

/* Fill status struct, returns 0 on success */
int mmio_pool_get_status(mmio_pool_status_t *out);

/* Initialize mmio subsystem (idempotent). */
void mmio_init(void);


