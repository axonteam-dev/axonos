/* boot_brk.h — persistent "black box" breadcrumbs across an unexplained reset.
 *
 * When the display path is taken over, the VGA text plane (and thus any
 * on-screen diagnostic) can be hidden, and a machine check / triple fault
 * loses all RAM state.  The RTC CMOS NVRAM is battery backed and survives
 * a full platform reset, so we stash the last bring-up stage there and print
 * it on the next boot.  Access uses ports 0x70/0x71 with the NMI-disable bit
 * set, exactly like cpu/etc/rtc.c.
 *
 * Each stage is written to several general-purpose CMOS slots in case the
 * BIOS POST clears some of them.  Stage slots: 0x42/0x46/0x4A, their magic:
 * 0x43/0x47/0x4B, fault code: 0x44.  None are touched by our RTC driver
 * (which only pokes the status/rate registers). */
#ifndef BOOT_BRK_H
#define BOOT_BRK_H

#include <stdint.h>
#include <serial.h>

#define BOOT_BRK_STAGE_R0 0x42
#define BOOT_BRK_VALID_R0 0x43
#define BOOT_BRK_STAGE_R1 0x46
#define BOOT_BRK_VALID_R1 0x47
#define BOOT_BRK_STAGE_R2 0x4A
#define BOOT_BRK_VALID_R2 0x4B
#define BOOT_BRK_FAULT_REG 0x44
#define BOOT_BRK_MAGIC     0x5Au

static inline void boot_brk_cmos_write(uint8_t reg, uint8_t val)
{
	/* Save IF and disable IRQs around the access: an RTC/PIT interrupt
	 * jumping in between the index and data outb would write to the wrong
	 * register (and could scramble unrelated CMOS bytes). */
	uint64_t flags;
	asm volatile("pushfq; popq %0" : "=r"(flags) :: "memory");
	asm volatile("cli" ::: "memory");
	outb(0x70, (uint8_t)(reg | 0x80)); /* bit7: keep NMI masked during access */
	outb(0x71, val);
	if (flags & 0x200)
		asm volatile("sti" ::: "memory");
}

static inline uint8_t boot_brk_cmos_read(uint8_t reg)
{
	uint64_t flags;
	uint8_t v;
	asm volatile("pushfq; popq %0" : "=r"(flags) :: "memory");
	asm volatile("cli" ::: "memory");
	outb(0x70, (uint8_t)(reg | 0x80));
	v = inb(0x71);
	if (flags & 0x200)
		asm volatile("sti" ::: "memory");
	return v;
}

/* Record that we reached `stage` and that the log is valid. */
static inline void boot_brk(uint8_t stage)
{
	boot_brk_cmos_write(BOOT_BRK_STAGE_R0, stage);
	boot_brk_cmos_write(BOOT_BRK_VALID_R0, BOOT_BRK_MAGIC);
	boot_brk_cmos_write(BOOT_BRK_STAGE_R1, stage);
	boot_brk_cmos_write(BOOT_BRK_VALID_R1, BOOT_BRK_MAGIC);
	boot_brk_cmos_write(BOOT_BRK_STAGE_R2, stage);
	boot_brk_cmos_write(BOOT_BRK_VALID_R2, BOOT_BRK_MAGIC);
}

/* Record a fault/diagnostic code without disturbing the stage value. */
static inline void boot_brk_fault(uint8_t code)
{
	boot_brk_cmos_write(BOOT_BRK_FAULT_REG, code);
	boot_brk_cmos_write(BOOT_BRK_VALID_R0, BOOT_BRK_MAGIC);
}

/* True if any slot holds the magic.  If several do, stage/fault are read from
 * the slot that made the report (R0 preferred). */
static inline int boot_brk_valid(void)
{
	return boot_brk_cmos_read(BOOT_BRK_VALID_R0) == BOOT_BRK_MAGIC ||
	       boot_brk_cmos_read(BOOT_BRK_VALID_R1) == BOOT_BRK_MAGIC ||
	       boot_brk_cmos_read(BOOT_BRK_VALID_R2) == BOOT_BRK_MAGIC;
}

static inline uint8_t boot_brk_stage(void)
{
	uint8_t s;
	if (boot_brk_cmos_read(BOOT_BRK_VALID_R0) == BOOT_BRK_MAGIC)
		return boot_brk_cmos_read(BOOT_BRK_STAGE_R0);
	if (boot_brk_cmos_read(BOOT_BRK_VALID_R1) == BOOT_BRK_MAGIC)
		return boot_brk_cmos_read(BOOT_BRK_STAGE_R1);
	s = boot_brk_cmos_read(BOOT_BRK_STAGE_R2);
	boot_brk_cmos_write(BOOT_BRK_VALID_R0, BOOT_BRK_MAGIC); /* mark slot 2 as reported */
	return s;
}

static inline uint8_t boot_brk_fault_code(void)
{
	return boot_brk_cmos_read(BOOT_BRK_FAULT_REG);
}

static inline void boot_brk_clear(void)
{
	boot_brk_cmos_write(BOOT_BRK_VALID_R0, 0);
	boot_brk_cmos_write(BOOT_BRK_VALID_R1, 0);
	boot_brk_cmos_write(BOOT_BRK_VALID_R2, 0);
}

#endif /* BOOT_BRK_H */