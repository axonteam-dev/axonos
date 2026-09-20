/* Display engine take-over for Gen6/7: read the pipe the firmware left
 * running, promote a stolen-memory framebuffer through the GTT, flip the
 * active primary plane, and publish fbdev (/dev/fb0, /dev/dri/card0).
 *
 * All writes are validated by read-back; any failure rolls the plane back to
 * the surface the BIOS was using, so the VBE console path remains intact.
 */
#include <intel.h>
#include "intel_regs.h"
#include <pci.h>
#include <mmio.h>
#include <vbe.h>
#include <fbdev.h>
#include <klog.h>
#include <string.h>
#include <stddef.h>
#include <boot_brk.h>
#include <apic_timer.h>

static uint32_t align_up_4k(uint32_t v)
{
	return (v + 0xFFFu) & ~0xFFFu;
}

/* Debug aid: paint the whole scanout a solid color. Once the primary plane is
 * live this color is the only reliable sign the display really scans our GTT
 * surface, and the color at reset pinpoints how far bring-up got. */
static void intel_fill_fb(intel_drv_t *d, uint32_t color)
{
	if (!d->fb.fb_va)
		return;
	uint32_t *p = (uint32_t *)d->fb.fb_va;
	uint32_t pixels = d->fb.len / 4u;
	for (uint32_t i = 0; i < pixels; i++)
		p[i] = color;
}

/* GEN6_GTT_ADDR_ENCODE: bits [28:0] of the address are in place, bits [39:29]
 * are carried in PTE bits [11:4]. */
static uint32_t decode_pte_phys(uint32_t pte)
{
	if ((pte & INTEL_GEN6_PTE_VALID) == 0)
		return 0;
	return (pte & INTEL_PTE_PHYS_MASK) | ((pte & 0xFF0u) << INTEL_PTE_PHYS_HIGH_SHIFT);
}

static int intel_find_active_pipe(intel_drv_t *d)
{
	void *mm = d->mmio;
	const int npipe = (d->gen >= 7) ? INTEL_MAX_PIPES : 2;
	int bringup_pipe = -1;
	uint32_t bringup_pc = 0, bringup_src = 0;
	int saw_format = 0;

	for (int p = 0; p < npipe; p++) {
		uint32_t base = INTEL_PIPE_OFFSET(p);
		uint32_t pbase = INTEL_PLANE_OFFSET(p);
		uint32_t pc = mmio_read32(mm, base + INTEL_PIPECONF_OFFSET);
		uint32_t cn = mmio_read32(mm, pbase);
		int pipe_on = (pc & INTEL_PIPECONF_ENABLE) != 0;
		int plane_on = (cn & INTEL_DISPLAY_PLANE_ENABLE) != 0;

		if (pipe_on && plane_on) {
			uint32_t fmt = (cn >> 26) & 0xFu;
			int bpp = 0, bppx = 0;

			switch (fmt) {
			case 4:  /* BGRX555 */
				bpp = 15; bppx = 2;
				break;
			case 5:  /* BGRX565 */
				bpp = 16; bppx = 2;
				break;
			case 6:  /* BGRX888 (XRGB8888) */
				bpp = 32; bppx = 4;
				break;
			default:
				klogprintf("intel: pipe%c plane up but unsupported format %u (dsp=0x%08x), skipping\n",
				           (char)('A' + p), (unsigned)fmt, (unsigned)cn);
				saw_format = 1;
				continue;
			}

			d->pipe.pipe = p;
			d->pipe.present = 1;
			d->pipe.bringup = 0;
			d->pipe.pipecfg = pc;
			d->pipe.dspcntr = cn;
			d->pipe.stride = mmio_read32(mm, pbase + (INTEL_DSPASTRIDE - INTEL_DSPACNTR));
			d->pipe.surf = mmio_read32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR));
			d->pipe.dspcntr_format = fmt;
			uint32_t src = mmio_read32(mm, INTEL_TRANS_OFFSET(p) + (INTEL_PIPESRC_A - INTEL_TRANS_A));
			d->pipe.src_w = (src & 0xFFFFu) + 1;
			d->pipe.src_h = ((src >> 16) & 0xFFFFu) + 1;
			d->pipe.bpp = (uint32_t)bpp;
			d->pipe.bytes_per_pixel = (uint32_t)bppx;
			klogprintf("intel: active pipe%c %ux%u pitch=%u bpp=%u surf=0x%x (adopt)\n",
			           (char)('A' + p), (unsigned)d->pipe.src_w, (unsigned)d->pipe.src_h,
			           (unsigned)d->pipe.stride, (unsigned)d->pipe.bpp,
			           (unsigned)d->pipe.surf);
			return 0;
		}

		if (pipe_on && !plane_on && bringup_pipe < 0) {
			bringup_pipe = p;
			bringup_pc = pc;
			bringup_src = mmio_read32(mm, INTEL_TRANS_OFFSET(p) + (INTEL_PIPESRC_A - INTEL_TRANS_A));
			klogprintf("intel: pipe%c enabled but primary plane off (conf=0x%08x dsp=0x%08x) — bring-up candidate\n",
			           (char)('A' + p), (unsigned)pc, (unsigned)cn);
		}
	}

	if (bringup_pipe >= 0) {
		d->pipe.pipe = bringup_pipe;
		d->pipe.present = 1;
		d->pipe.bringup = 1;
		d->pipe.pipecfg = bringup_pc;
		d->pipe.dspcntr = 0;
		d->pipe.dspcntr_format = 6;   /* we select BGRX888 */
		d->pipe.stride = 0;
		d->pipe.surf = 0;
		d->pipe.src_w = (bringup_src & 0xFFFFu) + 1;
		d->pipe.src_h = ((bringup_src >> 16) & 0xFFFFu) + 1;
		d->pipe.bpp = 32;
		d->pipe.bytes_per_pixel = 4;
		klogprintf("intel: bring-up pipe%c %ux%u at firmware timing\n",
		           (char)('A' + bringup_pipe), (unsigned)d->pipe.src_w,
		           (unsigned)d->pipe.src_h);
		return 0;
	}

	klogprintf("intel: no usable pipe to adopt or bring up%s\n",
	           saw_format ? " (unsupported plane format)" : "");
	return -1;
}

/* Where the firmware framebuffer lives: prefer the VBE LFB physical address,
 * else decode it from the plane's current GTT PTE. */
static uint32_t intel_bios_fb_pa(const intel_drv_t *d)
{
	uint64_t vbe_pa = vbe_get_frontbuffer_pa();
	if (vbe_pa && vbe_pa < (uint64_t)0x100000000ULL)
		return (uint32_t)vbe_pa;

	uint32_t surf = d->pipe.surf & ~0xFFFu;
	if (surf >= d->total_gtt_bytes)
		return 0;
	void *gsm = (uint8_t *)d->mmio + d->bar0_len / 2;
	uint32_t pte = mmio_read32(gsm, (size_t)(surf >> 12) * 4u);
	return decode_pte_phys(pte);
}

static uint32_t intel_pick_fb_pa(const intel_drv_t *d, uint32_t len, uint32_t *bios_pa)
{
	uint32_t base = d->stolen_base;
	uint32_t top = base + d->stolen_size;
	uint32_t bios = intel_bios_fb_pa(d);
	*bios_pa = bios;

	uint32_t pa = (top - len) & ~0xFFFu;
	/* Avoid overlapping the surface the plane still scans until the flip. */
	int guard = 4;
	while (bios && pa + len > bios && pa < bios + (16u << 20)) {
		if (bios >= pa + len)        /* moved above wasted */
			break;
		if (bios > len && bios - len >= base) {
			pa = (bios - len) & ~0xFFFu;
		} else {
			break;
		}
		if (--guard <= 0)
			break;
	}
	if (pa < base || pa + len > top)
		return 0;
	return pa;
}

static uint32_t intel_pick_gtt_off(const intel_drv_t *d, uint32_t len)
{
	uint32_t total = d->total_gtt_bytes;
	uint32_t off = (total - len) & ~0xFFFu;
	uint32_t bios = d->pipe.surf & ~0xFFFu;

	int guard = 4;
	while (bios && off + len > bios && off < bios + (16u << 20)) {
		if (bios > len) {
			off = (bios - len) & ~0xFFFu;
		} else {
			break;
		}
		if (--guard <= 0)
			break;
	}
	if (off + len > total)
		return 0;
	return off;
}

static int intel_setup_gtt_ptes(intel_drv_t *d)
{
	void *gsm = (uint8_t *)d->mmio + d->bar0_len / 2;
	uint32_t off = d->fb.gtt_off;
	uint32_t npages = (uint32_t)(d->fb.len >> 12);
	uint32_t pa = d->fb.fb_pa;

	for (uint32_t i = 0; i < npages; i++) {
		uint32_t pte = INTEL_GEN6_GTT_ADDR_ENCODE(pa) |
		              INTEL_GEN6_PTE_VALID | INTEL_GEN6_PTE_CACHE_LLC;
		mmio_write32(gsm, (size_t)((off >> 12) + i) * 4u, pte);
		pa += 4096;
	}
	/* Flush the GTT cache: write the flush bit, then post with a read. */
	mmio_write32(d->mmio, INTEL_GFX_FLSH_CNTL_GEN6, INTEL_GFX_FLSH_CNTL_EN);
	(void)mmio_read32(d->mmio, INTEL_GFX_FLSH_CNTL_GEN6);

	/* Validate one entry against what we wrote. */
	uint32_t check = mmio_read32(gsm, (size_t)(off >> 12) * 4u);
	if ((check & INTEL_GEN6_PTE_VALID) == 0) {
		klogprintf("intel: GTT PTE write did not stick (read=0x%08x)\n", (unsigned)check);
		return -1;
	}
	return 0;
}

/* Poll DSPSURFLIVE until it shows `target`.  Bounded by wall time (APIC
 * clock); if the clock isn't ticking yet, a fixed spin budget bounds it. */
static int intel_wait_surf(intel_drv_t *d, uint32_t target, uint32_t timeout_ms)
{
	void *mm = d->mmio;
	uint32_t pbase = INTEL_PLANE_OFFSET(d->pipe.pipe);
	uint32_t live = 0;
	uint32_t spins = 0;
	const uint32_t spin_budget = 100000u;   /* clock-less fallback bound */
	uint64_t t0 = apic_timer_get_time_ms();
	uint64_t deadline = t0 + (uint64_t)timeout_ms;

	for (;;) {
		live = mmio_read32(mm, pbase + (INTEL_DSPASURFLIVE - INTEL_DSPACNTR));
		if (live == target)
			return 0;
		__asm__ volatile("pause" ::: "memory");
		uint64_t now = apic_timer_get_time_ms();
		if (now != t0) {                  /* clock advancing: wall-time bound */
			if (now >= deadline)
				break;
		} else if (++spins >= spin_budget) {  /* stale clock: spin bound */
			break;
		}
	}
	klogprintf("intel: DSPSURFLIVE never reached 0x%x (live=0x%x)\n",
	           (unsigned)target, (unsigned)live);
	return -1;
}

static void intel_flip_plane(intel_drv_t *d, uint32_t surf)
{
	void *mm = d->mmio;
	uint32_t pbase = INTEL_PLANE_OFFSET(d->pipe.pipe);
	mmio_write32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR), surf);
	(void)mmio_read32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR));
}

/* WB framebuffer stores are invisible to the plane until they reach DRAM;
 * CLFLUSH the touched range (64-bit mode guarantees CLFLUSH), then fence so
 * the scanout engine samples coherent data. */
static void intel_fb_cache_flush(void *addr, size_t len)
{
	uintptr_t a = (uintptr_t)addr & ~(uintptr_t)63;
	uintptr_t end = (uintptr_t)addr + len;
	while (a < end) {
		__asm__ volatile("clflush (%0)" :: "r"(a) : "memory");
		a += 64;
	}
	__asm__ volatile("sfence" ::: "memory");
}

static void intel_copy_fw_fb(intel_drv_t *d)
{
	if (!d->fb.fb_va)
		return;
	if (vbe_is_available()) {
		const void *fw = vbe_get_frontbuffer();
		uint32_t fw_pitch = vbe_get_pitch();
		if (fw) {
			uint8_t *dst = (uint8_t *)d->fb.fb_va;
			uint32_t lines = d->fb.height;
			uint32_t row_probe = d->fb.width * d->pipe.bytes_per_pixel;
			if (row_probe > d->fb.pitch)
				row_probe = d->fb.pitch;
			for (uint32_t y = 0; y < lines; y++) {
				const uint8_t *src = (const uint8_t *)fw + (size_t)y * fw_pitch;
				memcpy(dst + (size_t)y * d->fb.pitch, src, row_probe);
			}
			intel_fb_cache_flush(d->fb.fb_va, (size_t)d->fb.height * d->fb.pitch);
			return;
		}
	}
	/* No firmware copy available: start from a black frame. */
	memset(d->fb.fb_va, 0, d->fb.len);
	intel_fb_cache_flush(d->fb.fb_va, d->fb.len);
}

int intel_display_takeover(intel_drv_t *d)
{
	void *mm = d->mmio;
	boot_brk(1);

	if (d->pte_bytes == 0 || d->total_gtt_bytes < (1u << 20)) {
		klogprintf("intel: bad GTT geometry (pte=0x%x total=0x%x)\n",
		           (unsigned)d->pte_bytes, (unsigned)d->total_gtt_bytes);
		return -1;
	}
	if (d->stolen_base == 0 || d->stolen_size < (16u << 20)) {
		klogprintf("intel: bad stolen geometry (base=0x%x size=0x%x)\n",
		           (unsigned)d->stolen_base, (unsigned)d->stolen_size);
		return -1;
	}

	if (intel_find_active_pipe(d) != 0) {
		klogprintf("intel: no BIOS-mode pipe to adopt — leaving VBE console untouched\n");
		return -1;
	}

	/* Frame buffer geometry: the plane is the source of truth. */
	uint32_t w = d->pipe.src_w;
	uint32_t h = d->pipe.src_h;
	uint32_t bpp = d->pipe.bpp;
	uint32_t bytes = d->pipe.bytes_per_pixel;
	uint32_t pitch = d->pipe.stride;
	if (d->pipe.bringup)
		pitch = (w * bytes + 63u) & ~63u;   /* linear stride, 64B aligned */
	if (pitch == 0 || pitch < w * bytes || w == 0 || h == 0) {
		klogprintf("intel: plane geometry invalid (w=%u h=%u pitch=%u bpp=%u)\n",
		           (unsigned)w, (unsigned)h, (unsigned)pitch, (unsigned)bpp);
		return -1;
	}
	uint64_t len64 = (uint64_t)pitch * (uint64_t)h;
	if (len64 >= 0x100000000ULL)
		return -1;
	uint32_t len = (uint32_t)len64;
	len = align_up_4k(len);
	if (len > d->stolen_size || len > d->total_gtt_bytes) {
		klogprintf("intel: fb len 0x%x exceeds stolen/gtt\n", (unsigned)len);
		return -1;
	}

	/* Cross-check against the VBE console: same mode expected (adopt only). */
	if (!d->pipe.bringup && vbe_is_available()) {
		if (vbe_get_width() != w || vbe_get_height() != h ||
		    vbe_get_pitch() != pitch || vbe_get_bpp() != bpp) {
			klogprintf("intel: VBE console geometry (w=%u h=%u p=%u bpp=%u) mismatch with plane (%ux%u p=%u bpp=%u)\n",
			           (unsigned)vbe_get_width(), (unsigned)vbe_get_height(),
			           (unsigned)vbe_get_pitch(), (unsigned)vbe_get_bpp(),
			           (unsigned)w, (unsigned)h, (unsigned)pitch, (unsigned)bpp);
			klogprintf("intel: aborting take-over to stay consistent with VBE console\n");
			return -1;
		}
	}

	/* Allocate the scanout buffer in stolen memory. */
	uint32_t bios_pa = 0;
	uint32_t fb_pa = intel_pick_fb_pa(d, len, &bios_pa);
	if (fb_pa == 0) {
		klogprintf("intel: no free stolen range for %u bytes\n", (unsigned)len);
		return -1;
	}
	d->fb.fb_pa = fb_pa;
	d->fb.len = len;
	d->fb.width = w;
	d->fb.height = h;
	d->fb.pitch = pitch;
	d->fb.bpp = bpp;
	d->fb.fb_va = mmio_map_framebuffer_wc((uint64_t)fb_pa, (size_t)len);
	if (!d->fb.fb_va) {
		klogprintf("intel: WM map failed for fb pa=0x%x len=0x%x\n",
		           (unsigned)fb_pa, (unsigned)len);
		return -1;
	}
	klogprintf("intel: fb pa=0x%x len=0x%x kva=%p (bios fb pa=0x%x)\n",
	           (unsigned)fb_pa, (unsigned)len, d->fb.fb_va, (unsigned)bios_pa);

	/* Make the new surface contain the current picture. */
	intel_copy_fw_fb(d);
	boot_brk(2);

	/* Move the plane onto our buffer. */
	uint32_t gtt_off = intel_pick_gtt_off(d, len);
	if (gtt_off == 0) {
		klogprintf("intel: no free GTT range for %u bytes\n", (unsigned)len);
		return -1;
	}
	d->fb.gtt_off = gtt_off;
	if (intel_setup_gtt_ptes(d) != 0)
		return -1;
	boot_brk(3);

	uint32_t pbase = INTEL_PLANE_OFFSET(d->pipe.pipe);
	uint32_t old_surf = d->pipe.surf & ~0xFFFu;
	uint32_t old_dspcntr = mmio_read32(mm, pbase);
	uint32_t old_vgacntrl = mmio_read32(mm, INTEL_VGACNTRL);
	uint32_t old_stride = d->pipe.stride;
	uint32_t old_tileoff = 0;

	if (d->pipe.bringup) {
		/* Primary plane bring-up (was disabled, pipe already up).
		 *
		 * ⚠ Gen6/SNB real iron: NEVER turn the plane on while DSPSURF is in
		 * the middle of a live flip from a not-yet-latched surface.  The GPU
		 * can hang (INVALID_DSPSURF) and then the PCH/SMI pulls a full
		 * platform reset — which is invisible to us (no #DF/#GP, CMOS fault
		 * stays 0, machine just resets by itself).  i915 does an orderly
		 * sequence: plane OFF → program SURF → plane ON → confirm SURFLIVE.
		 * We mirror that here: the surface is written while the plane is OFF,
		 * and SURFLIVE is only required to latch after the plane is enabled
		 * (the authoritative wait below). */

		/* 1. Plane OFF, then flush the write with a read fence. */
		uint32_t off_ctrl = INTEL_DISPPLANE_BGRX888 |
		                    ((uint32_t)(d->pipe.pipe << 24) & INTEL_DISPPLANE_SEL_PIPE_MASK);
		mmio_write32(mm, pbase, off_ctrl);   /* no PLANE_ENABLE bit */
		(void)mmio_read32(mm, pbase);
		boot_brk(3);

		/* 2. Geometry + surface, all while the plane is OFF. */
		mmio_write32(mm, pbase + (INTEL_DSPASTRIDE - INTEL_DSPACNTR), d->fb.pitch);
		mmio_write32(mm, pbase + (INTEL_DSPAPOS - INTEL_DSPACNTR), 0);
		mmio_write32(mm, pbase + (INTEL_DSPASIZE - INTEL_DSPACNTR),
		             (((h - 1u) & 0xFFFFu) << 16) | ((w - 1u) & 0xFFFFu));
		mmio_write32(mm, pbase + (INTEL_DSPATILEOFF - INTEL_DSPACNTR), 0);
		mmio_write32(mm, pbase + (INTEL_DSPAADDR - INTEL_DSPACNTR), 0);
		mmio_write32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR), gtt_off);
		/* Best effort, not a gate: on parts where SURFLIVE advances while
		 * the plane is OFF this confirms the latch before we enable; on
		 * parts where it does not, waiting would block the boot forever.
		 * i915 validates only after the plane is ON (wait below). */
		if (intel_wait_surf(d, gtt_off, 250) != 0)
			klogprintf("intel: SURFLIVE not confirmed while plane OFF — enabling anyway\n");
		boot_brk(4);

		/* 3. Only now the plane ON, surf already live and stable. */
		mmio_write32(mm, pbase,
		             off_ctrl | INTEL_DISPLAY_PLANE_ENABLE |
		             INTEL_DISPPLANE_BGRX888 |
		             ((uint32_t)(d->pipe.pipe << 24) & INTEL_DISPPLANE_SEL_PIPE_MASK));
		(void)mmio_read32(mm, pbase);
		boot_brk(5);
		/* The VGA plane is retired only after the whole take-over succeeds,
		 * so a fault in the console/fbdev path stays visible on VGA text. */
	} else {
		/* Plane already live: keep its config, just retarget the surface. */
		uint32_t dspcntr = mmio_read32(mm, pbase);
		old_tileoff = mmio_read32(mm, pbase + (INTEL_DSPATILEOFF - INTEL_DSPACNTR));
		dspcntr &= ~INTEL_DISPPLANE_TILED;   /* our buffer is linear */
		mmio_write32(mm, pbase, dspcntr);
		mmio_write32(mm, pbase + (INTEL_DSPASTRIDE - INTEL_DSPACNTR), d->fb.pitch);
		mmio_write32(mm, pbase + (INTEL_DSPATILEOFF - INTEL_DSPACNTR), 0);
		intel_flip_plane(d, gtt_off);
	}

	if (intel_wait_surf(d, gtt_off, 500) != 0) {
		klogprintf("intel: plane validation failed — rolling back\n");
		if (d->pipe.bringup) {
			/* Turn our plane back off and give the VGA plane back. */
			mmio_write32(mm, pbase, old_dspcntr & ~INTEL_DISPLAY_PLANE_ENABLE);
			mmio_write32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR), old_surf);
			mmio_write32(mm, INTEL_VGACNTRL, old_vgacntrl);
			(void)mmio_read32(mm, INTEL_VGACNTRL);
		} else {
			klogprintf("intel: restoring BIOS plane state (surf=0x%x)\n", (unsigned)old_surf);
			/* Restore everything the adopt path touched, not just the
			 * surface: a live plane left scanning the BIOS buffer with our
			 * stride/tileoff would corrupt the VBE console. */
			mmio_write32(mm, pbase, old_dspcntr);
			mmio_write32(mm, pbase + (INTEL_DSPASTRIDE - INTEL_DSPACNTR), old_stride);
			mmio_write32(mm, pbase + (INTEL_DSPATILEOFF - INTEL_DSPACNTR), old_tileoff);
			intel_flip_plane(d, old_surf);
			if (intel_wait_surf(d, old_surf, 250) != 0)
				klogprintf("intel: CRITICAL rollback failed, display may be off\n");
		}
		return -1;
	}
	d->took_over = 1;
	boot_brk(6);

	/* Green means DSPSURFLIVE latched our surface: plane + GTT are live. */
	if (d->pipe.bringup)
		intel_fill_fb(d, 0x0000FF00u);

	/* Move the text console onto our framebuffer, then publish fb0. */
	if (d->pipe.bringup) {
		klogprintf("intel: plane validation ok (surf=0x%x), attaching fb console\n",
		           (unsigned)gtt_off);
		if (vbe_attach_framebuffer(d->fb.fb_va, d->fb.width, d->fb.height,
		                           d->fb.pitch, d->fb.bpp) != 0) {
			klogprintf("intel: vbe_attach_framebuffer failed; console stays on VGA text\n");
		} else {
			boot_brk(7);
			/* Blue: vbe attach ok. A reset still showing blue means the
			 * crash is inside vbefb_init; black+text means it came up. */
			intel_fill_fb(d, 0x000000FFu);
			if (vbefb_init(d->fb.width, d->fb.height, d->fb.pitch, d->fb.bpp) != 0) {
				vbe_detach_framebuffer();
				klogprintf("intel: vbefb_init failed; console stays on VGA text\n");
			} else {
				boot_brk(8);
				klogprintf("intel: fbcon attached to Intel fb %ux%u bpp=%u\n",
				           (unsigned)d->fb.width, (unsigned)d->fb.height,
				           (unsigned)d->fb.bpp);
			}
		}
	} else {
		vbe_adopt_frontbuffer(d->fb.fb_va);
	}
	fbdev_register_linear(d->fb.fb_va, (uint64_t)d->fb.fb_pa, (size_t)d->fb.len,
	                      d->fb.width, d->fb.height, d->fb.pitch, d->fb.bpp);
	fbdev_sysfs_publish(d->bus, d->device, d->function);
	boot_brk(9);

	/* Everything above succeeded: retire the legacy VGA plane so our primary
	 * plane becomes the visible scanout. Done last so failures stay visible. */
	if (d->pipe.bringup) {
		klogprintf("intel: take-over complete, retiring VGA plane\n");
		mmio_write32(mm, INTEL_VGACNTRL, old_vgacntrl | INTEL_VGA_DISP_DISABLE);
		(void)mmio_read32(mm, INTEL_VGACNTRL);
	}
	boot_brk(10);
	return 0;
}