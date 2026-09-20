/* Intel HD Graphics (Gen6 Sandy Bridge / Gen7 Ivy Bridge) — AxonOS driver.
 *
 * Design (mirrors Linux i915 semantics):
 *  - probe the PCI graphics device (8086 + class 0x03), enable bus mastering;
 *  - map BAR0 (GTTMMADR) uncached; the display register block and the GTT PTE
 *    table live in this BAR (PTEs start at BAR0 + BAR0_len/2);
 *  - read GMCH_CTRL (0x50) and BSM (0x5c) for GTT/PTE size and the stolen
 *    memory base;
 *  - take over the pixel pipeline the BIOS left running: allocate a contiguous
 *    scanout buffer in stolen memory, map it, program its GTT PTEs, flip the
 *    active primary plane (DSPSURF), and hand the buffer to fbdev + sysfs so
 *    /dev/fb0 and /dev/dri/card0 serve X (fbdev/modeset style).
 *
 * Stability contract: we never reprogram the DPLL/FDI/transcoder/port clocks
 * in this phase.  If the plane flip cannot be validated (DSPSURFLIVE) we roll
 * the plane back to the firmware surface and keep the VBE console intact.
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

int intel_display_takeover(intel_drv_t *d);
static void intel_dump_state(const intel_drv_t *d);

static intel_drv_t g_intel;

static uint32_t intel_pci_bar_size(pci_device_t *p, int bar)
{
	uint32_t off = (uint32_t)(0x10 + 4 * bar);
	uint32_t orig = pci_config_read_dword(p->bus, p->device, p->function, (uint8_t)off);
	uint32_t flags = orig & 0xFu;
	if (flags == 0 || (flags & 0x1u) != 0)
		return 0;                         /* I/O BAR or unimplemented */
	pci_config_write_dword(p->bus, p->device, p->function, (uint8_t)off, 0xFFFFFFFFu);
	uint32_t sz = pci_config_read_dword(p->bus, p->device, p->function, (uint8_t)off);
	pci_config_write_dword(p->bus, p->device, p->function, (uint8_t)off, orig);
	sz &= 0xFFFFFFF0u;
	if (sz == 0)
		return 0;
	return (~sz) + 1;
}

static int intel_probe_pci(intel_drv_t *d)
{
	pci_device_t *devs = pci_get_devices();
	int n = pci_get_device_count();
	pci_device_t *igfx = NULL;

	for (int i = 0; i < n; i++) {
		pci_device_t *t = &devs[i];
		if (t->vendor_id == INTEL_GRAPHICS_VENDOR_ID && t->class_code == INTEL_GRAPHICS_CLASS) {
			igfx = t;
			break;
		}
	}
	if (!igfx)
		return -1;

	d->device_id = igfx->device_id;
	d->gen = intel_did_gen(igfx->device_id);
	if (d->gen != 6 && d->gen != 7) {
		klogprintf("intel: unsupported display device 0x%04x (gen %d)\n",
		           (unsigned)igfx->device_id, d->gen);
		return -1;
	}
	d->bus = igfx->bus;
	d->device = igfx->device;
	d->function = igfx->function;

	uint32_t cmd = pci_config_read_dword(igfx->bus, igfx->device, igfx->function, 0x04);
	cmd |= (1u << 0) | (1u << 1) | (1u << 2);   /* IO | MEM | bus master */
	pci_config_write_dword(igfx->bus, igfx->device, igfx->function, 0x04, cmd);

	d->bar0_phys = igfx->bar[0] & ~0xFu;
	d->bar0_len = intel_pci_bar_size(igfx, 0);
	if (igfx->bar[0] & 0x4u) {
		/* 64-bit BAR: caller must honor bar[1] high dword. */
		uint32_t hi = igfx->bar[1];
		if (hi == 0) {
			klogprintf("intel: BAR0 is 64-bit but high dword is 0, treating as 32-bit\n");
		} else {
			klogprintf("intel: BAR0 64-bit unsupported (hi=0x%08x) — aborting\n",
			           (unsigned)hi);
			return -1;
		}
	}
	d->bar2_phys = igfx->bar[2] & ~0xFu;
	d->bar2_len = intel_pci_bar_size(igfx, 2);
	if (d->bar0_phys == 0 || d->bar0_len < 0x10000) {
		klogprintf("intel: GTTMMADR BAR0 invalid (pa=0x%x len=0x%x)\n",
		           (unsigned)d->bar0_phys, (unsigned)d->bar0_len);
		return -1;
	}

	/* GMCH_CTRL: PTE-table size (bits 9:8) and stolen size (bits 15:3). */
	uint32_t gmch = 0;
	uint32_t bsm = 0;
	{
		uint32_t lo = pci_config_read_dword(igfx->bus, igfx->device, igfx->function,
		                                      INTEL_SNB_GMCH_CTRL);
		gmch = lo & 0xFFFFu;
		bsm = pci_config_read_dword(igfx->bus, igfx->device, igfx->function,
		                             INTEL_BSM);
	}
	d->gmch_ctrl = gmch;
	d->pte_bytes = ((gmch >> INTEL_GGMS_SHIFT) & 0x3u) << 20;
	d->total_gtt_bytes = (d->pte_bytes / 4u) << 12;
	d->stolen_size = ((gmch >> INTEL_GMS_SHIFT) & 0x1Fu) << 25;
	d->stolen_base = bsm & INTEL_BSM_MASK;

	d->mmio = mmio_map_phys((uint64_t)d->bar0_phys, (size_t)d->bar0_len);
	if (!d->mmio) {
		klogprintf("intel: BAR0 mmio map failed (pa=0x%x len=0x%x)\n",
		           (unsigned)d->bar0_phys, (unsigned)d->bar0_len);
		return -1;
	}
	d->present = 1;
	return 0;
}

int intel_kernel_init(void)
{
	if (g_intel.present)
		return 0;
	boot_brk(0x42);

	intel_drv_t d;
	memset(&d, 0, sizeof(d));
	if (intel_probe_pci(&d) != 0)
		return -1;
	boot_brk(0x43);

	klogprintf("intel: probed gen%d dev=0x%04x %02x:%02x.%u\n",
	           d.gen, (unsigned)d.device_id, d.bus, d.device, d.function);
	klogprintf("intel: BAR0 pa=0x%x len=0x%x BAR2 pa=0x%x len=0x%x\n",
	           (unsigned)d.bar0_phys, (unsigned)d.bar0_len,
	           (unsigned)d.bar2_phys, (unsigned)d.bar2_len);
	klogprintf("intel: GMCH_CTRL=0x%04x pte_bytes=0x%x gtt=0x%x stolen_base=0x%x stolen=0x%x\n",
	           (unsigned)d.gmch_ctrl, (unsigned)d.pte_bytes,
	           (unsigned)d.total_gtt_bytes, (unsigned)d.stolen_base,
	           (unsigned)d.stolen_size);

	intel_dump_state(&d);
	boot_brk(0x44);

	int r = intel_display_takeover(&d);
	if (r != 0) {
		klogprintf("intel: display take-over failed (%d) — keeping VBE console\n", r);
		return r;
	}
	g_intel = d;
	klogprintf("intel: ready — plane flip to fb pa=0x%x gtt_off=0x%x %ux%u pitch=%u bpp=%u\n",
	           (unsigned)d.fb.fb_pa, (unsigned)d.fb.gtt_off,
	           (unsigned)d.fb.width, (unsigned)d.fb.height,
	           (unsigned)d.fb.pitch, (unsigned)d.fb.bpp);
	return 0;
}

/* --- diagnostics: read back everything the BIOS left programmed, ---
   unconditionally, so a single flash tells us the real machine state. --- */
static int intel_decode_pte_phys(uint32_t pte)
{
	if ((pte & INTEL_GEN6_PTE_VALID) == 0)
		return 0;
	return (int)((pte & INTEL_PTE_PHYS_MASK) |
	             ((pte & 0xFF0u) << INTEL_PTE_PHYS_HIGH_SHIFT));
}

static void intel_dump_state(const intel_drv_t *d)
{
	void *mm = d->mmio;
	const int npipe = (d->gen >= 7) ? INTEL_MAX_PIPES : 2;
	void *gsm = (uint8_t *)d->mmio + d->bar0_len / 2;
	int vbe = vbe_is_available();

	klogprintf("intel: --- BIOS display state read-back ---\n");
	klogprintf("intel: vbe_console=%-3d vbe=%ux%u pitch=%u bpp=%u\n",
	           vbe, vbe ? (unsigned)vbe_get_width() : 0,
	           vbe ? (unsigned)vbe_get_height() : 0,
	           vbe ? (unsigned)vbe_get_pitch() : 0,
	           vbe ? (unsigned)vbe_get_bpp() : 0);
	klogprintf("intel: vga_cntrl=0x%08x (bit31 set => VGA plane disabled)\n",
	           (unsigned)mmio_read32(mm, INTEL_VGACNTRL));

	for (int p = 0; p < npipe; p++) {
		uint32_t tbase = INTEL_TRANS_OFFSET(p);
		uint32_t pbase = INTEL_PLANE_OFFSET(p);
		uint32_t pc = mmio_read32(mm, INTEL_PIPE_OFFSET(p) + INTEL_PIPECONF_OFFSET);
		uint32_t cn = mmio_read32(mm, pbase);
		uint32_t stride = mmio_read32(mm, pbase + (INTEL_DSPASTRIDE - INTEL_DSPACNTR));
		uint32_t surf = mmio_read32(mm, pbase + (INTEL_DSPASURF - INTEL_DSPACNTR));
		uint32_t live = mmio_read32(mm, pbase + (INTEL_DSPASURFLIVE - INTEL_DSPACNTR));
		uint32_t pos = mmio_read32(mm, pbase + (INTEL_DSPAPOS - INTEL_DSPACNTR));
		uint32_t size = mmio_read32(mm, pbase + (INTEL_DSPASIZE - INTEL_DSPACNTR));
		uint32_t src = mmio_read32(mm, tbase + (INTEL_PIPESRC_A - INTEL_TRANS_A));
		klogprintf("intel: pipe%c conf=0x%08x dsp=0x%08x fmt=%u stride=0x%x surf=0x%x live=0x%x pos=0x%x size=0x%x src=0x%08x\n",
		           (char)('A' + p), (unsigned)pc, (unsigned)cn,
		           (unsigned)((cn >> 26) & 0xFu), (unsigned)stride, (unsigned)surf,
		           (unsigned)live, (unsigned)pos, (unsigned)size, (unsigned)src);

		klogprintf("intel: pipe%c tm: htot=0x%x hbl=0x%x hsy=0x%x vtot=0x%x vbl=0x%x vsy=0x%x\n",
		           (char)('A' + p),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_HTOTAL_A - INTEL_TRANS_A)),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_HBLANK_A - INTEL_TRANS_A)),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_HSYNC_A - INTEL_TRANS_A)),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_VTOTAL_A - INTEL_TRANS_A)),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_VBLANK_A - INTEL_TRANS_A)),
		           (unsigned)mmio_read32(mm, tbase + (INTEL_VSYNC_A - INTEL_TRANS_A)));

		if (surf) {
			uint32_t s = surf & ~0xFFFu;
			uint32_t pte = 0;
			if (s < d->total_gtt_bytes)
				pte = mmio_read32(gsm, (size_t)(s >> 12) * 4u);
			klogprintf("intel: pipe%c surf gtt_off=0x%x pte=0x%08x phys=0x%x\n",
			           (char)('A' + p), (unsigned)s, (unsigned)pte,
			           (unsigned)intel_decode_pte_phys(pte));
		}
	}

	for (int p = 0; p < 2; p++) {
		uint32_t tx = mmio_read32(mm, INTEL_FDI_TX_CTL(p));
		uint32_t rx = mmio_read32(mm, INTEL_FDI_RX_CTL(p));
		uint32_t rm = mmio_read32(mm, INTEL_FDI_RX_MISC_A + (uint32_t)p * 0x1000u);
		uint32_t tu = mmio_read32(mm, INTEL_FDI_RXA_TUSIZE1 + (uint32_t)p * 0x1000u);
		uint32_t mr = mmio_read32(mm, INTEL_FDI_RXA_IMR + (uint32_t)p * 0x1000u);
		klogprintf("intel: fdi%c tx=0x%08x rx=0x%08x rx_misc=0x%08x tusize=0x%x imr=0x%x\n",
		           (char)('A' + p), (unsigned)tx, (unsigned)rx, (unsigned)rm,
		           (unsigned)tu, (unsigned)mr);
	}
	klogprintf("intel: pch dpll_a=0x%08x dpll_b=0x%08x fpa0=0x%08x fpa1=0x%08x fpb0=0x%08x fpb1=0x%08x\n",
	           (unsigned)mmio_read32(mm, INTEL_PCH_DPLL_A),
	           (unsigned)mmio_read32(mm, INTEL_PCH_DPLL_B),
	           (unsigned)mmio_read32(mm, INTEL_PCH_FPA0),
	           (unsigned)mmio_read32(mm, INTEL_PCH_FPA1),
	           (unsigned)mmio_read32(mm, INTEL_PCH_FPB0),
	           (unsigned)mmio_read32(mm, INTEL_PCH_FPB1));
	klogprintf("intel: pch dpll_sel=0x%08x dref=0x%08x hotplug=0x%08x\n",
	           (unsigned)mmio_read32(mm, INTEL_PCH_DPLL_SEL),
	           (unsigned)mmio_read32(mm, INTEL_PCH_DREF_CONTROL),
	           (unsigned)mmio_read32(mm, INTEL_PCH_PORT_HOTPLUG));
	for (int p = 0; p < 2; p++) {
		uint32_t tb = (p == 0) ? INTEL_PCH_TRANS_HTOTAL_A
		                       : INTEL_PCH_TRANS_HTOTAL_A + 0x1000u;
		uint32_t tc = (p == 0) ? INTEL_PCH_TRANSCONF_A
		                       : INTEL_PCH_TRANSCONF_A + 0x1000u;
		uint32_t m1 = (p == 0) ? INTEL_PCH_TRANS_DATA_M1_A
		                       : INTEL_PCH_TRANS_DATA_M1_A + 0x1000u;
		uint32_t n1 = (p == 0) ? INTEL_PCH_TRANS_DATA_N1_A
		                       : INTEL_PCH_TRANS_DATA_N1_A + 0x1000u;
		klogprintf("intel: pch trans%c htot=0x%08x vtot=0x%08x conf=0x%08x m1=0x%08x n1=0x%08x\n",
		           (char)('A' + p),
		           (unsigned)mmio_read32(mm, tb),
		           (unsigned)mmio_read32(mm, tb + (INTEL_PCH_TRANS_VTOTAL_A - INTEL_PCH_TRANS_HTOTAL_A)),
		           (unsigned)mmio_read32(mm, tc),
		           (unsigned)mmio_read32(mm, m1),
		           (unsigned)mmio_read32(mm, n1));
	}
	klogprintf("intel: pch adpa=0x%08x sdvob=0x%08x sdvoc=0x%08x gmbus0=0x%08x\n",
	           (unsigned)mmio_read32(mm, INTEL_PCH_ADPA),
	           (unsigned)mmio_read32(mm, INTEL_PCH_SDVOB),
	           (unsigned)mmio_read32(mm, INTEL_PCH_SDVOC),
	           (unsigned)mmio_read32(mm, INTEL_PCH_GMBUS0));
	klogprintf("intel: gfx_flsh=0x%08x\n",
	           (unsigned)mmio_read32(mm, INTEL_GFX_FLSH_CNTL_GEN6));
}