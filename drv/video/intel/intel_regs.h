/* Intel HD Graphics (Gen6 Sandy Bridge / Gen7 Ivy Bridge) — display registers.
 * Offsets mirror Linux i915 (v4.x i915_reg.h / i915_gem_gtt.h).  Registers are
 * absolute offsets into the GPU MMIO BAR (BAR0, GTTMMADR).  PCI config-space
 * registers carry GMCH/GTT sizes. */
#ifndef INTEL_REGS_H
#define INTEL_REGS_H

#include <stdint.h>

/* PCI config space (on the Intel graphics device itself) */
#define INTEL_SNB_GMCH_CTRL       0x50   /* GMCH Graphics Control */
#define   INTEL_GGMS_SHIFT        8      /* bits[9:8]: GTT PTE table size */
#define   INTEL_GGMS_MASK         (0x3u << 8)
#define   INTEL_GMS_SHIFT         3      /* bits[15:3]: stolen size, 32 MB units */
#define   INTEL_GMS_MASK          (0x1Fu << 3)
#define INTEL_BSM                 0x5C   /* Graphics Base of Stolen Memory */
#define   INTEL_BSM_MASK          0xFFFF0000u

/* --- GTT (global graphics translation table) ---
 * PTEs live in the second half of BAR0: gsm_phys = BAR0 + BAR0_len/2.
 * Each PTE is a 32-bit entry; index = gtt_offset / 4096. */
#define INTEL_GEN6_PTE_VALID      (1u << 0)
#define INTEL_GEN6_PTE_UNCACHED   (1u << 1)
#define INTEL_GEN6_PTE_CACHE_LLC  (2u << 1)
#define INTEL_GEN6_GTT_ADDR_ENCODE(addr) \
	((uint32_t)(addr) | (((uint32_t)(addr) >> 28) & 0xFF0u))
#define INTEL_PTE_PHYS_MASK       0xFFFFF000u
#define INTEL_PTE_PHYS_HIGH_SHIFT 28

/* Pipe/plane register bases (gen6: pipes A,B; gen7 adds C) */
#define INTEL_PIPE_A               0x70000
#define INTEL_PIPE_B               0x71000
#define INTEL_PIPE_C               0x72000
#define INTEL_PIPE_OFFSET(pipe)    (INTEL_PIPE_A + (uint32_t)(pipe) * 0x1000u)

#define INTEL_PIPECONF_OFFSET      0x8
#define INTEL_PIPECONF_ENABLE     (1u << 31)

/* Transcoder / timing (CPU timing regs live on the trans base: A 0x60000 ...) */
#define INTEL_TRANS_A              0x60000
#define INTEL_TRANS_OFFSET(pipe)   (INTEL_TRANS_A + (uint32_t)(pipe) * 0x1000u)

#define INTEL_HTOTAL_A             0x60000
#define INTEL_HBLANK_A             0x60004
#define INTEL_HSYNC_A              0x60008
#define INTEL_VTOTAL_A             0x6000C
#define INTEL_VBLANK_A             0x60010
#define INTEL_VSYNC_A              0x60014
#define INTEL_PIPESRC_A            0x6001C

/* Primary plane (DSP) registers.  plane == pipe on gen6/7. */
#define INTEL_DSPACNTR             0x70180
#define INTEL_DSPAADDR             0x70184
#define INTEL_DSPASTRIDE           0x70188
#define INTEL_DSPAPOS              0x7018C
#define INTEL_DSPASIZE             0x70190
#define INTEL_DSPASURF             0x7019C
#define INTEL_DSPATILEOFF          0x701A4
#define INTEL_DSPASURFLIVE         0x701AC
#define INTEL_PLANE_OFFSET(plane)  (INTEL_DSPACNTR + (uint32_t)(plane) * 0x1000u)

#define INTEL_DISPLAY_PLANE_ENABLE (1u << 31)
#define INTEL_DISPPLANE_GAMMA_ENABLE (1u << 30)
#define INTEL_DISPPLANE_TILED      (1u << 10)
#define INTEL_DISPPLANE_SEL_PIPE_MASK (3u << 24)
#define INTEL_DISPPLANE_PIXFORMAT_MASK (0xFu << 26)
#define   INTEL_DISPPLANE_BGRX555   (4u << 26)
#define   INTEL_DISPPLANE_BGRX565   (5u << 26)
#define   INTEL_DISPPLANE_BGRX888   (6u << 26)

/* VGA access control (disable legacy VGA plane at 0xA0000, we own the pipes) */
#define INTEL_VGACNTRL             0x71400
#define INTEL_VGA_DISP_DISABLE     (1u << 31)

/* FDI.  TX on the CPU side (trans base), RX on the PCH side (0xFxxxx). */
#define INTEL_FDI_TXA_CTL          0x60100
#define INTEL_FDI_TX_CTL(pipe)     (INTEL_FDI_TXA_CTL + (uint32_t)(pipe) * 0x1000u)
#define INTEL_FDI_RXA_CTL          0xF000C
#define INTEL_FDI_RX_MISC_A        0xF0010
#define INTEL_FDI_RXA_TUSIZE1      0xF0030
#define INTEL_FDI_RXA_TUSIZE2      0xF0038
#define INTEL_FDI_RXA_IIR          0xF0014
#define INTEL_FDI_RXA_IMR          0xF0018
#define INTEL_FDI_RX_CTL(pipe)     (INTEL_FDI_RXA_CTL + (uint32_t)(pipe) * 0x1000u)

/* PCH (Cougar Point / LPT) display: DPLL, dither, transcoder, ports */
#define INTEL_PCH_DPLL_A           0xC6014
#define INTEL_PCH_DPLL_B           0xC6018
#define INTEL_PCH_FPA0             0xC6040
#define INTEL_PCH_FPA1             0xC6044
#define INTEL_PCH_FPB0             0xC6048
#define INTEL_PCH_FPB1             0xC604C
#define INTEL_PCH_DPLL_TEST        0xC606C
#define INTEL_PCH_DREF_CONTROL     0xC6200
#define INTEL_PCH_DPLL_SEL         0xC7000

#define INTEL_PCH_TRANS_HTOTAL_A   0xE0000
#define INTEL_PCH_TRANS_HBLANK_A   0xE0004
#define INTEL_PCH_TRANS_HSYNC_A    0xE0008
#define INTEL_PCH_TRANS_VTOTAL_A   0xE000C
#define INTEL_PCH_TRANS_VBLANK_A   0xE0010
#define INTEL_PCH_TRANS_VSYNC_A    0xE0014
#define INTEL_PCH_TRANS_DATA_M1_A  0xE0030
#define INTEL_PCH_TRANS_DATA_N1_A  0xE0034
#define INTEL_PCH_TRANSCONF_A      0xF0008
#define INTEL_PCH_PORT_HOTPLUG     0xC4030
#define INTEL_PCH_ADPA             0xE1100
#define   INTEL_ADPA_DAC_ENABLE    (1u << 31)
#define   INTEL_ADPA_PIPE_SELECT   (1u << 30)
#define   INTEL_ADPA_HOTPLUG_ENABLE (1u << 25)
#define   INTEL_ADPA_HSYNC_CNTL_DISABLE (1u << 11)
#define   INTEL_ADPA_VSYNC_CNTL_DISABLE (1u << 10)
#define   INTEL_ADPA_HSYNC_ACTIVE_HIGH (1u << 3)
#define   INTEL_ADPA_VSYNC_ACTIVE_HIGH (1u << 4)
#define   INTEL_ADPA_CRT_HOTPLUG_DETECT (1u << 0)
#define INTEL_PCH_SDVOB            0xE1140   /* port B (HDMI/DVI) */
#define INTEL_PCH_SDVOC            0xE1150   /* port C (HDMI/DVI) */
#define   INTEL_SDVO_ENABLE        (1u << 31)
#define INTEL_PCH_GMBUS0           0xC5100
#define INTEL_PCH_GMBUS1           0xC5104
#define INTEL_PCH_GMBUS2           0xC5108
#define INTEL_PCH_GMBUS3           0xC510C
#define INTEL_PCH_GMBUS4           0xC5110

/* GTT flush register (write bit0, then read back to post) */
#define INTEL_GFX_FLSH_CNTL_GEN6   0x101008
#define INTEL_GFX_FLSH_CNTL_EN     (1u << 0)

/* Device IDs: Sandy Bridge (gen6) desktop, Ivy Bridge (gen7) desktop. */
static inline int intel_did_gen(uint16_t did)
{
	switch (did) {
	case 0x0102: case 0x0104: case 0x0106: case 0x010A:
	case 0x0112: case 0x0116: case 0x0122: case 0x0126:
		return 6;
	case 0x0152: case 0x0156: case 0x015A: case 0x0162:
	case 0x0166: case 0x016A:
		return 7;
	default:
		return 0;
	}
}

#endif /* INTEL_REGS_H */