/* Intel HD Graphics (Gen6 SNB / Gen7 IVB) driver — AxonOS */
#ifndef INTEL_H
#define INTEL_H

#include <stdint.h>
#include <stddef.h>

#define INTEL_GRAPHICS_VENDOR_ID 0x8086u
#define INTEL_GRAPHICS_CLASS 0x03u

/* Max active display pipes on gen6/7. */
#define INTEL_MAX_PIPES 3

/* Per-pipe mode state taken over from the firmware (BIOS/VBE) setup. */
typedef struct intel_pipe_state {
	int present;               /* pipe enabled (plane adopted or brought up) */
	int bringup;               /* 1: pipe runs, primary plane off -> we enable it */
	int pipe;                  /* pipe index (0=A,1=B,2=C) */
	uint32_t pipecfg;          /* PIPECONF read-back */
	uint32_t dspcntr;          /* DSPCNTR read-back */
	uint32_t stride;           /* DSPSTRIDE (bytes) */
	uint32_t dspcntr_format;   /* (DSPCNTR >> 26) & 0xF */
	uint32_t surf;             /* old DSPSURF (GTT offset) */
	uint32_t src_w, src_h;     /* PIPESRC size */
	uint32_t bpp;              /* 15/16/32 */
	uint32_t bytes_per_pixel;
} intel_pipe_state_t;

/* Frame buffer we promote to scanout: contiguous block in stolen memory. */
typedef struct intel_fb {
	uint32_t fb_pa;            /* physical base in stolen memory */
	void *fb_va;               /* WB-mapped kernel VA (identity for <4 GiB) */
	size_t len;                /* pitch * height, 4 KiB aligned */
	uint32_t gtt_off;          /* GTT offset our PTEs live at */
	uint32_t width, height, pitch, bpp;
} intel_fb_t;

/* Driver global state (single adapter, as on the target H61 board). */
typedef struct intel_drv {
	int present;
	int gen;
	uint16_t device_id;
	uint8_t bus, device, function;
	void *mmio;                /* BAR0 MMIO base (identity VA, UC) */
	uint32_t bar0_phys, bar0_len;
	uint32_t bar2_phys, bar2_len;
	uint32_t gmch_ctrl;
	uint32_t pte_bytes;        /* GTT PTE table size in bytes */
	uint32_t total_gtt_bytes;  /* addressable GTT in bytes */
	uint32_t stolen_base;
	uint32_t stolen_size;
	intel_pipe_state_t pipe;
	intel_fb_t fb;
	int took_over;             /* plane flipped to intel_fb */
} intel_drv_t;

/* Called from core/entry/init.c once after the VBE console is up.
 * Returns 0 on success, -1 when no Intel GPU or take-over failed
 * (VBE/BiOS console path then stays in effect). */
int intel_kernel_init(void);

#endif /* INTEL_H */