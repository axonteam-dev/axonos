#!/usr/bin/env python3
"""Exercise Gen6/7 display arithmetic and pipe decoding without GPU access."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
program = r'''
#include "drv/video/intel/intel_display.c"
#include <assert.h>

static uint32_t regs[0x73000 / 4];
uint32_t mmio_read32(const volatile void *base, size_t off) {
    (void)base;
    assert(off / 4 < sizeof(regs) / sizeof(regs[0]));
    return regs[off / 4];
}
void klogprintf(const char *fmt, ...) { (void)fmt; }

int main(void) {
    assert(align_up_4k(1) == 4096);
    assert(align_up_4k(0xfffff000ULL) == 0xfffff000u);
    assert(align_up_4k(0xfffff001ULL) == 0);
    assert(align_up_4k(0) == 0);
    assert(intel_pick_range(0x10000000, 0x4000000, 0x100000,
                            0x13f00000, 1) == 0x13e00000);
    assert(intel_pick_range(0x10000000, 0x1000000, 0x100000,
                            0x10000000, 1) == 0);
    assert(intel_pick_range(0, 0x1000000, 0x100000, 0, 1) == 0);
    assert(intel_pick_range(0xfff00000, 0x200000, 0x1000, 0, 0) == 0);
    assert(intel_pick_range(0x1000, 0x1000, 0x2000, 0, 0) == 0);

    intel_drv_t d = {0};
    d.gen = 6;
    regs[(INTEL_PIPE_A + INTEL_PIPECONF_OFFSET) / 4] = INTEL_PIPECONF_ENABLE;
    regs[INTEL_DSPACNTR / 4] = INTEL_DISPLAY_PLANE_ENABLE | INTEL_DISPPLANE_BGRX888;
    regs[INTEL_PIPESRC_A / 4] = (1919u << 16) | 1079u;
    assert(intel_find_active_pipe(&d) == 0);
    assert(d.pipe.src_w == 1920 && d.pipe.src_h == 1080 && !d.pipe.bringup);
    regs[INTEL_DSPACNTR / 4] = 0;
    d = (intel_drv_t){0};
    d.gen = 6;
    assert(intel_find_active_pipe(&d) == 0);
    assert(d.pipe.src_w == 1920 && d.pipe.src_h == 1080 && d.pipe.bringup);
    assert(intel_did_gen(0x3ea0) == 0);
    assert(intel_did_gen(0x0126) == 6 && intel_did_gen(0x0166) == 7);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-intel-host-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra",
                    "-ffunction-sections", "-fdata-sections",
                    "-fsanitize=undefined", "-Wl,--gc-sections",
                    "-I", str(root), "-I", str(root / "inc"),
                    str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: Intel Gen6/7 geometry, range bounds and device classification")
