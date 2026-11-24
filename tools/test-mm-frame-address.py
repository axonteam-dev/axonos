#!/usr/bin/env python3
"""Host-only check of the actual frame KVA-to-PA helper."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static uint64_t mm_user_frame_pa(")
end = mm.index("\nstatic void mm_user_frame_put(", start)
source = r'''
#include <assert.h>
#include <stdint.h>
#define DIRECT_MAP_BASE 0xffff800000000000ULL
#define DIRECT_MAP_SIZE (1ULL << 39)
''' + mm[start:end] + r'''
int main(void) {
    assert(mm_user_frame_pa((void *)(uintptr_t)0x200000) == 0x200000);
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    assert(mm_user_frame_pa((void *)(uintptr_t)(DIRECT_MAP_BASE + 0x140001000ULL))
           == 0x140001000ULL);
    assert(mm_user_frame_pa((void *)(uintptr_t)(DIRECT_MAP_BASE + DIRECT_MAP_SIZE))
           == DIRECT_MAP_BASE + DIRECT_MAP_SIZE);
#endif
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    for flags in ([], ["-DAXON_EXPERIMENTAL_DIRECT_MAP=1"]):
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        *flags, str(src), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
print("PASS: user frame kernel addresses convert to physical addresses")
