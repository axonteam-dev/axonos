#!/usr/bin/env python3
"""Check atomic publication and wraparound of the actual VMware UPDATE writer."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/video/vmware/vmwgfx_drv.c").read_text()
start = source.index("static int vmwgfx_fifo_free_bytes(")
end = source.index("/*\n * Coalesce UPDATEs", start)
snippet = source[start:end]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define SVGA_FIFO_MIN 0
#define SVGA_FIFO_MAX 1
#define SVGA_FIFO_NEXT 2
#define SVGA_FIFO_STOP 3
#define SVGA_FIFO_HOST_MAX_BYTES 1024
#define SVGA_CMD_UPDATE 1
typedef struct { void *fifo_va; uint32_t fifo_len; } vmwgfx_ctx_t;
static uint32_t *check_fifo, check_next;
static unsigned barriers;
static void vmwgfx_io_barrier(void) { assert(check_fifo[SVGA_FIFO_NEXT] == check_next); barriers++; }
''' + snippet + r'''
int main(void) {
    uint32_t fifo[32]; memset(fifo, 0, sizeof(fifo));
    vmwgfx_ctx_t ctx = { fifo, sizeof(fifo) };
    fifo[0] = 16; fifo[1] = 128; fifo[2] = 120; fifo[3] = 80;
    check_fifo = fifo; check_next = 120;
    assert(vmwgfx_fifo_emit_update(&ctx, 3, 4, 5, 6) == 0);
    assert(barriers == 1 && fifo[2] == 28);
    assert(fifo[30] == 1 && fifo[31] == 3 && fifo[4] == 4 && fifo[5] == 5 && fifo[6] == 6);
    fifo[2] = 120; fifo[3] = 24; check_next = 120; barriers = 0;
    assert(vmwgfx_fifo_emit_update(&ctx, 3, 4, 5, 6) == -1);
    assert(fifo[2] == 120 && barriers == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-vmware-fifo-", dir="/tmp/opencode") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: VMware UPDATE publishes one complete command, including on wrap")
