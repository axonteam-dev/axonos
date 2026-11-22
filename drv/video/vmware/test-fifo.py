#!/usr/bin/env python3
"""Host-side regression for serialized VMware damage and FIFO publication."""
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).with_name("vmwgfx_drv.c").read_text()
fifo = source[source.index("static int vmwgfx_fifo_free_bytes("):source.index("/*\n * leave_enabled:")]
callbacks = source[source.index("static void vmwgfx_flush_region("):source.index("static int vmwgfx_set_mode(")]
program = r'''
#include <stdint.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
typedef struct { int unused; } video_device_t;
typedef struct { void *fifo_va; uint32_t fifo_len, width, height; int present, scanout_on; } vmwgfx_ctx_t;
typedef pthread_mutex_t spinlock_t;
static spinlock_t g_vmwgfx_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int locked;
static void acquire_irqsave(spinlock_t *l, unsigned long *f) { *f = 0; pthread_mutex_lock(l); locked = 1; }
static void release_irqrestore(spinlock_t *l, unsigned long f) { (void)f; locked = 0; pthread_mutex_unlock(l); }
static vmwgfx_ctx_t g_vmwgfx;
static int g_upd_pending;
static uint32_t g_upd_x0, g_upd_y0, g_upd_x1, g_upd_y1;
static unsigned updates, syncs;
static uint32_t last_update[5];
enum { SVGA_FIFO_MIN, SVGA_FIFO_MAX, SVGA_FIFO_NEXT, SVGA_FIFO_STOP };
enum { SVGA_REG_SYNC = 21, SVGA_CMD_UPDATE = 1, SVGA_FIFO_HOST_MAX_BYTES = 65536 };
#define vmwgfx_io_barrier() __asm__ volatile("" ::: "memory")
static void svga_reg_write32(vmwgfx_ctx_t *ctx, int reg, int val) {
    assert(locked && reg == SVGA_REG_SYNC && val == 1);
    syncs++;
    volatile uint32_t *f = ctx->fifo_va;
    uint32_t p = f[SVGA_FIFO_STOP], end = f[SVGA_FIFO_NEXT];
    while (p != end) {
        uint32_t words[5];
        for (int i = 0; i < 5; i++) {
            words[i] = f[p / 4]; p += 4;
            if (p == f[SVGA_FIFO_MAX]) p = f[SVGA_FIFO_MIN];
        }
        assert(words[0] == SVGA_CMD_UPDATE && words[3] && words[4]);
        assert(words[1] + words[3] <= 128 && words[2] + words[4] <= 128);
        for (int i = 0; i < 5; i++) last_update[i] = words[i];
        updates++;
    }
    f[SVGA_FIFO_STOP] = p;
}
''' + fifo + callbacks + r'''
static void *worker(void *arg) {
    uintptr_t n = (uintptr_t)arg;
    for (unsigned i = 0; i < 100000; i++) {
        vmwgfx_flush_region(0, (i + n) % 128, (i * 3 + n) % 128, 1, 1);
        vmwgfx_display_sync(0);
    }
    return 0;
}
int main(void) {
    uint32_t ring[64] = {0};
    ring[SVGA_FIFO_MIN] = 16; ring[SVGA_FIFO_MAX] = sizeof(ring);
    ring[SVGA_FIFO_NEXT] = ring[SVGA_FIFO_STOP] = 16;
    g_vmwgfx = (vmwgfx_ctx_t){ring, sizeof(ring), 128, 128, 1, 1};
    /* A burst before sync becomes one bounding rectangle, including its tail. */
    for (unsigned i = 0; i < 100; i++)
        vmwgfx_flush_region(0, i, i, 1, 1);
    assert(updates == 0 && g_upd_pending);
    vmwgfx_display_sync(0);
    assert(updates == 1 && syncs == 1 && !g_upd_pending);
    assert(last_update[1] == 0 && last_update[2] == 0 &&
           last_update[3] == 100 && last_update[4] == 100);
    printf("burst: 100 damage calls, %u updates, %u syncs\n", updates, syncs);
    /* Full-frame present calls each sync immediately: no cross-call batching. */
    updates = syncs = 0;
    for (unsigned i = 0; i < 100; i++) {
        vmwgfx_flush_region(0, 0, 0, 128, 128);
        vmwgfx_display_sync(0);
    }
    assert(updates == 100 && syncs == 100 && !g_upd_pending);
    printf("full-frame presents: 100 calls, %u updates, %u syncs\n", updates, syncs);
    pthread_t a, b;
    assert(!pthread_create(&a, 0, worker, (void *)1));
    assert(!pthread_create(&b, 0, worker, (void *)2));
    assert(!pthread_join(a, 0)); assert(!pthread_join(b, 0));
    vmwgfx_display_sync(0); assert(!g_upd_pending);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="vmwgfx-fifo-", dir="/tmp/opencode") as tmp:
    c = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: concurrent VMware damage and FIFO publication")
