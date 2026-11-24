#!/usr/bin/env python3
"""Host test of serialization for the leaf-install wrapper only."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("int mm_map_user_page(")
end = mm.index("\n/* Ensure child mm", start)
source = r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
typedef struct { pthread_mutex_t page_table_lock; } mm_t;
typedef int mm_dm_ctx_t;
static atomic_int active, violations, calls;
static mm_dm_ctx_t mm_enter_direct_map(void) { return 0; }
static void mm_leave_direct_map(mm_dm_ctx_t dm) { (void)dm; }
static void acquire_irqsave(pthread_mutex_t *m, unsigned long *flags) {
    *flags = 0; assert(pthread_mutex_lock(m) == 0);
}
static void release_irqrestore(pthread_mutex_t *m, unsigned long flags) {
    (void)flags; assert(pthread_mutex_unlock(m) == 0);
}
static int mm_map_user_page_locked(mm_t *m, uint64_t va, uint64_t pa, uint64_t flags) {
    (void)m; (void)va; (void)pa; (void)flags;
    if (atomic_fetch_add(&active, 1) != 0) atomic_fetch_add(&violations, 1);
    for (int i = 0; i < 50; i++) __asm__ volatile("pause");
    atomic_fetch_add(&calls, 1);
    atomic_fetch_sub(&active, 1);
    return -7;
}
''' + mm[start:end] + r'''
static void *worker(void *p) {
    for (int i = 0; i < 2000; i++)
        assert(mm_map_user_page(p, 0x1000, 0x2000, 0) == -7);
    return 0;
}
int main(void) {
    mm_t mm = { .page_table_lock = PTHREAD_MUTEX_INITIALIZER };
    pthread_t threads[4];
    assert(mm_map_user_page(NULL, 0, 0, 0) == -1);
    for (int i = 0; i < 4; i++) assert(pthread_create(&threads[i], 0, worker, &mm) == 0);
    for (int i = 0; i < 4; i++) assert(pthread_join(threads[i], 0) == 0);
    assert(atomic_load(&calls) == 8000 && atomic_load(&violations) == 0);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-pthread", str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: leaf installs using the wrapper serialize")
