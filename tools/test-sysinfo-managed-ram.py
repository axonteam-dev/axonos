#!/usr/bin/env python3
"""sysinfo must report the same managed pools as /proc/meminfo."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void syscall_managed_ram(")
helper = source[start:source.index("\n}\n", start) + 3]
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
static size_t ht, hf, pt, pf, xt, xf;
static int ready;
static size_t heap_total_bytes(void) { return ht; }
static size_t heap_free_bytes(void) { return hf; }
static int pmm_ready(void) { return ready; }
static size_t pmm_total_pages(void) { return pt; }
static size_t pmm_free_pages(void) { return pf; }
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP)
static size_t ramfs_high_page_total_pages(void) { return xt; }
static size_t ramfs_high_page_free_pages(void) { return xf; }
#endif
''' + helper + r'''
int main(void) {
    uint64_t total, free_bytes;
    ht = 4096; hf = 1024; pt = 10; pf = 3; xt = 20; xf = 15;
    syscall_managed_ram(&total, &free_bytes);
    assert(total == 4096 && free_bytes == 1024);
    ready = 1;
    syscall_managed_ram(&total, &free_bytes);
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP)
    assert(total == 4096 + 30 * 4096 && free_bytes == 1024 + 18 * 4096);
#else
    assert(total == 4096 + 10 * 4096 && free_bytes == 1024 + 3 * 4096);
#endif
    hf = 100000000; syscall_managed_ram(&total, &free_bytes);
    assert(free_bytes == total);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-sysinfo-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    for flags in ([], ["-DAXON_EXPERIMENTAL_DIRECT_MAP=1"]):
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", *flags, str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
print("PASS: sysinfo reports managed RAM without invented free memory")
