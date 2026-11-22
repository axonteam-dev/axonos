#!/usr/bin/env python3
"""Verify meminfo does not claim firmware RAM excluded from the allocators."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "fs/virt/procfs.c").read_text()
start = source.index("static ssize_t procfs_show_meminfo(")
brace = source.index("{", start)
depth = 0
for end in range(brace, len(source)):
    depth += (source[end] == "{") - (source[end] == "}")
    if depth == 0:
        break
function = source[start:end + 1]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
static int ready = 1;
static int sysinfo_ram_mb(void) { return 4096; }
static uint64_t procfs_sum_unique_user_rss_kb(void) { return 128; }
static size_t heap_used_bytes(void) { return 128 * 1024; }
static size_t heap_total_bytes(void) { return 512 * 1024; }
static size_t heap_free_bytes(void) { return 384 * 1024; }
static int pmm_ready(void) { return ready; }
static size_t pmm_total_pages(void) { return 1024; }
static size_t pmm_free_pages(void) { return 256; }
static size_t pagecache_cached_pages(void) { return 32; }
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
static size_t ramfs_high_page_free_pages(void) { return 2048; }
static size_t ramfs_high_page_total_pages(void) { return 3072; }
#endif
''' + function + r'''
int main(void) {
    char out[2048];
    assert(procfs_show_meminfo(out, sizeof(out), NULL) > 0);
#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP
    assert(strstr(out, "MemTotal:       16896 kB\n"));
    assert(strstr(out, "MemFree:        9600 kB\n"));
#else
    assert(strstr(out, "MemTotal:       4608 kB\n"));
    assert(strstr(out, "MemFree:        1408 kB\n"));
#endif
    assert(strstr(out, "MemAvailable:   1408 kB\n"));
    assert(strstr(out, "Cached:        128 kB\n"));
    /* Before PMM initialization, do not claim all firmware RAM is free. */
    ready = 0;
    assert(procfs_show_meminfo(out, sizeof(out), NULL) > 0);
    assert(strstr(out, "MemTotal:       512 kB\n"));
    assert(strstr(out, "MemFree:        384 kB\n"));
    puts("PASS: meminfo reports allocator-managed and free memory");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-meminfo-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture)
    for flags in ([], ["-DAXON_EXPERIMENTAL_DIRECT_MAP=1"]):
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", *flags, str(src), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
