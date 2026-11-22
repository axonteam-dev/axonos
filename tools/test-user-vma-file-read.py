#!/usr/bin/env python3
"""Test exact page reads used by lazy file-backed mmap faults."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "mm/user_vma.c").read_text()
start = source.index("static int user_vma_read_file_page(")
end = source.index("\nstatic int user_vma_fill_file_page(", start)
helper = source[start:end]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

struct fs_file { int64_t size; const char *path; };
static uint8_t contents[8192];
static size_t max_read = 4096;
static size_t stop_read = (size_t)-1;

static ssize_t fs_read(struct fs_file *file, void *dst, size_t len, size_t off) {
    size_t available;
    (void)file;
    if (off >= stop_read || off >= sizeof(contents)) return 0;
    available = sizeof(contents) - off;
    if (off < stop_read && stop_read - off < available)
        available = stop_read - off;
    if (len > available) len = available;
    if (len > max_read) len = max_read;
    memcpy(dst, contents + off, len);
    return (ssize_t)len;
}
static void klogprintf(const char *fmt, ...) { (void)fmt; }
''' + helper + r'''

int main(void) {
    struct fs_file file = {.size = sizeof(contents), .path = "/lib/test.so"};
    uint8_t page[4096];
    for (size_t i = 0; i < sizeof(contents); ++i)
        contents[i] = (uint8_t)(i * 31u + 7u);

    /* Short positive reads are retried until a full in-file page is read. */
    max_read = 700;
    stop_read = (size_t)-1;
    assert(user_vma_read_file_page(&file, 0, page) == 0);
    assert(memcmp(page, contents, sizeof(page)) == 0);

    /* Only bytes past the actual EOF in the final page are zero-filled. */
    file.size = 4096 + 33;
    assert(user_vma_read_file_page(&file, 4096, page) == 0);
    assert(memcmp(page, contents + 4096, 33) == 0);
    for (size_t i = 33; i < sizeof(page); ++i) assert(page[i] == 0);

    /* EOF before the requested in-file bytes must not create executable zeroes. */
    file.size = 4096;
    stop_read = 2048;
    assert(user_vma_read_file_page(&file, 0, page) != 0);
    stop_read = (size_t)-1;

    /* A whole page at/after EOF is invalid, not a successful zero page. */
    assert(user_vma_read_file_page(&file, 4096, page) != 0);
    puts("PASS: lazy file mmap retries short reads, zeroes only EOF tail, rejects missing pages");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-vma-file-read-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
