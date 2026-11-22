#!/usr/bin/env python3
"""MAP_FIXED file mappings must not require ELF contents."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "mm/user_mmap.c").read_text()
start = source.index("uint64_t user_syscall_mmap(")
end = source.index("uint64_t user_syscall_mremap(", start)
mmap_source = source[start:end]
# Guard the eager file path, including the historical post-copy ELF check.
assert 'missing ELF magic' not in mmap_source
assert "eh[0] != 0x7f" not in mmap_source

program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    char name[] = "/tmp/axon-mmap-fixed-XXXXXX";
    int fd = mkstemp(name);
    assert(fd >= 0);
    assert(unlink(name) == 0);
    const char data[] = "not an ELF file";
    assert(write(fd, data, sizeof(data)) == sizeof(data));
    long page = sysconf(_SC_PAGESIZE);
    assert(page > 0);
    void *reservation = mmap(NULL, (size_t)page, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(reservation != MAP_FAILED);
    void *mapped = mmap(reservation, (size_t)page, PROT_READ,
                        MAP_PRIVATE | MAP_FIXED, fd, 0);
    assert(mapped == reservation);
    assert(memcmp(mapped, data, sizeof(data)) == 0);
    assert(munmap(mapped, (size_t)page) == 0);
    assert(close(fd) == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-mmap-fixed-test-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: fixed file mappings accept non-ELF contents (Linux reference and source guard)")
