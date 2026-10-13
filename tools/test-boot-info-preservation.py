#!/usr/bin/env python3
"""Reproduce the fixed-address MB2 copy corrupting a low initfs, without a VM."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
stub = (root / "boot/kzip_stub.c").read_text()


def function(signature):
    start = stub.index(signature)
    opening = stub.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (stub[end] == "{") - (stub[end] == "}")
        end += 1
    return stub[start:end]


program = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
enum { MB2_COPY_MAX = 2u * 1024u * 1024u };
static uint8_t mb2_copy[MB2_COPY_MAX] __attribute__((aligned(4096)));
''' + function("static void *memmove_local(void *dst, const void *src, size_t n) {") + "\n" + function("static uint32_t rd32(const uint8_t *p) {") + "\n" + function("static uint64_t preserve_multiboot_info(uint64_t multiboot_info) {") + r'''
int main(void) {
    const uintptr_t base = 0x00100000u;
    const size_t size = 64u * 1024u * 1024u;
    uint8_t *module = mmap((void *)base, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (module == MAP_FAILED) {
        perror("test: map the low initfs fixture (no existing mapping is replaced)");
        return 1;
    }
    assert((uintptr_t)module == base);
    memset(module, 0x5a, size);
    uint8_t info[4096]; memset(info, 0xa5, sizeof(info));
    uint32_t total = sizeof(info); memcpy(info, &total, sizeof(total));

    /* This is the previous copy policy. Demonstrate actual image corruption. */
    uint8_t *old_destination = (uint8_t *)(uintptr_t)0x01000000u;
    memcpy(old_destination, info, sizeof(info));
    assert(old_destination[sizeof(total)] != 0x5a);
    memset(old_destination, 0x5a, sizeof(info));

    uint64_t saved = preserve_multiboot_info((uint64_t)(uintptr_t)info);
    assert(saved == (uint64_t)(uintptr_t)mb2_copy);
    assert(memcmp((void *)(uintptr_t)saved, info, sizeof(info)) == 0);
    assert(memcmp(old_destination, module, sizeof(info)) == 0);
    for (size_t i = 0; i < size; i++) assert(module[i] == 0x5a);
    assert(preserve_multiboot_info(0) == 0);
    total = 8; memcpy(info, &total, sizeof(total));
    assert(preserve_multiboot_info((uint64_t)(uintptr_t)info) == (uint64_t)(uintptr_t)info);
    /* Overlapping source/destination within the reserved buffer is safe too. */
    total = sizeof(info); memcpy(info, &total, sizeof(total));
    memcpy(mb2_copy + 16, info, sizeof(info));
    assert(preserve_multiboot_info((uint64_t)(uintptr_t)(mb2_copy + 16)) == saved);
    assert(memcmp(mb2_copy, info, sizeof(info)) == 0);
    assert(munmap(module, size) == 0);
    puts("PASS: old 16MiB MB2 copy corrupts initfs; reserved BSS copy preserves every byte");
}
'''
assert "resb 131072" in (root / "boot/multiboot.asm").read_text()
with tempfile.TemporaryDirectory(prefix="axon-boot-info-") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie",
                    "-fsanitize=undefined", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
