#!/usr/bin/env python3
"""Exercise the kernel futex key function across COW and shared mappings."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/futex/futex.c").read_text()
start = source.index("static int futex_key(")
end = source.index("\nstatic int futex_wake_locked(", start)
function = source[start:end]

harness = r"""
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#define EINVAL 22
#define EFAULT 14
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
typedef struct mm { int id; } mm_t;
typedef struct thread { mm_t *mm; } thread_t;
static uint64_t frame;
static int shared;
static int present = 1;
static int mm_user_leaf_pa(mm_t *mm, uint64_t va, int write, uint64_t *out) {
    (void)mm; (void)write;
    if (!present) return -1;
    *out = frame + (va & 4095);
    return 0;
}
static int user_vma_is_shared_page_mm(mm_t *mm, uintptr_t va) {
    (void)mm; (void)va;
    return shared;
}
""" + function + r"""
int main(void) {
    mm_t a = {1}, b = {2};
    thread_t x = {&a}, y = {&b};
    uintptr_t wait_key, wake_key, private_key;
    mm_t *wait_owner, *wake_owner, *private_owner;
    const uintptr_t addr = 0x12340;
    frame = 0x90000;
    assert(futex_key(&x, addr, 0, &wait_key, &wait_owner) == 0);
    frame = 0xa0000; /* exit's clear_child_tid triggers COW */
    assert(futex_key(&x, addr, 0, &wake_key, &wake_owner) == 0);
    assert(wait_key == wake_key && wait_owner == wake_owner);
    assert(futex_key(&x, addr, 1, &private_key, &private_owner) == 0);
    assert(private_key != wait_key && private_owner == wait_owner);
    assert(futex_key(&y, addr, 0, &wake_key, &wake_owner) == 0);
    assert(wake_owner != wait_owner);
    shared = 1;
    assert(futex_key(&x, addr, 0, &wait_key, &wait_owner) == 0);
    assert(futex_key(&y, addr + 0x1000, 0, &wake_key, &wake_owner) == 0);
    assert(wait_owner == 0 && wake_owner == 0 && wait_key == wake_key);
    present = 0;
    assert(futex_key(&x, addr, 0, &wake_key, &wake_owner) == -EFAULT);
    assert(futex_key(&x, addr + 1, 0, &wake_key, &wake_owner) == -EINVAL);
    puts("PASS: futex COW-stable keys and shared aliases");
}
"""

with tempfile.TemporaryDirectory(prefix="futex-key-") as tmp:
    cfile = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    cfile.write_text(harness)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
