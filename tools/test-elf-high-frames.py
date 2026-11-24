#!/usr/bin/env python3
"""Host-only exercise of ELF copying into high physical frames."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
elf = (root / "core/elf.c").read_text()
start = elf.index("static int elf_copy_into_mm(")
end = elf.index("\n/*\n * Linux process-local layout", start)
store_start = elf.index("static int elf_store_u64_into_mm(")
store_end = elf.index("\nstatic int elf_va_to_file_off(", store_start)
load_start = elf.index("static int elf_load_u8_from_mm(")
load_end = elf.index("\nstatic int elf_apply_rela_buffer(", load_start)
source = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define MMIO_IDENTITY_LIMIT 0x100000000ULL
typedef struct { int unused; } mm_t;
static unsigned char high[8192];
static int mapped = 1;
static int mm_va_leaf_pa(mm_t *mm, uint64_t va, uint64_t *pa) {
    (void)mm;
    if (va < 0x400000 || va >= 0x402000) return -1;
    *pa = 0x100000000ULL + (va - 0x400000);
    return 0;
}
static void *frame_kva(uint64_t pa) {
    if (!mapped || pa < 0x100000000ULL || pa >= 0x100002000ULL) return 0;
    return high + (pa - 0x100000000ULL);
}
static void kprintf(const char *fmt, ...) { (void)fmt; }
''' + elf[start:end] + "\n" + elf[store_start:store_end] + "\n" + elf[load_start:load_end] + r'''
int main(void) {
    mm_t mm = {0};
    const unsigned char data[] = {1, 2, 3, 4, 5};
    assert(elf_copy_into_mm(&mm, 0x400ffe, data, sizeof data) == 0);
    assert(!memcmp(high + 4094, data, sizeof data));
    assert(elf_zero_into_mm(&mm, 0x400fff, 3) == 0);
    assert(high[4094] == 1 && high[4095] == 0);
    assert(high[4096] == 0 && high[4097] == 0 && high[4098] == 5);
    uint64_t value = 0x123456789abcdef0ULL, read_back = 0;
    assert(elf_store_u64_into_mm(&mm, 0x400ffc, value) == 0);
    assert(elf_load_u8_from_mm(&mm, 0x400ffc, &read_back, sizeof read_back) == 0);
    assert(read_back == value);
    assert(elf_store_u64_into_mm(&mm, UINT64_MAX - 1, value) != 0);
    mapped = 0;
    assert(elf_copy_into_mm(&mm, 0x400000, data, sizeof data) != 0);
    assert(elf_zero_into_mm(&mm, 0x400000, 1) != 0);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: ELF copy/zero use high frame kernel mappings")
