#!/usr/bin/env python3
"""A stale COW bit on a non-present PTE must not suppress demand paging."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/mm.c").read_text()
start = source.index("static int mm_pte_is_present_cow(")
end = source.index("\n}\n", start) + 2
helper = source[start:end]
assert "if (mm_pte_is_present_cow(l1[l1i]))" in source
program = r'''
#include <stdint.h>
#include <assert.h>
#define PG_PRESENT (1ULL << 0)
#define PG_SOFT_COW (1ULL << 9)
''' + helper + r'''
int main(void) {
    assert(!mm_pte_is_present_cow(0));
    assert(!mm_pte_is_present_cow(PG_SOFT_COW));
    assert(!mm_pte_is_present_cow(PG_PRESENT));
    assert(mm_pte_is_present_cow(PG_PRESENT | PG_SOFT_COW));
    return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cfile = Path(tmp) / "test.c"
    exe = Path(tmp) / "test"
    cfile.write_text(program)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("non-present COW PTE regression passed")
