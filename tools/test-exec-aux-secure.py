#!/usr/bin/env python3
"""Check AT_SECURE and auxv termination in both exec stack builders."""
from pathlib import Path
import re
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "core/elf.c").read_text()
start = source.index("static uint64_t elf_auxv_secure(")
helper = source[start:source.index("\n}\n", start) + 3]
assert source.count("const size_t aux_pairs = 10;") == 2
blocks = re.findall(r'sp64\[ax \+ 0\] = \(uint64_t\)AT_PHDR;.*?'
                    r'sp64\[ax \+19\] = 0;', source, re.S)
assert len(blocks) == 2

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef struct { unsigned uid, euid, gid, egid; } process_t;
typedef struct { process_t *process; unsigned uid, euid, gid, egid; } thread_t;
enum { AT_NULL=0, AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_PAGESZ=6,
       AT_BASE=7, AT_ENTRY=9, AT_CLKTCK=17, AT_SECURE=23, AT_RANDOM=25 };
typedef struct { int unused; } Elf64_Phdr;
static int pit_get_frequency(void) { return 250; }
''' + helper
for i, block in enumerate(blocks):
    thread_name = "tc" if i == 0 else "tip_tc"
    program += f'''
static void build_{i}(uint64_t *sp64, unsigned ax, thread_t *{thread_name}) {{
    uint64_t aux_phdr=1, aux_phent=2, aux_phnum=3, aux_base=4, aux_entry=5;
    uint64_t random_addr=6;
    {block}
}}
'''
program += r'''
int main(void) {
    thread_t t = {0};
    process_t p = {0};
    uint64_t stack[64];
    for (unsigned i=0; i<2; ++i) {
        for (unsigned ax=0; ax<5; ++ax) {
            for (unsigned n=0; n<64; ++n) stack[n] = ~0ULL;
            if (i == 0) build_0(stack, ax, &t); else build_1(stack, ax, &t);
            assert(stack[ax+16] == AT_SECURE && stack[ax+17] == 0);
            assert(stack[ax+18] == AT_NULL && stack[ax+19] == 0);
            assert(stack[ax+20] == ~0ULL);
        }
    }
    t.uid=1000; t.euid=0; assert(elf_auxv_secure(&t) == 1);
    t.euid=1000; t.gid=1000; t.egid=0; assert(elf_auxv_secure(&t) == 1);
    t.process=&p; assert(elf_auxv_secure(&t) == 0);
    p.uid=1000; p.euid=0; assert(elf_auxv_secure(&t) == 1);
    p.euid=1000; p.gid=1000; p.egid=0; assert(elf_auxv_secure(&t) == 1);
    assert(elf_auxv_secure(NULL) == 0);
    puts("PASS: both exec auxv builders emit credential-aware AT_SECURE and AT_NULL");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-aux-secure-") as tmp:
    c, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
