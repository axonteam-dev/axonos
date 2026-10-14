#!/usr/bin/env python3
"""Exercise real BSP-only private expedited membarrier registration and fence."""
from pathlib import Path
import subprocess
import tempfile

source=(Path(__file__).resolve().parents[1]/"syscall/dispatch/syscall_dispatch.c").read_text()
start=source.index("static long membarrier_private(")
body=source[start:source.index("\n}\n",start)+3]
program=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
typedef struct { uint32_t membarrier_private_registered; } mm_t;
'''+body+r'''
int main(void) {
    mm_t a={0},b={0};
    assert(membarrier_private(NULL,0,0)==24);
    assert(membarrier_private(&a,8,0)==-1);
    assert(membarrier_private(&a,16,0)==0);
    assert(membarrier_private(&a,8,0)==0);
    assert(membarrier_private(&b,8,0)==-1); /* another address space isn't registered */
    assert(membarrier_private(&a,16,1)==-22&&membarrier_private(&a,32,0)==-22);
    assert(membarrier_private(&a,1,0)==-22); /* unsupported global command never reports success */
    puts("PASS: private membarrier query, per-mm registration, real mfence and unsupported-command errors");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-membarrier-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
