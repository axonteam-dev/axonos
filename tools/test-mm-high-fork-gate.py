#!/usr/bin/env python3
"""Host-only gate checks; does not establish SMP or fork correctness."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
mm = (root / "core/mm.c").read_text()
start = mm.index("static int mm_high_fork_allowed(")
end = mm.index("\n/* Map one 4K user page", start)
source = r'''
#include <assert.h>
typedef struct { int refcount; } mm_t;
#if defined(AXON_EXPERIMENTAL_HIGH_USER_FRAMES) && AXON_EXPERIMENTAL_HIGH_USER_FRAMES && \
    defined(AXON_EXPERIMENTAL_HIGH_FORK) && AXON_EXPERIMENTAL_HIGH_FORK
static int cpus = 1;
static int smp_cpu_count(void) { return cpus; }
#endif
''' + mm[start:end] + r'''
int main(void) {
    mm_t parent = {1};
    assert(!mm_high_fork_allowed(0));
#if defined(AXON_EXPERIMENTAL_HIGH_USER_FRAMES) && AXON_EXPERIMENTAL_HIGH_USER_FRAMES && \
    defined(AXON_EXPERIMENTAL_HIGH_FORK) && AXON_EXPERIMENTAL_HIGH_FORK
    assert(mm_high_fork_allowed(&parent));
    cpus = 2;
    assert(!mm_high_fork_allowed(&parent));
    cpus = 1;
    parent.refcount = 2;
    assert(!mm_high_fork_allowed(&parent));
#else
    assert(!mm_high_fork_allowed(&parent));
#endif
}
'''
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(source)
    for flags in ([], ["-DAXON_EXPERIMENTAL_HIGH_USER_FRAMES=1"],
                  ["-DAXON_EXPERIMENTAL_HIGH_USER_FRAMES=1",
                   "-DAXON_EXPERIMENTAL_HIGH_FORK=1"]):
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        *flags, str(src), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
print("PASS: high-frame fork is opt-in, single-CPU and single-owner")
