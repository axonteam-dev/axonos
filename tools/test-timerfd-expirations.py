#!/usr/bin/env python3
"""Exercise the kernel's timerfd expiration and itimerspec helpers on the host."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("typedef struct timerfd_state_k {")
end = source.index("void timerfd_fs_file_destroy(", start)
helpers = source[start:end]

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef struct { int lock; } spinlock_t;
static uint64_t time_monotonic_us(void) { return 3500000; }
static void ktime_get_real_ts64(int64_t *s, int64_t *ns) {
    *s = 1700000000;
    *ns = 500000000;
}
''' + helpers + r'''
int main(void) {
    assert(sizeof(timerfd_itimerspec_k) == 32);
    timerfd_timespec_k ts = {.sec = 2, .nsec = 500000000};
    assert(timerfd_spec_valid(&ts));
    assert(timerfd_timespec_ns(&ts) == 2500000000ULL);
    ts.nsec = 1000000000;
    assert(!timerfd_spec_valid(&ts));
    assert(timerfd_now_ns(1) == 3500000000ULL);
    assert(timerfd_now_ns(0) == 1700000000500000000ULL);

    timerfd_state_k timer = {.armed = 1, .deadline_ns = 1000000000ULL};
    timerfd_update_at(&timer, 999999999);
    assert(timer.expirations == 0 && timer.armed);
    timerfd_update_at(&timer, 1000000000ULL);
    assert(timer.expirations == 1 && !timer.armed);
    timerfd_update_at(&timer, 2000000000ULL);
    assert(timer.expirations == 1);

    timer = (timerfd_state_k) {
        .armed = 1, .deadline_ns = 1000000000ULL, .interval_ns = 1000000000ULL
    };
    timerfd_update_at(&timer, 4500000000ULL);
    assert(timer.expirations == 4 && timer.deadline_ns == 5000000000ULL);
    timerfd_itimerspec_k result;
    timerfd_get_spec_locked(&timer, 4500000000ULL, &result);
    assert(result.interval.sec == 1 && result.interval.nsec == 0);
    assert(result.value.sec == 0 && result.value.nsec == 500000000);
    timerfd_update_at(&timer, 5000000000ULL);
    assert(timer.expirations == 5 && timer.deadline_ns == 6000000000ULL);
    puts("PASS: timerfd one-shot, periodic, absolute clock and ABI layout");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-timerfd-") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
