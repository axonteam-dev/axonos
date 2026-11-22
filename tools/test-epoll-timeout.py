#!/usr/bin/env python3
"""Compile the epoll elapsed-time calculation from the kernel."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
start = source.index('static int epoll_timeout_remaining(')
helper = source[start:source.index('\n}', start) + 2]
wait = source[source.index('case 232: /* epoll_wait */'):]
assert 'epoll_timeout_remaining(timeout, start_ms, time_monotonic_ms())' in wait
program = '#include <stdint.h>\n#include <assert.h>\n' + helper + '''
int main(void) {
    assert(epoll_timeout_remaining(-1, 100, 100000) == -1);
    assert(epoll_timeout_remaining(0, 100, 100) == 0);
    assert(epoll_timeout_remaining(20, 100, 101) == 19);
    assert(epoll_timeout_remaining(20, 100, 120) == 0);
    assert(epoll_timeout_remaining(20, 100, 10000) == 0);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='axon-epoll-timeout-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: epoll timeouts use elapsed monotonic time')
