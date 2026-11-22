#!/usr/bin/env python3
"""Verify select's evdev readiness branch uses queued input, not file size."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
select = source[source.index('select_common:'):]
branch = select[select.index('} else if (evdev_is_file(f)) {'):]
branch = branch[:branch.index('} else if (devfs_is_tty_file(f)) {')]
body = branch.replace('} else if', 'if', 1) + '}'
program = '''
#include <assert.h>
struct fs_file { int queued; };
static int evdev_is_file(struct fs_file *f) { return f != 0; }
static int evdev_bytes_available(struct fs_file *f) { return f->queued; }
static int ready(struct fs_file *f) { int can_r = 0;
''' + body + '''
return can_r; }
int main(void) { struct fs_file f = {0}; assert(!ready(&f));
    f.queued = 24; assert(ready(&f)); return 0; }
'''
with tempfile.TemporaryDirectory(prefix='axon-select-evdev-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: select reports queued evdev input')
