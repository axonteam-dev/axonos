#!/usr/bin/env python3
"""Exercise actual VT path parsers and check image getty configuration."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
devfs = (root / 'fs/virt/devfs.c').read_text()
dispatch = (root / 'syscall/dispatch/syscall_dispatch.c').read_text()
paths = devfs[devfs.index('static int devfs_vt_number('):devfs.index('static struct fs_file *devfs_alloc_file(')]
aliases = dispatch[dispatch.index('static int tty_alias_number('):dispatch.index('static const char *task_fs_root(')]
program = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define DEVFS_TTY_COUNT 12
static int devfs_get_active(void) { return 7; }
''' + paths + aliases + r'''
int main(void) {
    char path[32], alias[32];
    for (int n = 1; n <= 12; n++) {
        snprintf(path, sizeof(path), "/dev/tty%d", n); assert(devfs_path_to_tty(path) == n-1);
        snprintf(path, sizeof(path), "/dev/vc/%d", n); assert(devfs_path_to_tty(path) == n-1);
        snprintf(path, sizeof(path), "/dev/%d", n); assert(devfs_path_to_tty(path) == n-1);
        snprintf(alias, sizeof(alias), "/tty%d", n); map_tty_alias_path(alias, sizeof(alias));
        snprintf(path, sizeof(path), "/dev/tty%d", n); assert(!strcmp(alias, path));
    }
    assert(devfs_path_to_tty("/dev/tty0") == 7);
    assert(devfs_path_to_tty("/dev/vc/0") == 7);
    assert(devfs_path_to_tty("/dev/tty13") == -1);
    assert(devfs_path_to_tty("/dev/tty10x") == -1);
    assert(devfs_path_to_tty("/dev/tty01") == -1);
    assert(tty_alias_number("/tty13") == -1);
    assert(tty_alias_number("/tty10x") == -1);
}
'''
with tempfile.TemporaryDirectory(prefix='axon-vt-twelve-', dir='/tmp/opencode') as tmp:
    src, exe = Path(tmp) / 'test.c', Path(tmp) / 'test'
    src.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
builder = (root / 'tools/build-glibc-iso.sh').read_text()
assert 'for vt in range(1, 13):' in builder
assert 'getty@tty{vt}.service' in builder
assert 'console_getty.symlink_to("/dev/null")' in builder
print('PASS: twelve VT paths, aliases and systemd getty configuration')
