#!/usr/bin/env python3
"""Test O_TRUNC behavior for device handles returned as regular VFS files."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static int syscall_apply_open_truncate(")
end = source.index("\n}\n", start) + 3
helper = source[start:end]

# Both open entry points must share the implementation so the fix cannot drift.
assert source.count("syscall_apply_open_truncate(f)") == 2

program = r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#define FS_TYPE_REG 1
#define S_IFCHR 0020000u
#define S_IFBLK 0060000u
#define S_IFREG 0100000u

struct stat { unsigned int st_mode; };
struct fs_file {
    int type;
    long pos;
    size_t size;
    unsigned int mode;
    int stat_error;
    int truncate_error;
    int truncate_calls;
    int cgroup_noop;
};

static int vfs_fstat(struct fs_file *file, struct stat *st) {
    if (file->stat_error) return -1;
    st->st_mode = file->mode;
    return 0;
}
static int vfs_ftruncate(struct fs_file *file, long length) {
    assert(length == 0);
    file->truncate_calls++;
    if (file->truncate_error) return file->truncate_error;
    file->size = 0;
    return 0;
}
static int cgroupfs_open_truncate_noop(const struct fs_file *file) {
    return file->cgroup_noop;
}
''' + helper + r'''

int main(void) {
    struct fs_file file = {
        .type = FS_TYPE_REG, .pos = 17, .size = 123, .mode = S_IFCHR
    };
    assert(syscall_apply_open_truncate(&file) == 0);
    assert(file.pos == 0 && file.size == 123 && file.truncate_calls == 0);

    file.pos = 17;
    file.mode = S_IFBLK;
    assert(syscall_apply_open_truncate(&file) == 0);
    assert(file.pos == 0 && file.size == 123 && file.truncate_calls == 0);

    file.pos = 17;
    file.mode = S_IFREG;
    assert(syscall_apply_open_truncate(&file) == 0);
    assert(file.pos == 0 && file.size == 0 && file.truncate_calls == 1);

    file.pos = 17;
    file.size = 123;
    file.cgroup_noop = 1;
    assert(syscall_apply_open_truncate(&file) == 0);
    assert(file.pos == 0 && file.size == 123 && file.truncate_calls == 1);

    file.cgroup_noop = 0;
    file.truncate_error = -95;
    assert(syscall_apply_open_truncate(&file) == -95);
    assert(file.truncate_calls == 2);
    puts("PASS: O_TRUNC ignores char/block devices and preserves regular-file behavior");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-open-trunc-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
