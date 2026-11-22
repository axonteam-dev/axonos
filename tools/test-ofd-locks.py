#!/usr/bin/env python3
"""Exercise the in-kernel whole-file OFD lock implementation without a VM."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/fs.c").read_text()
implementation = source[source.index("#define OFD_LOCK_MAX 128"):
                        source.index("uint64_t fs_file_max_get(")]
assert "fs_ofd_lock_release(file);" in source[source.index("void fs_file_free("):
                                               source.index("void fs_file_free(") + 900]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
assert "F_OFD_SETLKW = 38" in dispatch and "fs_ofd_lock_try(f, fl.type, NULL, 0)" in dispatch

fixture = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
typedef struct { int busy; } spinlock_t;
typedef struct fs_file { ino_t ino; dev_t dev; mode_t mode; } fs_file;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(!lock->busy); lock->busy = 1; *flags = 0;
}
static void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags; assert(lock->busy); lock->busy = 0;
}
static int vfs_fstat(struct fs_file *file, struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_dev = file->dev;
    st->st_ino = file->ino;
    st->st_mode = file->mode;
    return 0;
}
''' + implementation + r'''
int main(void) {
    fs_file a = {.ino=101, .dev=1, .mode=S_IFREG},
            b = {.ino=101, .dev=1, .mode=S_IFREG},
            c = {.ino=101, .dev=1, .mode=S_IFREG},
            other = {.ino=101, .dev=2, .mode=S_IFREG},
            dir = {.ino=101, .dev=1, .mode=S_IFDIR};
    short conflict = 9;
    assert(fs_ofd_lock_try(&a, 1, NULL, 0) == 0); /* writer */
    assert(fs_ofd_lock_try(&a, 1, NULL, 0) == 0); /* idempotent */
    assert(fs_ofd_lock_try(&b, 1, NULL, 0) == -EAGAIN);
    assert(fs_ofd_lock_try(&b, 0, &conflict, 1) == 0 && conflict == 1);
    /* Query must not release the writer's existing lock. */
    assert(fs_ofd_lock_try(&a, 0, &conflict, 1) == 0 && conflict == 2);
    assert(fs_ofd_lock_try(&b, 1, NULL, 0) == -EAGAIN);
    assert(fs_ofd_lock_try(&other, 1, NULL, 0) == 0);
    assert(fs_ofd_lock_try(&dir, 1, NULL, 0) == -EINVAL);
    fs_ofd_lock_release(&a); /* last fd close */
    assert(fs_ofd_lock_try(&b, 0, NULL, 0) == 0);
    assert(fs_ofd_lock_try(&c, 0, NULL, 0) == 0); /* shared reader */
    assert(fs_ofd_lock_try(&a, 1, &conflict, 1) == 0 && conflict == 0);
    assert(fs_ofd_lock_try(&a, 1, NULL, 0) == -EAGAIN);
    assert(fs_ofd_lock_try(&b, 2, NULL, 0) == 0); /* unlock one reader */
    assert(fs_ofd_lock_try(&a, 1, NULL, 0) == -EAGAIN);
    fs_ofd_lock_release(&c);
    assert(fs_ofd_lock_try(&a, 1, NULL, 0) == 0);
    fs_ofd_lock_release(&a);
    fs_ofd_lock_release(&other);
    puts("PASS: OFD whole-file locks exclude writers, share readers, query and release on last close");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-ofd-", dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
