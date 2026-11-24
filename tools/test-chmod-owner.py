#!/usr/bin/env python3
"""chmod syscalls require ownership/capability and report actual failures."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("        case SYS_chmod: {")
end = source.index("        case SYS_chown:", start)
fd_start = source.index("        case 91: { /* fchmod(fd, mode) */")
fd_end = source.index("        case 93: { /* fchown", fd_start)
chown_end = source.index("        case 94: { /* lchown", fd_end)
helper_start = source.index("static int syscall_ext2_chown_file(")
path_helper_start = source.index("static int syscall_ext2_chown_path(", helper_start)
helper_end = source.index("\n}\n", path_helper_start) + 2
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#define SYS_chmod 90
#define MMIO_IDENTITY_LIMIT UINTPTR_MAX
#define THREAD_MAX_FD 32
#define AXON_CAP_FOWNER 3
#define AXON_CAP_CHOWN 0
#define EFAULT 14
#define ENOENT 2
#define EPERM 1
#define EROFS 30
#define EBADF 9
#define EIO 5
#define EINVAL 22
#define EOPNOTSUPP 95
typedef struct { uid_t euid; } thread_t;
struct fs_file { const char *path; unsigned type, flags; };
struct fs_driver { int id; };
static thread_t task;
static struct fs_file file = {"/test", 1, 0};
static struct fs_driver ext2_driver, other_driver;
static int capable, chmod_calls, chmod_result, is_ext2, ext2_calls, chown_calls;
static int open_kind, freed;
static char chmod_path[256];
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int syscall_task_capable(thread_t *t, int c) { (void)t; (void)c; return capable; }
static void resolve_user_path(thread_t *t, const char *p, char *out, size_t n) {
    (void)t; snprintf(out, n, "%s", p);
}
static int resolve_user_path_at(thread_t *t, int fd, const char *p, char *out, size_t n) {
    (void)fd; resolve_user_path(t,p,out,n); return 0;
}
static int vfs_stat(const char *p, struct stat *st) {
    (void)p; memset(st,0,sizeof *st); st->st_uid = 1000; st->st_gid = 1004; return 0;
}
static int vfs_fstat(struct fs_file *f, struct stat *st) { (void)f; return vfs_stat("", st); }
static int fs_resolve_symlink_path(const char *p, char *out, size_t cap) {
    snprintf(out, cap, "%s", strcmp(p, "/link") == 0 ? "/target" : p);
    return 0;
}
static int fs_chmod(const char *p, mode_t mode) {
    (void)mode; snprintf(chmod_path, sizeof chmod_path, "%s", p);
    chmod_calls++; return chmod_result;
}
static int fs_mount_is_readonly(const char *p) { (void)p; return 0; }
static int ramfs_fchmod_file(struct fs_file *f, mode_t mode) { (void)f; (void)mode; return -1; }
static struct fs_driver *ext2_get_driver(void) { return &ext2_driver; }
static struct fs_driver *fs_get_file_driver(struct fs_file *f) {
    (void)f; return is_ext2 ? &ext2_driver : &other_driver;
}
static int ext2_fchmod_file(struct fs_file *f, mode_t mode) {
    assert(f == &file && mode == 0600); ext2_calls++; return 0;
}
static int ext2_fchown_file(struct fs_file *f, uint32_t uid, uint32_t gid) {
    (void)f; (void)uid; (void)gid; chown_calls++; return 0;
}
static int syscall_id_in_group_as(const thread_t *t, gid_t gid, int real) {
    (void)t; (void)real; return gid == 1002;
}
static int devfs_chown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return -1; }
static int overlayfs_chown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return -1; }
static struct fs_file *fs_open(const char *p) { (void)p; open_kind = 1; return &file; }
static struct fs_file *fs_open_nofollow(const char *p) { (void)p; open_kind = 2; return &file; }
static void fs_file_free(struct fs_file *f) { assert(f == &file); freed++; }
static struct fs_file *syscall_fd_get(thread_t *t, int fd) { (void)t; return fd == 3 ? &file : NULL; }
static unsigned long long process_pid(thread_t *t) { (void)t; return 1; }
#define klogprintf_logonly(...) ((void)process_pid(cur))
''' + source[helper_start:helper_end] + r'''
static uint64_t run(unsigned nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4) {
    thread_t *cur = &task;
    switch (nr) {
''' + source[start:end] + source[fd_start:chown_end] + r'''
    default: return 99;
    }
}
int main(void) {
    task.euid = 1001;
    assert((int64_t)run(90,(uintptr_t)"/test",0600,0,0) == -EPERM && !chmod_calls);
    assert((int64_t)run(268,0,(uintptr_t)"/test",0600,0) == -EPERM && !chmod_calls);
    assert((int64_t)run(91,3,0600,0,0) == -EPERM && !chmod_calls);
    task.euid = 1000; chmod_result = -1;
    assert((int64_t)run(91,3,0600,0,0) == -EPERM);
    is_ext2 = 1;
    assert(run(91,3,0600,0,0) == 0 && ext2_calls == 1);
    chmod_result = 0;
    assert(run(90,(uintptr_t)"/test",0600,0,0) == 0);
    assert(run(90,(uintptr_t)"/link",0600,0,0) == 0 && !strcmp(chmod_path, "/target"));
    task.euid = 1001; capable = 1;
    assert(run(268,0,(uintptr_t)"/test",0600,0) == 0);
    capable = 0;
    assert((int64_t)run(93,3,1001,1002,0) == -EPERM && !chown_calls);
    task.euid = 1000;
    assert(run(93,3,UINT32_MAX,1002,0) == 0 && chown_calls == 1);
    assert(run(93,3,UINT32_MAX,1004,0) == 0 && chown_calls == 2);
    assert((int64_t)run(93,3,UINT32_MAX,1003,0) == -EPERM);
    capable = 1;
    assert(run(93,3,1001,1003,0) == 0 && chown_calls == 3);
    assert(syscall_ext2_chown_path(&task, "/link", 1, 2, 0) == 0);
    assert(open_kind == 1 && freed == 1 && chown_calls == 4);
    assert(syscall_ext2_chown_path(&task, "/link", 1, 2, 1) == 0);
    assert(open_kind == 2 && freed == 2 && chown_calls == 5);
    is_ext2 = 0;
    assert(syscall_ext2_chown_path(&task, "/link", 1, 2, 0) == -EOPNOTSUPP);
    assert(freed == 3 && chown_calls == 5);
    puts("PASS: chmod/fchown enforce ownership and report failed changes");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-chmod-owner-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
