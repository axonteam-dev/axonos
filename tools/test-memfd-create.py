#!/usr/bin/env python3
"""Exercise the real memfd syscall helper and anonymous RAMFS construction."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = dispatch.index("static uint64_t syscall_memfd_create(")
end = dispatch.index("\n}\n", start) + 2
assert "case SYS_memfd_create:" in dispatch
assert "f->is_memfd == 1 ? ret_err(EPERM) : ret_err(EOPNOTSUPP)" in dispatch
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { unsigned char fd_cloexec[8]; } process_t;
typedef struct { process_t *process; } thread_t;
struct fs_file { int is_memfd; };
static struct fs_file object;
static int fail_copy, alloc_fd = 3, freed, called;
static char captured[250];
static uint64_t ret_err(int e) { return (uint64_t)-(int64_t)e; }
static int copy_from_user_raw(void *dst, const void *src, size_t n) {
    if (fail_copy) return -1;
    memcpy(dst,src,n); return 0;
}
static struct fs_file *ramfs_create_memfd(const char *name) {
    called++; strcpy(captured,name); return &object;
}
static int thread_fd_alloc(struct fs_file *f) { assert(f==&object); return alloc_fd; }
static void fs_file_free(struct fs_file *f) { assert(f==&object); freed++; }
''' + dispatch[start:end] + r'''
int main(void) {
    process_t process = {{0}}; thread_t t = {&process};
    assert(syscall_memfd_create(&t,(uintptr_t)"test",1)==3);
    assert(process.fd_cloexec[3]==1 && object.is_memfd==1 && !strcmp(captured,"test"));
    assert(syscall_memfd_create(&t,(uintptr_t)"test",2)==3);
    assert(!process.fd_cloexec[3] && object.is_memfd==2);
    assert((int64_t)syscall_memfd_create(&t,0,0)==-EFAULT);
    assert((int64_t)syscall_memfd_create(&t,(uintptr_t)"test",4)==-EINVAL);
    char long_name[251]; memset(long_name,'x',sizeof long_name); long_name[250]=0;
    assert((int64_t)syscall_memfd_create(&t,(uintptr_t)long_name,0)==-EINVAL);
    fail_copy=1;
    assert((int64_t)syscall_memfd_create(&t,(uintptr_t)"test",0)==-EFAULT);
    fail_copy=0; alloc_fd=-23;
    assert((int64_t)syscall_memfd_create(&t,(uintptr_t)"test",0)==-ENFILE && freed==1);
    alloc_fd=-24;
    assert((int64_t)syscall_memfd_create(&t,(uintptr_t)"test",0)==-EMFILE && freed==2);
    assert(called==4);
    puts("PASS: memfd validates names and flags, sets CLOEXEC, unwinds fd errors");
}
'''

ramfs = (root / "fs/virt/ramfs.c").read_text()
start = ramfs.index("struct fs_file *ramfs_create_memfd(")
end = ramfs.index("\n}\n", start) + 2
anon = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define S_IFREG 0100000
#define FS_TYPE_REG 1
struct ramfs_node { unsigned mode,nlink,open_count; int is_memfd; };
struct ramfs_file_handle { struct ramfs_node *node; };
struct fs_file { const char *path; void *fs_private,*driver_private; int type,
    inode_kind_known,refcount,flags,is_memfd; };
static struct { void *driver_data; } ramfs_driver = {(void *)0x1234};
static void *ramfs_root = (void *)0x1234;
static int allocations, fail_at, live;
static void *kmalloc(size_t n) {
    if (++allocations==fail_at) return NULL;
    void *p=malloc(n); if (p) live++; return p;
}
static void kfree(void *p) { if (p) { live--; free(p); } }
static struct ramfs_node *ramfs_alloc_node(const char *name,int dir) {
    (void)name; (void)dir; struct ramfs_node *n=kmalloc(sizeof *n);
    if (n) memset(n,0,sizeof *n);
    return n;
}
static void ramfs_free_node_shallow(struct ramfs_node *n) { kfree(n); }
static void ramfs_set_create_owner(struct ramfs_node *n) { (void)n; }
static void ramfs_file_set_backing(struct fs_file *f,struct ramfs_node *n) { (void)f; (void)n; }
''' + ramfs[start:end] + r'''
int main(void) {
    for (int i=1;i<=4;i++) {
        allocations=live=0; fail_at=i;
        assert(!ramfs_create_memfd("icon") && live==0);
    }
    allocations=live=0; fail_at=0;
    struct fs_file *f=ramfs_create_memfd("icon"); assert(f && live==4);
    struct ramfs_file_handle *h=f->driver_private; struct ramfs_node *n=h->node;
    assert(!strcmp(f->path,"/memfd:icon (deleted)"));
    assert(f->refcount==1 && f->flags==2 && f->is_memfd && f->fs_private==ramfs_root);
    assert(n->nlink==0 && n->open_count==1 && n->is_memfd);
    kfree((void *)f->path); kfree(h); kfree(n); kfree(f); assert(!live);
    puts("PASS: anonymous memfd construction and failure cleanup");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-memfd-") as tmp:
    path = Path(tmp)
    for name, code in (("syscall", fixture), ("anon", anon)):
        src, binary = path / (name + ".c"), path / name
        src.write_text(code)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", str(src), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
