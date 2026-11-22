#!/usr/bin/env python3
"""Exercise the VFS inotify events consumed by systemd's network monitor."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("#define INOTIFY_QUEUE_DEPTH")
end = source.index("/* Linux timerfd(2)", start)
inotify = source[start:end]
vfs = (root / "fs/fs.c").read_text()
assert "inotify_notify_move(old_normalized, new_normalized, is_dir)" in vfs
assert "inotify_notify_entry(normalized, 0x00000200u" in vfs
assert "inotify_ready((inotify_state_k *)f->driver_private)" in source
assert "inotify_dequeue((inotify_state_k *)f->driver_private" in source
assert "syscall_path_access(cur, path, 4u)" in source

program = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
struct stat { dev_t st_dev; ino_t st_ino; };
typedef struct { void *process; } thread_t;
static thread_t current;
#define NS_TYPE_MNT 0
static thread_t *thread_get_current_user(void) { return &current; }
static uint32_t ns_inum(void *process, int type) { (void)process; (void)type; return 1; }
static int vfs_stat(const char *path, struct stat *st) {
    st->st_dev = 1;
    st->st_ino = (strcmp(path, "/run/systemd/netif/links") == 0 ||
                  strcmp(path, "/alias") == 0) ? 12 :
                 strcmp(path, "/other") == 0 ? 13 : 14;
    return 0;
}
typedef int spinlock_t;
static void acquire_irqsave(spinlock_t *lock, unsigned long *flags) { (void)lock; *flags = 0; }
static void release_irqrestore(spinlock_t *lock, unsigned long flags) { (void)lock; (void)flags; }
static void *kmalloc(size_t n) { return malloc(n); }
static void kfree(void *p) { free(p); }
enum { FS_TYPE_INOTIFY = 42 };
struct fs_file { int type; void *driver_private; const char *path; };
''' + inotify + r'''
static inotify_state_k *new_state(void) {
    inotify_state_k *s = calloc(1, sizeof(*s));
    assert(s);
    s->next_wd = 1;
    inotify_register(s);
    return s;
}
static void destroy(inotify_state_k *s) {
    struct fs_file *f = calloc(1, sizeof(*f));
    assert(f);
    f->type = FS_TYPE_INOTIFY;
    f->driver_private = s;
    inotify_fs_file_destroy(f);
}
int main(void) {
    inotify_state_k *a = new_state(), *b = new_state();
    struct stat links = {1, 12}, other = {1, 13};
    int wd = inotify_add(a, "/run/systemd/netif/links",
                         IN_MOVED_FROM_K | IN_MOVED_TO_K | IN_DELETE_K, &links, 1);
    assert(wd == 1);
    assert(inotify_add(a, "/run/systemd/netif/links", IN_MOVED_TO_K | 0x10000000u, &links, 1) == -EEXIST);
    assert(inotify_add(b, "/other", IN_MOVED_TO_K, &other, 1) == 1);
    assert(!inotify_ready(a) && !inotify_ready(b));

    /* Matching is on the watched directory, not an arbitrary path prefix. */
    inotify_notify_entry("/run/systemd/netif/links-other/2", IN_MOVED_TO_K, 4);
    assert(!inotify_ready(a));
    inotify_notify_entry("/alias/2", IN_MOVED_TO_K, 4);
    unsigned char data[4096];
    assert(inotify_dequeue(a, data, sizeof(data)) == 20);
    assert(((inotify_event_k *)data)->mask == IN_MOVED_TO_K);
    inotify_notify_move("/run/systemd/netif/links/.tmp",
                        "/run/systemd/netif/links/2", 0);
    assert(inotify_ready(a) && !inotify_ready(b));
    assert(inotify_dequeue(a, data, 16) == -EINVAL);
    ssize_t n = inotify_dequeue(a, data, sizeof(data));
    assert(n == 44);
    inotify_event_k *from = (inotify_event_k *)data;
    inotify_event_k *to = (inotify_event_k *)(data + 16 + from->len);
    assert(from->wd == wd && from->mask == IN_MOVED_FROM_K && !strcmp(from->name, ".tmp"));
    assert(to->wd == wd && to->mask == IN_MOVED_TO_K && !strcmp(to->name, "2"));
    assert(from->cookie && from->cookie == to->cookie && !inotify_ready(a));

    /* Repeated identical unread events coalesce, as on Linux. */
    inotify_notify_entry("/run/systemd/netif/links/2", IN_DELETE_K, 0);
    inotify_notify_entry("/run/systemd/netif/links/2", IN_DELETE_K, 0);
    assert(inotify_dequeue(a, data, sizeof(data)) == 20);
    assert(((inotify_event_k *)data)->mask == IN_DELETE_K);
    assert(!inotify_ready(a));

    /* The queue reports overflow instead of silently dropping all evidence. */
    for (int i = 0; i < 40; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/run/systemd/netif/links/%03d", i);
        inotify_notify_entry(path, IN_MOVED_TO_K, 0);
    }
    n = inotify_dequeue(a, data, sizeof(data));
    int events = 0, overflow = 0;
    for (ssize_t off = 0; off < n; ) {
        inotify_event_k *e = (inotify_event_k *)(data + off);
        if (e->mask == IN_Q_OVERFLOW_K) { assert(e->wd == -1); overflow++; }
        events++;
        off += 16 + e->len;
    }
    assert(events == INOTIFY_QUEUE_DEPTH && overflow == 1 && !inotify_ready(a));
    assert(inotify_remove(a, wd) == 0);
    assert(inotify_dequeue(a, data, sizeof(data)) == 16);
    assert(((inotify_event_k *)data)->mask == IN_IGNORED_K);
    assert(inotify_remove(a, wd) == -EINVAL);
    destroy(a);
    destroy(b);
    assert(!inotify_states);
    puts("PASS: inotify network-directory moves, delete, queue and poll readiness");
}
'''

with tempfile.TemporaryDirectory(prefix="axonos-inotify-") as tmp:
    path = Path(tmp)
    (path / "test.c").write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(path / "test.c"), "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
