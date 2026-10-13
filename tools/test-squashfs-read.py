#!/usr/bin/env python3
"""Read the actual initfs using the kernel SquashFS and miniz code on the host.

Mock only the allocator, direct-map guard and unused VFS types. In particular,
the decompressor asserts that image reads happen under the kernel root. No VM
or external SquashFS utility is used.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel-objects", type=Path,
                    help="link actual miniz/string/heap objects from this build directory")
args = parser.parse_args()
image = root / "iso/boot/initfs.sfs"
if not image.is_file():
    raise SystemExit("SKIP: local initfs.sfs is unavailable")

body = (root / "fs/virt/squashfs.c").read_text().split("static int sq_build_dir_blob(")[0]
body = "\n".join(line for line in body.splitlines() if not line.startswith("#include"))
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <mm.h>
struct fs_driver { int unused; };
struct fs_driver_ops { int unused; };
void *kmalloc(size_t n) { return malloc(n); }
void kfree(void *p) { free(p); }
void *krealloc(void *p, size_t n) { return realloc(p, n); }
void klogprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}
static int current_root = 1, guard_depth;
mm_dm_ctx_t mm_enter_direct_map(void) {
    mm_dm_ctx_t ctx = {current_root};
    current_root = 0; guard_depth++; return ctx;
}
void mm_leave_direct_map(mm_dm_ctx_t ctx) {
    assert(current_root == 0 && guard_depth > 0);
    guard_depth--; current_root = ctx.root;
}
extern int host_zlib_inflate(void *, size_t, size_t *, const void *, size_t);
int zlib_inflate(void *out, size_t cap, size_t *got, const void *in, size_t n) {
    assert(current_root == 0 && guard_depth > 0);
    return host_zlib_inflate(out, cap, got, in, n);
}
'''
tests = r'''
static void read_pages(struct squashfs_sb *s, const char *path) {
    struct squashfs_inode_info ino;
    int rc = sq_path_to_inode(s, path, &ino);
    assert(rc == 0);
    if (ino.type != SQUASHFS_REG_TYPE && ino.type != SQUASHFS_LREG_TYPE) {
        sq_inode_info_free(&ino); return;
    }
    uint8_t out[4096]; ssize_t n = 0;
    assert(sq_input_crc32((const uint8_t *)"123456789", 9) == 0xcbf43926u);
    /* Start at the faulting libc offset with cold data caches. */
    if (strstr(path, "libc.so.6") && ino.file_size > 0xcb000) {
        uint32_t size = ino.block_sizes[6] & ~SQUASHFS_COMPRESSED_BIT_BLOCK;
        uint64_t pos = ino.block_offsets[6];
        assert(sq_in_range(s, pos, size));
        printf("libc block6: pos=0x%llx size=%u crc=%08x\n",
               (unsigned long long)pos, size, sq_input_crc32(s->image + pos, size));
        assert(sq_file_read(s, &ino, out, sizeof(out), 0xca000, &n) == 0);
        assert(n == sizeof(out));
    }
    for (size_t off = 0; off < ino.file_size; off += sizeof(out)) {
        assert(sq_file_read(s, &ino, out, sizeof(out), off, &n) == 0);
        size_t remaining = ino.file_size - off;
        assert(n == (ssize_t)(remaining < sizeof(out) ? remaining : sizeof(out)));
        assert(current_root == 1 && guard_depth == 0);
    }
    assert(sq_file_read(s, &ino, out, sizeof(out), ino.file_size, &n) == 0 && n == 0);
    printf("PASS: kernel SquashFS/miniz reads %s (%llu bytes)\n", path,
           (unsigned long long)ino.file_size);
    sq_inode_info_free(&ino);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb"); assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f); assert(size > 96); rewind(f);
    uint8_t *image = malloc((size_t)size); assert(image);
    assert(fread(image, 1, (size_t)size, f) == (size_t)size); fclose(f);
    struct squashfs_sb *s = calloc(1, sizeof(*s)); assert(s);
    s->image = image; s->size = (size_t)size;
    memcpy(&s->sb, image, sizeof(s->sb)); s->block_size = s->sb.block_size;
    assert(s->sb.s_magic == 0x73717368 && s->sb.compression == 1);
    assert(sq_load_fragment_table(s) == 0);
    read_pages(s, "/usr/lib/x86_64-linux-gnu/libc.so.6");
    read_pages(s, "/usr/lib/systemd/systemd");
    read_pages(s, "/usr/sbin/openrc");
    read_pages(s, "/lib/librc.so.1");
    read_pages(s, "/lib/rc/sh/gendepends.sh");
    /* Malformed block bounds must fail and still restore the caller root. */
    uint8_t out[8]; size_t got;
    assert(sq_read_data_block(s, s->size, 9, out, sizeof(out), &got, 0) == -1);
    assert(current_root == 1 && guard_depth == 0);
    for (int i = 0; i < DATA_CACHE_SLOTS; i++) kfree(s->data_cache[i].data);
    kfree(s->frag_index); free(s); free(image);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="axon-squashfs-") as tmp:
    temp = Path(tmp)
    (temp / "heap.h").write_text("#include <stddef.h>\nvoid *kmalloc(size_t);\n"
                                 "void kfree(void *);\nvoid *krealloc(void *, size_t);\n")
    (temp / "mm.h").write_text("typedef struct { int root; } mm_dm_ctx_t;\n"
                               "mm_dm_ctx_t mm_enter_direct_map(void);\n"
                               "void mm_leave_direct_map(mm_dm_ctx_t);\n")
    (temp / "klog.h").write_text("void klogprintf(const char *, ...);\n")
    source = temp / "test.c"
    program = prefix + body + tests
    flags = ["cc", "-std=gnu11", "-O0", "-g", "-I" + tmp, "-I" + str(root / "inc")]
    inflate = temp / "inflate.o"
    libraries = [str(inflate)]
    if args.kernel_objects:
        objects = args.kernel_objects.resolve()
        subprocess.run(["objcopy", "--redefine-sym", "zlib_inflate=host_zlib_inflate",
                        str(objects / "fs/virt/zlib_inflate.c.o"), str(inflate)], check=True)
        libraries += [str(objects / "libc/string.c.o"), str(objects / "mem/heap.c.o")]
        flags += ["-no-pie", "-fno-builtin"]
        for line in ("void *kmalloc(size_t n) { return malloc(n); }",
                     "void kfree(void *p) { free(p); }",
                     "void *krealloc(void *p, size_t n) { return realloc(p, n); }"):
            program = program.replace(line, "")
        program = program.replace("struct fs_driver { int unused; };", r'''
#include <spinlock.h>
#include <heap.h>
extern void heap_init(uintptr_t, size_t);
void acquire_irqsave(spinlock_t *lock, unsigned long *flags) {
    assert(!lock->lock); lock->lock = 1; *flags = 0;
}
void release_irqrestore(spinlock_t *lock, unsigned long flags) {
    (void)flags; assert(lock->lock); lock->lock = 0;
}
void kprintf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}
struct fs_driver { int unused; };
''')
        program = program.replace("assert(argc == 2);", "assert(argc == 2);\n"
                                  "    void *arena = malloc(256u << 20); assert(arena);\n"
                                  "    heap_init((uintptr_t)arena, 256u << 20);")
    else:
        subprocess.run(flags + ["-Dzlib_inflate=host_zlib_inflate", "-c",
                        str(root / "fs/virt/zlib_inflate.c"), "-o", str(inflate)], check=True)
    source.write_text(program)
    binary = temp / "test"
    subprocess.run(flags + [str(source)] + libraries + ["-o", str(binary)], check=True)
    subprocess.run([str(binary), str(image)], check=True)
