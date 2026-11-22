#!/usr/bin/env python3
"""Exercise the actual SquashFS file reader and count cache-hit copies."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'fs/virt/squashfs.c').read_text()
def function(name):
    start = source.index('static int ' + name + '(')
    return source[start:source.index('\n}\n', start) + 3]

program = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define DATA_CACHE_SLOTS 32
#define SQUASHFS_COMPRESSED_BIT_BLOCK (1u << 24)
#define SQUASHFS_INVALID_FRAG 0xffffffffu
typedef int spinlock_t;
typedef int mm_dm_ctx_t;
static int direct, locked, allocations;
static size_t copied;
static mm_dm_ctx_t mm_enter_direct_map(void) { int old=direct; direct=1; return old; }
static void mm_leave_direct_map(mm_dm_ctx_t old) { direct=old; }
static void acquire(spinlock_t *l) { assert(direct && !locked); *l=locked=1; }
static void release(spinlock_t *l) { assert(locked); *l=locked=0; }
static void *track(void *d,const void *s,size_t n) { copied+=n; return memcpy(d,s,n); }
#define memcpy track
static void *kmalloc(size_t n) { allocations++; return malloc(n); }
static void kfree(void *p) { free(p); }
#define klogprintf(...) ((void)0)
struct data_cache_ent { uint64_t abs_pos; uint32_t comp_size; uint8_t *data; size_t len; int valid; };
struct squashfs_sb { const uint8_t *image; size_t size; uint32_t block_size; struct data_cache_ent data_cache[32]; spinlock_t data_cache_lock; };
struct squashfs_inode_info { uint32_t inode_number,block_count,fragment,frag_offset; uint64_t file_size,start_block,block_list_abs; uint32_t *block_sizes; uint64_t *block_offsets; };
struct squashfs_fragment_entry { uint64_t start_block; uint32_t size, unused; };
''' + function('sq_in_range') + function('sq_cached_slice') + r'''
static int sq_read_blocklist_size(struct squashfs_sb *s,const struct squashfs_inode_info *i,uint32_t n,uint32_t *o) { (void)s;(void)i;(void)n;(void)o; return -1; }
static int sq_read_data_block(struct squashfs_sb *s,uint64_t p,uint32_t f,void *b,size_t c,size_t *n,size_t e) { (void)s;(void)p;(void)f;(void)b;(void)c;(void)n;(void)e; return -1; }
static int sq_get_fragment_entry(struct squashfs_sb *s,uint32_t f,struct squashfs_fragment_entry *e) { (void)s;(void)f; e->start_block=1; e->size=7; return 0; }
''' + function('sq_file_read') + r'''
int main(void) {
    uint8_t *data=malloc(131072), image[16]={0}, out[4096];
    struct squashfs_sb s={.image=image,.size=sizeof(image),.block_size=131072};
    for (size_t i=0;i<131072;i++) data[i]=(uint8_t)(i*7);
    s.data_cache[0]=(struct data_cache_ent){.abs_pos=1,.comp_size=7,.data=data,.len=131072,.valid=1};
    uint32_t sizes[]={7}; uint64_t offsets[]={1};
    struct squashfs_inode_info ino={.file_size=131072,.block_count=1,.fragment=SQUASHFS_INVALID_FRAG,.block_sizes=sizes,.block_offsets=offsets};
    ssize_t n;
    for (size_t i=0;i<32;i++) { assert(!sq_file_read(&s,&ino,out,4096,i*4096,&n) && n==4096); assert(!memcmp(out,data+i*4096,4096)); }
    assert(copied==2*131072 && allocations==0 && !direct && !locked);
    assert(!sq_file_read(&s,&ino,out,4096,131070,&n) && n==2 && !memcmp(out,data+131070,2));
    assert(!sq_file_read(&s,&ino,out,4096,131072,&n) && n==0);
    ino.block_count=0; ino.fragment=0; ino.frag_offset=123; ino.file_size=19;
    assert(!sq_file_read(&s,&ino,out,4096,4,&n) && n==15 && !memcmp(out,data+127,15));
    free(data); puts("PASS: cached 4KiB reads copy 8KiB each without block allocations; EOF and fragment verified");
}
'''
with tempfile.TemporaryDirectory(prefix='axon-sq-data-') as tmp:
    c = Path(tmp) / 'test.c'
    exe = Path(tmp) / 'test'
    c.write_text(program)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
