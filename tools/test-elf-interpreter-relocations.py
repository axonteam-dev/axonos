#!/usr/bin/env python3
"""Compile actual ELF relocation dispatch: PT_INTERP tables belong to ld.so."""
from pathlib import Path
import struct
import subprocess
import tempfile

root=Path(__file__).resolve().parents[1]
source=(root/"core/elf.c").read_text()
start=source.index("static int elf_apply_rela_relative(")
body=source[start:source.index("\n}\n",start)+3]
program=r'''
#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define ELF_PT_INTERP PT_INTERP
#define ELF_PT_DYNAMIC PT_DYNAMIC
#define ELF_DT_NULL DT_NULL
#define ELF_DT_RELA DT_RELA
#define ELF_DT_RELASZ DT_RELASZ
#define ELF_DT_RELAENT DT_RELAENT
#define ELF_SHT_RELA SHT_RELA
#define kmalloc malloc
#define kfree free
#define d_un d_un.d_val
typedef struct { int unused; } mm_t;
typedef struct { mm_t *mm; } thread_t;
struct fs_file { int unused; };
static int reads, applies, thread_lookups;
static Elf64_Dyn dynamics[4];
static thread_t *elf_bprm_thread(void) { thread_lookups++; return NULL; }
static int elf_needs_private_user_pages(thread_t *t) { (void)t; return 0; }
static void elf_text_range(const Elf64_Phdr *p,int n,uint64_t b,uint64_t *lo,uint64_t *hi) {
    (void)p;(void)n;(void)b;*lo=0;*hi=0;
}
static ssize_t fs_read(struct fs_file *f,void *buf,size_t n,size_t off) {
    (void)f;(void)off;reads++;
    if(n==sizeof(dynamics)) memcpy(buf,dynamics,n);
    else memset(buf,0,n);
    return n;
}
static int elf_va_to_file_off(const Elf64_Phdr *p,int n,uint64_t b,uint64_t va,uint64_t *off) {
    (void)p;(void)n;(void)b;(void)va;*off=0;return 0;
}
static int elf_apply_rela_buffer(mm_t *m,uint64_t b,const Elf64_Rela *r,size_t n,size_t stride,uint64_t lo,uint64_t hi) {
    (void)m;(void)b;(void)r;(void)n;(void)stride;(void)lo;(void)hi;applies++;return 0;
}
'''+body+r'''
int main(void) {
    struct fs_file f={0};Elf64_Ehdr eh={.e_type=ET_DYN};
    Elf64_Phdr ph[2]={{.p_type=PT_DYNAMIC,.p_filesz=sizeof(dynamics)}, {.p_type=PT_INTERP}};
    dynamics[0].d_tag=DT_RELA; dynamics[0].d_un=0xd80;
    dynamics[1].d_tag=DT_RELASZ; dynamics[1].d_un=10302864; /* exact Alpine dockerd size */
    dynamics[2].d_tag=DT_RELAENT; dynamics[2].d_un=sizeof(Elf64_Rela);
    assert(elf_apply_rela_relative(&f,0x400000,&eh,ph,2)==0);
    assert(!reads&&!applies&&!thread_lookups); /* don't parse, allocate or relocate ld.so's tables */
    eh.e_type=ET_EXEC; /* interpreted non-PIE executables have the same ownership */
    assert(elf_apply_rela_relative(&f,0,&eh,ph,2)==0&&!reads&&!applies);
    eh.e_type=ET_DYN;
    ph[1].p_type=PT_NULL;
    assert(elf_apply_rela_relative(&f,0,&eh,ph,2)==-1&&reads==1&&!applies); /* static bounds unchanged */
    reads=0;dynamics[1].d_un=sizeof(Elf64_Rela);
    assert(elf_apply_rela_relative(&f,0,&eh,ph,2)==0&&reads==2&&applies==1);
    puts("PASS: large PT_INTERP RELA/IFUNC dispatch stays with ld.so; static relocation path retained");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-elf-interp-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                    "-fsanitize=undefined",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
