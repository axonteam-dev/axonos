#pragma once

#include <stdint.h>
#include <thread.h>

/* mmap(addr,len,prot,flags,fd,off) — returns map address or negative errno encoding. */
uint64_t user_syscall_mmap(thread_t *cur, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6);

uint64_t user_syscall_munmap(uint64_t a1, uint64_t a2);
uint64_t user_syscall_mprotect(uint64_t a1, uint64_t a2, uint64_t a3);
/* Linux x86_64 #25: mremap(old, old_len, new_len, flags, [new_addr]). */
uint64_t user_syscall_mremap(thread_t *cur, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5);
/* Linux x86_64 #26: msync(addr, len, flags). */
uint64_t user_syscall_msync(thread_t *cur, uint64_t a1, uint64_t a2, uint64_t a3);
