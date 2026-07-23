#pragma once

#include <stdint.h>
#include <idt.h>

/* Linux x86_64 native vsyscall page (legacy; glibc/Go still call it). */
#define VSYSCALL_PAGE     0xffffffffff600000ULL
#define VSYSCALL_PAGE_END 0xffffffffff601000ULL
#define VSYSCALL_GETTIMEOFDAY (VSYSCALL_PAGE + 0x000ULL)
#define VSYSCALL_TIME         (VSYSCALL_PAGE + 0x400ULL)
#define VSYSCALL_GETCPU       (VSYSCALL_PAGE + 0x800ULL)

/* If regs->rip is in the vsyscall page, emulate and fix up iret frame. */
int vsyscall_try_emulate(cpu_registers_t *regs);
