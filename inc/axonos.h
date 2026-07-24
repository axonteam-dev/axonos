#pragma once

#include <stdint.h>

#define OS_NAME "axonOS"
#define OS_VERSION "4.0.1"
#define OS_PREFIX "stable.b1"
#define OS_AUTHORS "Axon Team"

/* Syscall globals (defined in syscall64/syscall.c). */
extern uint64_t syscall_kernel_rsp0;
extern uint64_t syscall_user_rsp_saved;
extern uint64_t syscall_user_return_rip;
extern uint64_t syscall_user_return_rax;
void syscall_set_user_brk(uintptr_t base);

int fault_try_grow_user_heap(uint64_t cr2);
int fault_try_mmap_lazy_anon(uint64_t cr2);
int fault_try_user_vma_nonpresent(uint64_t cr2, uint64_t err);
int syscall_try_handle_uaccess_fault(uint64_t fault_addr, uint64_t *resume_rip_out);

void kernel_sysfs_populate_default(void);
void syscall_net_ensure_resolv(void);
