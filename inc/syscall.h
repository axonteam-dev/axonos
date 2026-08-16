#pragma once

#include <stdint.h>

typedef struct syscall_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax, rsp;
} syscall_frame_t;
#include <idt.h>

/* Linux x86_64 syscall numbers used by the kernel ABI. */
#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_stat    4
#define SYS_fstat   5
#define SYS_lstat   6
#define SYS_poll    7
#define SYS_lseek   8
#define SYS_mmap    9
#define SYS_mprotect 10
#define SYS_munmap  11
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigsuspend 130
#define SYS_ioctl   16
#define SYS_readv   19
#define SYS_writev  20
#define SYS_dup2    33
#define SYS_getrandom 318
#define SYS_clock_gettime 228
#define SYS_uname   63
#define SYS_getcwd  79
#define SYS_chdir   80
#define SYS_fchdir  81
#define SYS_readlink 89
#define SYS_readlinkat 267
#define SYS_set_tid_address 218
#define SYS_prlimit64 302
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_rseq 334
#define SYS_futex 202
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_sigaltstack 131
#define SYS_ioctl   16
#define SYS_getdents64 217
#define SYS_getdents 78
#define SYS_getpid  39
#define SYS_getppid 110
#define SYS_getuid  102
#define SYS_getgid  104
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_capget  125
#define SYS_capset  126
#define SYS_setuid  105
#define SYS_setgid  106
#define SYS_setreuid 113
#define SYS_setregid 114
#define SYS_getgroups 115
#define SYS_setgroups 116
#define SYS_setsid  112
#define SYS_kill    62
#define SYS_syslog  103
#define SYS_getpgrp 111
#define SYS_setpgid 109
#define SYS_gettid  186
#define SYS_mmap    9
#define SYS_ftruncate 77
#define SYS_munmap  11
#define SYS_madvise 28
#define SYS_mincore 27
#define SYS_shmget  29
#define SYS_shmat   30
#define SYS_shmctl  31
#define SYS_brk     12
#define SYS_pipe    22
#define SYS_eventfd 284
#define SYS_eventfd2 290
#define SYS_dup3    292
#define SYS_pipe2   293
#define SYS_arch_prctl 158
#define SYS_prctl 157
#define SYS_exit    60
#define SYS_execve  59
#define SYS_vfork   58
#define SYS_fork    57
#define SYS_clone   56
#define SYS_clone3  435
#define SYS_add_key 248
#define SYS_request_key 249
#define SYS_keyctl  250
#define SYS_wait4   61
#define SYS_exit_group 231
#define SYS_openat  257
#define SYS_newfstatat 262
#define SYS_statx 332
/* Linux x86_64 extended attributes */
#define SYS_setxattr 188
#define SYS_lsetxattr 189
#define SYS_fsetxattr 190
#define SYS_getxattr 191
#define SYS_lgetxattr 192
#define SYS_fgetxattr 193
#define SYS_listxattr 194
#define SYS_llistxattr 195
#define SYS_flistxattr 196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#define SYS_tgkill  234
#define SYS_sendfile 40
#define SYS_shmdt   67
#define SYS_mount   165
#define SYS_umount2 166
#define SYS_rt_sigtimedwait 128
#define SYS_clock_nanosleep 230
#define SYS_select  23
#define SYS_sched_yield 24
#define SYS_socket  41
#define SYS_connect 42
#define SYS_accept  43
#define SYS_sendto  44
#define SYS_recvfrom 45
#define SYS_sendmsg 46
#define SYS_recvmsg 47
#define SYS_shutdown 48
#define SYS_bind    49
#define SYS_listen  50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_getsockopt 55
#define SYS_accept4 288
#define SYS_epoll_create 213
#define SYS_epoll_ctl_old 214
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_epoll_pwait 281
#define SYS_epoll_create1 291
#define SYS_epoll_pwait2 441
#define SYS_getrlimit 97
#define SYS_setrlimit 160
#define SYS_sysinfo  99
#define SYS_sched_getaffinity 204
#define SYS_sched_setaffinity 203
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_getpriority       140
#define SYS_setpriority       141
#define SYS_nanosleep 35
/* Linux x86_64: gettimeofday = 96, reboot = 169. */
#define SYS_gettimeofday 96
#define SYS_time 201
#define SYS_getcpu 309
#define SYS_reboot 169
#define SYS_access 21
#define SYS_link   86
#define SYS_symlink 88
#define SYS_symlinkat 266
#define SYS_mkdir  83
#define SYS_rmdir  84
#define SYS_mknod  133
#define SYS_mknodat 259
#define SYS_rename 82
#define SYS_umask  95
#define SYS_chmod  90
#define SYS_chown  92
#define SYS_utimensat 280
/* Linux x86_64: preadv/pwritev */
#define SYS_preadv 295
#define SYS_pwritev 296
#define SYS_pwrite64 18
/* Linux x86_64: I/O privilege (Xorg xf86EnableIOPorts). */
#define SYS_iopl   172
#define SYS_ioperm 173

/* AxonOS: resolve hostname via DNS, returns IPv4 in network byte order */
#define SYS_resolve 1000

/* initialize syscall subsystem (register handler) */
void syscall_init(void);
/* Optional in-kernel DHCP helper (prefer userspace udhcpc). */
int syscall_net_preinit(void);

/* ISR-compatible handler (called by IDT dispatcher) */
void isr_syscall(cpu_registers_t* regs);

/* Common syscall dispatcher used by both int0x80 and SYSCALL entry. */
uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);
/* Refresh saved_user_* from live per-CPU syscall stack frame (before schedule in syscall). */
void syscall_frame_refresh(thread_t *t);
/* Run deferred fork child GPR refresh after parent syscall (before iretq unblock). */
void syscall_deferred_unblocks(void);
/* Linux ordering: unblock fork child immediately before parent SYSCALL iretq. */
/* Returns 1 when a child became runnable during this call. */
int syscall_publish_deferred_fork_child(void);
void syscall_restore_user_fs_before_iretq(void);
/* Linux wait_for_vfork_done — after syscall_do, before iretq. */
uint64_t syscall_maybe_vfork_wait(uint64_t parent_ret);
/* Point this CPU's syscall_entry64 stack at t's private kstack (or global default). */
void syscall_bind_kstack_for_thread(thread_t *t);
/* Linux fork child: iretq from cloned syscall GPR frame with rax=0. */
__attribute__((noreturn)) void syscall_child_return_from_frame(uint64_t *frame);

/* Control flag and helper for syscall_entry64. */
extern uint64_t syscall_exit_to_shell_flag;
__attribute__((noreturn)) void syscall_return_to_shell(void);
/* Terminate current user thread after fatal trap (GPF etc.); schedule parent/shell. */
void syscall_user_fatal_exit(int signo);
/* Deliver pending user signal before SYSCALL iretq (patches syscall frame). */
int maybe_deliver_pending_signal(uint64_t syscall_ret);
/* Deliver pending user signal before interrupt/exception iretq (patches regs). */
int maybe_deliver_pending_signal_iretq(cpu_registers_t *regs);
/* vfork child exec (or fatal exit): restore parent snapshot and unblock blocked parent. */


