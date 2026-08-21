#ifndef SYSCALL_INTERNAL_H
#define SYSCALL_INTERNAL_H
#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <thread.h>
#include <fs.h>
#include <mmio.h>
#include <heap.h>
#include <syscall.h>
#include <gdt.h>
#include <paging.h>
#include <exec.h>
#include <pit.h>
#include <ext2.h>
#include <devfs.h>
#include <procfs.h>
#include <sysfs.h>
#include <rtc.h>
#include <spinlock.h>
#include <fat32.h>
#include <e1000.h>
#include <usb.h>
#include <usbdevfs.h>
#include <net_tcp.h>
#include <dns.h>
#include <mm.h>
#include <smp.h>
#include <loadavg.h>
#include <console.h>
#include <ramfs.h>
#include <dhcp.h>
#include <debug.h>
#include <klog.h>
#include <fbdev.h>
#include <power.h>
#include <iothread.h>
#include <stdio.h>
#include <user_vma.h>
#include <user_as.h>
#include <user_map.h>
#include <user_mmap.h>
#include <user_brk.h>
#include <user_mm.h>
#include "syscall_net.h"
#include "syscall_shm.h"
/* Pipe: kernel buffer + two fd ends. driver_private = pipe_t*, fs_private = 0 read / 1 write */
#define PIPE_BUF_SIZE 4096
typedef struct pipe {
    uint8_t *buf;
    size_t size;
    size_t head;   /* write position */
    size_t tail;   /* read position */
    int refcount;  /* 2 when both ends open */
    int reader_waiter_tid;
    int writer_waiter_tid;
    spinlock_t lock;
} pipe_t;

#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#define STAT_COPY_SIZE 144
#define NET_FRAME_BUF 2048
#define mark_user_identity_range_2m_sys user_map_mark_identity_2m
extern void kprintf(const char *fmt, ...);
extern uint64_t virt_to_phys(uint64_t va);
extern void syscall_entry64(void);
extern void user_thread_entry(void);
extern uint64_t syscall_user_rsp_saved;
extern uint64_t syscall_kernel_rsp0;
extern uint64_t syscall_kernel_rsp0_by_apic[256];
extern uint64_t syscall_user_return_rip;
extern uint64_t syscall_user_return_rax;
extern uint64_t syscall_exit_to_shell_flag;
enum { MSR_EFER=0xC0000080u, MSR_STAR=0xC0000081u, MSR_LSTAR=0xC0000082u, MSR_FMASK=0xC0000084u, MSR_FS_BASE=0xC0000100u };
static inline uint64_t msr_read_u64(uint32_t msr){uint32_t lo,hi;__asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(msr));return ((uint64_t)hi<<32)|lo;}
static inline void msr_write_u64(uint32_t msr,uint64_t v){uint32_t lo=(uint32_t)v,hi=(uint32_t)(v>>32);__asm__ volatile("wrmsr"::"a"(lo),"d"(hi),"c"(msr));}
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define EBADF 9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EFAULT 14
#define ENOTTY 25
#define EINVAL 22
#define ENOSYS 38
#define ERANGE 34
#define EMFILE 24
#define ENOEXEC 8
#define ENAMETOOLONG 36
#define EPIPE 32
#define EEXIST 17
#define EADDRINUSE 98
#define EACCES 13
#define EBUSY 16
#define ENOTDIR 20
#define EISDIR 21
#define ENOSPC 28
#define ENOTEMPTY 39
#define EIDRM 43
#define EAFNOSUPPORT 97
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define EDESTADDRREQ 89
#define ENETDOWN 100
#define ENETUNREACH 101
#define ENOTCONN 107
#define EISCONN 106
#define ENODEV 19
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define ESPIPE 29
#define ECONNRESET 104
#ifndef AXON_WGET_DNS_TRACE
#define AXON_WGET_DNS_TRACE 0
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
void debug_dump_kernel_syscall_stack(void);
void fork_child_return_entry(void);

int user_range_ok(const void *uaddr, size_t nbytes);
int user_recv_range_ok(const void *uaddr, size_t nbytes);
int copy_from_user_raw(void *kdst, const void *usrc, size_t n);
int copy_to_user_safe(void *uptr, const void *kptr, size_t n);
int copy_to_user_recv_safe(void *uptr, const void *kptr, size_t n);
size_t user_strnlen_bounded(const char *s, size_t max);
int user_read_u64(const void *uaddr, uint64_t *out);
int user_write_u64(void *uaddr, uint64_t value);
int user_write_u8(void *uaddr, uint8_t value);
char *copy_user_cstr(const char *u, size_t maxlen);
thread_t *uaccess_thread(void);
int uaccess_arm(thread_t *t, const void *uptr, size_t n, void *resume_rip, int recv_range);
void uaccess_clear(thread_t *t);
void rebuild_syscall_frame(thread_t *t);
void exit_group_reap_peer_threads(thread_t *cur);
void vfork_restore_parent_stack(thread_t *child);
void vfork_restore_parent_memory(thread_t *child);
void thread_set_pending_signal(thread_t *t, int signum);
void *copy_from_user_safe(const void *uptr, size_t count, size_t max, size_t *out_copied);
ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur);
ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur);
uintptr_t user_stack_top_for_tid_like_exec(uint64_t tid);
void fork_tls_layout_for_tid(uint64_t tid, uintptr_t stack_top, uintptr_t *tls_region, uintptr_t *fs_base, uintptr_t *pthread_fake);
uint64_t fork_reloc_user_ptr(uint64_t val, uintptr_t slice_lo, uintptr_t slice_hi, uintptr_t child_slice_base, uintptr_t slot_lo, uintptr_t slot_hi, uintptr_t child_slot_base);
void fork_reloc_range_u64(uintptr_t base, uintptr_t nbytes, uintptr_t slice_lo, uintptr_t slice_hi, uintptr_t child_slice_base, uintptr_t slot_lo, uintptr_t slot_hi, uintptr_t child_slot_base);
int fork_copy_parent_tls(uintptr_t child_tls, uintptr_t parent_tls, mm_t *child_mm, mm_t *parent_mm);
void fork_seed_glibc_tls(uintptr_t tls_region, uintptr_t fs_base, uintptr_t pthread_fake);
int fork_should_keep_parent_fs(uint64_t parent_fs_base);
void fork_stop_child(thread_t *child);
void fork_dbg(thread_t *cur, int step, const char *msg, unsigned long long a, unsigned long long b, unsigned long long c);
void clone3_dbg(thread_t *cur, int step, const char *msg, unsigned long long a, unsigned long long b, unsigned long long c);
void sysv_shm_detach_all_for_tid(uint64_t tid);
int kernel_resolve_full(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be);
int net_stack_init(void);
extern net_state_t g_net;
uint64_t ret_err(int e);
uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);
#endif
