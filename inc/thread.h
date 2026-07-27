#ifndef THREAD_H
#define THREAD_H
#include <stdint.h>
#include <context.h>
#include <fs.h>

typedef struct mm_struct mm_t;
typedef struct process process_t;
typedef struct syscall_frame syscall_frame_t;

typedef enum {
        THREAD_READY,
        THREAD_RUNNING,
        THREAD_BLOCKED,
        THREAD_TERMINATED,
        THREAD_SLEEPING
} thread_state_t;

#define THREAD_MAX_FD 1024

typedef struct thread {
        context_t context;
        uint64_t kernel_stack;         // kernel mode stack
        uint64_t user_stack;           // user mode stack
        uint64_t user_stack_base;      // low address of active user stack region (if known)
        uint64_t user_stack_limit;     // high address (exclusive) of active user stack region
        uint64_t user_rip;             // user mode rip
        uint64_t user_fs_base;         // TLS base for userspace
        uint64_t user_interp_base;     // AT_BASE (ld-linux-x86-64.so.2 load address)
        uint8_t ring;                  // user mode ring
        thread_state_t state;
        struct thread* next;
        uint64_t tid;
        process_t *process;             /* Linux process identity/lifecycle owner */
        char name[32];                 // thread name (urmomissofaturmomissofaturmomiss)
        /* Process start tick for /proc/<pid>/stat starttime. */
        uint64_t start_ticks;
        /* Accumulated USER_HZ (100Hz) runtime for /proc/<pid>/stat utime/stime. */
        uint64_t utime_ticks;
        uint64_t stime_ticks;

        /* POSIX-ish job control identifiers */
        int pgid;                      // process group id
        int sid;                       // session id
        uint32_t sleep_until;          // sleep until (in timer ticks)
        uint64_t clear_child_tid;      // clear child tid
        struct fs_file* fds[THREAD_MAX_FD];

        /* current working directory for userland syscalls (POSIX-like).
           For kernel threads this is ignored; for user processes it's used to resolve relative paths. */
        char cwd[256];
        /* POSIX credentials (real, effective, saved for setuid) */
        uid_t uid;
        uid_t euid;
        uid_t suid;
        /* Linux iopl(2) level 0..3 (CAP_SYS_RAWIO); used by Xorg xf86EnableIOPorts. */
        uint8_t iopl;
        gid_t gid;
        gid_t egid;
        gid_t sgid;
#ifndef AXON_NGROUPS_MAX
#define AXON_NGROUPS_MAX 32
#endif
        int ngroups;
        gid_t groups[AXON_NGROUPS_MAX];
        /* file mode creation mask (umask) for mkdir/open */
        unsigned int umask;

        /* attached tty index or -1 */
        int attached_tty;
        
        /* per-thread brk state (heap) */
        uintptr_t user_brk_base;
        uintptr_t user_brk_cur;
        uintptr_t user_mmap_next;
        /* High-water end of anon/file-private mmap (max addr+len). Fork uses this — not
         * mmap_next, which is only a bump cursor and can sit at 32MiB before any map. */
        uintptr_t user_mmap_hi;
        /* exec trampoline support: when set, kernel will patch the saved syscall return
           frame so that on syscall return the thread resumes at exec_trampoline_rip/rsp
           with RAX=exec_trampoline_rax. Used to implement vfork-by-reusing-current-thread. */
        int exec_trampoline_flag;
        uint64_t exec_trampoline_rip;
        uint64_t exec_trampoline_rsp;
        uint64_t exec_trampoline_rax;

        /* pointer to rseq area in userspace (for minimal rseq support) */
        void *rseq_ptr;

        /* parent thread id (for wait/waitpid) */
        int parent_tid;
        
        /* saved syscall return site for current syscall (per-thread) */
        uint64_t saved_user_rip;
        uint64_t saved_user_rsp;

        /* saved user register snapshot captured at syscall entry (per-thread).
           Needed for vfork trampoline without relying on global, non-reentrant state. */
        uint64_t saved_user_rbx;
        uint64_t saved_user_rbp;
        uint64_t saved_user_r12;
        uint64_t saved_user_r13;
        uint64_t saved_user_r14;
        uint64_t saved_user_r15;
        uint64_t saved_user_rdi;
        uint64_t saved_user_rsi;
        uint64_t saved_user_rdx;
        uint64_t saved_user_r8;
        uint64_t saved_user_r9;
        uint64_t saved_user_r10;
        uint64_t saved_user_r11;
        uint64_t saved_user_rcx;

        /* pointer to saved syscall frame (kmalloc copy; safe across thread_schedule). */
        uint64_t *saved_syscall_frame;
        syscall_frame_t *active_syscall_frame;
        /* Private syscall stack (syscall_entry64 rsp); avoids sharing per-CPU stack. */
        uint64_t syscall_kstack_top;
        void *syscall_kstack_raw;
        uint64_t *syscall_frame_kbuf;
        /* Syscall args copied here at entry — survive thread_schedule() on shared per-CPU syscall stack. */
        uint64_t sc_a1;
        uint64_t sc_a2;
        uint64_t sc_a3;
        uint64_t sc_a4;
        uint64_t sc_a5;
        uint64_t sc_a6;
        /* active kernel-side access to userspace */
        uintptr_t uaccess_begin;
        uintptr_t uaccess_end;
        uint64_t uaccess_resume_rip;
        int uaccess_active;
        /* pending signal bitmask (1-based signal numbers, bit0 unused) */
        uint64_t pending_signals;
        /* per-thread signal mask (blocked signals); used by rt_sigprocmask and signal delivery */
        uint64_t saved_sig_mask;
        /* Linux sigaltstack(2) — Go runtime.minit queries this at startup. */
        uint64_t sas_ss_sp;
        uint64_t sas_ss_size;
        int sas_ss_flags; /* SS_DISABLE=2 when unset */
        /* if non-negative, tid of thread waiting for this child (wait/waitpid) */
        int waiter_tid;
        /* fork/clone3: unblock child after parent syscall returns (avoid clobbering per-CPU syscall stack). */
        /* Rare CLONE_THREAD deferral only; normal fork uses wake_up_new_task. */
        struct thread *fork_child_to_publish;
        /* Set by SYS_vfork; cleared when child exec/exits. Parent sleeps in
         * syscall_maybe_vfork_wait() AFTER syscall_do returns (asm frame intact). */
        int vfork_waiting;
        /* Parent vfork retval (child pid) while waiting in SYS_vfork. */
        uint64_t vfork_saved_ret;
        /* Nested SYS_fork from SYS_vfork: share parent mm (Linux CLONE_VM). */
        int fork_request_vfork;
        /* Sticky: last wait4 returned ECHILD. Used to break BusyBox waitfor()
         * when it then kill(own_pid,0) — which succeeds and spins forever. */
        int wait4_last_echild;
        
        /* exit status encoded like wait(2) returns (status word) */
        int exit_status;
        /* process address space descriptor (CR3 + page-table root). */
        mm_t *mm;
        /* Parent (or AS baseline) mm retained at fork for mm_make_private_range COW compare; exec clears. */
        mm_t *mm_ptemplate;
        /* Unix-like static scheduling weight: -20 (high) .. 19 (low). Default 0. */
        int nice;
        /* Monotonic ticket when entering THREAD_READY; lower runs earlier at same priority. */
        uint32_t sched_fifo_seq;
        /* CFS-like weighted runtime. Scheduler picks the smallest value;
         * nice changes growth rate, never absolute eligibility. */
        uint64_t sched_vruntime;
        /* If >= 0, runnable only on that logical CPU; -1 = any CPU (SMP). */
        int bound_cpu;
        /* Logical CPU that owns this thread while THREAD_READY (-1 if not ready / running). */
        int sched_target_cpu;
        /* Snapshot of exec environment for /proc/<pid>/environ (NUL-separated KEY=val). */
        char **proc_environ;
        /* Append-only extension fields; every object including thread.h rebuilds with this ABI. */
        uint64_t syscall_entry_rip;   /* RCX/RIP at last SYSCALL entry (snapshot only). */
        uint64_t fork_child_user_rip; /* Fork child iretq RIP; fork_child_return_entry. */
        uint64_t fork_locked_syscall_rip; /* frame[13] captured at syscall entry (per-thread). */
        uint64_t fork_child_trap_rip; /* frame[13] at fork/clone/clone3 syscall entry (immutable). */
        uint64_t robust_list_head;    /* set_robust_list head (userspace VA). */
        uint32_t robust_list_len;     /* set_robust_list len. */
        uint64_t fork_libc_mt_r14;    /* glibc MT __fork: r14=rsp at d4160, snap at clone. */
        uint64_t fork_gpr_snap[16];   /* syscall GPR frame at clone; restore for MT __fork ret. */
        /* 1 = pthread/clone3 child: keep %rdx (start_routine) across iretq. */
        uint8_t clone_preserve_rdx;
        /* 1 = SYS_clone/clone3 is nesting do_fork; skip parent frame rebuild. */
        uint8_t fork_from_clone;
        /* Successful execve: release pre-exec mm AFTER switching to new_mm but
         * BEFORE enter_user_mode (which never returns). */
        mm_t *exec_discard_mm;
        mm_t *exec_discard_template;
        /* Eager x87/SSE/AVX context. raw owns the allocation; state is
         * 64-byte aligned for XSAVE/XRSTOR. */
        void *fpu_state_raw;
        void *fpu_state;
} thread_t;

extern int init;

void thread_init();
/* Per-CPU idle thread created at boot (cpu index 0 .. smp_cpu_count()-1). */
thread_t *thread_idle_for_cpu(int cpu);
/* Mark thread runnable with a fresh FIFO position (no-op if already READY). */
void thread_note_ready(thread_t *t);
/* tid==0 → current thread. nice clamped to [-20,19]. Returns 0 or -1. */
int thread_nice_set(int tid, int nice);
/* tid==0 → current. Returns nice or -1 if no such thread. */
int thread_nice_get(int tid);
thread_t* thread_create(void (*entry)(void), const char* name);
/* Create a thread but keep it BLOCKED initially (not runnable) so callers can
   safely initialize fields before scheduling can run it. */
thread_t* thread_create_blocked(void (*entry)(void), const char* name);
void thread_yield();
void thread_ring3_preempt_if_waiters(void);
void thread_request_resched(void);
void thread_cond_resched(void);
/* Charge the current task one timer tick (user vs system) for /proc accounting. */
void thread_account_timer_tick(int user_mode);
/* Aggregate USER_HZ counters for /proc/stat (cpu line). */
void thread_cpu_times_user_hz(uint64_t *user, uint64_t *nice, uint64_t *system,
                              uint64_t *idle);
/* Per-CPU USER_HZ counters for /proc/stat cpuN lines. */
void thread_cpu_times_user_hz_cpu(int cpu, uint64_t *user, uint64_t *nice,
                                  uint64_t *system, uint64_t *idle);
void thread_schedule();
thread_t* thread_current();
void thread_stop(int pid);
thread_t* thread_get(int pid);
int thread_get_pid(const char* name);
void thread_block(int pid);
/* Atomically mark current thread BLOCKED (with no timeout) under scheduler lock.
   Returns 1 if state changed to BLOCKED, 0 otherwise. */
int thread_block_current_atomic(void);
/* Block until unblock OR timeout_ms expires. sleep_until stores a monotonic-ms deadline. */
void thread_block_with_timeout(int pid, uint32_t timeout_ms);
/* Mark sleeping/timeout-blocked threads READY when their monotonic-ms deadline expires.
   IRQ-safe and does not context-switch; timer handlers call this before returning. */
void thread_wake_expired_timeouts(void);
void thread_unblock(int pid);
/* Unblock a fork/clone child and prefer it on the next schedule (after parent iretq). */
void thread_unblock_fork_child(int pid);
/* Send SIGINT to foreground process group (Ctrl+C → terminate blocking program) */
void thread_send_sigint_to_pgrp(int pgrp);
void thread_send_sighup_to_pgrp(int pgrp);
int thread_get_state(int pid);
int thread_get_count();
/* Reparent living children of exiting parent to init. Returns count reparented. */
int thread_reparent_orphans(int dead_parent_tid);
/* Remove TERMINATED zombies with no wait4 waiter (returns count reaped). */
int thread_reap_unwaited_zombies(void);
int thread_reap(int pid);
/* Non-idle threads in READY or RUNNING (scheduler load sample). */
int thread_runnable_nonidle_count(void);
void thread_sleep(uint32_t ms);

// access thread by index (0..thread_get_count()-1)
thread_t* thread_get_by_index(int idx);
int thread_get_init_user_tid(void);
void thread_mark_init_user(thread_t* t);

// register user thread (process) for display in list
thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name);

// access to current user thread
thread_t* thread_get_current_user();
void thread_set_current_user(thread_t* t);
/* Force per-CPU scheduler current (syscall stack-owner fixup only). */
void thread_set_current(thread_t *t);
// find a user thread attached to given tty (or NULL)
thread_t* thread_find_by_tty(int tty);
// find any child of given parent tid, or NULL
thread_t* thread_find_child_of(int parent_tid);

// per-thread fd helpers
int thread_fd_alloc(struct fs_file *file); /* returns fd or -1 */
int thread_fd_close(int fd);
int thread_fd_dup(int oldfd);
int thread_fd_dup2(int oldfd, int newfd);
int thread_fd_isatty(int fd);

void thread_proc_env_free(thread_t *t);
void thread_proc_env_set(thread_t *t, const char *const envp[]);
void thread_proc_env_inherit(thread_t *child, thread_t *parent);

#endif // THREAD_H 