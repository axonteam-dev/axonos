#include <thread.h>
#include <heap.h>
#include <klog.h>
#include <debug.h>
#include <string.h>
#include <pit.h>
#include <mmio.h>
#include <vga.h>
#include <context.h>
#include <devfs.h>
#include <gdt.h>
#include <mm.h>
#include <paging.h>
#include <power.h>
#include <exec.h>
#include <spinlock.h>
#include <smp.h>
#include <fs.h>
#include <stdio.h>
#include <syscall.h>
#include <process.h>
#include <fpu.h>

#define MAX_THREADS 512
thread_t* threads[MAX_THREADS];
int thread_count = 0;
static thread_t *volatile current_cpu[SMP_MAX_CPUS];
static spinlock_t sched_lock = { 0 };
static uint32_t sched_fifo_counter;
/*
 * The active ring-3 task is CPU-local.  Keeping one global pointer lets a
 * sibling CPU's fork/vfork child replace the caller seen by wait4(), signal
 * delivery, and exec helpers.  In particular BusyBox init then observes
 * ECHILD even though kill(child, 0) succeeds.
 */
static thread_t* current_user[SMP_MAX_CPUS] = { NULL };
static thread_t* idle_thread_by_cpu[SMP_MAX_CPUS];
static volatile uint8_t need_resched[SMP_MAX_CPUS];
/* Raw timer-tick CPU accounting (converted to USER_HZ in /proc). */
static uint64_t cpu_user_ticks;
static uint64_t cpu_nice_ticks;
static uint64_t cpu_system_ticks;
static uint64_t cpu_idle_ticks;
int init = 0;
static int init_user_tid = -1;

static void thread_note_ready_nolock(thread_t *t);
static int thread_is_any_idle(const thread_t *t);

static inline int thread_time_after_eq32(uint32_t now, uint32_t deadline) {
        return (int32_t)(now - deadline) >= 0;
}

static uint32_t thread_ms_to_timer_ticks(uint32_t ms) {
        uint32_t freq = (uint32_t)pit_get_frequency();
        if (freq == 0) freq = 1000u;
        uint64_t ticks64 = ((uint64_t)ms * (uint64_t)freq + 999u) / 1000u;
        if (ticks64 == 0) ticks64 = 1;
        if (ticks64 > 0x7FFFFFFFULL) ticks64 = 0x7FFFFFFFULL;
        return (uint32_t)ticks64;
}

void thread_wake_expired_timeouts(void) {
        uint32_t now = (uint32_t)timer_ticks;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t || t->sleep_until == 0)
                        continue;
                if ((t->state == THREAD_SLEEPING || t->state == THREAD_BLOCKED) &&
                    thread_time_after_eq32(now, t->sleep_until)) {
                        t->sleep_until = 0;
                        thread_note_ready_nolock(t);
                }
        }
        release_irqrestore(&sched_lock, irqf);
}

/* forward declaration */
thread_t* thread_get(int pid);
thread_t* thread_current(void);

static int thread_is_any_idle(const thread_t *t) {
        if (!t)
                return 0;
        for (int i = 0; i < SMP_MAX_CPUS; i++) {
                if (idle_thread_by_cpu[i] == t)
                        return 1;
        }
        return 0;
}

void thread_account_timer_tick(int user_mode) {
        thread_t *cur = thread_current();
        if (!cur || thread_is_any_idle(cur) || cur->ring != 3) {
                cpu_idle_ticks++;
                return;
        }
        if (user_mode) {
                cur->utime_ticks++;
                if (cur->nice > 0)
                        cpu_nice_ticks++;
                else
                        cpu_user_ticks++;
        } else {
                cur->stime_ticks++;
                cpu_system_ticks++;
        }
}

void thread_cpu_times_user_hz(uint64_t *user, uint64_t *nice, uint64_t *system,
                              uint64_t *idle) {
        uint32_t freq = (uint32_t)pit_get_frequency();
        if (freq == 0)
                freq = 1000u;
        /* Convert timer ticks → USER_HZ (100). */
        uint64_t scale_num = 100ull;
        uint64_t scale_den = (uint64_t)freq;
        if (user)
                *user = (cpu_user_ticks * scale_num) / scale_den;
        if (nice)
                *nice = (cpu_nice_ticks * scale_num) / scale_den;
        if (system)
                *system = (cpu_system_ticks * scale_num) / scale_den;
        if (idle)
                *idle = (cpu_idle_ticks * scale_num) / scale_den;
}

/* declared below (needs main_thread, sched_lock, KERNEL_STACK_SIZE, thread_is_any_idle) */
int thread_reap(int pid);

int thread_runnable_nonidle_count(void) {
        int n = 0;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t || thread_is_any_idle(t))
                        continue;
                if (t->state == THREAD_READY || t->state == THREAD_RUNNING)
                        n++;
        }
        release_irqrestore(&sched_lock, irqf);
        return n;
}

thread_t *thread_idle_for_cpu(int cpu) {
        if (cpu < 0 || cpu >= SMP_MAX_CPUS)
                return NULL;
        return idle_thread_by_cpu[cpu];
}

static uint64_t thread_vruntime_delta(const thread_t *t) {
        int nice = t ? t->nice : 0;
        if (nice < -20) nice = -20;
        if (nice > 19) nice = 19;
        /* Lower nice grows more slowly and therefore receives a larger share.
         * Every runnable task still advances and remains eligible. */
        return (uint64_t)(nice + 21);
}

static inline void sched_set_current(thread_t *t) {
        current_cpu[smp_sched_cpu_id()] = t;
}

static void thread_note_ready_nolock(thread_t *t) {
        if (!t)
                return;
        if (t->state == THREAD_READY)
                return;
        /* Never resurrect a killed/exited thread (SIGKILL from another task). */
        if (t->state == THREAD_TERMINATED)
                return;
        /*
         * Linux wait_for_vfork_done: parent stays unscheduled until
         * complete_vfork_done(). If we READY a vfork parent early it can
         * re-bind its syscall kstack; the child then SYSCALL's onto that
         * stack, smashes the wait frame/TLS, and GPF's (seen at BusyBox
         * locale setup rip=0x4b9375 with garbage RAX).
         */
        if (t->vfork_waiting)
                return;
        t->sched_fifo_seq = ++sched_fifo_counter;
        t->state = THREAD_READY;
}

/* Called from context_switch_with_prev after outgoing context is fully saved (SMP-safe).
 * Unlocks only — IF must stay 0 until asm restores next thread (avoid IRQ during switch tail). */
void thread_schedule_prev_saved(thread_t *t) {
        if (t && t->state == THREAD_RUNNING) {
                t->sched_vruntime += thread_vruntime_delta(t);
                if (t->vfork_waiting)
                        t->state = THREAD_BLOCKED;
                else
                        thread_note_ready_nolock(t);
        }
        release(&sched_lock);
}

void thread_note_ready(thread_t *t) {
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        thread_note_ready_nolock(t);
        release_irqrestore(&sched_lock, irqf);
}

int thread_nice_set(int tid, int nice) {
        if (nice < -20)
                nice = -20;
        if (nice > 19)
                nice = 19;
        thread_t *t = (tid == 0) ? thread_current() : thread_get(tid);
        if (!t)
                return -1;
        t->nice = nice;
        return 0;
}

int thread_nice_get(int tid) {
        thread_t *t = (tid == 0) ? thread_current() : thread_get(tid);
        if (!t)
                return -1;
        return t->nice;
}

void thread_mark_init_user(thread_t* t) {
        if (!t) return;
        if (!t->process) {
                process_t *p = process_create_init();
                if (p)
                        process_attach_thread(p, t);
        }
        if (init_user_tid < 0) {
                init_user_tid = (int)t->tid;
                return;
        }
        thread_t *it = thread_get(init_user_tid);
        if (!it || it->state == THREAD_TERMINATED) {
                init_user_tid = (int)t->tid;
        }
}
static thread_t main_thread;

static int thread_context_valid(thread_t *t) {
        if (!t) return 0;
        uintptr_t tp = (uintptr_t)t;
        if (tp < 0x1000 || tp + sizeof(thread_t) >= (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
        uintptr_t rsp = (uintptr_t)t->context.rsp;
        if (rsp < 0x1000 || rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT - 16) return 0;
        return 1;
}

/* 8KiB was too small for syscall_do; 128KiB covers fork/clone COW walks on large AS. */
#define KERNEL_STACK_SIZE (128 * 1024)
#define SYSCALL_KSTACK_SIZE (128 * 1024)

static void thread_free_resources(thread_t *t) {
        if (!t) return;
        /* mm may have been released in SYS_exit, but be defensive */
        if (t->mm && t->mm != mm_kernel()) {
                mm_release(t->mm);
                t->mm = mm_kernel();
        }
        if (t->mm_ptemplate) {
                mm_release(t->mm_ptemplate);
                t->mm_ptemplate = NULL;
        }
        /* kernel_stack points to top; allocation was KERNEL_STACK_SIZE+16 */
        if (t->kernel_stack) {
                void *raw = (void *)(uintptr_t)(t->kernel_stack - (uint64_t)KERNEL_STACK_SIZE);
                kfree(raw);
                t->kernel_stack = 0;
        }
        if (t->syscall_kstack_raw) {
                kfree(t->syscall_kstack_raw);
                t->syscall_kstack_raw = NULL;
                t->syscall_kstack_top = 0;
        }
        if (t->syscall_frame_kbuf) {
                kfree(t->syscall_frame_kbuf);
                t->syscall_frame_kbuf = NULL;
        }
        fpu_thread_destroy(t);
        thread_proc_env_free(t);
        kfree(t);
}

/* Reap a terminated user/kernel thread: remove slot so fork can reuse it. */
int thread_reap(int pid) {
        thread_t *victim = NULL;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if ((int)t->tid != pid) continue;
                if (t->state != THREAD_TERMINATED) break;
                /* don't reap main or idle threads */
                if (t == &main_thread || thread_is_any_idle(t)) break;
                threads[i] = NULL;
                victim = t;
                break;
        }
        /* shrink high-water mark when top slots are empty */
        while (thread_count > 1 && threads[thread_count - 1] == NULL)
                thread_count--;
        release_irqrestore(&sched_lock, irqf);
        if (victim) {
                thread_free_resources(victim);
                return 0;
        }
        return -1;
}

/* True if a TERMINATED child may be freed without wait4 (matches thread_schedule auto-reap). */
static int thread_zombie_autoreap_ok(thread_t *t) {
        if (!t || t->state != THREAD_TERMINATED) return 0;
        /* Never free the stack/object of the task executing this scheduler
         * call. A later scheduling pass on another task will reclaim it. */
        if (t == thread_current()) return 0;
        if (t == &main_thread || thread_is_any_idle(t)) return 0;
        if (t->waiter_tid >= 0) return 0;
        if (t->exit_status == (int)0x80000000) return 0;
        /* Boot often leaves a dead /sbin/init while /linuxrc stays PID1-ish. */
        if (t->name[0] && (strstr(t->name, "/sbin/init") ||
                           strcmp(t->name, "init") == 0))
                return 1;
        if (t->parent_tid < 0) return 1;
        thread_t *pt = thread_get(t->parent_tid);
        if (!pt) return 1;
        if (pt->state == THREAD_TERMINATED) return 1;
        return 0;
}

/* Reparent living children of dead_parent to init (PID 1). Returns count moved. */
int thread_reparent_orphans(int dead_parent_tid) {
        int init_tid = thread_get_init_user_tid();
        if (init_tid < 0 || dead_parent_tid < 0) return 0;
        if (dead_parent_tid == init_tid) return 0;
        int n = 0;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if (t->parent_tid != dead_parent_tid) continue;
                if (t->state == THREAD_TERMINATED) continue;
                t->parent_tid = init_tid;
                n++;
        }
        release_irqrestore(&sched_lock, irqf);
        return n;
}

/* Drop zombies safe to reap without wait4 (httpd-style: parent exited, no living waiter). */
int thread_reap_unwaited_zombies(void) {
        int n = 0;
        for (;;) {
                thread_t *victim = NULL;
                unsigned long irqf;
                acquire_irqsave(&sched_lock, &irqf);
                for (int i = 1; i < thread_count; ++i) {
                        thread_t *t = threads[i];
                        if (!t) continue;
                        if (!thread_zombie_autoreap_ok(t)) continue;
                        threads[i] = NULL;
                        victim = t;
                        while (thread_count > 1 && threads[thread_count - 1] == NULL)
                                thread_count--;
                        break;
                }
                release_irqrestore(&sched_lock, irqf);
                if (!victim) break;
                thread_free_resources(victim);
                n++;
        }
        return n;
}

/* A real idle task: used when all other threads are BLOCKED/SLEEPING/TERMINATED.
   It must be a normal schedulable thread with its own saved context, otherwise
   the scheduler can end up "returning" into a terminated thread (e.g. after SYS_exit_group)
   when there are no READY threads. */
static void idle_task_entry(void) {
        for (;;) {
                /* Drive scheduling from a safe thread context.
                   IRQ handlers must not context_switch(), so when an interrupt
                   unblocks a thread (e.g. keyboard input waking a tty reader),
                   we rely on the idle task to notice READY threads and switch. */
                thread_schedule();
                asm volatile("sti; hlt" ::: "memory");
        }
}

void thread_init() {
        mm_init();
        process_init();
        memset(&main_thread, 0, sizeof(main_thread));
        (void)fpu_thread_init(&main_thread);
        main_thread.sched_target_cpu = -1;
        main_thread.state = THREAD_RUNNING;
        main_thread.tid = 0;
        main_thread.nice = 0;
        main_thread.sched_fifo_seq = 0;
        main_thread.start_ticks = timer_ticks;
        main_thread.context.rflags = 0x202; // ensure IF set for idle/main thread
        main_thread.sleep_until = 0;
        //for (int i=0;i<THREAD_MAX_FD;i++) main_thread.fds[i]=NULL;
        sched_set_current(&main_thread);
        threads[0] = &main_thread;
        thread_count = 1;
        strncpy(main_thread.name, "idle", sizeof(main_thread.name));
        main_thread.name[sizeof(main_thread.name) - 1] = '\0';
        /* default credentials: root */
        main_thread.uid = main_thread.euid = main_thread.suid = 0;
        main_thread.gid = main_thread.egid = main_thread.sgid = 0;
        main_thread.ngroups = 1;
        main_thread.groups[0] = 0;
        main_thread.attached_tty = devfs_get_active();
        strncpy(main_thread.cwd, "/", sizeof(main_thread.cwd));
        main_thread.cwd[sizeof(main_thread.cwd) - 1] = '\0';
        main_thread.rseq_ptr = NULL;
        main_thread.parent_tid = -1;
        main_thread.saved_user_rip = 0;
        main_thread.saved_user_rsp = 0;
        main_thread.waiter_tid = -1;
        main_thread.exit_status = 0;
        main_thread.exec_trampoline_flag = 0;
        main_thread.exec_trampoline_rip = 0;
        main_thread.exec_trampoline_rsp = 0;
        main_thread.exec_trampoline_rax = 0;
        main_thread.mm = mm_retain(mm_kernel());
        main_thread.bound_cpu = 0;

        for (int i = 0; i < SMP_MAX_CPUS; i++)
                idle_thread_by_cpu[i] = NULL;

        int ncpu = smp_cpu_count();
        if (ncpu > SMP_MAX_CPUS)
                ncpu = SMP_MAX_CPUS;
        for (int i = 0; i < ncpu; i++) {
                char iname[16];
                if (i < 10) {
                        memcpy(iname, "idle", 4);
                        iname[4] = (char)('0' + i);
                        iname[5] = '\0';
                } else {
                        memcpy(iname, "idle", 4);
                        iname[4] = (char)('0' + i / 10);
                        iname[5] = (char)('0' + i % 10);
                        iname[6] = '\0';
                }
                thread_t *it = thread_create(idle_task_entry, iname);
                if (it) {
                        it->nice = 19;
                        it->bound_cpu = i;
                        idle_thread_by_cpu[i] = it;
                }
        }
        /* After idlers exist; before this, pit_handler must not thread_schedule()
         * while threads[] / thread_count are being set up. */
        init = 1;
}

// для старта потока
static void thread_trampoline(void) {
        register void (*entry)(void) __asm__("r12");
        // Log RFLAGS at thread start to ensure IF bit is set in thread context
        unsigned long long _rflags = 0;
        asm volatile("pushfq; pop %%rax" : "=a"(_rflags));
        thread_t* _self = thread_current();
        int _tid = _self ? _self->tid : -1;
        if (_self && _self->parent_tid >= 0) {
                devel_printf("sched-fork[43] trampoline tid=%d entry=0x%llx rsp=0x%llx cr3=0x%llx\n",
                        _tid,
                        (unsigned long long)(uintptr_t)entry,
                        (unsigned long long)_self->context.rsp,
                        (unsigned long long)paging_read_cr3());
        }
        if (_tid == thread_get_init_user_tid()) {
                devel_printf("thread_trampoline: PID1 entry=0x%llx rflags=0x%x\n",
                        (unsigned long long)(uintptr_t)entry,
                        (unsigned int)_rflags);
        }
        entry();

        // Поток завершился - помечаем как завершенный
        thread_t* self = thread_current();
        if (self) {
                self->state = THREAD_TERMINATED;
        }

        // Переключаемся на другой поток
        thread_yield();

        // На всякий случай - если что-то пошло не так
        for (;;) {
                asm volatile("hlt");
        }
}

static thread_t* thread_create_with_state(void (*entry)(void), const char* name, thread_state_t st) {
        /* Find a free slot so we can reuse reaped threads. */
        int slot = -1;
        unsigned long irqf0;
        acquire_irqsave(&sched_lock, &irqf0);
        for (int i = 1; i < MAX_THREADS; i++) {
                if (threads[i] == NULL) { slot = i; break; }
        }
        release_irqrestore(&sched_lock, irqf0);
        if (slot < 0) {
                (void)thread_reap_unwaited_zombies();
                acquire_irqsave(&sched_lock, &irqf0);
                for (int i = 1; i < MAX_THREADS; i++) {
                        if (threads[i] == NULL) { slot = i; break; }
                }
                release_irqrestore(&sched_lock, irqf0);
        }
        if (slot < 0) return NULL;
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) {
                (void)thread_reap_unwaited_zombies();
                t = (thread_t*)kmalloc(sizeof(thread_t));
                if (!t) return NULL;
        }
        memset(t, 0, sizeof(thread_t));
        if (fpu_thread_init(t) != 0) {
                kfree(t);
                return NULL;
        }
        t->bound_cpu = -1;
        t->sched_target_cpu = -1;
        void *stack_mem = kmalloc(KERNEL_STACK_SIZE + 16);
        if (!stack_mem) { kprintf("OOM thread: kmalloc(stack %u) failed\n", (unsigned)(KERNEL_STACK_SIZE + 16)); fpu_thread_destroy(t); kfree(t); return NULL; }
        t->kernel_stack = (uint64_t)stack_mem + KERNEL_STACK_SIZE;
        {
                void *sc_mem = kmalloc(SYSCALL_KSTACK_SIZE + 16);
                if (!sc_mem) {
                        kfree(stack_mem);
                        fpu_thread_destroy(t);
                        kfree(t);
                        return NULL;
                }
                t->syscall_kstack_raw = sc_mem;
                t->syscall_kstack_top = (uint64_t)sc_mem + SYSCALL_KSTACK_SIZE;
        }
        {
                uint64_t *kbuf = (uint64_t *)kmalloc(16 * sizeof(uint64_t));
                if (!kbuf) {
                        kfree(t->syscall_kstack_raw);
                        kfree((void *)((uintptr_t)t->kernel_stack - KERNEL_STACK_SIZE));
                        fpu_thread_destroy(t);
                        kfree(t);
                        return NULL;
                }
                t->syscall_frame_kbuf = kbuf;
        }
        uint64_t* stack = (uint64_t*)t->kernel_stack;
        // Ensure 16-byte alignment for the stack pointer before ret
        uint64_t sp = ((uint64_t)&stack[-1]) & ~0xFULL;
        *((uint64_t*)sp) = (uint64_t)thread_trampoline; // ret пойдёт на trampoline
        t->context.rsp = sp;
        t->context.r12 = (uint64_t)entry; // entry передаётся через r12
        t->context.rflags = 0x202;
        t->state = st;
        thread_t *creator = thread_current();
        t->nice = creator ? creator->nice : 0;
        t->sched_fifo_seq = 0;
        t->sched_vruntime = creator ? creator->sched_vruntime : 0;
        t->start_ticks = timer_ticks;
        t->sleep_until = 0;
        strncpy(t->name, name, sizeof(t->name));
        t->name[sizeof(t->name) - 1] = '\0';
        /* default credentials (root) */
        t->uid = t->euid = t->suid = 0;
        t->gid = t->egid = t->sgid = 0;
        t->ngroups = 1;
        t->groups[0] = 0;
        t->attached_tty = -1;
        t->user_brk_base = 0;
        t->user_brk_cur = 0;
        t->user_mmap_next = 0;
        t->user_mmap_hi = 0;
        t->mm_ptemplate = NULL;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->saved_user_rip = 0;
        t->saved_user_rsp = 0;
        t->saved_user_rbx = 0;
        t->saved_user_rbp = 0;
        t->saved_user_r12 = 0;
        t->saved_user_r13 = 0;
        t->saved_user_r14 = 0;
        t->saved_user_r15 = 0;
        t->saved_user_rdi = 0;
        t->saved_user_rsi = 0;
        t->saved_user_rdx = 0;
        t->saved_user_r8 = 0;
        t->saved_user_r9 = 0;
        t->saved_user_r10 = 0;
        t->saved_user_r11 = 0;
        t->saved_user_rcx = 0;
        t->syscall_entry_rip = 0;
        t->fork_child_user_rip = 0;
        t->fork_locked_syscall_rip = 0;
        t->fork_child_trap_rip = 0;
        t->saved_syscall_frame = NULL;
        t->sc_a1 = t->sc_a2 = t->sc_a3 = t->sc_a4 = t->sc_a5 = t->sc_a6 = 0;
        t->fork_child_to_publish = NULL;
        t->proc_environ = NULL;
        t->uaccess_begin = 0;
        t->uaccess_end = 0;
        t->uaccess_resume_rip = 0;
        t->uaccess_active = 0;
        t->pending_signals = 0;
        t->saved_sig_mask = 0;
        t->sas_ss_sp = 0;
        t->sas_ss_size = 0;
        t->sas_ss_flags = 2; /* SS_DISABLE */
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        {
                thread_t *tc = thread_current();
                if (tc && tc->mm) t->mm = mm_retain(tc->mm);
                else t->mm = mm_retain(mm_kernel());
        }
        strncpy(t->cwd, "/", sizeof(t->cwd));
        t->cwd[sizeof(t->cwd) - 1] = '\0';
        /* Use next free slot and tid so we never overwrite an existing thread. */
        {
                unsigned long irqf;
                acquire_irqsave(&sched_lock, &irqf);
                threads[slot] = t;
                t->tid = slot;
                if (slot >= thread_count) thread_count = slot + 1;
                if (st == THREAD_READY)
                        t->sched_fifo_seq = ++sched_fifo_counter;
                release_irqrestore(&sched_lock, irqf);
        }
        return t;
}

thread_t* thread_create(void (*entry)(void), const char* name) {
        return thread_create_with_state(entry, name, THREAD_READY);
}

thread_t* thread_create_blocked(void (*entry)(void), const char* name) {
        return thread_create_with_state(entry, name, THREAD_BLOCKED);
}

thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name){
        if (thread_count >= MAX_THREADS) return NULL;
        // Sanity checks: reject clearly invalid user contexts (entry==0 or tiny stack)
        if (user_rip == 0 || user_rsp < 0x1000) {
                klogprintf("fatal: refusing to register user thread with invalid rip=0x%llx rsp=0x%llx\n",
                               (unsigned long long)user_rip, (unsigned long long)user_rsp);
                return NULL;
        }
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) { kprintf("OOM thread_register_user: kmalloc(thread_t) failed\n"); return NULL; }
        memset(t, 0, sizeof(thread_t));
        if (fpu_thread_init(t) != 0) {
                kfree(t);
                return NULL;
        }
        {
                void *sc_mem = kmalloc(SYSCALL_KSTACK_SIZE + 16);
                if (sc_mem) {
                        t->syscall_kstack_raw = sc_mem;
                        t->syscall_kstack_top = (uint64_t)sc_mem + SYSCALL_KSTACK_SIZE;
                }
        }
        {
                uint64_t *kbuf = (uint64_t *)kmalloc(16 * sizeof(uint64_t));
                if (kbuf)
                        t->syscall_frame_kbuf = kbuf;
        }
        t->bound_cpu = 0;
        t->sched_target_cpu = -1;
        //for (int i=0;i<THREAD_MAX_FD;i++) t->fds[i]=NULL;
        t->ring = 3;
        t->user_rip = user_rip;
        t->user_stack = user_rsp;
        /* A registered task is not RUNNING until selected by thread_schedule(). */
        t->state = THREAD_READY;
        t->nice = 0;
        t->sched_fifo_seq = 0;
        t->start_ticks = timer_ticks;
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name ? name : "user", sizeof(t->name));
        t->name[sizeof(t->name) - 1] = '\0';
        /* initialize POSIX-ish job control ids */
        t->pgid = (int)t->tid;
        t->sid = (int)t->tid;
        /* inherit credentials, file descriptors and attached tty from current thread if available */
        thread_t *tc = thread_current();
        if (tc) {
                t->nice = tc->nice;
                t->sched_vruntime = tc->sched_vruntime;
                t->uid = tc->uid;
                t->euid = tc->euid;
                t->suid = tc->suid;
                t->gid = tc->gid;
                t->egid = tc->egid;
                t->sgid = tc->sgid;
                t->ngroups = tc->ngroups;
                if (t->ngroups < 0)
                    t->ngroups = 0;
                if (t->ngroups > AXON_NGROUPS_MAX)
                    t->ngroups = AXON_NGROUPS_MAX;
                if (t->ngroups > 0)
                    memcpy(t->groups, tc->groups, (size_t)t->ngroups * sizeof(gid_t));
                t->umask = tc->umask;
                /* copy fd table and bump refcount so close in parent doesn't free shared files (e.g. pipe) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    t->fds[i] = tc->fds[i];
                    if (t->fds[i]) {
                        if (t->fds[i]->refcount <= 0) t->fds[i]->refcount = 1;
                        else t->fds[i]->refcount++;
                    }
                }
                t->attached_tty = tc->attached_tty >= 0 ? tc->attached_tty : devfs_get_active();
                strncpy(t->cwd, tc->cwd[0] ? tc->cwd : "/", sizeof(t->cwd));
                t->cwd[sizeof(t->cwd) - 1] = '\0';
        } else {
                t->uid = t->euid = t->suid = 0;
                t->gid = t->egid = t->sgid = 0;
                t->ngroups = 1;
                t->groups[0] = 0;
                t->attached_tty = devfs_get_active();
        }
        if (!t->cwd[0]) { strncpy(t->cwd, "/", sizeof(t->cwd)); t->cwd[sizeof(t->cwd)-1] = '\0'; }
        t->user_brk_base = 0;
        t->user_brk_cur = 0;
        t->user_mmap_next = 0;
        t->user_mmap_hi = 0;
        t->mm_ptemplate = NULL;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->saved_user_rip = 0;
        t->saved_user_rsp = 0;
        t->saved_user_rbx = 0;
        t->saved_user_rbp = 0;
        t->saved_user_r12 = 0;
        t->saved_user_r13 = 0;
        t->saved_user_r14 = 0;
        t->saved_user_r15 = 0;
        t->saved_user_rdi = 0;
        t->saved_user_rsi = 0;
        t->saved_user_rdx = 0;
        t->saved_user_r8 = 0;
        t->saved_user_r9 = 0;
        t->saved_user_r10 = 0;
        t->saved_user_r11 = 0;
        t->saved_user_rcx = 0;
        t->syscall_entry_rip = 0;
        t->fork_child_user_rip = 0;
        t->fork_locked_syscall_rip = 0;
        t->fork_child_trap_rip = 0;
        t->saved_syscall_frame = NULL;
        t->sc_a1 = t->sc_a2 = t->sc_a3 = t->sc_a4 = t->sc_a5 = t->sc_a6 = 0;
        t->fork_child_to_publish = NULL;
        t->proc_environ = NULL;
        t->uaccess_begin = 0;
        t->uaccess_end = 0;
        t->uaccess_resume_rip = 0;
        t->uaccess_active = 0;
        t->pending_signals = 0;
        t->saved_sig_mask = 0;
        t->sas_ss_sp = 0;
        t->sas_ss_size = 0;
        t->sas_ss_flags = 2; /* SS_DISABLE */
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        {
                thread_t *tc = thread_current();
                if (tc && tc->mm) t->mm = mm_retain(tc->mm);
                else t->mm = mm_retain(mm_kernel());
        }
        threads[thread_count++] = t;
        t->sched_fifo_seq = ++sched_fifo_counter;
        return t;
}

int thread_get_init_user_tid(void) {
        return init_user_tid;
}

// Entry for kernel-created user threads: set up per-thread kernel stack as TSS, mark as current_user
// then enter user mode at saved rip/rsp. This function is used as the entry point passed to thread_create().
void user_thread_entry(void) {
	thread_t *self = thread_current();
	devel_printf("user_thread_entry: entered self=0x%llx tid=%d init=%d\n",
		(unsigned long long)(uintptr_t)self,
		self ? (int)self->tid : -1,
		thread_get_init_user_tid());
	/* Если init_tid ещё не установлен (ранний PID1 или shebang-интерпретатор),
	   фиксируем первым вошедшим в ring3 потоком. Это гарантирует трассировку syscalls. */
	if (self && thread_get_init_user_tid() < 0)
		thread_mark_init_user(self);
	if (!self) {
		for (;;) asm volatile("hlt");
	}
	// mark as user thread
	self->ring = 3;
	thread_set_current_user(self);
	if (!self->kernel_stack) {
		void *ks = kmalloc(KERNEL_STACK_SIZE + 16);
		if (ks)
			self->kernel_stack = (uint64_t)ks + KERNEL_STACK_SIZE;
	}
	/* Keep stack metadata consistent with the RSP we are about to run (exec layout vs live use). */
	if (self->user_stack) {
		uintptr_t us = (uintptr_t)self->user_stack;
		uintptr_t sb = (us > (uintptr_t)USER_STACK_SIZE) ? (us - (uintptr_t)USER_STACK_SIZE) : 0x200000u;
		uintptr_t se = sb + (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE;
		if (se > (uintptr_t)USER_STACK_TOP)
			se = (uintptr_t)USER_STACK_TOP;
		if (self->user_stack_base == 0)
			self->user_stack_base = sb;
		if (self->user_stack_limit == 0)
			self->user_stack_limit = se;
	}
	tss_set_rsp0(self->kernel_stack);
	syscall_bind_kstack_for_thread(self);
	// restore user FS base (TLS) so user code can access fs-relative data like stack-protector
	{
		uint64_t fsbase = self->user_fs_base;
		uint32_t msr = 0xC0000100u; /* MSR_FS_BASE */
		/* Read current MSR_FS_BASE for debug */
		{
			uint32_t _lo = 0, _hi = 0;
			asm volatile("rdmsr" : "=a"(_lo), "=d"(_hi) : "c"(msr));
			uint64_t cur = ((uint64_t)_hi << 32) | _lo;
			qemu_debug_printf("user_thread_entry: rdmsr before set MSR_FS_BASE=0x%llx target=0x%llx tid=%d\n",
			                  (unsigned long long)cur, (unsigned long long)fsbase, (int)self->tid);
		}
		/* Write desired FS base then verify by reading back */
		{
			uint32_t lo = (uint32_t)(fsbase & 0xFFFFFFFFu);
			uint32_t hi = (uint32_t)(fsbase >> 32);
			asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
			uint32_t _lo = 0, _hi = 0;
			asm volatile("rdmsr" : "=a"(_lo), "=d"(_hi) : "c"(msr));
			uint64_t after = ((uint64_t)_hi << 32) | _lo;
			qemu_debug_printf("user_thread_entry: rdmsr after set MSR_FS_BASE=0x%llx tid=%d\n",
			                  (unsigned long long)after, (int)self->tid);
		}
	}
	asm volatile("xor %%rax, %%rax" ::: "rax");
	qemu_debug_printf("user_thread_entry: entering user mode rip=0x%llx rsp=0x%llx tid=%d\n",
			  (unsigned long long)self->user_rip,
			  (unsigned long long)self->user_stack,
			  (int)self->tid);
	if (self->tid == (uint64_t)thread_get_init_user_tid()) {
		devel_printf("user_thread_entry: PID1 rip=0x%llx rsp=0x%llx fs=0x%llx\n",
			(unsigned long long)self->user_rip,
			(unsigned long long)self->user_stack,
			(unsigned long long)self->user_fs_base);
	}
	/* Init path never calls mark_broad_user_ranges; ensure full user mappings before user mode.
	   fork/vfork/clone3 children set user_stack_base; re-marking their private mm causes #PF. */
	if (self->user_stack_base == 0 &&
	    (uintptr_t)self->user_rip != (uintptr_t)USER_VFORK_TRAMP)
		exec_ensure_user_mappings();
	// Jump to user mode
	enter_user_mode(self->user_rip, self->user_stack);
	// Should not return
	for (;;) asm volatile("hlt");
}

int thread_fd_alloc(struct fs_file *file) {
    if (!file) return -1;
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur) return -1;
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        struct fs_file *existing = cur->process ?
                cur->process->fds[i] : cur->fds[i];
        if (existing == NULL) {
            cur->fds[i] = file;
            if (cur->process)
                    cur->process->fds[i] = file;
            /*
             * Adopt the creator's existing open-file reference. Creating a
             * descriptor is not dup(): callers pass a newly opened/allocated
             * fs_file with refcount 1. Incrementing here left an unowned
             * reference behind, leaking every open and preventing pipe EOF.
             */
            if (file->refcount <= 0)
                    file->refcount = 1;
            return i;
        }
    }
    return -1;
}

int thread_fd_close(int fd) {
    static int pipe_fd_trace_left = 160;
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return -1;
    struct fs_file *f = cur->process ? cur->process->fds[fd] : cur->fds[fd];
    if (!f) return -1;
    if (f->type == FS_TYPE_PIPE && pipe_fd_trace_left-- > 0)
        devel_printf("pipe-fd: close tid=%d fd=%d end=%c file=%p ref=%d pipe=%p\n",
                (int)(cur->tid ? cur->tid : 1), fd,
                fs_pipe_is_write_end(f) ? 'W' : 'R',
                (void *)f, f->refcount, f->driver_private);
    cur->fds[fd] = NULL;
    if (cur->process) {
        cur->process->fds[fd] = NULL;
        cur->process->fd_cloexec[fd] = 0;
    }
    /* Linux: close() auto-removes fd from all epoll interest lists. */
    epoll_notify_fd_closed(cur, fd);
    fs_file_free(f);
    return 0;
}

int thread_fd_dup(int oldfd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || oldfd < 0 || oldfd >= THREAD_MAX_FD) return -1;
    struct fs_file *f = cur->process ?
        cur->process->fds[oldfd] : cur->fds[oldfd];
    if (!f) return -1;
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        if ((cur->process ? cur->process->fds[i] : cur->fds[i]) == NULL) {
            cur->fds[i] = f;
            if (cur->process)
                cur->process->fds[i] = f;
            if (f->refcount <= 0) f->refcount = 1;
            else f->refcount++;
            return i;
        }
    }
    return -1;
}

int thread_fd_dup2(int oldfd, int newfd) {
    static int pipe_dup_trace_left = 80;
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || oldfd < 0 || oldfd >= THREAD_MAX_FD || newfd < 0 || newfd >= THREAD_MAX_FD) return -1;
    if (oldfd == newfd) return newfd;
    struct fs_file *f = cur->process ?
        cur->process->fds[oldfd] : cur->fds[oldfd];
    if (!f) return -1;
    if (f->type == FS_TYPE_PIPE && pipe_dup_trace_left-- > 0)
        devel_printf("pipe-fd: dup2 tid=%d old=%d new=%d end=%c file=%p ref=%d pipe=%p\n",
                (int)(cur->tid ? cur->tid : 1), oldfd, newfd,
                fs_pipe_is_write_end(f) ? 'W' : 'R',
                (void *)f, f->refcount, f->driver_private);
    /* close newfd if open; process->fds is authoritative for a process. */
    struct fs_file *replaced = cur->process ?
        cur->process->fds[newfd] : cur->fds[newfd];
    if (replaced)
        fs_file_free(replaced);
    cur->fds[newfd] = NULL;
    if (cur->process) {
        cur->process->fds[newfd] = NULL;
        /* Linux dup2 clears close-on-exec on the new descriptor. */
        cur->process->fd_cloexec[newfd] = 0;
    }
    cur->fds[newfd] = f;
    if (cur->process)
        cur->process->fds[newfd] = f;
    if (f->refcount <= 0) f->refcount = 1;
    else f->refcount++;
    return newfd;
}

int thread_fd_isatty(int fd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return 0;
    struct fs_file *f = cur->process ? cur->process->fds[fd] : cur->fds[fd];
    if (!f) return 0;
    return devfs_is_tty_file(f);
}

thread_t* thread_current(void) {
        return current_cpu[smp_sched_cpu_id()];
}

void thread_request_resched(void) {
        int cpu = smp_sched_cpu_id();
        if (cpu >= 0 && cpu < SMP_MAX_CPUS)
                need_resched[cpu] = 1;
}

void thread_cond_resched(void) {
        int cpu = smp_sched_cpu_id();
        if (cpu < 0 || cpu >= SMP_MAX_CPUS || !need_resched[cpu])
                return;
        /* Leave the flag set so thread_schedule() can expire the current slice
         * when another READY task is waiting (tty reader after keypress). */
        thread_schedule();
}

/* If a ring-3 thread is spinning, run pthread helpers / syscall waiters (OpenSSL init). */
void thread_ring3_preempt_if_waiters(void) {
        thread_t *cur = thread_current();
        if (!cur || cur->ring != 3 || cur->state != THREAD_RUNNING)
                return;
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t || t == cur || thread_is_any_idle(t))
                        continue;
                if (t->state == THREAD_READY) {
                        thread_request_resched();
                        thread_schedule();
                        return;
                }
        }
        if (thread_runnable_nonidle_count() > 1) {
                thread_request_resched();
                thread_schedule();
                return;
        }
}

void thread_yield() {
        thread_schedule();
}

void thread_stop(int pid) {
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_TERMINATED) {
                        kprintf("thread_stop: stopping tid=%d name=%s\n", pid, threads[i]->name);
                        threads[i]->state = THREAD_TERMINATED;
                    threads[i]->sleep_until = 0;
                    release_irqrestore(&sched_lock, irqf);
                        return;
                }
        }
        release_irqrestore(&sched_lock, irqf);
        klogprintf("thread_stop: thread %d not found or already terminated\n", pid);
}

void thread_block(int pid) {
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (!threads[i] || threads[i]->tid != (uint64_t)(unsigned)pid)
                        continue;
                if (threads[i]->state == THREAD_BLOCKED) {
                        threads[i]->sleep_until = 0;
                        release_irqrestore(&sched_lock, irqf);
                        return; /* idempotent — vfork arms block twice */
                }
                if (threads[i]->state != THREAD_TERMINATED) {
                        threads[i]->state = THREAD_BLOCKED;
                        threads[i]->sleep_until = 0; /* no timeout */
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
                break;
        }
        release_irqrestore(&sched_lock, irqf);
        klogprintf("thread_block: thread %d not found or terminated\n", pid);
}

int thread_block_current_atomic(void) {
        unsigned long irqf;
        int blocked = 0;
        acquire_irqsave(&sched_lock, &irqf);
        thread_t *cur = thread_current();
        if (cur && cur->state == THREAD_RUNNING) {
                cur->state = THREAD_BLOCKED;
                cur->sleep_until = 0;
                blocked = 1;
        }
        release_irqrestore(&sched_lock, irqf);
        return blocked;
}

void thread_block_with_timeout(int pid, uint32_t timeout_ms) {
        uint32_t now = (uint32_t)timer_ticks;
        uint32_t deadline = timeout_ms ? now + thread_ms_to_timer_ticks(timeout_ms) : 0xFFFFFFFFu;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_BLOCKED) {
                        threads[i]->state = THREAD_BLOCKED;
                        threads[i]->sleep_until = deadline;
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
        }
        release_irqrestore(&sched_lock, irqf);
}

void thread_sleep(uint32_t ms) {
        if (ms == 0) return;

        /* Use common timer ticks so sleep works even when PIT is disabled (APIC timer). */
        thread_t *c = thread_current();
        if (!c)
                return;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        c->sleep_until = (uint32_t)timer_ticks + thread_ms_to_timer_ticks(ms);
        c->state = THREAD_SLEEPING;
        release_irqrestore(&sched_lock, irqf);
        thread_yield();
}

void thread_schedule() {
        /* Run pending power actions in normal thread context (not IRQ-only idle). */
        power_poll();

        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);

        /* Auto-reap zombies that no living parent will wait4. */
        for (int i = 1; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if (!thread_zombie_autoreap_ok(t)) continue;
                /* Remove from table under lock; free after releasing lock. */
                threads[i] = NULL;
                /* shrink high-water mark when top slots are empty */
                while (thread_count > 1 && threads[thread_count - 1] == NULL)
                        thread_count--;
                release_irqrestore(&sched_lock, irqf);
                thread_free_resources(t);
                acquire_irqsave(&sched_lock, &irqf);
                /* restart scan because arrays changed */
                i = 0;
        }

        uint32_t now = (uint32_t)timer_ticks;
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->state == THREAD_SLEEPING) {
                        if (thread_time_after_eq32(now, threads[i]->sleep_until)) {
                                threads[i]->sleep_until = 0;
                                thread_note_ready_nolock(threads[i]);
                        }
                } else if (threads[i] && threads[i]->state == THREAD_BLOCKED && threads[i]->sleep_until != 0) {
                        if (thread_time_after_eq32(now, threads[i]->sleep_until)) {
                                threads[i]->sleep_until = 0;
                                thread_note_ready_nolock(threads[i]);
                        }
                }
        }

        thread_t *cur = thread_current();
        if (!cur) {
                int cid = smp_sched_cpu_id();
                thread_t *d = (cid == 0) ? &main_thread : idle_thread_by_cpu[cid];
                if (!d && cid != 0) {
                        release_irqrestore(&sched_lock, irqf);
                        for (;;)
                                asm volatile("cli; hlt" ::: "memory");
                }
                if (!d)
                        d = &main_thread;
                sched_set_current(d);
                cur = d;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                release_irqrestore(&sched_lock, irqf);
                return;
        }

        /* CFS-like fairness: lowest weighted runtime first, FIFO as a tie
           breaker. nice affects CPU share, never absolute eligibility. */
        thread_t *pick = NULL;
        uint64_t best_vruntime = 0;
        uint32_t best_seq = 0;
        int my_cpu = smp_sched_cpu_id();
        thread_t *my_idle = NULL;
        if (my_cpu >= 0 && my_cpu < SMP_MAX_CPUS)
                my_idle = idle_thread_by_cpu[my_cpu];

        /*
         * Slice expiry: a RUNNING htop/poll task otherwise keeps the BSP forever
         * while a tty reader sits READY after keyboard unblock. Requeue current
         * with a bumped vruntime so the waiter wins the next pick.
         */
        if (my_cpu >= 0 && my_cpu < SMP_MAX_CPUS && need_resched[my_cpu] &&
            cur && cur->state == THREAD_RUNNING && !thread_is_any_idle(cur)) {
                int peer_ready = 0;
                for (int i = 0; i < thread_count; ++i) {
                        thread_t *t = threads[i];
                        if (!t || t == cur || thread_is_any_idle(t))
                                continue;
                        if (t->state == THREAD_READY && !t->vfork_waiting) {
                                peer_ready = 1;
                                break;
                        }
                }
                need_resched[my_cpu] = 0;
                if (peer_ready) {
                        cur->sched_vruntime += thread_vruntime_delta(cur) * 8u;
                        thread_note_ready_nolock(cur);
                }
        } else if (my_cpu >= 0 && my_cpu < SMP_MAX_CPUS) {
                need_resched[my_cpu] = 0;
        }

        for (int pass = 0; pass < 2 && !pick; pass++) {
                for (int i = 0; i < thread_count; ++i) {
                        thread_t *t = threads[i];
                        if (!t || t->state != THREAD_READY)
                                continue;
                        /* Frozen vfork parent must not run (see note_ready guard). */
                        if (t->vfork_waiting)
                                continue;
                        /*
                         * syscall_entry64 still has a legacy global register/RSP
                         * snapshot used by the assembly prologue.  Two ring-3
                         * tasks entering SYSCALL on separate CPUs overwrite that
                         * snapshot before C can copy it to thread-local storage.
                         * Keep userspace on BSP until that entry ABI is entirely
                         * per-CPU; kernel/idle work may still run on APs.
                         */
                        if (t->ring == 3 && my_cpu != 0)
                                continue;
                        if ((int)(t->tid ? t->tid : 1) == thread_get_init_user_tid()) {
                                static int pid1_see_left = 24;
                                if (pid1_see_left-- > 0)
                                        devel_printf("sched: see PID1 pass=%d tid=%d state=%d rsp=0x%llx bound=%d cpu=%d\n",
                                                pass,
                                                (int)t->tid,
                                                (int)t->state,
                                                (unsigned long long)t->context.rsp,
                                                t->bound_cpu,
                                                my_cpu);
                        }
                        if (t->bound_cpu >= 0 && t->bound_cpu != my_cpu)
                                continue;
                        if (pass == 0 && thread_is_any_idle(t))
                                continue;
                        if (pass == 1 && thread_is_any_idle(t) && t != my_idle)
                                continue;
                        if (!thread_context_valid(t)) {
                                if ((int)(t->tid ? t->tid : 1) == thread_get_init_user_tid()) {
                                        kprintf("sched: PID1 context invalid t=0x%llx rsp=0x%llx kstack=0x%llx\n",
                                                (unsigned long long)(uintptr_t)t,
                                                (unsigned long long)t->context.rsp,
                                                (unsigned long long)t->kernel_stack);
                                }
                                t->state = THREAD_TERMINATED;
                                continue;
                        }
                        if (pick == NULL ||
                            t->sched_vruntime < best_vruntime ||
                            (t->sched_vruntime == best_vruntime &&
                             t->sched_fifo_seq < best_seq)) {
                                pick = t;
                                best_vruntime = t->sched_vruntime;
                                best_seq = t->sched_fifo_seq;
                        }
                }
        }

        if (pick == cur) {
                /* Slice-expiry may have marked us READY for fair picking; if we
                 * keep the CPU, restore RUNNING so blockers and preempt checks
                 * still see an active task. */
                if (cur && cur->state == THREAD_READY)
                        cur->state = THREAD_RUNNING;
                release_irqrestore(&sched_lock, irqf);
                return;
        }

        if (pick) {
                thread_t *prev = cur;
                if ((int)(pick->tid ? pick->tid : 1) == thread_get_init_user_tid()) {
                        static int pid1_sw_left = 24;
                        if (pid1_sw_left-- > 0)
                                devel_printf("sched: switching to PID1 from tid=%d prev_state=%d pick_rsp=0x%llx\n",
                                        prev ? (int)prev->tid : -1,
                                        prev ? (int)prev->state : -1,
                                        (unsigned long long)pick->context.rsp);
                }
                if (!thread_context_valid(prev)) {
                        prev = &main_thread;
                        sched_set_current(&main_thread);
                        cur = &main_thread;
                }
                sched_set_current(pick);
                cur = pick;
                if (cur->bound_cpu == my_cpu && !thread_is_any_idle(cur))
                        cur->bound_cpu = -1;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                if (cur->kernel_stack) {
                        tss_set_rsp0(cur->kernel_stack);
                }
                if (cur->ring == 3)
                        thread_set_current_user(cur);
                else
                        thread_set_current_user(NULL);
                if (cur->ring == 3) {
                        set_user_fs_base(cur->user_fs_base);
                } else {
                        set_user_fs_base(0);
                }
                int dbg_fork_first = DEVEL_DEBUG && cur->ring == 3 && cur->parent_tid >= 0 &&
                        cur->fork_child_user_rip != 0;
                if (dbg_fork_first) {
                        uint64_t live_rsp = 0, live_pa = 0, child_rsp_pa = 0;
                        asm volatile("mov %%rsp, %0" : "=r"(live_rsp));
                        int live_rc = mm_va_leaf_pa(cur->mm, live_rsp, &live_pa);
                        int child_rc = mm_va_leaf_pa(cur->mm, cur->context.rsp,
                                                    &child_rsp_pa);
                        devel_printf("sched-fork[40] tid=%d mm=0x%llx live-rsp=0x%llx/%d->0x%llx "
                                "child-rsp=0x%llx/%d->0x%llx ret=0x%llx entry=0x%llx\n",
                                (int)(cur->tid ? cur->tid : 1),
                                (unsigned long long)(cur->mm ? cur->mm->cr3 : 0),
                                (unsigned long long)live_rsp, live_rc,
                                (unsigned long long)live_pa,
                                (unsigned long long)cur->context.rsp, child_rc,
                                (unsigned long long)child_rsp_pa,
                                (unsigned long long)(cur->context.rsp
                                    ? *(uint64_t *)(uintptr_t)cur->context.rsp : 0),
                                (unsigned long long)cur->context.r12);
                }
                mm_switch(cur->mm);
                if (dbg_fork_first)
                        devel_printf("sched-fork[41] child cr3 active=0x%llx\n",
                                (unsigned long long)paging_read_cr3());
                syscall_bind_kstack_for_thread(cur);
                if (!thread_context_valid(cur)) {
                        cur->state = THREAD_TERMINATED;
                        sched_set_current(&main_thread);
                        cur = &main_thread;
                        cur->sched_target_cpu = -1;
                        cur->state = THREAD_RUNNING;
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
                fpu_switch(prev, cur);
                if (dbg_fork_first)
                        devel_printf("sched-fork[42] fpu ready; switching context\n");
                context_switch_with_prev(&prev->context, &cur->context, prev);
                restore_irqflags(irqf);
                return;
        }

        if (cur->state == THREAD_RUNNING) {
                release_irqrestore(&sched_lock, irqf);
                return;
        }
        if (my_idle && cur != my_idle && thread_context_valid(my_idle)) {
                thread_t *prev = cur;
                if (!thread_context_valid(prev))
                        prev = &main_thread;
                sched_set_current(my_idle);
                cur = my_idle;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                mm_switch(cur->mm);
                fpu_switch(prev, cur);
                context_switch_with_prev(&prev->context, &cur->context, prev);
                restore_irqflags(irqf);
                return;
        }
        sched_set_current(&main_thread);
        cur = &main_thread;
        cur->sched_target_cpu = -1;
        cur->state = THREAD_RUNNING;
        mm_switch(cur->mm);
        release_irqrestore(&sched_lock, irqf);
}

void thread_unblock(int pid) {
        unsigned long irqf;
        int woke = 0;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid &&
                    (threads[i]->state == THREAD_BLOCKED || threads[i]->state == THREAD_SLEEPING)) {
                        threads[i]->sleep_until = 0;
                        thread_note_ready_nolock(threads[i]);
                        woke = 1;
                        break;
                }
        }
        release_irqrestore(&sched_lock, irqf);
        /* Keyboard/pipe wakeups must be visible to the next schedule point —
         * otherwise a busy htop syscall keeps the shell READY but unscheduled. */
        if (woke)
                thread_request_resched();
}

/* Wake a fork child only after the parent syscall frame is complete. */
void thread_unblock_fork_child(int pid) {
        unsigned long irqf;
        int cpu = smp_sched_cpu_id();
        int woke = 0;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t || t->tid != (uint64_t)(unsigned)pid)
                        continue;
                /* Keep the first post-fork dispatch on the parent's CPU; another
                   CPU can otherwise run the child before the parent has iretq'd. */
                if (cpu >= 0 && cpu < SMP_MAX_CPUS)
                        t->bound_cpu = cpu;
                if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
                        thread_t *cur = current_cpu[cpu >= 0 && cpu < SMP_MAX_CPUS ? cpu : 0];
                        t->sleep_until = 0;
                        /*
                         * Linux wake_up_new_task / place_entity: put the child
                         * ahead of the forking parent so vfork/waitpid do not
                         * sit an extra timer quantum (felt as ~1s under load).
                         */
                        if (cur && cur->sched_vruntime > 0)
                                t->sched_vruntime = cur->sched_vruntime - 1;
                        else
                                t->sched_vruntime = 0;
                        thread_note_ready_nolock(t);
                        /* note_ready bumps fifo_seq; win equal-vruntime ties. */
                        t->sched_fifo_seq = 0;
                        woke = 1;
                }
                break;
        }
        release_irqrestore(&sched_lock, irqf);
        if (woke)
                thread_request_resched();
}

/* SIGINT (Ctrl+C): terminate all threads in the foreground process group. */
void thread_send_sigint_to_pgrp(int pgrp) {
        if (pgrp < 0) return;
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if (t->pgid != pgrp) continue;
                if (t->state != THREAD_TERMINATED) {
                        t->pending_signals |= (1ULL << (2 - 1)); /* SIGINT */
                        if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
                                t->sleep_until = 0;
                                thread_note_ready(t);
                        }
                }
        }
}

/* SIGHUP: used when activating an empty VT so init respawns getty on the visible console. */
void thread_send_sighup_to_pgrp(int pgrp) {
        if (pgrp < 0) return;
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if (t->pgid != pgrp) continue;
                if (t->state == THREAD_TERMINATED) continue;
                t->pending_signals |= (1ULL << (1 - 1)); /* SIGHUP */
                if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
                        t->sleep_until = 0;
                        thread_note_ready(t);
                }
        }
}

// get thread info by pid
thread_t* thread_get(int pid) {
        uint64_t want = (uint64_t)(unsigned)pid;
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == want) {
                        return threads[i];
                }
        }
        return NULL;
}

thread_t* thread_find_child_of(int parent_tid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->parent_tid == parent_tid) return threads[i];
        }
        return NULL;
}

thread_t* thread_get_by_index(int idx) {
    if (idx < 0 || idx >= thread_count) return NULL;
    return threads[idx];
}

int thread_get_pid(const char* name) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && strcmp(threads[i]->name, name) == 0) {
                        return threads[i]->tid;
                }
        }
        return -1;
}

int thread_get_state(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid) {
                        return threads[i]->state;
                }
        }
        return -1;
}

int thread_get_count() {
        return thread_count;
}

thread_t* thread_get_current_user(void) {
        int cpu = smp_sched_cpu_id();
        if (cpu < 0 || cpu >= SMP_MAX_CPUS)
                cpu = 0;
        return current_user[cpu];
}

void thread_set_current_user(thread_t* t) {
        int cpu = smp_sched_cpu_id();
        if (cpu < 0 || cpu >= SMP_MAX_CPUS)
                cpu = 0;
        current_user[cpu] = t;
}

void thread_set_current(thread_t *t) {
        if (!t) return;
        sched_set_current(t);
}
thread_t* thread_find_by_tty(int tty) {
    for (int i = 0; i < thread_count; ++i) {
        if (threads[i] && threads[i]->attached_tty == tty) return threads[i];
    }
    return NULL;
}

void thread_proc_env_free(thread_t *t) {
        if (!t || !t->proc_environ)
                return;
        for (int i = 0; t->proc_environ[i]; i++)
                kfree(t->proc_environ[i]);
        kfree(t->proc_environ);
        t->proc_environ = NULL;
}

void thread_proc_env_set(thread_t *t, const char *const envp[]) {
        if (!t)
                return;
        thread_proc_env_free(t);
        if (!envp || !envp[0])
                return;
        int n = 0;
        while (envp[n])
                n++;
        char **arr = (char **)kmalloc((size_t)(n + 1) * sizeof(char *));
        if (!arr)
                return;
        for (int i = 0; i < n; i++) {
                size_t l = strlen(envp[i]);
                char *s = (char *)kmalloc(l + 1);
                if (!s) {
                        for (int j = 0; j < i; j++)
                                kfree(arr[j]);
                        kfree(arr);
                        return;
                }
                memcpy(s, envp[i], l + 1);
                arr[i] = s;
        }
        arr[n] = NULL;
        t->proc_environ = arr;
}

void thread_proc_env_inherit(thread_t *child, thread_t *parent) {
        if (!child || !parent)
                return;
        thread_proc_env_free(child);
        if (!parent->proc_environ)
                return;
        int n = 0;
        while (n < 512 && parent->proc_environ[n]) {
                const char *e = parent->proc_environ[n];
                uintptr_t eu = (uintptr_t)e;
                if (!e || eu < 0x1000u || eu >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                        break;
                n++;
        }
        if (n == 0)
                return;
        char **arr = (char **)kmalloc((size_t)(n + 1) * sizeof(char *));
        if (!arr)
                return;
        for (int i = 0; i < n; i++) {
                size_t l = strlen(parent->proc_environ[i]);
                char *s = (char *)kmalloc(l + 1);
                if (!s) {
                        for (int j = 0; j < i; j++)
                                kfree(arr[j]);
                        kfree(arr);
                        return;
                }
                memcpy(s, parent->proc_environ[i], l + 1);
                arr[i] = s;
        }
        arr[n] = NULL;
        child->proc_environ = arr;
}