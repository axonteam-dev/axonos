#include <process.h>
#include <thread.h>
#include <heap.h>
#include <string.h>
#include <spinlock.h>
#include <vga.h>
#include <debug.h>
#include <mm.h>
#include <paging.h>
#include <exec.h>
#include <mmio.h>
#include <pit.h>

extern void kprintf(const char *fmt, ...);

#define PROCESS_TABLE_MAX 1024

static process_t *process_table[PROCESS_TABLE_MAX];
static uint64_t next_pid = 1;
static spinlock_t process_lock = { 0 };

void process_init(void) {
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    memset(process_table, 0, sizeof(process_table));
    next_pid = 1;
    release_irqrestore(&process_lock, flags);
}

static process_t *process_alloc_locked(process_t *parent) {
    int slot = -1;
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        if (!process_table[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return NULL;

    process_t *p = (process_t *)kmalloc(sizeof(*p));
    if (!p)
        return NULL;
    memset(p, 0, sizeof(*p));
    p->pid = next_pid++;
    if (p->pid == 0)
        p->pid = next_pid++;
    p->state = PROCESS_ALIVE;
    p->parent = parent;
    p->pgid = (int)p->pid;
    p->sid = (int)p->pid;
    strncpy(p->cwd, "/", sizeof(p->cwd));
    p->cwd[sizeof(p->cwd) - 1] = '\0';
    strncpy(p->fs_root, "/", sizeof(p->fs_root));
    p->fs_root[sizeof(p->fs_root) - 1] = '\0';
    /* Default: one supplementary group matching egid (root). */
    p->ngroups = 1;
    p->groups[0] = 0;
    p->dumpable = 1; /* Linux SUID_DUMP_USER */
    p->rlim_nofile_cur = PROCESS_RLIMIT_NOFILE_SOFT;
    p->rlim_nofile_max = PROCESS_RLIMIT_NOFILE_HARD;
    p->rlim_stack_cur = 8ULL * 1024ULL * 1024ULL;
    p->rlim_stack_max = 8ULL * 1024ULL * 1024ULL;
    p->rlim_nproc_cur = 4096ULL;
    p->rlim_nproc_max = 4096ULL;
    p->rlim_as_cur = ~0ULL;
    p->rlim_as_max = ~0ULL;

    if (parent) {
        p->next_sibling = parent->first_child;
        parent->first_child = p;
        p->uid = parent->uid;
        p->euid = parent->euid;
        p->suid = parent->suid;
        p->gid = parent->gid;
        p->egid = parent->egid;
        p->sgid = parent->sgid;
        p->ngroups = parent->ngroups;
        if (p->ngroups < 0)
            p->ngroups = 0;
        p->dumpable = parent->dumpable;
        if (p->ngroups > AXON_NGROUPS_MAX)
            p->ngroups = AXON_NGROUPS_MAX;
        if (p->ngroups > 0)
            memcpy(p->groups, parent->groups, (size_t)p->ngroups * sizeof(gid_t));
        p->umask = parent->umask;
        p->pgid = parent->pgid;
        p->sid = parent->sid;
        p->rlim_nofile_cur = parent->rlim_nofile_cur;
        p->rlim_nofile_max = parent->rlim_nofile_max;
        p->rlim_stack_cur = parent->rlim_stack_cur;
        p->rlim_stack_max = parent->rlim_stack_max;
        p->rlim_nproc_cur = parent->rlim_nproc_cur;
        p->rlim_nproc_max = parent->rlim_nproc_max;
        p->rlim_as_cur = parent->rlim_as_cur;
        p->rlim_as_max = parent->rlim_as_max;
        memcpy(p->cwd, parent->cwd, sizeof(p->cwd));
        memcpy(p->fs_root, parent->fs_root, sizeof(p->fs_root));
        memcpy(p->signal_handlers, parent->signal_handlers,
               sizeof(p->signal_handlers));
        memcpy(p->signal_flags, parent->signal_flags,
               sizeof(p->signal_flags));
        memcpy(p->signal_restorer, parent->signal_restorer,
               sizeof(p->signal_restorer));
        memcpy(p->signal_masks, parent->signal_masks,
               sizeof(p->signal_masks));
    }
    process_table[slot] = p;
    return p;
}

process_t *process_create(process_t *parent) {
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process_t *p = process_alloc_locked(parent);
    release_irqrestore(&process_lock, flags);
    return p;
}

process_t *process_create_init(void) {
    return process_create(NULL);
}

void process_claim_pid1(process_t *process) {
    if (!process)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    /* Previous failed init attempts may still hold PID 1 as zombies. */
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        process_t *o = process_table[i];
        if (!o || o == process || o->pid != 1)
            continue;
        o->pid = next_pid++;
        if (o->pid == 0 || o->pid == 1)
            o->pid = next_pid++;
    }
    process->pid = 1;
    process->pgid = 1;
    process->sid = 1;
    if (next_pid <= 1)
        next_pid = 2;
    release_irqrestore(&process_lock, flags);
}

void process_attach_thread(process_t *process, thread_t *thread) {
    if (!process || !thread)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    /*
     * Linux: TGID/PID is allocated at process creation and is not reused until
     * the zombie is waited on (process_reap). Do not overwrite process->pid with
     * thread->tid — tid slots are recycled by thread_reap while a zombie may
     * still hold that number, producing duplicate PIDs. BusyBox ash records the
     * fork() return value and matches waitpid(-1) against it; colliding PIDs
     * leave ps_status at -1 so getstatus() yields a non-zero exit and
     * `if ! mountinfo` / `if ! mount` take the failure path despite exit(0).
     */
    int first_attach = (process->leader == NULL);
    if (first_attach)
        process->leader = thread;
    thread->process = process;
    thread->linux_tgid = (int)process->pid;
    process->mm = thread->mm;
    /* Fork sets sid/pgid on the thread after process_create inherited them.
     * Do not clobber inherited process session ids with unset (0) thread fields. */
    if (thread->pgid > 0)
        process->pgid = thread->pgid;
    if (thread->sid > 0)
        process->sid = thread->sid;
    process->uid = thread->uid;
    process->euid = thread->euid;
    process->suid = thread->suid;
    process->gid = thread->gid;
    process->egid = thread->egid;
    process->sgid = thread->sgid;
    process->ngroups = thread->ngroups;
    if (process->ngroups < 0)
        process->ngroups = 0;
    if (process->ngroups > AXON_NGROUPS_MAX)
        process->ngroups = AXON_NGROUPS_MAX;
    if (process->ngroups > 0)
        memcpy(process->groups, thread->groups,
               (size_t)process->ngroups * sizeof(gid_t));
    process->umask = thread->umask;
    memcpy(process->cwd, thread->cwd, sizeof(process->cwd));
    memcpy(process->fs_root, thread->fs_root, sizeof(process->fs_root));
    /*
     * Publish fds only on the first attach (leader / new process).
     * CLONE_THREAD peers arrive with empty thread->fds; copying that over the
     * shared process table wiped stdin/stdout so the next open()/socket()
     * reused fd 0/1/2. write() via syscall_fd_get then hit a socket instead of
     * the tty → curl error 23 ("passed N returned 0").
     */
    if (first_attach) {
        for (int i = 0; i < PROCESS_MAX_FD; ++i)
            process->fds[i] = thread->fds[i];
    }
    release_irqrestore(&process_lock, flags);
}

void process_sync_from_thread(process_t *process, thread_t *thread) {
    if (!process || !thread)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process->mm = thread->mm;
    if (thread->pgid > 0)
        process->pgid = thread->pgid;
    if (thread->sid > 0)
        process->sid = thread->sid;
    process->uid = thread->uid;
    process->euid = thread->euid;
    process->suid = thread->suid;
    process->gid = thread->gid;
    process->egid = thread->egid;
    process->sgid = thread->sgid;
    process->ngroups = thread->ngroups;
    if (process->ngroups < 0)
        process->ngroups = 0;
    if (process->ngroups > AXON_NGROUPS_MAX)
        process->ngroups = AXON_NGROUPS_MAX;
    if (process->ngroups > 0)
        memcpy(process->groups, thread->groups,
               (size_t)process->ngroups * sizeof(gid_t));
    process->umask = thread->umask;
    memcpy(process->cwd, thread->cwd, sizeof(process->cwd));
    memcpy(process->fs_root, thread->fs_root, sizeof(process->fs_root));
    for (int i = 0; i < PROCESS_MAX_FD; ++i)
        process->fds[i] = thread->fds[i];
    release_irqrestore(&process_lock, flags);
}

process_t *process_find(uint64_t pid) {
    process_t *result = NULL;
    process_t *zombie = NULL;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        process_t *p = process_table[i];
        if (!p || p->pid != pid)
            continue;
        /* Linux kill/waitpid(pid>0): pid is TGID, not a tid slot. */
        if (p->state == PROCESS_ALIVE) {
            if (p->leader && p->leader->state != THREAD_TERMINATED) {
                result = p;
                break;
            }
            if (!zombie)
                zombie = p;
            continue;
        }
        if (!zombie)
            zombie = p;
    }
    if (!result)
        result = zombie;
    release_irqrestore(&process_lock, flags);
    return result;
}

static int process_wait_spec_match(const process_t *p, int pid, int pgid) {
    if (!p)
        return 0;
    if (pid > 0)
        return p->pid == (uint64_t)(unsigned)pid;
    if (pid == -1)
        return 1;
    if (pid == 0)
        return p->pgid == pgid;
    return p->pgid == -pid;
}

static void process_relink_child_locked(process_t *parent, process_t *p) {
    int linked = 0;
    if (p->parent != parent)
        p->parent = parent;
    for (process_t *c = parent->first_child; c; c = c->next_sibling) {
        if (c == p) {
            linked = 1;
            break;
        }
    }
    if (!linked) {
        p->next_sibling = parent->first_child;
        parent->first_child = p;
    }
}

process_t *process_find_child(process_t *parent, int pid, int pgid,
                              int zombies_only, int *has_match) {
    if (has_match)
        *has_match = 0;
    if (!parent)
        return NULL;
    process_t *result = NULL;
    int matched = 0;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    /* Linux waitpid(pid>0): TGID only. Relink lost sibling/parent pointers so
     * the real_parent invariant holds; do not match by tid slot. */
    for (process_t *p = parent->first_child; p; p = p->next_sibling) {
        if (!process_wait_spec_match(p, pid, pgid))
            continue;
        matched = 1;
        if (!zombies_only || p->state == PROCESS_ZOMBIE) {
            result = p;
            break;
        }
    }
    if (!matched) {
        /* Repair: child may still have parent==us while missing from first_child. */
        for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
            process_t *p = process_table[i];
            if (!p || p->parent != parent)
                continue;
            if (!process_wait_spec_match(p, pid, pgid))
                continue;
            process_relink_child_locked(parent, p);
            matched = 1;
            if (!result && (!zombies_only || p->state == PROCESS_ZOMBIE))
                result = p;
            if (result)
                break;
        }
    }
    if (!matched) {
        /* Restore real_parent when parent_tid names any thread of this process
         * (fork from a worker, not only the group leader). */
        for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
            process_t *p = process_table[i];
            thread_t *pt;
            int cpt;
            if (!p || p == parent || !p->leader)
                continue;
            cpt = p->leader->parent_tid;
            if (cpt < 0)
                continue;
            pt = thread_get(cpt);
            if (!pt || pt->process != parent)
                continue;
            if (!process_wait_spec_match(p, pid, pgid))
                continue;
            process_relink_child_locked(parent, p);
            matched = 1;
            if (!result && (!zombies_only || p->state == PROCESS_ZOMBIE))
                result = p;
            if (result)
                break;
        }
    }
    if (has_match)
        *has_match = matched;
    release_irqrestore(&process_lock, flags);
    return result;
}

void process_mark_zombie(process_t *process, int status) {
    if (!process)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process->exit_status = status;
    process->state = PROCESS_ZOMBIE;
    release_irqrestore(&process_lock, flags);
}

void process_reparent_children(process_t *process, process_t *new_parent) {
    if (!process || process == new_parent)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process_t *child = process->first_child;
    process->first_child = NULL;
    while (child) {
        process_t *next = child->next_sibling;
        child->parent = new_parent;
        if (child->leader) {
            if (new_parent)
                child->leader->linux_ppid = (int)new_parent->pid;
            else
                child->leader->linux_ppid = 1;
        }
        if (new_parent) {
            child->next_sibling = new_parent->first_child;
            new_parent->first_child = child;
        } else {
            child->next_sibling = NULL;
        }
        child = next;
    }
    release_irqrestore(&process_lock, flags);
}

int process_reap(process_t *parent, process_t *child) {
    if (!parent || !child || child->state != PROCESS_ZOMBIE)
        return -1;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process_t **link = &parent->first_child;
    while (*link && *link != child)
        link = &(*link)->next_sibling;
    if (*link != child) {
        release_irqrestore(&process_lock, flags);
        return -1;
    }
    *link = child->next_sibling;
    child->parent = NULL;
    child->next_sibling = NULL;
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        if (process_table[i] == child) {
            process_table[i] = NULL;
            break;
        }
    }
    release_irqrestore(&process_lock, flags);
    kfree(child);
    return 0;
}

int process_reap_zombie(process_t *child) {
    if (!child || child->state != PROCESS_ZOMBIE)
        return -1;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    if (child->parent) {
        process_t **link = &child->parent->first_child;
        while (*link && *link != child)
            link = &(*link)->next_sibling;
        if (*link == child)
            *link = child->next_sibling;
    }
    child->parent = NULL;
    child->next_sibling = NULL;
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        if (process_table[i] == child) {
            process_table[i] = NULL;
            break;
        }
    }
    release_irqrestore(&process_lock, flags);
    kfree(child);
    return 0;
}

int process_discard(process_t *parent, process_t *child) {
    if (!parent || !child)
        return -1;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    process_t **link = &parent->first_child;
    while (*link && *link != child)
        link = &(*link)->next_sibling;
    if (*link != child || child->parent != parent) {
        release_irqrestore(&process_lock, flags);
        return -1;
    }
    *link = child->next_sibling;
    child->parent = NULL;
    child->next_sibling = NULL;
    child->leader = NULL;
    child->mm = NULL;
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        if (process_table[i] == child) {
            process_table[i] = NULL;
            break;
        }
    }
    release_irqrestore(&process_lock, flags);
    kfree(child);
    return 0;
}

void process_set_vfork_parent(process_t *child, process_t *parent) {
    if (!child || !parent)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    child->vfork_parent = parent;
    child->vfork_parent_blocked = 1;
    release_irqrestore(&process_lock, flags);
}

void process_release_vfork_parent(process_t *child,
                                  process_vfork_release_reason_t reason) {
    if (!child)
        return;
    thread_t *wake = NULL;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    if (child->vfork_parent_blocked && child->vfork_parent) {
        wake = child->vfork_parent->leader;
        child->vfork_parent_blocked = 0;
        child->vfork_parent = NULL;
    }
    release_irqrestore(&process_lock, flags);
    if (wake) {
        /*
         * Linux complete_vfork_done(): clear vfork wait and wake the parent.
         * Do NOT mm_switch/CR3 to the parent here — this runs on the child's
         * CPU after activate_mm(new). Switching would leave enter_user_mode
         * on the parent's aspace so _start pops the parent's stack word as
         * argc (seen: argc=0x3ffffe40 → envp=0x23ffff020 → mount #PF).
         * Parent CR3 is installed by the scheduler when it actually runs.
         */
        wake->vfork_waiting = 0;
        if (wake->name[0] &&
            (strstr(wake->name, "linuxrc") || strstr(wake->name, "/bin/sh") ||
             strstr(wake->name, "busybox") || strstr(wake->name, "init")))
            devel_printf("vfork-release: parent=%d child_pid=%llu reason=%d\n",
                (int)(wake->tid ? wake->tid : 1),
                (unsigned long long)child->pid,
                (int)reason);
        thread_unblock((int)(wake->tid ? wake->tid : 1));
    }
}

void process_exec_reset(process_t *process, thread_t *thread) {
    if (!process)
        return;
    for (int fd = 0; fd < PROCESS_MAX_FD; ++fd) {
        if (!process->fd_cloexec[fd])
            continue;
        struct fs_file *file = process->fds[fd];
        if (!file)
            continue;
        int n = 0;
        for (int j = fd; j < PROCESS_MAX_FD; ++j) {
            if (!process->fd_cloexec[j] || process->fds[j] != file)
                continue;
            process->fds[j] = NULL;
            process->fd_cloexec[j] = 0;
            if (thread)
                thread->fds[j] = NULL;
            n++;
        }
        for (int k = 0; k < n; k++)
            fs_file_free(file);
    }
    for (int sig = 1; sig <= PROCESS_SIGNAL_MAX; ++sig) {
        /* SIG_DFL=0 and SIG_IGN=1; ignored dispositions survive exec. */
        if (process->signal_handlers[sig] > 1) {
            process->signal_handlers[sig] = 0;
            process->signal_flags[sig] = 0;
            process->signal_restorer[sig] = 0;
            process->signal_masks[sig] = 0;
        }
    }
    /* POSIX/Linux execve: interval timers are disarmed; the signal mask is kept. */
    process->itimer_expire_ms = 0;
    process->itimer_interval_ms = 0;
    process_posix_timers_flush_pid(process->pid);
    if (thread) {
        thread->robust_list_head = 0;
        thread->robust_list_len = 0;
        thread->clear_child_tid = 0;
        thread->restore_sigmask = 0;
    }
}

uint64_t process_pid(const thread_t *thread) {
    if (thread && thread->process)
        return thread->process->pid;
    return thread ? (thread->tid ? thread->tid : 1) : 0;
}

uint64_t process_ppid(const thread_t *thread) {
    if (thread && thread->process && thread->process->parent)
        return thread->process->parent->pid;
    return 0;
}

/* Ensure `child` is linked under `parent` for wait4. Safe if already linked. */
int process_adopt_child(process_t *parent, process_t *child) {
    if (!parent || !child || child == parent)
        return -1;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    if (child->parent && child->parent != parent) {
        process_t **link = &child->parent->first_child;
        while (*link && *link != child)
            link = &(*link)->next_sibling;
        if (*link == child)
            *link = child->next_sibling;
    }
    int linked = 0;
    for (process_t *c = parent->first_child; c; c = c->next_sibling) {
        if (c == child) { linked = 1; break; }
    }
    child->parent = parent;
    if (!linked) {
        child->next_sibling = parent->first_child;
        parent->first_child = child;
    }
    release_irqrestore(&process_lock, flags);
    return 0;
}

int process_collect_signal_targets(process_t *caller, int pid,
                                   process_t **out, int out_max) {
    if (!out || out_max <= 0)
        return 0;
    int mcount = 0;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        process_t *p = process_table[i];
        if (!p || p->state != PROCESS_ALIVE || !p->leader)
            continue;
        if (p->leader->state == THREAD_TERMINATED)
            continue;
        int match;
        if (pid > 0)
            match = p->pid == (uint64_t)(unsigned)pid;
        else if (pid == 0)
            match = caller && p->pgid == caller->pgid;
        else if (pid == -1)
            match = p->pid != 1;
        else
            match = p->pgid == -pid;
        if (!match)
            continue;
        if (mcount < out_max)
            out[mcount] = p;
        mcount++;
    }
    release_irqrestore(&process_lock, flags);
    return mcount > out_max ? out_max : mcount;
}

int process_signal_targets(process_t *caller, int pid, int sig) {
    process_t *matched[PROCESS_TABLE_MAX];
    int mcount = process_collect_signal_targets(caller, pid, matched,
                                                 PROCESS_TABLE_MAX);

    int count = 0;
    /* Linux kill(2): deliver to every live thread in the thread group. */
    for (int mi = 0; mi < mcount; ++mi) {
        process_t *p = matched[mi];
        int hit = 0;
        for (int i = 0; i < thread_get_count(); ++i) {
            thread_t *t = thread_get_by_index(i);
            if (!t || t->state == THREAD_TERMINATED) continue;
            if (t->process != p) continue;
            hit = 1;
            count++;
            if (sig == 0)
                continue;
            t->pending_signals |= (1ULL << (sig - 1));
            if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING)
                thread_unblock((int)(t->tid ? t->tid : 1));
        }
        if (!hit && p->leader && p->leader->state != THREAD_TERMINATED) {
            count++;
            if (sig != 0) {
                p->leader->pending_signals |= (1ULL << (sig - 1));
                if (p->leader->state == THREAD_BLOCKED ||
                    p->leader->state == THREAD_SLEEPING)
                    thread_unblock((int)(p->leader->tid ? p->leader->tid : 1));
            }
        }
    }
    return count;
}

#ifndef SIGALRM
#define SIGALRM 14
#endif

void process_arm_itimer_real(process_t *p, uint64_t expire_ms, uint32_t interval_ms) {
    if (!p)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    p->itimer_interval_ms = interval_ms;
    p->itimer_expire_ms = expire_ms;
    release_irqrestore(&process_lock, flags);
}

void process_get_itimer_real(process_t *p, uint32_t *value_ms, uint32_t *interval_ms,
                             uint64_t now_ms) {
    if (value_ms)
        *value_ms = 0;
    if (interval_ms)
        *interval_ms = 0;
    if (!p)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    if (interval_ms)
        *interval_ms = p->itimer_interval_ms;
    if (value_ms) {
        if (p->itimer_expire_ms == 0 || now_ms >= p->itimer_expire_ms)
            *value_ms = 0;
        else {
            uint64_t rem = p->itimer_expire_ms - now_ms;
            *value_ms = rem > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)rem;
        }
    }
    release_irqrestore(&process_lock, flags);
}

void process_itimer_tick(uint64_t now_ms) {
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
        process_t *p = process_table[i];
        if (!p || p->state != PROCESS_ALIVE || p->itimer_expire_ms == 0)
            continue;
        if (now_ms < p->itimer_expire_ms)
            continue;
        if (p->itimer_interval_ms)
            p->itimer_expire_ms = now_ms + (uint64_t)p->itimer_interval_ms;
        else
            p->itimer_expire_ms = 0;
        process_t *fire = p;
        release_irqrestore(&process_lock, flags);
        for (int ti = 0; ti < thread_get_count(); ++ti) {
            thread_t *t = thread_get_by_index(ti);
            if (!t || t->process != fire || t->state == THREAD_TERMINATED)
                continue;
            t->pending_signals |= (1ULL << (SIGALRM - 1));
            if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING)
                thread_unblock((int)(t->tid ? t->tid : 1));
        }
        thread_request_resched();
        acquire_irqsave(&process_lock, &flags);
    }
    release_irqrestore(&process_lock, flags);
    process_posix_timer_tick(now_ms);
}

/* ---- POSIX interval timers (timer_create / timer_settime) ---- */

#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EAGAIN
#define EAGAIN 11
#endif
#ifndef ESRCH
#define ESRCH 3
#endif

enum {
    AXON_SIGEV_SIGNAL = 0,
    AXON_SIGEV_NONE = 1,
    AXON_SIGEV_THREAD = 2,
    AXON_SIGEV_THREAD_ID = 4,
};

#define AXON_POSIX_TIMER_MAX 128

typedef struct {
    int used;
    int32_t id;
    int clockid;
    int notify;
    int signo;
    int32_t notify_tid; /* SIGEV_THREAD_ID target (musl timer helper) */
    uint64_t owner_pid;
    uint64_t expire_ms; /* 0 = disarmed */
    uint32_t interval_ms;
} axon_posix_timer_t;

static axon_posix_timer_t g_posix_timers[AXON_POSIX_TIMER_MAX];
static int32_t g_posix_timer_next_id = 1;
static spinlock_t g_posix_timer_lock = { 0 };

int process_posix_timer_create(int clockid, const void *sevp, size_t sev_len,
                               int32_t *out_id) {
    if (!out_id)
        return -EFAULT;
    /* Linux: CLOCK_REALTIME=0, CLOCK_MONOTONIC=1, CLOCK_BOOTTIME=7, … */
    if (clockid < 0)
        return -EINVAL;

    int notify = AXON_SIGEV_SIGNAL;
    int signo = SIGALRM;
    int32_t notify_tid = 0;
    if (sevp && sev_len >= 20) {
        const uint8_t *b = (const uint8_t *)sevp;
        int32_t n_signo = 0, n_notify = 0, n_tid = 0;
        memcpy(&n_signo, b + 8, 4);
        memcpy(&n_notify, b + 12, 4);
        memcpy(&n_tid, b + 16, 4);
        notify = n_notify;
        if (n_signo > 0 && n_signo < 64)
            signo = n_signo;
        if (notify == AXON_SIGEV_THREAD_ID)
            notify_tid = n_tid;
        if (notify == AXON_SIGEV_THREAD) {
            /* Kernel never sees raw SIGEV_THREAD (musl converts). Reject. */
            return -EINVAL;
        }
        if (notify != AXON_SIGEV_SIGNAL && notify != AXON_SIGEV_NONE &&
            notify != AXON_SIGEV_THREAD_ID)
            return -EINVAL;
    }

    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    uint64_t owner_pid = cur && cur->process ? cur->process->pid : 0;

    unsigned long flags;
    acquire_irqsave(&g_posix_timer_lock, &flags);
    int slot = -1;
    for (int i = 0; i < AXON_POSIX_TIMER_MAX; i++) {
        if (!g_posix_timers[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        release_irqrestore(&g_posix_timer_lock, flags);
        return -EAGAIN; /* Linux: too many timers */
    }
    int32_t id = g_posix_timer_next_id++;
    if (g_posix_timer_next_id <= 0)
        g_posix_timer_next_id = 1;
    axon_posix_timer_t *t = &g_posix_timers[slot];
    memset(t, 0, sizeof(*t));
    t->used = 1;
    t->id = id;
    t->clockid = clockid;
    t->notify = notify;
    t->signo = signo;
    t->notify_tid = notify_tid;
    t->owner_pid = owner_pid;
    release_irqrestore(&g_posix_timer_lock, flags);
    *out_id = id;
    return 0;
}

int process_posix_timer_settime(int32_t timerid, int flags,
                                uint64_t value_ms, uint32_t interval_ms,
                                uint64_t *old_value_ms, uint32_t *old_interval_ms) {
    (void)flags; /* TIMER_ABSTIME: treat as relative for now (monotonic ms). */
    uint64_t now = pit_get_time_ms();
    unsigned long fl;
    acquire_irqsave(&g_posix_timer_lock, &fl);
    axon_posix_timer_t *t = NULL;
    for (int i = 0; i < AXON_POSIX_TIMER_MAX; i++) {
        if (g_posix_timers[i].used && g_posix_timers[i].id == timerid) {
            t = &g_posix_timers[i];
            break;
        }
    }
    if (!t) {
        release_irqrestore(&g_posix_timer_lock, fl);
        return -EINVAL;
    }
    if (old_interval_ms)
        *old_interval_ms = t->interval_ms;
    if (old_value_ms) {
        if (t->expire_ms == 0 || now >= t->expire_ms)
            *old_value_ms = 0;
        else
            *old_value_ms = t->expire_ms - now;
    }
    t->interval_ms = interval_ms;
    if (value_ms == 0)
        t->expire_ms = 0;
    else
        t->expire_ms = now + value_ms;
    release_irqrestore(&g_posix_timer_lock, fl);
    return 0;
}

void process_posix_timers_flush_pid(uint64_t pid) {
    unsigned long fl;
    if (!pid)
        return;
    acquire_irqsave(&g_posix_timer_lock, &fl);
    for (int i = 0; i < AXON_POSIX_TIMER_MAX; i++) {
        if (g_posix_timers[i].used && g_posix_timers[i].owner_pid == pid)
            memset(&g_posix_timers[i], 0, sizeof(g_posix_timers[i]));
    }
    release_irqrestore(&g_posix_timer_lock, fl);
}

int process_posix_timer_delete(int32_t timerid) {
    unsigned long fl;
    acquire_irqsave(&g_posix_timer_lock, &fl);
    for (int i = 0; i < AXON_POSIX_TIMER_MAX; i++) {
        if (g_posix_timers[i].used && g_posix_timers[i].id == timerid) {
            memset(&g_posix_timers[i], 0, sizeof(g_posix_timers[i]));
            release_irqrestore(&g_posix_timer_lock, fl);
            return 0;
        }
    }
    release_irqrestore(&g_posix_timer_lock, fl);
    return -EINVAL;
}

void process_posix_timer_tick(uint64_t now_ms) {
    unsigned long fl;
    acquire_irqsave(&g_posix_timer_lock, &fl);
    for (int i = 0; i < AXON_POSIX_TIMER_MAX; i++) {
        axon_posix_timer_t *tm = &g_posix_timers[i];
        if (!tm->used || tm->expire_ms == 0 || now_ms < tm->expire_ms)
            continue;
        int notify = tm->notify;
        int signo = tm->signo;
        int32_t notify_tid = tm->notify_tid;
        uint64_t owner_pid = tm->owner_pid;
        if (tm->interval_ms)
            tm->expire_ms = now_ms + (uint64_t)tm->interval_ms;
        else
            tm->expire_ms = 0;
        release_irqrestore(&g_posix_timer_lock, fl);

        if (notify != AXON_SIGEV_NONE && signo > 0 && signo < 64) {
            uint64_t bit = 1ULL << (signo - 1);
            if (notify == AXON_SIGEV_THREAD_ID && notify_tid > 0) {
                thread_t *t = thread_get((int)notify_tid);
                if (t && t->state != THREAD_TERMINATED) {
                    t->pending_signals |= bit;
                    if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING)
                        thread_unblock((int)(t->tid ? t->tid : 1));
                }
            } else {
                for (int ti = 0; ti < thread_get_count(); ++ti) {
                    thread_t *t = thread_get_by_index(ti);
                    if (!t || t->state == THREAD_TERMINATED)
                        continue;
                    if (owner_pid && t->process && t->process->pid != owner_pid)
                        continue;
                    t->pending_signals |= bit;
                    if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING)
                        thread_unblock((int)(t->tid ? t->tid : 1));
                }
            }
            thread_request_resched();
        }

        acquire_irqsave(&g_posix_timer_lock, &fl);
    }
    release_irqrestore(&g_posix_timer_lock, fl);
}
