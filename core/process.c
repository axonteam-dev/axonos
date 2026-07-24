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
    /* Default: one supplementary group matching egid (root). */
    p->ngroups = 1;
    p->groups[0] = 0;
    p->dumpable = 1; /* Linux SUID_DUMP_USER */

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
        memcpy(p->cwd, parent->cwd, sizeof(p->cwd));
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

void process_attach_thread(process_t *process, thread_t *thread) {
    if (!process || !thread)
        return;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    /*
     * Linux TGID = PID of the thread-group leader. First attach wins as leader;
     * CLONE_THREAD peers must not overwrite leader (that broke kill/ps).
     * Unify process->pid with leader->tid so /proc and kill share one namespace.
     */
    if (!process->leader) {
        process->leader = thread;
        process->pid = thread->tid ? thread->tid : 1;
        if (next_pid <= process->pid)
            next_pid = process->pid + 1;
    }
    thread->process = process;
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
    for (int i = 0; i < PROCESS_MAX_FD; ++i)
        process->fds[i] = thread->fds[i];
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
        /* Prefer a live task with a live leader. Do not mutate state here —
         * demoting to ZOMBIE during lookup left /sbin/init stuck as Z in htop. */
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

process_t *process_find_child(process_t *parent, int pid, int pgid,
                              int zombies_only, int *has_match) {
    if (has_match)
        *has_match = 0;
    if (!parent)
        return NULL;
    process_t *result = NULL;
    unsigned long flags;
    acquire_irqsave(&process_lock, &flags);
    for (process_t *p = parent->first_child; p; p = p->next_sibling) {
        int match = 0;
        if (pid > 0)
            match = p->pid == (uint64_t)(unsigned)pid;
        else if (pid == -1)
            match = 1;
        else if (pid == 0)
            match = p->pgid == pgid;
        else
            match = p->pgid == -pid;
        if (!match)
            continue;
        if (has_match)
            *has_match = 1;
        if (!zombies_only || p->state == PROCESS_ZOMBIE) {
            result = p;
            break;
        }
    }
    /* Repair: child may still have parent==us while missing from first_child
     * (lost sibling link). BusyBox waitfor then gets ECHILD + kill(pid,0)==0. */
    if (!result || (has_match && !*has_match)) {
        for (int i = 0; i < PROCESS_TABLE_MAX; ++i) {
            process_t *p = process_table[i];
            if (!p || p->parent != parent)
                continue;
            int match = 0;
            if (pid > 0)
                match = p->pid == (uint64_t)(unsigned)pid;
            else if (pid == -1)
                match = 1;
            else if (pid == 0)
                match = p->pgid == pgid;
            else
                match = p->pgid == -pid;
            if (!match)
                continue;
            /* Relink into the sibling list if absent. */
            int linked = 0;
            for (process_t *c = parent->first_child; c; c = c->next_sibling) {
                if (c == p) { linked = 1; break; }
            }
            if (!linked) {
                p->next_sibling = parent->first_child;
                parent->first_child = p;
            }
            if (has_match)
                *has_match = 1;
            if (!result && (!zombies_only || p->state == PROCESS_ZOMBIE))
                result = p;
            if (result && (!has_match || *has_match))
                break;
        }
    }
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
        }
    }
    if (thread) {
        thread->pending_signals = 0;
        thread->saved_sig_mask = 0;
        thread->robust_list_head = 0;
        thread->robust_list_len = 0;
        thread->clear_child_tid = 0;
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
}
