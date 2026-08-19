#ifndef PROCESS_H
#define PROCESS_H

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

/* Match THREAD_MAX_FD; docker/containerd expect ≥1024 NOFILE soft. */
#define PROCESS_MAX_FD 1024
#define PROCESS_SIGNAL_MAX 64
/* Linux-ish defaults for RLIMIT_NOFILE (getrlimit/setrlimit/prlimit64). */
#define PROCESS_RLIMIT_NOFILE_SOFT 1024ULL
#define PROCESS_RLIMIT_NOFILE_HARD 1048576ULL
#ifndef AXON_NGROUPS_MAX
#define AXON_NGROUPS_MAX 32
#endif

typedef struct mm_struct mm_t;
typedef struct thread thread_t;

typedef enum process_state {
    PROCESS_ALIVE = 0,
    PROCESS_ZOMBIE,
} process_state_t;

typedef enum process_vfork_release_reason {
    PROCESS_VFORK_EXEC_COMMIT = 1,
    PROCESS_VFORK_EXIT,
    PROCESS_VFORK_FATAL,
} process_vfork_release_reason_t;

typedef struct process {
    uint64_t pid;
    process_state_t state;
    int exit_status;

    struct process *parent;
    struct process *first_child;
    struct process *next_sibling;
    thread_t *leader;

    mm_t *mm;
    struct fs_file *fds[PROCESS_MAX_FD];
    uint8_t fd_cloexec[PROCESS_MAX_FD];
    char cwd[256];
    char fs_root[256];
    uid_t uid, euid, suid;
    gid_t gid, egid, sgid;
    /* Supplementary groups (getgroups/setgroups). ngroups==0 means empty list. */
    int ngroups;
    gid_t groups[AXON_NGROUPS_MAX];
    unsigned int umask;
    int pgid;
    int sid;

    uint64_t signal_handlers[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_flags[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_restorer[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_masks[PROCESS_SIGNAL_MAX + 1];

    int vfork_parent_blocked;
    struct process *vfork_parent;

    /* ITIMER_REAL (setitimer/alarm): expire at monotonic ms; 0 = disarmed. */
    uint64_t itimer_expire_ms;
    uint32_t itimer_interval_ms;
    /* prctl(PR_SET_DUMPABLE): 0/1/2 — Linux default is 1 (SUID_DUMP_USER). */
    int dumpable;
    /* Resource limits (Linux rlimit64). Only NOFILE is enforced on open. */
    uint64_t rlim_nofile_cur;
    uint64_t rlim_nofile_max;
    uint64_t rlim_stack_cur;
    uint64_t rlim_stack_max;
    uint64_t rlim_nproc_cur;
    uint64_t rlim_nproc_max;
    uint64_t rlim_as_cur;
    uint64_t rlim_as_max;
} process_t;

void process_init(void);
process_t *process_create(process_t *parent);
process_t *process_create_init(void);
void process_attach_thread(process_t *process, thread_t *thread);
/* Force getpid()==1 for system init (openrc-init refuses otherwise). */
void process_claim_pid1(process_t *process);
void process_sync_from_thread(process_t *process, thread_t *thread);
process_t *process_find(uint64_t pid);
process_t *process_find_child(process_t *parent, int pid, int pgid,
                              int zombies_only, int *has_match);
void process_mark_zombie(process_t *process, int status);
void process_reparent_children(process_t *process, process_t *new_parent);
int process_reap(process_t *parent, process_t *child);
/* Linux SIGCHLD IGN / SA_NOCLDWAIT: drop the zombie without wait(). */
int process_reap_zombie(process_t *child);
/* Roll back a process that was never published to userspace. */
int process_discard(process_t *parent, process_t *child);
int process_adopt_child(process_t *parent, process_t *child);
void process_set_vfork_parent(process_t *child, process_t *parent);
void process_release_vfork_parent(process_t *child,
                                  process_vfork_release_reason_t reason);
void process_exec_reset(process_t *process, thread_t *thread);
void process_posix_timers_flush_pid(uint64_t pid);
uint64_t process_pid(const thread_t *thread);
uint64_t process_ppid(const thread_t *thread);
int process_signal_targets(process_t *caller, int pid, int sig);
/* Fill out[] with live PROCESS_ALIVE targets matching kill(2) pid rules.
 * Returns number of entries written (capped at out_max). */
int process_collect_signal_targets(process_t *caller, int pid,
                                   process_t **out, int out_max);
/* ITIMER_REAL: arm/disarm and fire expired timers (call from timer IRQ). */
void process_arm_itimer_real(process_t *p, uint64_t expire_ms, uint32_t interval_ms);
void process_get_itimer_real(process_t *p, uint32_t *value_ms, uint32_t *interval_ms,
                             uint64_t now_ms);
void process_itimer_tick(uint64_t now_ms);

/* POSIX timers (timer_create/settime) — Linux SIGEV_SIGNAL / SIGEV_THREAD_ID. */
int process_posix_timer_create(int clockid, const void *sevp, size_t sev_len, int32_t *out_id);
int process_posix_timer_settime(int32_t timerid, int flags,
                                uint64_t value_ms, uint32_t interval_ms,
                                uint64_t *old_value_ms, uint32_t *old_interval_ms);
int process_posix_timer_delete(int32_t timerid);
void process_posix_timer_tick(uint64_t now_ms);

#endif
