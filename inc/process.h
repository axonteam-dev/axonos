#ifndef PROCESS_H
#define PROCESS_H

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

#define PROCESS_MAX_FD 256
#define PROCESS_SIGNAL_MAX 64

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
    uid_t uid, euid, suid;
    gid_t gid, egid, sgid;
    unsigned int umask;
    int pgid;
    int sid;

    uint64_t signal_handlers[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_flags[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_restorer[PROCESS_SIGNAL_MAX + 1];
    uint64_t signal_masks[PROCESS_SIGNAL_MAX + 1];

    int vfork_parent_blocked;
    struct process *vfork_parent;
} process_t;

void process_init(void);
process_t *process_create(process_t *parent);
process_t *process_create_init(void);
void process_attach_thread(process_t *process, thread_t *thread);
void process_sync_from_thread(process_t *process, thread_t *thread);
process_t *process_find(uint64_t pid);
process_t *process_find_child(process_t *parent, int pid, int pgid,
                              int zombies_only, int *has_match);
void process_mark_zombie(process_t *process, int status);
void process_reparent_children(process_t *process, process_t *new_parent);
int process_reap(process_t *parent, process_t *child);
int process_adopt_child(process_t *parent, process_t *child);
void process_set_vfork_parent(process_t *child, process_t *parent);
void process_release_vfork_parent(process_t *child,
                                  process_vfork_release_reason_t reason);
void process_exec_reset(process_t *process, thread_t *thread);
uint64_t process_pid(const thread_t *thread);
uint64_t process_ppid(const thread_t *thread);
int process_signal_targets(process_t *caller, int pid, int sig);

#endif
