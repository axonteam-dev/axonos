#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

struct process;
struct cgroup;

void cgroup_init(void);
struct cgroup *cgroup_root(void);
int cgroup_can_fork(struct process *parent);
void cgroup_task_enter(struct process *p, struct cgroup *cg);
void cgroup_task_leave(struct process *p);
int cgroup_show_path(struct process *p, char *buf, size_t cap);

int cgroupfs_register(void);
int cgroupfs_mount(const char *path);
int cgroupfs_fill_stat(struct fs_file *file, struct stat *st);
