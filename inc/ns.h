#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <utsname_host.h>

struct process;
struct thread;
struct fs_file;
struct fs_driver;
struct nsproxy;
struct uts_namespace;
struct ipc_namespace;
struct mnt_namespace;
struct pid_namespace;
struct net_namespace;
struct user_namespace;
struct cgroup_namespace;
struct ns_common;

/* Linux clone(2) namespace bits (uapi linux/sched.h). */
#define AXON_CLONE_NEWTIME	0x00000080ULL
#define AXON_CLONE_NEWNS	0x00020000ULL
#define AXON_CLONE_NEWCGROUP	0x02000000ULL
#define AXON_CLONE_NEWUTS	0x04000000ULL
#define AXON_CLONE_NEWIPC	0x08000000ULL
#define AXON_CLONE_NEWUSER	0x10000000ULL
#define AXON_CLONE_NEWPID	0x20000000ULL
#define AXON_CLONE_NEWNET	0x40000000ULL

#define AXON_CLONE_NEWNS_MASK (AXON_CLONE_NEWNS | AXON_CLONE_NEWUTS | \
	AXON_CLONE_NEWIPC | AXON_CLONE_NEWUSER | AXON_CLONE_NEWPID | \
	AXON_CLONE_NEWNET | AXON_CLONE_NEWCGROUP | AXON_CLONE_NEWTIME)

#define NS_MNT_MAX 32

enum ns_type {
	NS_TYPE_MNT = 0,
	NS_TYPE_UTS,
	NS_TYPE_IPC,
	NS_TYPE_PID,
	NS_TYPE_USER,
	NS_TYPE_NET,
	NS_TYPE_CGROUP,
	NS_TYPE_TIME,
	NS_TYPE_COUNT
};

struct ns_mount {
	char path[64];
	size_t path_len;
	struct fs_driver *driver;
};

struct uid_gid_map {
	uint32_t first;
	uint32_t lower;
	uint32_t count;
};

void ns_init(void);

/* Process lifetime. */
void ns_process_init_install(struct process *p);
void ns_process_inherit(struct process *child, struct process *parent);
int ns_clone_process(struct process *parent, struct process *child, uint64_t clone_flags);
int ns_unshare(struct process *p, uint64_t flags);
int ns_setns_file(struct process *p, struct fs_file *f, int nstype);
void ns_process_exit(struct process *p);

uint32_t ns_inum(struct process *p, enum ns_type type);
const char *ns_type_name(enum ns_type type);
int ns_type_from_name(const char *name);
uint64_t ns_clone_flag_for_type(enum ns_type type);
int ns_path_is_proc_ns(const char *path);
int ns_parse_proc_ns_path(const char *path, int *pid_out, enum ns_type *type_out);
int ns_readlink_proc(const char *path, char *buf, size_t bufsz);

/* nsfs fd: bind an open /proc/<pid>/ns/<type> handle for setns(2). */
int ns_bind_proc_file(struct fs_file *f, struct process *target, enum ns_type type);
int ns_file_type(const struct fs_file *f, enum ns_type *type_out, uint32_t *inum_out);

/* UTS */
const char *ns_uts_nodename(void);
const char *ns_uts_domainname(void);
int ns_uts_set_nodename(const char *buf, size_t len);
int ns_uts_set_domainname(const char *buf, size_t len);

/* Mount namespace table used by the VFS. */
struct ns_mount *ns_mnt_vec(int **countp);
struct ipc_namespace *ns_current_ipc(void);
struct net_namespace *ns_current_net(void);
struct pid_namespace *ns_current_pid_ns(void);
int ns_ipc_same(struct ipc_namespace *a, struct ipc_namespace *b);
int ns_net_same(struct net_namespace *a, struct net_namespace *b);
int ns_net_is_init(struct net_namespace *n);

/* PID namespace: getpid/getppid. */
uint32_t ns_pid_local(const struct process *p);
uint64_t ns_getppid(const struct process *p);
int ns_pid_is_ns_init(const struct process *p);

/* User namespace maps. */
int ns_uid_map_show(struct process *p, char *buf, size_t cap);
int ns_gid_map_show(struct process *p, char *buf, size_t cap);
int ns_uid_map_write(struct process *writer, struct process *target,
		     const char *buf, size_t len);
int ns_gid_map_write(struct process *writer, struct process *target,
		     const char *buf, size_t len);

/* mountinfo body for the caller's mount namespace. */
int ns_show_mountinfo(char *buf, size_t cap);
int ns_show_mountinfo_for(struct process *p, char *buf, size_t cap);
