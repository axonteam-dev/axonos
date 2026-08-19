#include <ns.h>
#include <process.h>
#include <thread.h>
#include <heap.h>
#include <string.h>
#include <spinlock.h>
#include <vga.h>
#include <cgroup.h>

#define NS_INO_BASE 0xF0000000u

struct ns_common {
	uint32_t inum;
	int refs;
	int type;
};

struct uts_namespace {
	struct ns_common ns;
	char nodename[UTS_NODENAME_MAX];
	char domainname[UTS_NODENAME_MAX];
};

struct ipc_namespace {
	struct ns_common ns;
};

struct mnt_namespace {
	struct ns_common ns;
	struct ns_mount mounts[NS_MNT_MAX];
	int mount_count;
};

struct pid_namespace {
	struct ns_common ns;
	struct pid_namespace *parent;
	uint32_t last_pid;
};

struct net_namespace {
	struct ns_common ns;
};

struct user_namespace {
	struct ns_common ns;
	struct user_namespace *parent;
	uid_t owner;
	int uid_map_count;
	int gid_map_count;
	struct uid_gid_map uid_map[5];
	struct uid_gid_map gid_map[5];
};

struct cgroup_namespace {
	struct ns_common ns;
};

struct time_namespace {
	struct ns_common ns;
};

struct nsproxy {
	int refs;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net_namespace *net_ns;
	struct user_namespace *user_ns;
	struct cgroup_namespace *cgroup_ns;
	struct time_namespace *time_ns;
};

static spinlock_t g_ns_lock;
static uint32_t g_ns_next_inum = NS_INO_BASE;
static struct nsproxy g_init_nsproxy;
static struct uts_namespace g_init_uts;
static struct ipc_namespace g_init_ipc;
static struct mnt_namespace g_init_mnt;
static struct pid_namespace g_init_pid;
static struct net_namespace g_init_net;
static struct user_namespace g_init_user;
static struct cgroup_namespace g_init_cgroup;
static struct time_namespace g_init_time;
static int g_ns_ready;

static const char *g_ns_names[NS_TYPE_COUNT] = {
	"mnt", "uts", "ipc", "pid", "user", "net", "cgroup", "time"
};

static void ns_common_init(struct ns_common *n, int type)
{
	n->type = type;
	n->refs = 1;
	n->inum = g_ns_next_inum++;
	if (g_ns_next_inum < NS_INO_BASE)
		g_ns_next_inum = NS_INO_BASE;
}

static process_t *ns_current_proc(void)
{
	thread_t *t = thread_get_current_user();

	if (!t)
		t = thread_current();
	if (t && t->process)
		return t->process;
	return NULL;
}

static struct nsproxy *ns_of(process_t *p)
{
	if (p && p->nsproxy)
		return p->nsproxy;
	return g_ns_ready ? &g_init_nsproxy : NULL;
}

static void nsproxy_get(struct nsproxy *ns)
{
	if (ns && ns != &g_init_nsproxy)
		ns->refs++;
}

static void uts_get(struct uts_namespace *n)
{
	if (n && n != &g_init_uts)
		n->ns.refs++;
}

static void ipc_get(struct ipc_namespace *n)
{
	if (n && n != &g_init_ipc)
		n->ns.refs++;
}

static void mnt_get(struct mnt_namespace *n)
{
	if (n && n != &g_init_mnt)
		n->ns.refs++;
}

static void pid_get(struct pid_namespace *n)
{
	if (n && n != &g_init_pid)
		n->ns.refs++;
}

static void net_get(struct net_namespace *n)
{
	if (n && n != &g_init_net)
		n->ns.refs++;
}

static void user_get(struct user_namespace *n)
{
	if (n && n != &g_init_user)
		n->ns.refs++;
}

static void cgroup_ns_get(struct cgroup_namespace *n)
{
	if (n && n != &g_init_cgroup)
		n->ns.refs++;
}

static void time_get(struct time_namespace *n)
{
	if (n && n != &g_init_time)
		n->ns.refs++;
}

static void uts_put(struct uts_namespace *n)
{
	if (!n || n == &g_init_uts)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void ipc_put(struct ipc_namespace *n)
{
	if (!n || n == &g_init_ipc)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void mnt_put(struct mnt_namespace *n)
{
	if (!n || n == &g_init_mnt)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void pid_put(struct pid_namespace *n)
{
	if (!n || n == &g_init_pid)
		return;
	if (--n->ns.refs <= 0) {
		if (n->parent)
			pid_put(n->parent);
		kfree(n);
	}
}

static void net_put(struct net_namespace *n)
{
	if (!n || n == &g_init_net)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void user_put(struct user_namespace *n)
{
	if (!n || n == &g_init_user)
		return;
	if (--n->ns.refs <= 0) {
		if (n->parent)
			user_put(n->parent);
		kfree(n);
	}
}

static void cgroup_ns_put(struct cgroup_namespace *n)
{
	if (!n || n == &g_init_cgroup)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void time_put(struct time_namespace *n)
{
	if (!n || n == &g_init_time)
		return;
	if (--n->ns.refs <= 0)
		kfree(n);
}

static void nsproxy_put(struct nsproxy *ns)
{
	if (!ns || ns == &g_init_nsproxy)
		return;
	if (--ns->refs > 0)
		return;
	uts_put(ns->uts_ns);
	ipc_put(ns->ipc_ns);
	mnt_put(ns->mnt_ns);
	pid_put(ns->pid_ns);
	if (ns->pid_ns_for_children && ns->pid_ns_for_children != ns->pid_ns)
		pid_put(ns->pid_ns_for_children);
	net_put(ns->net_ns);
	user_put(ns->user_ns);
	cgroup_ns_put(ns->cgroup_ns);
	time_put(ns->time_ns);
	kfree(ns);
}

static struct nsproxy *nsproxy_dup(struct nsproxy *old)
{
	struct nsproxy *n;

	if (!old)
		old = &g_init_nsproxy;
	n = (struct nsproxy *)kmalloc(sizeof(*n));
	if (!n)
		return NULL;
	memset(n, 0, sizeof(*n));
	n->refs = 1;
	n->uts_ns = old->uts_ns;
	n->ipc_ns = old->ipc_ns;
	n->mnt_ns = old->mnt_ns;
	n->pid_ns = old->pid_ns;
	n->pid_ns_for_children = old->pid_ns_for_children ?
		old->pid_ns_for_children : old->pid_ns;
	n->net_ns = old->net_ns;
	n->user_ns = old->user_ns;
	n->cgroup_ns = old->cgroup_ns;
	n->time_ns = old->time_ns;
	uts_get(n->uts_ns);
	ipc_get(n->ipc_ns);
	mnt_get(n->mnt_ns);
	pid_get(n->pid_ns);
	if (n->pid_ns_for_children != n->pid_ns)
		pid_get(n->pid_ns_for_children);
	net_get(n->net_ns);
	user_get(n->user_ns);
	cgroup_ns_get(n->cgroup_ns);
	time_get(n->time_ns);
	return n;
}

static int uts_set_name(char *dst, size_t dstsz, const char *buf, size_t len)
{
	size_t n;

	if (!buf || dstsz == 0)
		return -1;
	n = len;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == '\0'))
		n--;
	if (n >= dstsz)
		n = dstsz - 1;
	if (n > 0)
		memcpy(dst, buf, n);
	dst[n] = '\0';
	return 0;
}

void ns_init(void)
{
	unsigned long fl = 0;

	if (g_ns_ready)
		return;
	acquire_irqsave(&g_ns_lock, &fl);
	memset(&g_init_uts, 0, sizeof(g_init_uts));
	memset(&g_init_ipc, 0, sizeof(g_init_ipc));
	memset(&g_init_mnt, 0, sizeof(g_init_mnt));
	memset(&g_init_pid, 0, sizeof(g_init_pid));
	memset(&g_init_net, 0, sizeof(g_init_net));
	memset(&g_init_user, 0, sizeof(g_init_user));
	memset(&g_init_cgroup, 0, sizeof(g_init_cgroup));
	memset(&g_init_time, 0, sizeof(g_init_time));
	ns_common_init(&g_init_uts.ns, NS_TYPE_UTS);
	ns_common_init(&g_init_ipc.ns, NS_TYPE_IPC);
	ns_common_init(&g_init_mnt.ns, NS_TYPE_MNT);
	ns_common_init(&g_init_pid.ns, NS_TYPE_PID);
	ns_common_init(&g_init_net.ns, NS_TYPE_NET);
	ns_common_init(&g_init_user.ns, NS_TYPE_USER);
	ns_common_init(&g_init_cgroup.ns, NS_TYPE_CGROUP);
	ns_common_init(&g_init_time.ns, NS_TYPE_TIME);
	memcpy(g_init_uts.nodename, "axoniso", 8);
	memcpy(g_init_uts.domainname, "local", 6);
	g_init_pid.last_pid = 1;
	g_init_user.uid_map_count = 1;
	g_init_user.uid_map[0].first = 0;
	g_init_user.uid_map[0].lower = 0;
	g_init_user.uid_map[0].count = 0xFFFFFFFFu;
	g_init_user.gid_map_count = 1;
	g_init_user.gid_map[0] = g_init_user.uid_map[0];
	g_init_nsproxy.refs = 1;
	g_init_nsproxy.uts_ns = &g_init_uts;
	g_init_nsproxy.ipc_ns = &g_init_ipc;
	g_init_nsproxy.mnt_ns = &g_init_mnt;
	g_init_nsproxy.pid_ns = &g_init_pid;
	g_init_nsproxy.pid_ns_for_children = &g_init_pid;
	g_init_nsproxy.net_ns = &g_init_net;
	g_init_nsproxy.user_ns = &g_init_user;
	g_init_nsproxy.cgroup_ns = &g_init_cgroup;
	g_init_nsproxy.time_ns = &g_init_time;
	g_ns_ready = 1;
	release_irqrestore(&g_ns_lock, fl);
	cgroup_init();
}

void ns_process_init_install(process_t *p)
{
	if (!p)
		return;
	ns_init();
	p->nsproxy = &g_init_nsproxy;
	p->ns_pid = (uint32_t)p->pid;
	cgroup_task_enter(p, cgroup_root());
}

void ns_process_inherit(process_t *child, process_t *parent)
{
	struct nsproxy *ns;
	struct pid_namespace *birth;

	if (!child)
		return;
	ns_init();
	if (!parent) {
		ns_process_init_install(child);
		return;
	}
	ns = ns_of(parent);
	child->nsproxy = ns;
	nsproxy_get(ns);
	birth = ns && ns->pid_ns_for_children ? ns->pid_ns_for_children : (ns ? ns->pid_ns : &g_init_pid);
	if (ns && birth && birth != ns->pid_ns) {
		struct nsproxy *fresh = nsproxy_dup(ns);

		if (fresh) {
			/* dup already holds birth via pid_ns_for_children. Re-point
			 * pid_ns at the same object without a second get. */
			pid_put(fresh->pid_ns);
			fresh->pid_ns = birth;
			nsproxy_put(child->nsproxy);
			child->nsproxy = fresh;
		}
	}
	child->ns_pid = (uint32_t)child->pid;
	if (birth && birth != &g_init_pid) {
		if (birth->last_pid < 1)
			birth->last_pid = 1;
		child->ns_pid = birth->last_pid;
		birth->last_pid++;
		if (birth->last_pid < 2)
			birth->last_pid = 2;
	}
	cgroup_task_enter(child, parent->cgroup ? parent->cgroup : cgroup_root());
}

static int ns_make_unique(struct nsproxy *ns, uint64_t flags)
{
	if (flags & AXON_CLONE_NEWUTS) {
		struct uts_namespace *u = (struct uts_namespace *)kmalloc(sizeof(*u));

		if (!u)
			return -1;
		memset(u, 0, sizeof(*u));
		ns_common_init(&u->ns, NS_TYPE_UTS);
		memcpy(u->nodename, ns->uts_ns->nodename, UTS_NODENAME_MAX);
		memcpy(u->domainname, ns->uts_ns->domainname, UTS_NODENAME_MAX);
		uts_put(ns->uts_ns);
		ns->uts_ns = u;
	}
	if (flags & AXON_CLONE_NEWIPC) {
		struct ipc_namespace *i = (struct ipc_namespace *)kmalloc(sizeof(*i));

		if (!i)
			return -1;
		memset(i, 0, sizeof(*i));
		ns_common_init(&i->ns, NS_TYPE_IPC);
		ipc_put(ns->ipc_ns);
		ns->ipc_ns = i;
	}
	if (flags & AXON_CLONE_NEWNS) {
		struct mnt_namespace *m = (struct mnt_namespace *)kmalloc(sizeof(*m));

		if (!m)
			return -1;
		memset(m, 0, sizeof(*m));
		ns_common_init(&m->ns, NS_TYPE_MNT);
		m->mount_count = ns->mnt_ns->mount_count;
		memcpy(m->mounts, ns->mnt_ns->mounts, sizeof(m->mounts));
		mnt_put(ns->mnt_ns);
		ns->mnt_ns = m;
	}
	if (flags & AXON_CLONE_NEWNET) {
		struct net_namespace *n = (struct net_namespace *)kmalloc(sizeof(*n));

		if (!n)
			return -1;
		memset(n, 0, sizeof(*n));
		ns_common_init(&n->ns, NS_TYPE_NET);
		net_put(ns->net_ns);
		ns->net_ns = n;
	}
	if (flags & AXON_CLONE_NEWCGROUP) {
		struct cgroup_namespace *c = (struct cgroup_namespace *)kmalloc(sizeof(*c));

		if (!c)
			return -1;
		memset(c, 0, sizeof(*c));
		ns_common_init(&c->ns, NS_TYPE_CGROUP);
		cgroup_ns_put(ns->cgroup_ns);
		ns->cgroup_ns = c;
	}
	if (flags & AXON_CLONE_NEWTIME) {
		struct time_namespace *t = (struct time_namespace *)kmalloc(sizeof(*t));

		if (!t)
			return -1;
		memset(t, 0, sizeof(*t));
		ns_common_init(&t->ns, NS_TYPE_TIME);
		time_put(ns->time_ns);
		ns->time_ns = t;
	}
	if (flags & AXON_CLONE_NEWUSER) {
		struct user_namespace *u = (struct user_namespace *)kmalloc(sizeof(*u));

		if (!u)
			return -1;
		memset(u, 0, sizeof(*u));
		ns_common_init(&u->ns, NS_TYPE_USER);
		u->parent = ns->user_ns;
		user_get(u->parent);
		u->owner = 0;
		user_put(ns->user_ns);
		ns->user_ns = u;
	}
	if (flags & AXON_CLONE_NEWPID) {
		struct pid_namespace *p = (struct pid_namespace *)kmalloc(sizeof(*p));

		if (!p)
			return -1;
		memset(p, 0, sizeof(*p));
		ns_common_init(&p->ns, NS_TYPE_PID);
		p->parent = ns->pid_ns;
		pid_get(p->parent);
		p->last_pid = 1;
		if (ns->pid_ns_for_children && ns->pid_ns_for_children != ns->pid_ns)
			pid_put(ns->pid_ns_for_children);
		pid_put(ns->pid_ns);
		ns->pid_ns = p;
		ns->pid_ns_for_children = p;
	}
	return 0;
}

int ns_clone_process(process_t *parent, process_t *child, uint64_t clone_flags)
{
	struct nsproxy *fresh;
	unsigned long fl = 0;

	if (!child)
		return -1;
	if (!(clone_flags & AXON_CLONE_NEWNS_MASK))
		return 0;
	acquire_irqsave(&g_ns_lock, &fl);
	fresh = nsproxy_dup(ns_of(parent ? parent : child));
	if (!fresh) {
		release_irqrestore(&g_ns_lock, fl);
		return -1;
	}
	if (ns_make_unique(fresh, clone_flags) != 0) {
		nsproxy_put(fresh);
		release_irqrestore(&g_ns_lock, fl);
		return -1;
	}
	nsproxy_put(child->nsproxy);
	child->nsproxy = fresh;
	if (clone_flags & AXON_CLONE_NEWPID)
		child->ns_pid = 1;
	release_irqrestore(&g_ns_lock, fl);
	return 0;
}

int ns_unshare(process_t *p, uint64_t flags)
{
	uint64_t other = flags & ~AXON_CLONE_NEWPID;
	unsigned long fl = 0;
	struct nsproxy *fresh;
	struct pid_namespace *pn;

	if (!p)
		return -1;
	if (!(flags & AXON_CLONE_NEWNS_MASK))
		return 0;
	if (other && ns_clone_process(p, p, other) != 0)
		return -1;
	if (!(flags & AXON_CLONE_NEWPID))
		return 0;
	/* Linux unshare(CLONE_NEWPID): caller stays in its pid ns; children
	 * are born in a new one as pid 1, 2, ... */
	acquire_irqsave(&g_ns_lock, &fl);
	fresh = nsproxy_dup(ns_of(p));
	if (!fresh) {
		release_irqrestore(&g_ns_lock, fl);
		return -1;
	}
	pn = (struct pid_namespace *)kmalloc(sizeof(*pn));
	if (!pn) {
		nsproxy_put(fresh);
		release_irqrestore(&g_ns_lock, fl);
		return -1;
	}
	memset(pn, 0, sizeof(*pn));
	ns_common_init(&pn->ns, NS_TYPE_PID);
	pn->parent = fresh->pid_ns;
	pid_get(pn->parent);
	pn->last_pid = 1;
	if (fresh->pid_ns_for_children && fresh->pid_ns_for_children != fresh->pid_ns)
		pid_put(fresh->pid_ns_for_children);
	fresh->pid_ns_for_children = pn;
	nsproxy_put(p->nsproxy);
	p->nsproxy = fresh;
	release_irqrestore(&g_ns_lock, fl);
	return 0;
}

int ns_setns_file(process_t *p, struct fs_file *f, int nstype)
{
	enum ns_type type;
	uint32_t inum = 0;
	struct nsproxy *fresh;
	process_t *cur;
	unsigned long fl = 0;
	int i;

	if (!p || !f)
		return -1;
	if (ns_file_type(f, &type, &inum) != 0)
		return -1;
	if (nstype != 0 && (uint64_t)nstype != ns_clone_flag_for_type(type))
		return -22; /* EINVAL */
	cur = ns_current_proc();
	if (!cur)
		return -1;
	acquire_irqsave(&g_ns_lock, &fl);
	fresh = nsproxy_dup(ns_of(p));
	if (!fresh) {
		release_irqrestore(&g_ns_lock, fl);
		return -12;
	}
	/* Steal the matching ns object from the process that owns this inum. */
	for (i = 0; i < 1024; i++) {
		process_t *o = process_find((uint64_t)(unsigned)(i + 1));
		struct nsproxy *ons;
		struct ns_common *want = NULL;

		if (!o || !o->nsproxy)
			continue;
		ons = o->nsproxy;
		switch (type) {
		case NS_TYPE_MNT: want = &ons->mnt_ns->ns; break;
		case NS_TYPE_UTS: want = &ons->uts_ns->ns; break;
		case NS_TYPE_IPC: want = &ons->ipc_ns->ns; break;
		case NS_TYPE_PID: want = &ons->pid_ns->ns; break;
		case NS_TYPE_USER: want = &ons->user_ns->ns; break;
		case NS_TYPE_NET: want = &ons->net_ns->ns; break;
		case NS_TYPE_CGROUP: want = &ons->cgroup_ns->ns; break;
		case NS_TYPE_TIME: want = &ons->time_ns->ns; break;
		default: break;
		}
		if (!want || want->inum != inum)
			continue;
		switch (type) {
		case NS_TYPE_MNT:
			mnt_get(ons->mnt_ns);
			mnt_put(fresh->mnt_ns);
			fresh->mnt_ns = ons->mnt_ns;
			break;
		case NS_TYPE_UTS:
			uts_get(ons->uts_ns);
			uts_put(fresh->uts_ns);
			fresh->uts_ns = ons->uts_ns;
			break;
		case NS_TYPE_IPC:
			ipc_get(ons->ipc_ns);
			ipc_put(fresh->ipc_ns);
			fresh->ipc_ns = ons->ipc_ns;
			break;
		case NS_TYPE_PID:
			/* Linux setns(pid_ns): only children are born in the target ns. */
			if (fresh->pid_ns_for_children &&
			    fresh->pid_ns_for_children != fresh->pid_ns)
				pid_put(fresh->pid_ns_for_children);
			fresh->pid_ns_for_children = ons->pid_ns;
			if (fresh->pid_ns_for_children != fresh->pid_ns)
				pid_get(fresh->pid_ns_for_children);
			break;
		case NS_TYPE_USER:
			user_get(ons->user_ns);
			user_put(fresh->user_ns);
			fresh->user_ns = ons->user_ns;
			break;
		case NS_TYPE_NET:
			net_get(ons->net_ns);
			net_put(fresh->net_ns);
			fresh->net_ns = ons->net_ns;
			break;
		case NS_TYPE_CGROUP:
			cgroup_ns_get(ons->cgroup_ns);
			cgroup_ns_put(fresh->cgroup_ns);
			fresh->cgroup_ns = ons->cgroup_ns;
			break;
		case NS_TYPE_TIME:
			time_get(ons->time_ns);
			time_put(fresh->time_ns);
			fresh->time_ns = ons->time_ns;
			break;
		default:
			break;
		}
		nsproxy_put(p->nsproxy);
		p->nsproxy = fresh;
		release_irqrestore(&g_ns_lock, fl);
		return 0;
	}
	nsproxy_put(fresh);
	release_irqrestore(&g_ns_lock, fl);
	return -2; /* ENOENT */
}

void ns_process_exit(process_t *p)
{
	if (!p)
		return;
	cgroup_task_leave(p);
	nsproxy_put(p->nsproxy);
	p->nsproxy = NULL;
}

uint32_t ns_inum(process_t *p, enum ns_type type)
{
	struct nsproxy *ns = ns_of(p);

	if (!ns)
		return 0;
	switch (type) {
	case NS_TYPE_MNT: return ns->mnt_ns->ns.inum;
	case NS_TYPE_UTS: return ns->uts_ns->ns.inum;
	case NS_TYPE_IPC: return ns->ipc_ns->ns.inum;
	case NS_TYPE_PID: return ns->pid_ns->ns.inum;
	case NS_TYPE_USER: return ns->user_ns->ns.inum;
	case NS_TYPE_NET: return ns->net_ns->ns.inum;
	case NS_TYPE_CGROUP: return ns->cgroup_ns->ns.inum;
	case NS_TYPE_TIME: return ns->time_ns->ns.inum;
	default: return 0;
	}
}

const char *ns_type_name(enum ns_type type)
{
	if ((unsigned)type >= NS_TYPE_COUNT)
		return "ns";
	return g_ns_names[type];
}

int ns_type_from_name(const char *name)
{
	int i;

	if (!name)
		return -1;
	for (i = 0; i < NS_TYPE_COUNT; i++) {
		if (strcmp(name, g_ns_names[i]) == 0)
			return i;
	}
	return -1;
}

uint64_t ns_clone_flag_for_type(enum ns_type type)
{
	switch (type) {
	case NS_TYPE_MNT: return AXON_CLONE_NEWNS;
	case NS_TYPE_UTS: return AXON_CLONE_NEWUTS;
	case NS_TYPE_IPC: return AXON_CLONE_NEWIPC;
	case NS_TYPE_PID: return AXON_CLONE_NEWPID;
	case NS_TYPE_USER: return AXON_CLONE_NEWUSER;
	case NS_TYPE_NET: return AXON_CLONE_NEWNET;
	case NS_TYPE_CGROUP: return AXON_CLONE_NEWCGROUP;
	case NS_TYPE_TIME: return AXON_CLONE_NEWTIME;
	default: return 0;
	}
}

int ns_path_is_proc_ns(const char *path)
{
	enum ns_type t;
	int pid;

	return ns_parse_proc_ns_path(path, &pid, &t) == 0;
}

int ns_parse_proc_ns_path(const char *path, int *pid_out, enum ns_type *type_out)
{
	const char *p;
	const char *slash;
	int pid = -1;
	char name[16];
	size_t n;
	int t;

	if (!path || strncmp(path, "/proc/", 6) != 0)
		return -1;
	p = path + 6;
	slash = strchr(p, '/');
	if (!slash)
		return -1;
	if (strncmp(p, "self/", 5) == 0) {
		thread_t *ct = thread_get_current_user();

		if (!ct)
			ct = thread_current();
		pid = ct && ct->process ? (int)ct->process->pid : (ct ? (int)ct->tid : -1);
		p = slash + 1;
	} else {
		pid = 0;
		while (p < slash && *p >= '0' && *p <= '9') {
			pid = pid * 10 + (*p - '0');
			p++;
		}
		if (p != slash || pid <= 0)
			return -1;
		p = slash + 1;
	}
	if (strncmp(p, "ns/", 3) != 0)
		return -1;
	p += 3;
	n = strlen(p);
	if (n == 0 || n >= sizeof(name))
		return -1;
	memcpy(name, p, n);
	name[n] = '\0';
	t = ns_type_from_name(name);
	if (t < 0)
		return -1;
	if (pid_out)
		*pid_out = pid;
	if (type_out)
		*type_out = (enum ns_type)t;
	return 0;
}

int ns_readlink_proc(const char *path, char *buf, size_t bufsz)
{
	int pid;
	enum ns_type type;
	process_t *p;
	uint32_t inum;
	int n;

	if (ns_parse_proc_ns_path(path, &pid, &type) != 0 || !buf || bufsz == 0)
		return -1;
	p = process_find((uint64_t)(unsigned)pid);
	if (!p)
		return -1;
	inum = ns_inum(p, type);
	n = snprintf(buf, bufsz, "%s:[%u]", ns_type_name(type), inum);
	if (n < 0)
		return -1;
	if ((size_t)n >= bufsz)
		return (int)bufsz;
	return n;
}

int ns_bind_proc_file(struct fs_file *f, process_t *target, enum ns_type type)
{
	if (!f || !target)
		return -1;
	/* Pin the ns identity at open(2) time. Path re-parse after unshare
	 * would see the new ns; Linux nsfs fds stay bound to the old one. */
	f->backing_id = ((uint64_t)ns_inum(target, type) << 8) | (unsigned)type;
	f->backing_gen = 0x4E535346ULL; /* 'NSFS' */
	return 0;
}

int ns_file_type(const struct fs_file *f, enum ns_type *type_out, uint32_t *inum_out)
{
	int pid = 0;
	enum ns_type type;
	process_t *p;

	if (!f)
		return -1;
	if (f->backing_gen == 0x4E535346ULL) {
		type = (enum ns_type)(f->backing_id & 0xffu);
		if (type_out)
			*type_out = type;
		if (inum_out)
			*inum_out = (uint32_t)(f->backing_id >> 8);
		return 0;
	}
	if (ns_parse_proc_ns_path(f->path, &pid, &type) != 0)
		return -1;
	p = process_find((uint64_t)(unsigned)pid);
	if (!p)
		return -1;
	if (type_out)
		*type_out = type;
	if (inum_out)
		*inum_out = ns_inum(p, type);
	return 0;
}

const char *ns_uts_nodename(void)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	if (!ns || !ns->uts_ns)
		return "axoniso";
	return ns->uts_ns->nodename;
}

const char *ns_uts_domainname(void)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	if (!ns || !ns->uts_ns)
		return "local";
	return ns->uts_ns->domainname;
}

int ns_uts_set_nodename(const char *buf, size_t len)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	if (!ns || !ns->uts_ns)
		return -1;
	return uts_set_name(ns->uts_ns->nodename, sizeof(ns->uts_ns->nodename), buf, len);
}

int ns_uts_set_domainname(const char *buf, size_t len)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	if (!ns || !ns->uts_ns)
		return -1;
	return uts_set_name(ns->uts_ns->domainname, sizeof(ns->uts_ns->domainname), buf, len);
}

static struct ns_mount *mnt_vec_of(process_t *p, int **countp)
{
	struct nsproxy *ns = ns_of(p);

	if (!ns || !ns->mnt_ns) {
		if (countp)
			*countp = &g_init_mnt.mount_count;
		return g_init_mnt.mounts;
	}
	if (countp)
		*countp = &ns->mnt_ns->mount_count;
	return ns->mnt_ns->mounts;
}

struct ns_mount *ns_mnt_vec(int **countp)
{
	return mnt_vec_of(ns_current_proc(), countp);
}

struct ipc_namespace *ns_current_ipc(void)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	return ns ? ns->ipc_ns : &g_init_ipc;
}

struct net_namespace *ns_current_net(void)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	return ns ? ns->net_ns : &g_init_net;
}

struct pid_namespace *ns_current_pid_ns(void)
{
	struct nsproxy *ns = ns_of(ns_current_proc());

	return ns ? ns->pid_ns : &g_init_pid;
}

int ns_ipc_same(struct ipc_namespace *a, struct ipc_namespace *b)
{
	if (!a)
		a = &g_init_ipc;
	if (!b)
		b = &g_init_ipc;
	return a == b;
}

int ns_net_same(struct net_namespace *a, struct net_namespace *b)
{
	if (!a)
		a = &g_init_net;
	if (!b)
		b = &g_init_net;
	return a == b;
}

int ns_net_is_init(struct net_namespace *n)
{
	return !n || n == &g_init_net;
}

uint32_t ns_pid_local(const struct process *p)
{
	if (!p)
		return 0;
	if (p->ns_pid)
		return p->ns_pid;
	return (uint32_t)p->pid;
}

uint64_t ns_getppid(const process_t *p)
{
	struct nsproxy *ns;
	struct nsproxy *pns;

	if (!p || !p->parent)
		return 0;
	ns = ns_of((process_t *)p);
	pns = ns_of(p->parent);
	if (ns && pns && ns->pid_ns != pns->pid_ns)
		return 0;
	return ns_pid_local(p->parent);
}

int ns_pid_is_ns_init(const process_t *p)
{
	return p && p->ns_pid == 1 && p->nsproxy &&
		p->nsproxy->pid_ns && p->nsproxy->pid_ns != &g_init_pid;
}

static int map_show(const struct uid_gid_map *map, int n, char *buf, size_t cap)
{
	int i;
	size_t w = 0;

	if (!buf || cap == 0)
		return 0;
	if (n <= 0) {
		buf[0] = '\0';
		return 0;
	}
	for (i = 0; i < n; i++) {
		int wr = snprintf(buf + w, cap > w ? cap - w : 0, "%u %u %u\n",
				  map[i].first, map[i].lower, map[i].count);
		if (wr < 0)
			break;
		w += (size_t)wr;
		if (w >= cap) {
			w = cap;
			break;
		}
	}
	return (int)w;
}

int ns_uid_map_show(process_t *p, char *buf, size_t cap)
{
	struct nsproxy *ns = ns_of(p);

	if (!ns || !ns->user_ns)
		return 0;
	return map_show(ns->user_ns->uid_map, ns->user_ns->uid_map_count, buf, cap);
}

int ns_gid_map_show(process_t *p, char *buf, size_t cap)
{
	struct nsproxy *ns = ns_of(p);

	if (!ns || !ns->user_ns)
		return 0;
	return map_show(ns->user_ns->gid_map, ns->user_ns->gid_map_count, buf, cap);
}

static int map_parse(struct uid_gid_map *map, int *count, const char *buf, size_t len)
{
	unsigned long first = 0, lower = 0, cnt = 0;
	size_t i = 0;
	int n = 0;

	while (i < len && n < 5) {
		while (i < len && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n'))
			i++;
		if (i >= len)
			break;
		first = 0;
		while (i < len && buf[i] >= '0' && buf[i] <= '9') {
			first = first * 10u + (unsigned)(buf[i] - '0');
			i++;
		}
		while (i < len && (buf[i] == ' ' || buf[i] == '\t'))
			i++;
		lower = 0;
		while (i < len && buf[i] >= '0' && buf[i] <= '9') {
			lower = lower * 10u + (unsigned)(buf[i] - '0');
			i++;
		}
		while (i < len && (buf[i] == ' ' || buf[i] == '\t'))
			i++;
		cnt = 0;
		while (i < len && buf[i] >= '0' && buf[i] <= '9') {
			cnt = cnt * 10u + (unsigned)(buf[i] - '0');
			i++;
		}
		if (cnt == 0)
			return -1;
		map[n].first = (uint32_t)first;
		map[n].lower = (uint32_t)lower;
		map[n].count = (uint32_t)cnt;
		n++;
	}
	*count = n;
	return n > 0 ? 0 : -1;
}

int ns_uid_map_write(process_t *writer, process_t *target, const char *buf, size_t len)
{
	struct nsproxy *ns = ns_of(target);

	(void)writer;
	if (!ns || !ns->user_ns || ns->user_ns == &g_init_user)
		return -1;
	if (ns->user_ns->uid_map_count != 0)
		return -1;
	return map_parse(ns->user_ns->uid_map, &ns->user_ns->uid_map_count, buf, len);
}

int ns_gid_map_write(process_t *writer, process_t *target, const char *buf, size_t len)
{
	struct nsproxy *ns = ns_of(target);

	(void)writer;
	if (!ns || !ns->user_ns || ns->user_ns == &g_init_user)
		return -1;
	if (ns->user_ns->gid_map_count != 0)
		return -1;
	return map_parse(ns->user_ns->gid_map, &ns->user_ns->gid_map_count, buf, len);
}

static const char *mnt_fstype(const char *drv, int is_root)
{
	if (is_root)
		return (drv && (strcmp(drv, "overlay") == 0 || strcmp(drv, "overlayfs") == 0))
			? "overlay" : (drv ? drv : "rootfs");
	if (!drv)
		return "unknown";
	if (strcmp(drv, "procfs") == 0)
		return "proc";
	if (strcmp(drv, "devfs") == 0)
		return "devtmpfs";
	if (strcmp(drv, "sysfs") == 0)
		return "sysfs";
	if (strcmp(drv, "cgroup2") == 0)
		return "cgroup2";
	if (strcmp(drv, "ramfs") == 0)
		return "ramfs";
	return drv;
}

int ns_show_mountinfo_for(process_t *p, char *buf, size_t cap)
{
	int *cnt = NULL;
	struct ns_mount *vec;
	size_t w = 0;
	int i;
	int have_root = 0;

	if (!buf || cap == 0)
		return 0;
	vec = mnt_vec_of(p, &cnt);
	if (!vec || !cnt)
		return 0;
	for (i = 0; i < *cnt; i++) {
		struct ns_mount *m = &vec[i];
		const char *drv;
		int is_root;
		const char *fstype;
		int wr;
		int parent = (i == 0) ? 0 : 1;

		if (!m->driver || !m->driver->ops)
			continue;
		drv = m->driver->ops->name ? m->driver->ops->name : "unknown";
		is_root = (m->path[0] == '/' && m->path[1] == '\0');
		if (is_root)
			have_root = 1;
		fstype = mnt_fstype(drv, is_root);
		/* Linux fs/proc_namespace.c show_mountinfo */
		wr = snprintf(buf + w, cap > w ? cap - w : 0,
			      "%d %d 0:0 / %s rw,relatime - %s %s rw\n",
			      i + 1, parent, m->path, fstype, fstype);
		if (wr < 0)
			break;
		w += (size_t)wr;
		if (w >= cap) {
			w = cap;
			break;
		}
	}
	if (!have_root && w < cap) {
		int wr = snprintf(buf + w, cap - w,
				  "1 0 0:0 / / rw,relatime - overlay overlay rw\n");
		if (wr > 0)
			w += (size_t)wr;
	}
	return (int)w;
}

int ns_show_mountinfo(char *buf, size_t cap)
{
	return ns_show_mountinfo_for(ns_current_proc(), buf, cap);
}
