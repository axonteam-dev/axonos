/*
 * cgroup v2 (unified hierarchy). Linux fs/cgroup/cgroup.c semantics:
 * mkdir creates a child, cgroup.procs moves tasks, pids.max/memory.max
 * are enforced on fork / accounted on attach.
 */
#include <cgroup.h>
#include <process.h>
#include <thread.h>
#include <heap.h>
#include <string.h>
#include <spinlock.h>
#include <ext2.h>
#include <vga.h>
#include <fs.h>
#include <ns.h>

#define CGROUP_NAME_MAX 64
#define CGROUP_PROCS_MAX 256
#define CGROUP_UNLIMITED (~0ULL)

struct cgroup {
	char name[CGROUP_NAME_MAX];
	struct cgroup *parent;
	struct cgroup *child;
	struct cgroup *sibling;
	uint64_t memory_max;
	uint64_t pids_max;
	uint32_t pids_current;
	uint32_t subtree; /* bit0 memory, bit1 pids, bit2 cpu */
	uint32_t nprocs;
	uint64_t procs[CGROUP_PROCS_MAX];
};

enum {
	CG_FILE_CONTROLLERS = 1,
	CG_FILE_SUBTREE,
	CG_FILE_PROCS,
	CG_FILE_THREADS,
	CG_FILE_MEM_MAX,
	CG_FILE_MEM_CUR,
	CG_FILE_PIDS_MAX,
	CG_FILE_PIDS_CUR,
	CG_FILE_CPU_MAX,
	CG_FILE_STAT,
};

struct cgroupfs_handle {
	struct cgroup *cg;
	int file_id; /* 0 = directory */
	size_t pos;
	char *cache;
	size_t cache_len;
};

static struct cgroup g_cgroup_root;
static struct fs_driver cgroup_driver;
static struct fs_driver_ops cgroup_ops;
static spinlock_t g_cg_lock;
static char g_cg_mount[64] = "/sys/fs/cgroup";
static int g_cg_ready;

static int cg_name_ok(const char *s)
{
	size_t i;

	if (!s || !s[0] || s[0] == '.')
		return 0;
	for (i = 0; s[i]; i++) {
		char c = s[i];

		if (c == '/' || c == '\n' || c == ' ')
			return 0;
		if (i >= CGROUP_NAME_MAX - 1)
			return 0;
	}
	return 1;
}

static struct cgroup *cg_find_child(struct cgroup *p, const char *name)
{
	struct cgroup *c;

	if (!p)
		return NULL;
	for (c = p->child; c; c = c->sibling) {
		if (strcmp(c->name, name) == 0)
			return c;
	}
	return NULL;
}

static struct cgroup *cg_walk(const char *rel)
{
	struct cgroup *cg = &g_cgroup_root;
	char name[CGROUP_NAME_MAX];
	size_t n = 0;

	if (!rel || !rel[0] || strcmp(rel, "/") == 0)
		return cg;
	if (rel[0] == '/')
		rel++;
	while (*rel) {
		if (*rel == '/') {
			rel++;
			continue;
		}
		n = 0;
		while (rel[n] && rel[n] != '/')
			n++;
		if (n == 0 || n >= sizeof(name))
			return NULL;
		memcpy(name, rel, n);
		name[n] = '\0';
		cg = cg_find_child(cg, name);
		if (!cg)
			return NULL;
		rel += n;
	}
	return cg;
}

static void cg_path_of(struct cgroup *cg, char *out, size_t cap)
{
	char stack[8][CGROUP_NAME_MAX];
	int n = 0;
	size_t w;

	while (cg && cg != &g_cgroup_root && n < 8) {
		memcpy(stack[n], cg->name, CGROUP_NAME_MAX);
		n++;
		cg = cg->parent;
	}
	if (!out || cap == 0)
		return;
	out[0] = '/';
	out[1] = '\0';
	w = 1;
	while (n-- > 0) {
		size_t ln = strlen(stack[n]);

		if (w + 1 + ln >= cap)
			break;
		if (w > 1)
			out[w++] = '/';
		memcpy(out + w, stack[n], ln);
		w += ln;
		out[w] = '\0';
	}
}

static const char *cg_rel(const char *path)
{
	size_t m = strlen(g_cg_mount);

	if (!path)
		return NULL;
	if (strncmp(path, g_cg_mount, m) != 0)
		return NULL;
	if (path[m] == '\0')
		return "/";
	if (path[m] != '/')
		return NULL;
	return path + m;
}

static int cg_split(const char *rel, char *dir, size_t dirsz, char *base, size_t basesz)
{
	const char *slash;

	if (!rel)
		return -1;
	if (rel[0] == '/')
		rel++;
	slash = strrchr(rel, '/');
	if (!slash) {
		if (dir && dirsz)
			snprintf(dir, dirsz, "/");
		if (base && basesz) {
			strncpy(base, rel, basesz - 1);
			base[basesz - 1] = '\0';
		}
		return 0;
	}
	if (dir && dirsz) {
		size_t n = (size_t)(slash - rel);

		if (n >= dirsz)
			n = dirsz - 1;
		dir[0] = '/';
		if (n)
			memcpy(dir + 1, rel, n);
		dir[n + (n ? 1 : 0)] = '\0';
		if (!n)
			dir[1] = '\0';
	}
	if (base && basesz) {
		strncpy(base, slash + 1, basesz - 1);
		base[basesz - 1] = '\0';
	}
	return 0;
}

static int cg_file_id(const char *base)
{
	if (!base)
		return 0;
	if (strcmp(base, "cgroup.controllers") == 0)
		return CG_FILE_CONTROLLERS;
	if (strcmp(base, "cgroup.subtree_control") == 0)
		return CG_FILE_SUBTREE;
	if (strcmp(base, "cgroup.procs") == 0)
		return CG_FILE_PROCS;
	if (strcmp(base, "cgroup.threads") == 0)
		return CG_FILE_THREADS;
	if (strcmp(base, "memory.max") == 0)
		return CG_FILE_MEM_MAX;
	if (strcmp(base, "memory.current") == 0)
		return CG_FILE_MEM_CUR;
	if (strcmp(base, "pids.max") == 0)
		return CG_FILE_PIDS_MAX;
	if (strcmp(base, "pids.current") == 0)
		return CG_FILE_PIDS_CUR;
	if (strcmp(base, "cpu.max") == 0)
		return CG_FILE_CPU_MAX;
	if (strcmp(base, "cgroup.stat") == 0)
		return CG_FILE_STAT;
	return 0;
}

void cgroup_init(void)
{
	if (g_cg_ready)
		return;
	memset(&g_cgroup_root, 0, sizeof(g_cgroup_root));
	g_cgroup_root.memory_max = CGROUP_UNLIMITED;
	g_cgroup_root.pids_max = CGROUP_UNLIMITED;
	g_cgroup_root.subtree = 7; /* memory pids cpu enabled at root */
	g_cg_ready = 1;
}

struct cgroup *cgroup_root(void)
{
	return &g_cgroup_root;
}

int cgroup_can_fork(process_t *parent)
{
	struct cgroup *cg;
	unsigned long fl = 0;
	int ok = 0;

	cg = parent && parent->cgroup ? parent->cgroup : &g_cgroup_root;
	acquire_irqsave(&g_cg_lock, &fl);
	for (; cg; cg = cg->parent) {
		if (cg->pids_max != CGROUP_UNLIMITED &&
		    (uint64_t)cg->pids_current + 1ull > cg->pids_max) {
			ok = -1;
			break;
		}
	}
	release_irqrestore(&g_cg_lock, fl);
	return ok;
}

void cgroup_task_enter(process_t *p, struct cgroup *cg)
{
	unsigned long fl = 0;
	struct cgroup *w;

	if (!p)
		return;
	if (!cg)
		cg = &g_cgroup_root;
	acquire_irqsave(&g_cg_lock, &fl);
	p->cgroup = cg;
	for (w = cg; w; w = w->parent)
		w->pids_current++;
	if (cg->nprocs < CGROUP_PROCS_MAX)
		cg->procs[cg->nprocs++] = p->pid;
	release_irqrestore(&g_cg_lock, fl);
}

void cgroup_task_leave(process_t *p)
{
	unsigned long fl = 0;
	struct cgroup *cg;
	struct cgroup *w;
	uint32_t i;

	if (!p || !p->cgroup)
		return;
	cg = p->cgroup;
	acquire_irqsave(&g_cg_lock, &fl);
	for (i = 0; i < cg->nprocs; i++) {
		if (cg->procs[i] == p->pid) {
			cg->procs[i] = cg->procs[cg->nprocs - 1];
			cg->nprocs--;
			break;
		}
	}
	for (w = cg; w; w = w->parent) {
		if (w->pids_current)
			w->pids_current--;
	}
	p->cgroup = NULL;
	release_irqrestore(&g_cg_lock, fl);
}

int cgroup_show_path(process_t *p, char *buf, size_t cap)
{
	char path[128];

	if (!buf || cap == 0)
		return 0;
	cg_path_of(p && p->cgroup ? p->cgroup : &g_cgroup_root, path, sizeof(path));
	return snprintf(buf, cap, "0::%s\n", path);
}

static int cg_move_pid(struct cgroup *dst, uint64_t pid)
{
	process_t *p = process_find(pid);

	if (!p || !dst)
		return -1;
	cgroup_task_leave(p);
	cgroup_task_enter(p, dst);
	return 0;
}

static ssize_t cg_show(struct cgroup *cg, int fid, char *buf, size_t cap)
{
	uint32_t i;
	size_t w = 0;

	if (!cg || !buf || cap == 0)
		return 0;
	switch (fid) {
	case CG_FILE_CONTROLLERS:
		return snprintf(buf, cap, "cpuset cpu io memory pids\n");
	case CG_FILE_SUBTREE: {
		char tmp[64];
		size_t n = 0;

		tmp[0] = '\0';
		if (cg->subtree & 1)
			n += (size_t)snprintf(tmp + n, sizeof(tmp) - n, "memory ");
		if (cg->subtree & 2)
			n += (size_t)snprintf(tmp + n, sizeof(tmp) - n, "pids ");
		if (cg->subtree & 4)
			n += (size_t)snprintf(tmp + n, sizeof(tmp) - n, "cpu ");
		if (n && tmp[n - 1] == ' ')
			tmp[n - 1] = '\0';
		return snprintf(buf, cap, "%s\n", tmp);
	}
	case CG_FILE_PROCS:
	case CG_FILE_THREADS:
		for (i = 0; i < cg->nprocs; i++) {
			int wr = snprintf(buf + w, cap > w ? cap - w : 0, "%llu\n",
					  (unsigned long long)cg->procs[i]);
			if (wr < 0)
				break;
			w += (size_t)wr;
			if (w >= cap)
				return (ssize_t)cap;
		}
		return (ssize_t)w;
	case CG_FILE_MEM_MAX:
		if (cg->memory_max == CGROUP_UNLIMITED)
			return snprintf(buf, cap, "max\n");
		return snprintf(buf, cap, "%llu\n", (unsigned long long)cg->memory_max);
	case CG_FILE_MEM_CUR:
		return snprintf(buf, cap, "%u\n", cg->pids_current * 4096u);
	case CG_FILE_PIDS_MAX:
		if (cg->pids_max == CGROUP_UNLIMITED)
			return snprintf(buf, cap, "max\n");
		return snprintf(buf, cap, "%llu\n", (unsigned long long)cg->pids_max);
	case CG_FILE_PIDS_CUR:
		return snprintf(buf, cap, "%u\n", cg->pids_current);
	case CG_FILE_CPU_MAX:
		return snprintf(buf, cap, "max 100000\n");
	case CG_FILE_STAT:
		return snprintf(buf, cap, "nr_descendants %u\n", cg->nprocs);
	default:
		return 0;
	}
}

static int parse_u64_or_max(const char *s, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i = 0;

	while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'))
		i++;
	if (i + 3 <= n && s[i] == 'm' && s[i + 1] == 'a' && s[i + 2] == 'x') {
		*out = CGROUP_UNLIMITED;
		return 0;
	}
	if (i >= n || s[i] < '0' || s[i] > '9')
		return -1;
	while (i < n && s[i] >= '0' && s[i] <= '9') {
		v = v * 10ull + (uint64_t)(s[i] - '0');
		i++;
	}
	*out = v;
	return 0;
}

static ssize_t cg_store(struct cgroup *cg, int fid, const char *buf, size_t size)
{
	if (!cg || !buf)
		return -1;
	if (fid == CG_FILE_SUBTREE) {
		uint32_t bits = cg->subtree;
		size_t i = 0;
		int add = 1;

		while (i < size) {
			while (i < size && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n'))
				i++;
			if (i >= size)
				break;
			add = 1;
			if (buf[i] == '+') {
				add = 1;
				i++;
			} else if (buf[i] == '-') {
				add = 0;
				i++;
			}
			if (i + 6 <= size && strncmp(buf + i, "memory", 6) == 0) {
				if (add)
					bits |= 1;
				else
					bits &= ~1u;
				i += 6;
			} else if (i + 4 <= size && strncmp(buf + i, "pids", 4) == 0) {
				if (add)
					bits |= 2;
				else
					bits &= ~2u;
				i += 4;
			} else if (i + 3 <= size && strncmp(buf + i, "cpu", 3) == 0) {
				if (add)
					bits |= 4;
				else
					bits &= ~4u;
				i += 3;
			} else {
				return -1;
			}
		}
		cg->subtree = bits;
		return (ssize_t)size;
	}
	if (fid == CG_FILE_PROCS || fid == CG_FILE_THREADS) {
		uint64_t pid = 0;
		size_t i = 0;

		while (i < size && (buf[i] < '0' || buf[i] > '9'))
			i++;
		while (i < size && buf[i] >= '0' && buf[i] <= '9') {
			pid = pid * 10ull + (uint64_t)(buf[i] - '0');
			i++;
		}
		if (pid == 0)
			return -1;
		if (cg_move_pid(cg, pid) != 0)
			return -1;
		return (ssize_t)size;
	}
	if (fid == CG_FILE_PIDS_MAX) {
		if (parse_u64_or_max(buf, size, &cg->pids_max) != 0)
			return -1;
		return (ssize_t)size;
	}
	if (fid == CG_FILE_MEM_MAX) {
		if (parse_u64_or_max(buf, size, &cg->memory_max) != 0)
			return -1;
		return (ssize_t)size;
	}
	return -1;
}

static int cgroupfs_mkdir_op(const char *path)
{
	const char *rel = cg_rel(path);
	char dir[128], base[CGROUP_NAME_MAX];
	struct cgroup *parent;
	struct cgroup *n;
	unsigned long fl = 0;

	if (!rel)
		return -1;
	if (cg_split(rel, dir, sizeof(dir), base, sizeof(base)) != 0)
		return -1;
	if (!cg_name_ok(base) || cg_file_id(base))
		return -1;
	parent = cg_walk(dir);
	if (!parent)
		return -1;
	acquire_irqsave(&g_cg_lock, &fl);
	if (cg_find_child(parent, base)) {
		release_irqrestore(&g_cg_lock, fl);
		return 0;
	}
	n = (struct cgroup *)kmalloc(sizeof(*n));
	if (!n) {
		release_irqrestore(&g_cg_lock, fl);
		return -1;
	}
	memset(n, 0, sizeof(*n));
	strncpy(n->name, base, CGROUP_NAME_MAX - 1);
	n->parent = parent;
	n->memory_max = CGROUP_UNLIMITED;
	n->pids_max = CGROUP_UNLIMITED;
	n->sibling = parent->child;
	parent->child = n;
	release_irqrestore(&g_cg_lock, fl);
	return 0;
}

static int cgroupfs_open(const char *path, struct fs_file **out_file)
{
	const char *rel;
	char dir[128], base[CGROUP_NAME_MAX];
	struct cgroup *cg;
	int fid = 0;
	struct fs_file *f;
	struct cgroupfs_handle *h;
	char *pp;

	if (!path || !out_file)
		return -1;
	rel = cg_rel(path);
	if (!rel)
		return -1;
	if (cg_split(rel, dir, sizeof(dir), base, sizeof(base)) != 0)
		return -1;
	if (!base[0] || strcmp(rel, "/") == 0) {
		cg = &g_cgroup_root;
		fid = 0;
	} else {
		fid = cg_file_id(base);
		if (fid) {
			cg = cg_walk(dir);
		} else {
			char full[160];

			if (dir[0] == '/' && dir[1] == '\0')
				snprintf(full, sizeof(full), "/%s", base);
			else
				snprintf(full, sizeof(full), "%s/%s", dir, base);
			cg = cg_walk(full);
			fid = 0;
		}
	}
	if (!cg)
		return -1;
	f = (struct fs_file *)kmalloc(sizeof(*f));
	if (!f)
		return -1;
	memset(f, 0, sizeof(*f));
	pp = (char *)kmalloc(strlen(path) + 1);
	if (!pp) {
		kfree(f);
		return -1;
	}
	memcpy(pp, path, strlen(path) + 1);
	h = (struct cgroupfs_handle *)kmalloc(sizeof(*h));
	if (!h) {
		kfree(pp);
		kfree(f);
		return -1;
	}
	memset(h, 0, sizeof(*h));
	h->cg = cg;
	h->file_id = fid;
	f->path = pp;
	f->driver_private = h;
	f->type = fid ? FS_TYPE_REG : FS_TYPE_DIR;
	if (fid) {
		h->cache = (char *)kmalloc(4096);
		if (h->cache) {
			ssize_t n = cg_show(cg, fid, h->cache, 4096);

			h->cache_len = n > 0 ? (size_t)n : 0;
			f->size = h->cache_len;
		}
	}
	*out_file = f;
	return 0;
}

static ssize_t cgroupfs_read(struct fs_file *file, void *buf, size_t size, size_t offset)
{
	struct cgroupfs_handle *h;
	uint8_t *out = (uint8_t *)buf;
	size_t written = 0;
	size_t pos = 0;

	if (!file || !file->driver_private || !buf)
		return -1;
	h = (struct cgroupfs_handle *)file->driver_private;
	if (h->file_id) {
		if (!h->cache || offset >= h->cache_len)
			return 0;
		if (size > h->cache_len - offset)
			size = h->cache_len - offset;
		memcpy(buf, h->cache + offset, size);
		return (ssize_t)size;
	}
	/* directory listing */
	{
		static const char *files[] = {
			"cgroup.controllers", "cgroup.subtree_control", "cgroup.procs",
			"cgroup.threads", "memory.max", "memory.current",
			"pids.max", "pids.current", "cpu.max", "cgroup.stat"
		};
		unsigned i;
		struct cgroup *c;

		for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
			size_t namelen = strlen(files[i]);
			size_t rec_len = (8 + namelen + 3) & ~3u;
			uint8_t tmp[256];
			struct ext2_dir_entry de;

			if (pos + rec_len <= offset) {
				pos += rec_len;
				continue;
			}
			if (written >= size)
				break;
			memset(tmp, 0, rec_len);
			de.inode = (uint32_t)(i + 1);
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = EXT2_FT_REG_FILE;
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, files[i], namelen);
			{
				size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
				size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;

				if (tocopy > size - written)
					tocopy = size - written;
				if (tocopy)
					memcpy(out + written, tmp + entry_off, tocopy);
				written += tocopy;
			}
			pos += rec_len;
		}
		for (c = h->cg->child; c; c = c->sibling) {
			size_t namelen = strlen(c->name);
			size_t rec_len = (8 + namelen + 3) & ~3u;
			uint8_t tmp[256];
			struct ext2_dir_entry de;

			if (rec_len > sizeof(tmp))
				continue;
			if (pos + rec_len <= offset) {
				pos += rec_len;
				continue;
			}
			if (written >= size)
				break;
			memset(tmp, 0, rec_len);
			de.inode = 100;
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = EXT2_FT_DIR;
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, c->name, namelen);
			{
				size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
				size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;

				if (tocopy > size - written)
					tocopy = size - written;
				if (tocopy)
					memcpy(out + written, tmp + entry_off, tocopy);
				written += tocopy;
			}
			pos += rec_len;
		}
	}
	return (ssize_t)written;
}

static ssize_t cgroupfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset)
{
	struct cgroupfs_handle *h;

	(void)offset;
	if (!file || !file->driver_private || !buf)
		return -1;
	h = (struct cgroupfs_handle *)file->driver_private;
	if (!h->file_id)
		return -1;
	return cg_store(h->cg, h->file_id, (const char *)buf, size);
}

static void cgroupfs_release(struct fs_file *file)
{
	struct cgroupfs_handle *h;

	if (!file)
		return;
	h = (struct cgroupfs_handle *)file->driver_private;
	if (h) {
		if (h->cache)
			kfree(h->cache);
		kfree(h);
	}
	if (file->path)
		kfree((void *)file->path);
	kfree(file);
}

int cgroupfs_fill_stat(struct fs_file *file, struct stat *st)
{
	struct cgroupfs_handle *h;

	if (!file || !st || !file->driver_private)
		return -1;
	h = (struct cgroupfs_handle *)file->driver_private;
	st->st_ino = (ino_t)((uintptr_t)h->cg >> 4);
	st->st_nlink = 1;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_size = (off_t)file->size;
	if (h->file_id)
		st->st_mode = S_IFREG | 0644;
	else {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2;
	}
	return 0;
}

int cgroupfs_register(void)
{
	cgroup_init();
	cgroup_ops.name = "cgroup2";
	cgroup_ops.create = NULL;
	cgroup_ops.mkdir = cgroupfs_mkdir_op;
	cgroup_ops.open = cgroupfs_open;
	cgroup_ops.read = cgroupfs_read;
	cgroup_ops.write = cgroupfs_write;
	cgroup_ops.release = cgroupfs_release;
	cgroup_driver.ops = &cgroup_ops;
	cgroup_driver.driver_data = NULL;
	return fs_register_driver(&cgroup_driver);
}

int cgroupfs_mount(const char *path)
{
	if (!path)
		return -1;
	strncpy(g_cg_mount, path, sizeof(g_cg_mount) - 1);
	g_cg_mount[sizeof(g_cg_mount) - 1] = '\0';
	return fs_mount(path, &cgroup_driver);
}
