/*
 * Unix98 PTY (Linux /dev/ptmx + /dev/pts/N)
 *
 * Master write → slave read (m2s); slave write → master read (s2m).
 * Termios is stored and returned via TCGETS/TCSETS; line discipline is
 * pass-through (raw rings) — enough for tmux/shell after tcsetattr.
 */
#include <pty.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <heap.h>
#include <spinlock.h>
#include <thread.h>
#include <stat.h>
#include <stdio.h>

#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

#define PTY_BUF_CAP 4096
#define PTY_HANDLE_MAGIC 0x50545948u /* 'PTYH' */

struct pty_ring {
	char buf[PTY_BUF_CAP];
	size_t head;
	size_t tail;
	size_t count;
	spinlock_t lock;
	int waiters[8];
	int waiters_count;
};

struct pty_pair {
	int index;
	int in_use;
	int locked;
	int master_opens;
	int slave_opens;
	int fg_pgrp;
	int controlling_sid;
	uint32_t term_lflag;
	uint8_t term_vmin;
	uint8_t term_vtime;
	uint16_t ws_row;
	uint16_t ws_col;
	struct pty_ring m2s;
	struct pty_ring s2m;
};

struct pty_handle {
	uint32_t magic;
	struct pty_pair *pair;
	int is_master;
};

static struct pty_pair g_ptys[PTY_MAX];
static spinlock_t g_pty_table_lock;

static struct pty_handle *pty_handle_of(struct fs_file *f) {
	struct pty_handle *h;
	if (!f || !f->driver_private)
		return NULL;
	h = (struct pty_handle *)f->driver_private;
	if (h->magic != PTY_HANDLE_MAGIC || !h->pair)
		return NULL;
	return h;
}

int pty_is_file(struct fs_file *f) {
	return pty_handle_of(f) != NULL;
}

int pty_is_master(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	return h ? h->is_master : 0;
}

int pty_get_index(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	return h ? h->pair->index : -1;
}

static void pty_ring_init(struct pty_ring *r) {
	memset(r, 0, sizeof(*r));
}

static void pty_ring_wake(struct pty_ring *r) {
	int i;
	for (i = 0; i < r->waiters_count; i++) {
		if (r->waiters[i] >= 0)
			thread_unblock(r->waiters[i]);
	}
	r->waiters_count = 0;
}

static size_t pty_ring_write(struct pty_ring *r, const char *src, size_t n) {
	size_t done = 0;
	unsigned long flags = 0;
	acquire_irqsave(&r->lock, &flags);
	while (done < n && r->count < PTY_BUF_CAP - 1) {
		r->buf[r->tail] = src[done++];
		r->tail = (r->tail + 1) % PTY_BUF_CAP;
		r->count++;
	}
	if (done)
		pty_ring_wake(r);
	release_irqrestore(&r->lock, flags);
	return done;
}

static ssize_t pty_ring_read(struct pty_ring *r, char *dst, size_t n, int *eof) {
	size_t done = 0;
	*eof = 0;
	for (;;) {
		unsigned long flags = 0;
		acquire_irqsave(&r->lock, &flags);
		while (done < n && r->count > 0) {
			dst[done++] = r->buf[r->head];
			r->head = (r->head + 1) % PTY_BUF_CAP;
			r->count--;
		}
		if (done > 0) {
			release_irqrestore(&r->lock, flags);
			return (ssize_t)done;
		}
		/* empty — block */
		{
			thread_t *cur = thread_current();
			if (!cur)
				cur = thread_get_current_user();
			if (!cur) {
				release_irqrestore(&r->lock, flags);
				return 0;
			}
			if (r->waiters_count < (int)(sizeof(r->waiters) / sizeof(r->waiters[0])))
				r->waiters[r->waiters_count++] = (int)cur->tid;
			release_irqrestore(&r->lock, flags);
			thread_block((int)cur->tid);
			thread_yield();
			if (cur->pending_signals & ~cur->saved_sig_mask)
				return -4; /* EINTR */
			/* caller may set *eof if peer closed */
			(void)eof;
		}
	}
}

static size_t pty_ring_avail(struct pty_ring *r) {
	size_t c;
	unsigned long flags = 0;
	acquire_irqsave(&r->lock, &flags);
	c = r->count;
	release_irqrestore(&r->lock, flags);
	return c;
}

static void pty_ring_flush(struct pty_ring *r) {
	unsigned long flags = 0;
	acquire_irqsave(&r->lock, &flags);
	r->head = r->tail = 0;
	r->count = 0;
	release_irqrestore(&r->lock, flags);
}

static struct fs_file *pty_alloc_file(const char *path, struct pty_pair *pair, int is_master) {
	struct fs_file *f;
	struct pty_handle *h;
	char *pp;
	size_t plen;

	f = (struct fs_file *)kmalloc(sizeof(*f));
	h = (struct pty_handle *)kmalloc(sizeof(*h));
	if (!f || !h) {
		if (f) kfree(f);
		if (h) kfree(h);
		return NULL;
	}
	plen = strlen(path) + 1;
	pp = (char *)kmalloc(plen);
	if (!pp) {
		kfree(f);
		kfree(h);
		return NULL;
	}
	memcpy(pp, path, plen);
	memset(f, 0, sizeof(*f));
	h->magic = PTY_HANDLE_MAGIC;
	h->pair = pair;
	h->is_master = is_master;
	f->path = pp;
	f->type = FS_TYPE_REG;
	f->size = 0;
	f->pos = 0;
	f->refcount = 1;
	f->driver_private = h;
	return f;
}

int pty_open_ptmx(struct fs_file **out) {
	int i;
	struct pty_pair *p = NULL;
	struct fs_file *f;
	unsigned long flags = 0;

	if (!out)
		return -1;
	acquire_irqsave(&g_pty_table_lock, &flags);
	for (i = 0; i < PTY_MAX; i++) {
		if (!g_ptys[i].in_use) {
			p = &g_ptys[i];
			memset(p, 0, sizeof(*p));
			p->index = i;
			p->in_use = 1;
			p->locked = 1;
			p->fg_pgrp = -1;
			p->controlling_sid = -1;
			p->term_lflag = 0x00000002u | 0x00000008u | 0x00000001u; /* ICANON|ECHO|ISIG */
			p->term_vmin = 1;
			p->term_vtime = 0;
			p->ws_row = 24;
			p->ws_col = 80;
			pty_ring_init(&p->m2s);
			pty_ring_init(&p->s2m);
			p->master_opens = 1;
			break;
		}
	}
	release_irqrestore(&g_pty_table_lock, flags);
	if (!p)
		return -1;
	f = pty_alloc_file("/dev/ptmx", p, 1);
	if (!f) {
		acquire_irqsave(&g_pty_table_lock, &flags);
		p->in_use = 0;
		release_irqrestore(&g_pty_table_lock, flags);
		return -1;
	}
	*out = f;
	return 0;
}

int pty_open_slave(int index, struct fs_file **out) {
	struct pty_pair *p;
	struct fs_file *f;
	char path[32];
	unsigned long flags = 0;

	if (!out || index < 0 || index >= PTY_MAX)
		return -1;
	acquire_irqsave(&g_pty_table_lock, &flags);
	p = &g_ptys[index];
	if (!p->in_use || p->locked) {
		release_irqrestore(&g_pty_table_lock, flags);
		return -1;
	}
	p->slave_opens++;
	release_irqrestore(&g_pty_table_lock, flags);

	snprintf(path, sizeof(path), "/dev/pts/%d", index);
	f = pty_alloc_file(path, p, 0);
	if (!f) {
		acquire_irqsave(&g_pty_table_lock, &flags);
		if (p->slave_opens > 0)
			p->slave_opens--;
		release_irqrestore(&g_pty_table_lock, flags);
		return -1;
	}
	*out = f;
	return 0;
}

ssize_t pty_read(struct fs_file *f, void *buf, size_t n) {
	struct pty_handle *h = pty_handle_of(f);
	struct pty_ring *r;
	int eof = 0;

	if (!h || !buf || n == 0)
		return -1;
	r = h->is_master ? &h->pair->s2m : &h->pair->m2s;

	for (;;) {
		if (pty_ring_avail(r) > 0)
			return pty_ring_read(r, (char *)buf, n, &eof);
		if (h->is_master && h->pair->slave_opens == 0)
			return 0;
		if (!h->is_master && h->pair->master_opens == 0)
			return 0;
		/* Block until data or peer close (re-check after wake). */
		{
			unsigned long flags = 0;
			thread_t *cur = thread_current();
			if (!cur)
				cur = thread_get_current_user();
			if (!cur)
				return 0;
			acquire_irqsave(&r->lock, &flags);
			if (r->count > 0) {
				release_irqrestore(&r->lock, flags);
				continue;
			}
			if (r->waiters_count < (int)(sizeof(r->waiters) / sizeof(r->waiters[0])))
				r->waiters[r->waiters_count++] = (int)cur->tid;
			release_irqrestore(&r->lock, flags);
			thread_block((int)cur->tid);
			thread_yield();
			if (cur->pending_signals & ~cur->saved_sig_mask)
				return -4;
		}
	}
}

ssize_t pty_write(struct fs_file *f, const void *buf, size_t n) {
	struct pty_handle *h = pty_handle_of(f);
	struct pty_ring *r;
	size_t done = 0;
	const char *src = (const char *)buf;

	if (!h || !buf)
		return -1;
	if (n == 0)
		return 0;
	r = h->is_master ? &h->pair->m2s : &h->pair->s2m;

	while (done < n) {
		size_t w = pty_ring_write(r, src + done, n - done);
		if (w == 0) {
			/* full — short write or yield and retry once */
			thread_yield();
			w = pty_ring_write(r, src + done, n - done);
			if (w == 0)
				break;
		}
		done += w;
	}
	return done ? (ssize_t)done : -1;
}

void pty_release_handle(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	struct pty_pair *p;
	unsigned long flags = 0;

	if (!h)
		return;
	p = h->pair;
	acquire_irqsave(&g_pty_table_lock, &flags);
	if (h->is_master) {
		if (p->master_opens > 0)
			p->master_opens--;
		pty_ring_wake(&p->m2s);
		pty_ring_wake(&p->s2m);
	} else {
		if (p->slave_opens > 0)
			p->slave_opens--;
		pty_ring_wake(&p->m2s);
		pty_ring_wake(&p->s2m);
	}
	if (p->master_opens == 0 && p->slave_opens == 0)
		p->in_use = 0;
	release_irqrestore(&g_pty_table_lock, flags);
	h->magic = 0;
	kfree(h);
	f->driver_private = NULL;
}

int pty_available(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return 0;
	return (int)pty_ring_avail(h->is_master ? &h->pair->s2m : &h->pair->m2s);
}

int pty_set_locked(struct fs_file *f, int locked) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h || !h->is_master)
		return -1;
	h->pair->locked = locked ? 1 : 0;
	return 0;
}

int pty_get_locked(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return 1;
	return h->pair->locked;
}

uint32_t pty_get_lflag(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	return h ? h->pair->term_lflag : 0;
}

void pty_set_termios(struct fs_file *f, uint32_t lflag, uint8_t vtime, uint8_t vmin) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	h->pair->term_lflag = lflag;
	h->pair->term_vtime = vtime;
	h->pair->term_vmin = vmin;
}

void pty_get_winsize(struct fs_file *f, uint16_t *row, uint16_t *col) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	if (row)
		*row = h->pair->ws_row;
	if (col)
		*col = h->pair->ws_col;
}

void pty_set_winsize(struct fs_file *f, uint16_t row, uint16_t col) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	if (row)
		h->pair->ws_row = row;
	if (col)
		h->pair->ws_col = col;
}

int pty_get_fg_pgrp(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	return h ? h->pair->fg_pgrp : -1;
}

int pty_set_fg_pgrp(struct fs_file *f, int pgid) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h || pgid <= 0)
		return -1;
	h->pair->fg_pgrp = pgid;
	return 0;
}

int pty_get_controlling_sid(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	return h ? h->pair->controlling_sid : -1;
}

void pty_set_controlling_sid(struct fs_file *f, int sid) {
	struct pty_handle *h = pty_handle_of(f);
	if (h)
		h->pair->controlling_sid = sid;
}

void pty_flush_input(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	/* Input from the peer: flush the ring the reader would consume. */
	pty_ring_flush(h->is_master ? &h->pair->s2m : &h->pair->m2s);
}

int pty_list_slaves(char out_names[][16], int max) {
	int n = 0, i;
	unsigned long flags = 0;
	if (!out_names || max <= 0)
		return 0;
	acquire_irqsave(&g_pty_table_lock, &flags);
	for (i = 0; i < PTY_MAX && n < max; i++) {
		if (g_ptys[i].in_use && !g_ptys[i].locked) {
			snprintf(out_names[n], 16, "%d", i);
			n++;
		}
	}
	release_irqrestore(&g_pty_table_lock, flags);
	return n;
}

int pty_fill_stat(struct fs_file *f, struct stat *st) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h || !st)
		return -1;
	memset(st, 0, sizeof(*st));
	st->st_mode = (mode_t)(S_IFCHR | 0620);
	st->st_nlink = 1;
	st->st_ino = (ino_t)(1000 + h->pair->index + (h->is_master ? 0 : 100));
	return 0;
}
