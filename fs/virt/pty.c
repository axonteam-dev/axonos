/*
 * Unix98 PTY (Linux /dev/ptmx + /dev/pts/N)
 *
 * Master write → slave read (m2s); slave write → master read (s2m).
 * Line discipline (OPOST/ONLCR, ICRNL, VERASE, ECHO) is applied here so
 * SSH sessions do not staircase and backspace matches Linux termios.
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
#define PTY_NCCS 19

/* Linux x86 termbits (octal in asm-generic/termbits.h). */
#define TCS_IGNCR   0x00000080u
#define TCS_INLCR   0x00000040u
#define TCS_ICRNL   0x00000100u
#define TCS_IXON    0x00000400u
#define TCS_IUTF8   0x00004000u
#define TCS_OPOST   0x00000001u
#define TCS_ONLCR   0x00000004u
#define TCS_OCRNL   0x00000008u
#define TCS_ISIG    0x00000001u
#define TCS_ICANON  0x00000002u
#define TCS_ECHO    0x00000008u
#define TCS_ECHOE   0x00000010u
#define TCS_ECHOK   0x00000020u
#define TCS_ECHONL  0x00000040u
#define TCS_ECHOCTL 0x00000200u
#define TCS_IEXTEN  0x00008000u

#define TCS_VINTR  0
#define TCS_VQUIT  1
#define TCS_VERASE 2
#define TCS_VKILL  3
#define TCS_VEOF   4
#define TCS_VTIME  5
#define TCS_VMIN   6

#define TCS_CFLAG_DEF 0x00000CB7u /* CS8|CREAD|CLOCAL|B38400-ish */

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
	uint32_t term_iflag;
	uint32_t term_oflag;
	uint32_t term_cflag;
	uint32_t term_lflag;
	uint8_t term_cc[PTY_NCCS];
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

static int pty_ring_erase_last(struct pty_ring *r) {
	unsigned long flags = 0;
	int ok = 0;
	acquire_irqsave(&r->lock, &flags);
	if (r->count > 0) {
		size_t last = (r->tail + PTY_BUF_CAP - 1) % PTY_BUF_CAP;
		if (r->buf[last] != '\n') {
			r->tail = last;
			r->count--;
			ok = 1;
		}
	}
	release_irqrestore(&r->lock, flags);
	return ok;
}

static void pty_init_termios(struct pty_pair *p) {
	memset(p->term_cc, 0, sizeof(p->term_cc));
	p->term_iflag = TCS_ICRNL | TCS_IXON;
	p->term_oflag = TCS_OPOST | TCS_ONLCR;
	p->term_cflag = TCS_CFLAG_DEF;
	p->term_lflag = TCS_ISIG | TCS_ICANON | TCS_ECHO | TCS_ECHOE | TCS_ECHOK | TCS_IEXTEN;
	p->term_cc[TCS_VINTR] = 3;
	p->term_cc[TCS_VQUIT] = 034;
	p->term_cc[TCS_VERASE] = 0177; /* DEL — what SSH/xterm send for Backspace */
	p->term_cc[TCS_VKILL] = 025;
	p->term_cc[TCS_VEOF] = 4;
	p->term_cc[TCS_VTIME] = 0;
	p->term_cc[TCS_VMIN] = 1;
	p->term_cc[8] = 021; /* VSTART */
	p->term_cc[9] = 023; /* VSTOP */
	p->term_cc[10] = 032; /* VSUSP */
}

static size_t pty_ring_free(struct pty_ring *r) {
	size_t used = pty_ring_avail(r);
	if (used >= PTY_BUF_CAP - 1)
		return 0;
	return (PTY_BUF_CAP - 1) - used;
}

/* Slave → master: OPOST (ONLCR turns NL into CRNL — SSH staircase fix).
 * Returns 1 if the source byte was consumed, 0 if the output ring is full. */
static size_t pty_opost_one(struct pty_pair *p, unsigned char c) {
	uint32_t oflag = p->term_oflag;
	char tmp[2];
	size_t tn = 1;

	tmp[0] = (char)c;
	if ((oflag & TCS_OPOST) && (oflag & TCS_ONLCR) && c == '\n') {
		tmp[0] = '\r';
		tmp[1] = '\n';
		tn = 2;
	} else if ((oflag & TCS_OPOST) && (oflag & TCS_OCRNL) && c == '\r') {
		tmp[0] = '\n';
		tn = 1;
	} else if (!(oflag & TCS_OPOST)) {
		tn = 1;
	}
	if (pty_ring_free(&p->s2m) < tn)
		return 0;
	return pty_ring_write(&p->s2m, tmp, tn) == tn ? 1 : 0;
}

static void pty_echo_char(struct pty_pair *p, unsigned char c) {
	uint32_t lflag = p->term_lflag;
	if (!(lflag & TCS_ECHO) && !((lflag & TCS_ECHONL) && c == '\n'))
		return;
	if ((lflag & TCS_ECHOCTL) && c < 32 && c != '\t' && c != '\n' && c != '\r') {
		char vis[2];
		vis[0] = '^';
		vis[1] = (char)(c + '@');
		(void)pty_ring_write(&p->s2m, vis, 2);
		return;
	}
	if ((lflag & TCS_ECHOCTL) && c == 127) {
		(void)pty_ring_write(&p->s2m, "^?", 2);
		return;
	}
	(void)pty_opost_one(p, c);
}

static size_t pty_output_from_slave(struct pty_pair *p, const char *src, size_t n) {
	size_t i;
	for (i = 0; i < n; i++) {
		if (!pty_opost_one(p, (unsigned char)src[i]))
			break;
	}
	return i;
}

static size_t pty_input_from_master(struct pty_pair *p, const char *src, size_t n) {
	uint32_t iflag = p->term_iflag;
	uint32_t lflag = p->term_lflag;
	unsigned char verase = p->term_cc[TCS_VERASE];
	unsigned char vkill = p->term_cc[TCS_VKILL];
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)src[i];
		char ch;

		if ((iflag & TCS_IGNCR) && c == '\r')
			continue;
		if ((iflag & TCS_ICRNL) && c == '\r')
			c = '\n';
		else if ((iflag & TCS_INLCR) && c == '\n')
			c = '\r';

		if ((lflag & TCS_ICANON) && verase && c == verase) {
			if (pty_ring_erase_last(&p->m2s) && (lflag & TCS_ECHO) && (lflag & TCS_ECHOE)) {
				(void)pty_ring_write(&p->s2m, "\b \b", 3);
			}
			continue;
		}
		if ((lflag & TCS_ICANON) && vkill && c == vkill) {
			while (pty_ring_erase_last(&p->m2s)) {
				if ((lflag & TCS_ECHO) && (lflag & TCS_ECHOE))
					(void)pty_ring_write(&p->s2m, "\b \b", 3);
			}
			continue;
		}

		if (pty_ring_free(&p->m2s) < 1)
			break;
		ch = (char)c;
		if (pty_ring_write(&p->m2s, &ch, 1) != 1)
			break;
		pty_echo_char(p, c);
	}
	return i;
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
			p->locked = 0;
			p->fg_pgrp = -1;
			p->controlling_sid = -1;
			pty_init_termios(p);
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
	/*
	 * Linux: the /dev/pts/N inode exists as soon as ptmx is opened.
	 * TIOCSPTLCK is advisory; glibc grantpt() stats (and some openpty
	 * paths open) the slave while still locked. Treating lock as
	 * "no such file" made dropbear log openpty: ENOENT.
	 */
	if (!p->in_use) {
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
		/* Linux O_NONBLOCK: dpkg child FlushSTDIN would hang forever. */
		if (f->flags & 0x800)
			return -11;
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
	size_t done = 0;
	const char *src = (const char *)buf;

	if (!h || !buf)
		return -1;
	if (n == 0)
		return 0;

	while (done < n) {
		size_t w;
		if (h->is_master)
			w = pty_input_from_master(h->pair, src + done, n - done);
		else
			w = pty_output_from_slave(h->pair, src + done, n - done);
		if (w == 0) {
			thread_yield();
			if (h->is_master)
				w = pty_input_from_master(h->pair, src + done, n - done);
			else
				w = pty_output_from_slave(h->pair, src + done, n - done);
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

int pty_peer_hungup(struct fs_file *f) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return 0;
	if (h->is_master)
		return h->pair->slave_opens == 0;
	return h->pair->master_opens == 0;
}

static struct pty_ring *pty_in_ring(struct pty_handle *h) {
	return h->is_master ? &h->pair->s2m : &h->pair->m2s;
}

int pty_add_waiter(struct fs_file *f, int tid) {
	struct pty_handle *h = pty_handle_of(f);
	struct pty_ring *r;
	unsigned long flags = 0;
	int i;

	if (!h || tid < 0)
		return -1;
	r = pty_in_ring(h);
	acquire_irqsave(&r->lock, &flags);
	for (i = 0; i < r->waiters_count; i++) {
		if (r->waiters[i] == tid) {
			release_irqrestore(&r->lock, flags);
			return 0;
		}
	}
	if (r->waiters_count >= (int)(sizeof(r->waiters) / sizeof(r->waiters[0]))) {
		release_irqrestore(&r->lock, flags);
		return -1;
	}
	r->waiters[r->waiters_count++] = tid;
	release_irqrestore(&r->lock, flags);
	return 0;
}

void pty_remove_waiter(struct fs_file *f, int tid) {
	struct pty_handle *h = pty_handle_of(f);
	struct pty_ring *r;
	unsigned long flags = 0;
	int i;

	if (!h || tid < 0)
		return;
	r = pty_in_ring(h);
	acquire_irqsave(&r->lock, &flags);
	for (i = 0; i < r->waiters_count; i++) {
		if (r->waiters[i] == tid) {
			r->waiters[i] = r->waiters[r->waiters_count - 1];
			r->waiters_count--;
			break;
		}
	}
	release_irqrestore(&r->lock, flags);
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

void pty_get_termios(struct fs_file *f, uint32_t *iflag, uint32_t *oflag,
		     uint32_t *cflag, uint32_t *lflag, uint8_t *cc, size_t ncc) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	if (iflag) *iflag = h->pair->term_iflag;
	if (oflag) *oflag = h->pair->term_oflag;
	if (cflag) *cflag = h->pair->term_cflag;
	if (lflag) *lflag = h->pair->term_lflag;
	if (cc && ncc) {
		size_t n = ncc < PTY_NCCS ? ncc : PTY_NCCS;
		memcpy(cc, h->pair->term_cc, n);
	}
}

void pty_set_termios(struct fs_file *f, uint32_t iflag, uint32_t oflag,
		     uint32_t cflag, uint32_t lflag, const uint8_t *cc, size_t ncc) {
	struct pty_handle *h = pty_handle_of(f);
	if (!h)
		return;
	h->pair->term_iflag = iflag;
	h->pair->term_oflag = oflag;
	h->pair->term_cflag = cflag;
	h->pair->term_lflag = lflag;
	if (cc && ncc) {
		size_t n = ncc < PTY_NCCS ? ncc : PTY_NCCS;
		memcpy(h->pair->term_cc, cc, n);
	}
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
	/* Linux: /dev/ptmx is 5:2; Unix98 slaves are major 136 + index. */
	if (h->is_master)
		st->st_rdev = MKDEV(5, 2);
	else
		st->st_rdev = MKDEV(136, (unsigned)h->pair->index);
	return 0;
}
