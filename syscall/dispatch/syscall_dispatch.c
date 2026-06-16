#include "syscall_internal.h"

static uint64_t last_syscall_debug = 0;
static uint64_t g_execve_retry_eagain = 0;
static uint64_t g_execve_retry_ok = 0;
static uint64_t g_execve_retry_fail = 0;
static uint64_t g_execve_retry_last_log_ms = 0;

static inline int is_watch_proc(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    const char *nm = t->name;
    return (strstr(nm, "busybox") || strstr(nm, "wget") || strstr(nm, "uget") ||
            strstr(nm, "adduser") || strstr(nm, "addgroup")) ? 1 : 0;
}

static inline int path_is_passwdish(const char *p) {
    if (!p) return 0;
    return (strncmp(p, "/etc/passwd", 11) == 0) ||
           (strncmp(p, "/etc/group", 10) == 0) ||
           (strncmp(p, "/etc/shadow", 11) == 0) ||
           (strncmp(p, "/etc/gshadow", 12) == 0);
}

static int g_syscall_trace_on = 1;
static int g_syscall_trace_budget = 4000;

static inline int syscall_trace_pick(uint64_t num) {
    switch ((int)num) {
        case 0: case 1: case 3: case 9: case 10: case 11: case 12: case 16:
        case 23: case 35: case 42: case 57: case 59: case 60: case 61: case 72:
        case 78: case 79: case 87: case 89: case 97: case 158: case 202: case 231:
        case 217: case 257: case 258: case 259: case 260: case 262: case 263:
        case 264: case 265: case 268: case 271: case 7:
            return 1;
        default:
            return 0;
    }
}

uint64_t ret_err(int e) {
    /* Temporary diagnostics for userland failures (wget, adduser, addgroup). */
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (t && t->name[0]) {
        const char *nm = t->name;
        int watch = 0;
        if (strstr(nm, "wget")) watch = 1;
        else if (strstr(nm, "uget")) watch = 1;
        else if (strstr(nm, "addgroup")) watch = 1;
        else if (strstr(nm, "adduser")) watch = 1;
        if (watch) {
            /* Rate-limit repetitive error logs (e.g. connect/read retries in wget).
               Excessive kprintf in hot paths can itself destabilize networking timings. */
            static uint64_t err_last_ms = 0;
            static uint64_t err_last_sys = ~0ULL;
            static int err_last_no = 0;
            static int err_repeat = 0;
            uint64_t now_ms = pit_get_time_ms();
            int suppress = 0;
            if (last_syscall_debug == err_last_sys && e == err_last_no && (now_ms - err_last_ms) < 2500ULL) {
                err_repeat++;
                if (err_repeat > 8) suppress = 1;
            } else {
                if (err_repeat > 8) {
                    qemu_debug_printf("SYSCALL-ERR: syscall=%llu errno=%d pid=%s (suppressed %d repeats)\n",
                        (unsigned long long)err_last_sys, err_last_no, nm, err_repeat - 8);
                }
                err_last_sys = last_syscall_debug;
                err_last_no = e;
                err_repeat = 0;
                err_last_ms = now_ms;
            }
            /* close(3)+EBADF is often harmless in libc fallback paths. */
            if (last_syscall_debug == 3u && e == EBADF)
                return (uint64_t)(-(int64_t)e);
            /* read(2)+EAGAIN on wget sockets is expected during polling; don't spam logs. */
            if (last_syscall_debug == SYS_read && e == EAGAIN)
                return (uint64_t)(-(int64_t)e);
            if (!suppress) {
                qemu_debug_printf("SYSCALL-ERR: syscall=%llu errno=%d pid=%s\n",
                    (unsigned long long)last_syscall_debug, e, nm);
                qemu_debug_printf("SYSCALL-ERR: syscall=%llu err=%d tid=%llu name=%s brk=0x%llx mmap_next=0x%llx\n",
                    (unsigned long long)last_syscall_debug,
                    e,
                    (unsigned long long)(t->tid ? t->tid : 1),
                    nm,
                    (unsigned long long)(uint64_t)t->user_brk_cur,
                    (unsigned long long)(uint64_t)t->user_mmap_next);
            }
        }
    }
    if (e == ENOMEM) {
        oom_serial_notify(last_syscall_debug, (t && t->name[0]) ? t->name : 0);
        qemu_debug_printf("ENOMEM: syscall=%llu name=%s heap_used=%llu heap_total=%llu\n",
            (unsigned long long)last_syscall_debug,
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes());
        qemu_debug_printf("ENOMEM: syscall=%llu tid=%llu name=%s brk=0x%llx mmap_next=0x%llx heap_used=%llu heap_total=%llu heap_peak=%llu\n",
            (unsigned long long)last_syscall_debug,
            (unsigned long long)(t ? (t->tid ? t->tid : 1) : 0),
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)(t ? (uint64_t)t->user_brk_cur : 0),
            (unsigned long long)(t ? (uint64_t)t->user_mmap_next : 0),
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes(),
            (unsigned long long)heap_peak_bytes());
    }
    return (uint64_t)(-(int64_t)e);
}

/* minimal signal numbers used */
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef ESPIPE
#define ESPIPE 29
#endif
#ifndef SIGINT
#define SIGINT 2
#endif

void thread_set_pending_signal(thread_t *t, int signum) {
    if (!t || signum <= 0 || signum > 63) return;
    t->pending_signals |= (1ULL << (signum - 1));
    /* Wake any thread blocked in sigtimedwait so it can observe the signal. */
    if (t->state == THREAD_BLOCKED) {
        thread_unblock((int)(t->tid ? t->tid : 1));
    }
}

static int thread_fetch_pending_signal(thread_t *t, uint64_t mask) {
    if (!t) return 0;
    if (mask == 0) mask = ~0ULL;
    /* Always allow SIGCHLD to wake waits to avoid init deadlocks. */
    mask |= (1ULL << (SIGCHLD - 1));
    for (int sig = 1; sig <= 63; sig++) {
        uint64_t bit = 1ULL << (sig - 1);
        if ((mask & bit) && (t->pending_signals & bit)) {
            t->pending_signals &= ~bit;
            return sig;
        }
    }
    return 0;
}

static int is_init_user(thread_t *t) {
    int init_tid = thread_get_init_user_tid();
    return t && init_tid >= 0 && (int)t->tid == init_tid;
}

static int has_terminated_child(thread_t *t) {
    if (!t) return 0;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return 1;
        }
    }
    return 0;
}

static thread_t *find_terminated_child(thread_t *t) {
    if (!t) return NULL;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return c;
        }
    }
    return NULL;
}

/* Returns 1 if path contains . or .. components that need normalization. */
static int path_needs_normalize(const char *p) {
    if (!p) return 0;
    if (p[0] == '.' && (p[1] == '\0' || p[1] == '/')) return 1;
    if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
    for (; *p; p++) {
        if (*p == '/' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
        if (*p == '/' && p[1] == '.' && p[2] == '.' && (p[3] == '\0' || p[3] == '/')) return 1;
    }
    return 0;
}

/* Normalize path by resolving . and .. components. Modifies buf in place. */
static void normalize_path(char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    char tmp[512];
    const char *comps[64];
    size_t comp_len[64];
    int n = 0;
    const char *p = buf;
    while (*p && n < (int)(sizeof(comps) / sizeof(comps[0]))) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 0) continue;
        if (len == 1 && start[0] == '.') continue;  /* skip . */
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (n > 0) n--;  /* pop .. */
            continue;
        }
        comps[n] = start;
        comp_len[n] = len;
        n++;
    }
    size_t pos = 0;
    tmp[pos++] = '/';
    for (int i = 0; i < n && pos < sizeof(tmp) - 1; i++) {
        if (i > 0) tmp[pos++] = '/';
        for (size_t j = 0; j < comp_len[i] && pos < sizeof(tmp) - 1; j++)
            tmp[pos++] = comps[i][j];
    }
    tmp[pos] = '\0';
    strncpy(buf, tmp, cap - 1);
    buf[cap - 1] = '\0';
}

static void map_tty_alias_path(char *buf, size_t cap) {
    if (!buf || cap < 10) return;
    if (strncmp(buf, "/tty", 4) == 0 &&
        buf[4] >= '1' && buf[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
        buf[5] == '\0') {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "/dev/tty%c", buf[4]);
        strncpy(buf, tmp, cap - 1);
        buf[cap - 1] = '\0';
    }
}

static void resolve_user_path(thread_t *cur, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    const char *path = path_u;
    char path_local[256];
    if (path_u && user_range_ok(path_u, 1)) {
        size_t L = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
        if (!user_range_ok(path_u, L + 1) || copy_from_user_raw(path_local, path_u, L + 1) != 0) {
            strncpy(out, "/", out_cap);
            out[out_cap - 1] = '\0';
            return;
        }
        path_local[L] = '\0';
        path = path_local;
    }
    if (!path || !path[0]) {
        strncpy(out, "/", out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
    if (path[0] == '/') {
        strncpy(out, path, out_cap);
        out[out_cap - 1] = '\0';
        if (path_needs_normalize(out)) normalize_path(out, out_cap);
        map_tty_alias_path(out, out_cap);
        return;
    }
    /* "." means current directory. */
    if (strcmp(path, ".") == 0) {
        strncpy(out, cwd, out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    /* ".." means parent directory. */
    if (strcmp(path, "..") == 0) {
        if (strcmp(cwd, "/") == 0) {
            strncpy(out, "/", out_cap);
            out[out_cap - 1] = '\0';
        } else {
            const char *slash = strrchr(cwd, '/');
            if (slash && slash > cwd) {
                size_t len = (size_t)(slash - cwd);
                if (len >= out_cap) len = out_cap - 1;
                memcpy(out, cwd, len);
                out[len] = '\0';
            } else {
                strncpy(out, "/", out_cap);
                out[out_cap - 1] = '\0';
            }
        }
        return;
    }
    /* Build full path and normalize (handles ./run, a/./b, a/../b, etc.) */
    if (strcmp(cwd, "/") == 0) {
        snprintf(out, out_cap, "/%s", path);
    } else {
        snprintf(out, out_cap, "%s/%s", cwd, path);
    }
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    map_tty_alias_path(out, out_cap);
}

/* Resolve path for openat: dirfd base or cwd. Returns 0 on success, negative errno on error. */
static int resolve_user_path_at(thread_t *cur, int dirfd, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return -EFAULT;
    out[0] = '\0';
    const char *path = path_u;
    char path_local[256];
    if (path_u && user_range_ok(path_u, 1)) {
        size_t L = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
        if (!user_range_ok(path_u, L + 1) || copy_from_user_raw(path_local, path_u, L + 1) != 0) return -EFAULT;
        path_local[L] = '\0';
        path = path_local;
    }
    if (!path || !path[0]) return -ENOENT;
    /* Absolute path: dirfd ignored, use standard resolve */
    if (path[0] == '/') {
        resolve_user_path(cur, path, out, out_cap);
        return 0;
    }
    /* AT_FDCWD = -100: use current working directory */
    enum { AT_FDCWD = -100 };
    if (dirfd == AT_FDCWD) {
        resolve_user_path(cur, path, out, out_cap);
        return 0;
    }
    /* dirfd: resolve relative to that directory */
    if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return -EBADF;
    struct fs_file *f = cur->fds[dirfd];
    if (!f) return -EBADF;
    if (f->type != FS_TYPE_DIR) return -ENOTDIR;
    const char *base = f->path ? f->path : "/";
    size_t bl = strlen(base);
    int has_trailing = (bl > 1 && base[bl - 1] == '/');
    size_t pl = strlen(path);
    if (has_trailing) {
        snprintf(out, out_cap, "%s%s", base, path);
    } else {
        snprintf(out, out_cap, "%s/%s", base, path);
    }
    out[out_cap - 1] = '\0';
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    return 0;
}

/* Minimal tty state for job control-ish ioctls (single session). */
static uint64_t user_pgrp = 1;

/* Signal delivery: handlers, restorers, and per-thread mask. */
typedef void (*user_sighandler_t)(int);
#define SA_SIGINFO 0x4
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0x01000000u
#endif
#define SIG_DFL ((user_sighandler_t)0)
#define SIG_IGN ((user_sighandler_t)1)
typedef struct {
    user_sighandler_t handler;
    uint64_t restorer;   /* glibc passes __restore_rt; we need it for sigreturn */
    uint64_t flags;      /* SA_SIGINFO etc. */
} user_sigaction_t;
static user_sigaction_t user_sig_actions[65]; /* 1..64 */
/* Legacy global mask; rt_sigprocmask uses per-thread saved_sig_mask when available */
static uint64_t user_sig_mask = 0;
/* Compatibility shim for tools (e.g. ping) that expect periodic SIGALRM. */
static uint32_t user_itimer_interval_ms = 0;

/* write()/writev() on sockets: glibc DNS may use writev; fs_write() does not handle SYSCALL_FTYPE_SOCKET. */
static ssize_t net_sock_write_userspace(thread_t *cur, int fd, ksock_net_t *s, const void *bufp, size_t cnt) {
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        (void)cur;
        (void)fd;
        if (!s->connected) return -ENOTCONN;
        if (cnt == 0) return 0;
        return unix_stream_write_from_user(s, bufp, cnt);
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (!bufp || cnt == 0) return -EINVAL;
        if (cnt < sizeof(nlmsghdr_k) || !user_range_ok(bufp, cnt)) return -EFAULT;
        uint8_t pkt[256];
        size_t cp = (cnt > sizeof(pkt)) ? sizeof(pkt) : cnt;
        if (copy_from_user_raw(pkt, bufp, cp) != 0) return -EFAULT;
        nlmsghdr_k *h = (nlmsghdr_k *)pkt;
        if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > cnt) return -EINVAL;
        if (s->nl_pid == 0) s->nl_pid = (uint32_t)((cur && cur->tid) ? cur->tid : 1);
        (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
        return (ssize_t)cnt;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            if (!s->connected) return -EDESTADDRREQ;
            if (cnt > 2048) return -EINVAL;
            if (s->local_port == 0)
                s->local_port = net_alloc_ephemeral_port();
            uint8_t *payload = (uint8_t *)kmalloc(cnt);
            if (!payload) return -ENOMEM;
            if (copy_from_user_raw(payload, bufp, cnt) != 0) {
                kfree(payload);
                return -EFAULT;
            }
            int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
            kfree(payload);
            if (r != 0) return (ssize_t)(e1000_is_ready() ? -EIO : -ENETDOWN);
            return (ssize_t)cnt;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->tcp.peer_rst) return -ECONNRESET;
        if (s->tcp.peer_fin) return -EPIPE;
        if (!s->connected || !s->tcp.established) return -ENOTCONN;
        size_t total = 0;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, &s->tcp);
        while (total < cnt) {
            size_t chunk = cnt - total;
            if (chunk > 4096) chunk = 4096;
            uint8_t *tmp = (uint8_t *)kmalloc(chunk);
            if (!tmp) return (ssize_t)((total > 0) ? (ssize_t)total : -ENOMEM);
            if (copy_from_user_raw(tmp, (const uint8_t *)bufp + total, chunk) != 0) {
                kfree(tmp);
                return (ssize_t)((total > 0) ? (ssize_t)total : -EFAULT);
            }
            if (total == 0)
                net_debug_log_tls443_tx(s, tmp, chunk, "write");
            int wr = net_tcp_send(&s->tcp, &ops, tmp, chunk, 30000);
            kfree(tmp);
            if (wr < 0) {
                return (ssize_t)((total > 0) ? (ssize_t)total : -EIO);
            }
            total += (size_t)wr;
            if ((size_t)wr < chunk) break;
        }
        (void)net_tcp_flush_tx(&s->tcp, &ops, 5000);
        for (int p = 0; p < 64; p++) {
            e1000_poll();
            (void)net_tcp_service(&s->tcp, &ops, 128);
            if (s->tcp.rx_len > 0)
                break;
        }
        (void)net_tcp_window_update(&s->tcp, &ops);
        return (ssize_t)total;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (!s->connected) return -EDESTADDRREQ;
        if (cnt > 2048) return -EINVAL;
        if (s->local_port == 0)
            s->local_port = net_alloc_ephemeral_port();
        uint8_t *payload = (uint8_t *)kmalloc(cnt);
        if (!payload) return -ENOMEM;
        if (copy_from_user_raw(payload, bufp, cnt) != 0) {
            kfree(payload);
            return -EFAULT;
        }
        int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
        kfree(payload);
        if (r != 0) return (ssize_t)(e1000_is_ready() ? -EIO : -ENETDOWN);
        return (ssize_t)cnt;
    }
    return -EINVAL;
}

/* read()/readv() on sockets; readv uses repeated calls (UDP rx_pending_off preserves datagram). */
static ssize_t net_sock_read_userspace(thread_t *cur, ksock_net_t *s, void *bufp, size_t cnt) {
    (void)cur;
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        if (!s->connected) return -ENOTCONN;
        if (cnt == 0) return 0;
        return unix_stream_read_to_user(s, bufp, cnt, 0);
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (cnt == 0) return 0;
        if (!bufp || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->nl_rx_off >= s->nl_rx_len)
            return 0; /* EOF after dump — ip(8) treats EAGAIN as OVERRUN */
        size_t avail = s->nl_rx_len - s->nl_rx_off;
        size_t ncopy = (avail > cnt) ? cnt : avail;
        if (copy_to_user_safe(bufp, s->nl_rx + s->nl_rx_off, ncopy) != 0) return -EFAULT;
        s->nl_rx_off += ncopy;
        return (ssize_t)ncopy;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            size_t cap = cnt > 8192 ? 8192 : cnt;
            uint8_t *utmp = (uint8_t *)kmalloc(cap);
            if (!utmp) return -ENOMEM;
            if (!s->rx_has_pending) {
                int pr = net_udp_recv_into_pending(s);
                if (pr != 1) {
                    kfree(utmp);
                    if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                    return -EIO;
                }
            }
            int n = 0;
            ksock_rx_pending_normalize(s);
            if (s->rx_has_pending) {
                size_t avail = ksock_rx_pending_avail(s);
                n = (int)((avail > cap) ? cap : avail);
                if (n > 0) memcpy(utmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                s->rx_pending_off += (size_t)n;
                if (s->rx_pending_off >= s->rx_pending_len) {
                    s->rx_has_pending = 0;
                    s->rx_pending_off = 0;
                    s->rx_pending_len = 0;
                }
            }
            if (n > 0 && copy_to_user_safe(bufp, utmp, (size_t)n) != 0) {
                kfree(utmp);
                return -EFAULT;
            }
            kfree(utmp);
            if (n <= 0) return -EAGAIN;
            return (ssize_t)n;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
        if (!s->tcp.established && s->tcp.connect_pending) {
            net_tcp_ops_t cops;
            net_make_tcp_ops(&cops, &s->tcp);
            e1000_poll();
            if (net_tcp_connect_poll(&s->tcp, &cops, 200) == 0)
                s->connected = 1;
        }
        if (!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) {
            if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
            if (s->tcp.rx_len == 0) return -ENOTCONN;
        }
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops, &s->tcp);
        size_t chunk = cnt;
        if (chunk > 16384) chunk = 16384;
        uint8_t *tmp = (uint8_t *)kmalloc(chunk);
        if (!tmp) return -ENOMEM;
        size_t total = 0;
        for (;;) {
            for (int pump = 0; pump < 512; pump++) {
                e1000_poll();
                (void)net_tcp_service(&s->tcp, &ops, 256);
                if (s->tcp.rx_len > 0)
                    break;
                if (s->tcp.peer_rst)
                    break;
            }
            if (s->tcp.established && s->tcp.rx_len < sizeof(s->tcp.rx_buf))
                (void)net_tcp_window_update(&s->tcp, &ops);
            uint32_t tmo = s->nonblock ? 0u : 120000u;
            int rr = net_tcp_recv(&s->tcp, &ops, tmp + total, chunk - total, tmo);
            if (rr > 0) {
                total += (size_t)rr;
                if (total >= chunk || rr < (int)(chunk - total))
                    break;
                for (int pump = 0; pump < 16; pump++) {
                    e1000_poll();
                    (void)net_tcp_service(&s->tcp, &ops, 64);
                }
                continue;
            }
            if (total > 0)
                break;
            kfree(tmp);
            if (rr == 0) return 0;
            if (rr == -4) return -ECONNRESET;
            if (rr == -2)
                return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
            return (ssize_t)(s->nonblock ? -EAGAIN : -EIO);
        }
        if (copy_to_user_safe(bufp, tmp, total) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        return (ssize_t)total;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        if (!s->rx_has_pending) {
            int pr = net_udp_recv_into_pending(s);
            if (pr != 1) {
                kfree(tmp);
                if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                return -EIO;
            }
        }
        int n = 0;
        ksock_rx_pending_normalize(s);
        if (s->rx_has_pending) {
            size_t avail = ksock_rx_pending_avail(s);
            n = (int)((avail > cap) ? cap : avail);
            if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
            s->rx_pending_off += (size_t)n;
            if (s->rx_pending_off >= s->rx_pending_len) {
                s->rx_has_pending = 0;
                s->rx_pending_off = 0;
                s->rx_pending_len = 0;
            }
        }
        if (n > 0 && copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        if (n <= 0) return -EAGAIN;
        return (ssize_t)n;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_ICMP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
        int n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, NULL);
        if (n < 0) {
            kfree(tmp);
            return -EIO;
        }
        if (n == 0) {
            kfree(tmp);
            return -ETIMEDOUT;
        }
        if (copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        return (ssize_t)n;
    }
    return -EINVAL;
}

/* Linux x86_64 rt_sigframe layout for signal delivery. */
#pragma pack(push, 1)
typedef struct {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx;
    uint64_t rsp, rip, eflags;
    uint16_t cs, gs, fs;
    uint16_t ss;
    uint64_t err, trapno, oldmask, cr2;
    uint64_t fpstate;
    uint64_t reserved1[8];
} k_sigcontext_t;
typedef struct {
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_ss_sp, uc_stack_ss_size;
    uint32_t uc_stack_ss_flags, uc_pad;
    uint64_t uc_sigmask[2];
    k_sigcontext_t uc_mcontext;
} k_ucontext_t;
#pragma pack(pop)
#define RT_SIGFRAME_UC_OFF  8
#define RT_SIGFRAME_SIZE   (8 + sizeof(k_ucontext_t))


/* Build signal frame and patch syscall return for delivery. Called from syscall_entry64. */
int maybe_deliver_pending_signal(void) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || cur->ring != 3) return 0;
    uint64_t blocked = cur->saved_sig_mask;
    uint64_t pending = cur->pending_signals & ~blocked;
    if (!pending) return 0;
    int sig = 0;
    for (int s = 1; s <= 63 && !sig; s++) {
        if (pending & (1ULL << (s - 1))) sig = s;
    }
    if (sig <= 0) return 0;
    user_sigaction_t *sa = &user_sig_actions[sig];
    user_sighandler_t h = sa->handler;
    uint64_t restorer = sa->restorer;
    if (h == SIG_IGN) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        return maybe_deliver_pending_signal();
    }
    if (h == SIG_DFL) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        /* Default action Term: terminate process (SIGINT, SIGQUIT, SIGTERM, SIGPIPE, etc.).
           Process must actually exit so parent's wait() returns and shell gets control back. */
        if (sig == SIGINT || sig == 3 /*SIGQUIT*/ || sig == 15 /*SIGTERM*/ || sig == 13 /*SIGPIPE*/) {
            cur->exit_status = sig; /* WIFSIGNALED, WTERMSIG = sig */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                if (cur->fds[i]) {
                    struct fs_file *f = cur->fds[i];
                    cur->fds[i] = NULL;
                    fs_file_free(f);
                }
            }
            thread_yield(); /* let pipe reader run before waking parent */
            if (cur->parent_tid >= 0) {
                thread_t *pt = thread_get(cur->parent_tid);
                if (pt) {
                    thread_set_pending_signal(pt, SIGCHLD);
                    if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty)
                        devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                }
            }
            if (cur->vfork_parent_tid >= 0) {
                vfork_restore_parent_memory(cur);
                vfork_restore_parent_stack(cur);
                thread_unblock(cur->vfork_parent_tid);
                cur->vfork_parent_tid = -1;
            }
            if (cur->waiter_tid >= 0) thread_unblock(cur->waiter_tid);
            if (cur->clear_child_tid != 0 && cur->clear_child_tid < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                uint32_t zero = 0;
                copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                { extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                  futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0); }
                cur->clear_child_tid = 0;
            }
            cur->state = THREAD_TERMINATED;
            if (cur->mm && cur->mm != mm_kernel()) {
                mm_release(cur->mm);
                cur->mm = mm_kernel();
            }
            thread_yield();
            for (;;) asm volatile("sti; hlt" ::: "memory");
        }
        return maybe_deliver_pending_signal();
    }
    if (!restorer) return 0;
    uint64_t old_rsp = cur->saved_user_rsp;
    uint64_t old_rip = cur->saved_user_rip;
    if (!old_rsp || !old_rip) return 0;
    uintptr_t frame_start = ((uintptr_t)old_rsp - RT_SIGFRAME_SIZE) & ~15ULL;
    if (frame_start < 0x200000ULL) return 0;
    if (mark_user_identity_range_2m_sys((uint64_t)frame_start, (uint64_t)(frame_start + RT_SIGFRAME_SIZE)) != 0)
        return 0;
    k_ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    uc.uc_mcontext.r8  = cur->saved_user_r8;
    uc.uc_mcontext.r9  = cur->saved_user_r9;
    uc.uc_mcontext.r10 = cur->saved_user_r10;
    uc.uc_mcontext.r11 = cur->saved_user_r11;
    uc.uc_mcontext.r12 = cur->saved_user_r12;
    uc.uc_mcontext.r13 = cur->saved_user_r13;
    uc.uc_mcontext.r14 = cur->saved_user_r14;
    uc.uc_mcontext.r15 = cur->saved_user_r15;
    uc.uc_mcontext.rdi = cur->saved_user_rdi;
    uc.uc_mcontext.rsi = cur->saved_user_rsi;
    uc.uc_mcontext.rbp = cur->saved_user_rbp;
    uc.uc_mcontext.rbx = cur->saved_user_rbx;
    uc.uc_mcontext.rdx = cur->saved_user_rdx;
    uc.uc_mcontext.rax = syscall_user_return_rax;
    uc.uc_mcontext.rcx = cur->saved_user_rcx;
    uc.uc_mcontext.rsp = old_rsp;
    uc.uc_mcontext.rip = old_rip;
    uc.uc_mcontext.eflags = cur->saved_user_r11;
    uc.uc_mcontext.cs = 0x1B;
    uc.uc_mcontext.gs = 0;
    uc.uc_mcontext.fs = 0;
    uc.uc_mcontext.ss = 0x23;
    uc.uc_sigmask[0] = blocked;
    if (copy_to_user_safe((void *)(uintptr_t)(frame_start + RT_SIGFRAME_UC_OFF), &uc, sizeof(uc)) != 0)
        return 0;
    if (copy_to_user_safe((void *)(uintptr_t)frame_start, &restorer, sizeof(restorer)) != 0)
        return 0;
    cur->pending_signals &= ~(1ULL << (sig - 1));
    uint64_t *frame = cur->saved_syscall_frame;
    if (!frame) return 0;
    frame[8]  = (uint64_t)sig;
    frame[13] = (uint64_t)(uintptr_t)h;
    frame[15] = (uint64_t)frame_start;
    syscall_user_rsp_saved = (uint64_t)frame_start;
    asm volatile("mfence" ::: "memory");
    return 1;
}

/* Simple getrandom() state (non-crypto). */
static uint32_t user_rand_state = 0xA53C9E11u;

static inline int is_leap_year(int y) {
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

/* Convert rtc_datetime_t (year full e.g. 2025) to unix epoch seconds (UTC assumed). */
static uint64_t rtc_datetime_to_epoch(const rtc_datetime_t *dt) {
    if (!dt) return 0;
    int year = (int)dt->year;
    int month = (int)dt->month;
    int day = (int)dt->day;
    int hour = (int)dt->hour;
    int minute = (int)dt->minute;
    int second = (int)dt->second;
    /* Normalize month/year for algorithm: treat March as month 1 */
    if (month <= 2) {
        year -= 1;
        month += 12;
    }
    /* Days since epoch (1970-01-01) using proleptic Gregorian calendar */
    int64_t y = year;
    int64_t m = month;
    int64_t days = 365 * (y - 1970) + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
    /* month days cumulative for months starting at March=3 .. Feb=14 in this scheme */
    static const int mdays[] = {
        0,31,61,92,122,153,184,214,245,275,306,337, /* not used fully */
    };
    /* Simpler add days from months */
    static const int month_days_norm[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
    for (int mo = 1; mo < month; mo++) {
        days += month_days_norm[mo];
        if (mo == 2 && is_leap_year(year + (month <= 2 ? 1 : 0))) days += 1;
    }
    days += (day - 1);
    uint64_t secs = (uint64_t)days * 86400ULL + (uint64_t)hour * 3600ULL + (uint64_t)minute * 60ULL + (uint64_t)second;
    return secs;
}

/* Minimal signal numbers we use here */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif

/* Send simple signals to all threads in given pgrp.
   SIGHUP -> mark terminated (default action).
   SIGCONT -> move sleeping/blocked to ready.
*/
static void send_signal_to_pgrp(int pgrp, int signum) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->pgid != pgrp) continue;
        if (signum == SIGHUP) {
            if (t->state != THREAD_TERMINATED) {
                t->exit_status = (0 & 0xFF) << 8;
                t->state = THREAD_TERMINATED;
                if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
            }
        } else if (signum == SIGCONT) {
            if (t->state == THREAD_SLEEPING || t->state == THREAD_BLOCKED) {
                t->sleep_until = 0;
                thread_note_ready(t);
            }
        }
    }
}

/* Send SIGHUP to all members of a session (except leader) */
static void send_hup_to_session(int sid) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->sid != sid) continue;
        if ((int)t->tid == sid) continue; /* skip leader */
        if (t->state != THREAD_TERMINATED) {
            t->exit_status = (0 & 0xFF) << 8;
            t->state = THREAD_TERMINATED;
            if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
        }
    }
    /* Also clear controlling_sid on dev ttys owned by this session */
    devfs_clear_controlling_by_sid(sid);
}

/* Verbose per-syscall trace for /usr/bin/wget (budget-limited). Set left=0 to disable. */
static void axon_wget_sc_log(uint64_t num, uint64_t rax, uint64_t a1, uint64_t a2, uint64_t a3) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (!t || !t->name[0]) return;
    if (!strstr(t->name, "wget")) return;
    static int wget_sc_left = 512;
    static int wget_sc_warned;
    if (wget_sc_left <= 0) {
        if (!wget_sc_warned) {
            wget_sc_warned = 1;
            qemu_debug_printf("WGET-SC: trace budget exhausted (disable in axon_wget_sc_log)\n");
        }
        return;
    }
    wget_sc_left--;
    int64_t sr = (int64_t)rax;
    if (sr < 0 && sr >= -4096) {
        qemu_debug_printf("WGET-SC nr=%llu ERR=%d a1=0x%llx a2=0x%llx a3=0x%llx\n",
            (unsigned long long)num, (int)(-sr),
            (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
    } else {
        qemu_debug_printf("WGET-SC nr=%llu rax=0x%llx a1=0x%llx a2=0x%llx\n",
            (unsigned long long)num, (unsigned long long)rax,
            (unsigned long long)a1, (unsigned long long)a2);
    }
}

/* Fork COW: privatize program data/bss/heap and anon mmap (parent CR3 = share baseline). */
static int fork_privatize_child_mm(thread_t *child, thread_t *parent, thread_t *dbg_cur) {
    if (!child || !parent || !child->mm || !parent->mm) return -1;
    uintptr_t brk_lo = parent->user_brk_base ? (uintptr_t)parent->user_brk_base : 0x00800000u;
    uintptr_t brk_hi = parent->user_brk_cur ? (uintptr_t)parent->user_brk_cur : brk_lo;
    if (brk_hi < brk_lo) brk_hi = brk_lo;
    if (parent->user_mmap_hi > brk_hi)
        brk_hi = (uintptr_t)parent->user_mmap_hi;
    mm_t *parent_mm = parent->mm ? parent->mm : mm_kernel();
    mm_switch(parent_mm);
    uint64_t live_cr3 = paging_read_cr3() & ~0xFFFULL;
    fork_dbg(dbg_cur, 10, "cow-ranges",
        (unsigned long long)brk_lo,
        (unsigned long long)brk_hi,
        (unsigned long long)live_cr3);
    fork_dbg(dbg_cur, 11, "heap-stats",
        (unsigned long long)heap_used_bytes(),
        (unsigned long long)heap_free_bytes(),
        (unsigned long long)heap_largest_free());
    fork_dbg(dbg_cur, 16, "cow-share",
        (unsigned long long)(uintptr_t)parent_mm->pml4,
        (unsigned long long)(uintptr_t)child->mm->pml4,
        (unsigned long long)live_cr3);
    /* ET_EXEC/PIE .data/.bss through brk (axon-harness globals live here, not only brk-4K). */
    uintptr_t data_lo = 0x400000u;
    if (brk_lo > data_lo && brk_hi > data_lo) {
        uintptr_t data_hi = brk_hi + 0x1000u;
        uintptr_t cap = brk_lo + (uintptr_t)(4u << 20);
        if (data_hi > cap) data_hi = cap;
        if (data_hi > data_lo)
            (void)mm_cow_private_writable(child->mm, (uint64_t)data_lo, (uint64_t)data_hi);
    }
    /* brk page + page below (legacy single-page path). */
    uintptr_t bss_pg = (brk_lo >= 0x1000u) ? ((brk_lo - 0x1000u) & ~0xFFFULL) : 0;
    uintptr_t heap_pg = brk_lo & ~0xFFFULL;
    int r_bss = 0;
    if (bss_pg >= 0x1000u)
        r_bss = mm_make_private_range(child->mm, (uint64_t)bss_pg, (uint64_t)(bss_pg + 0x1000u), 1, parent_mm);
    int r_heap = (heap_pg != bss_pg)
        ? mm_make_private_range(child->mm, (uint64_t)heap_pg, (uint64_t)(heap_pg + 0x1000u), 1, parent_mm)
        : 0;
    fork_dbg(dbg_cur, 12, "cow-bss",
        (unsigned long long)bss_pg,
        (unsigned long long)(unsigned)(r_bss == 0 ? 1u : 0u),
        (unsigned long long)(unsigned)(r_bss ? 1u : 0u));
    fork_dbg(dbg_cur, 13, "cow-heap",
        (unsigned long long)heap_pg,
        (unsigned long long)(unsigned)(r_heap == 0 ? 1u : 0u),
        (unsigned long long)(unsigned)(r_heap ? 1u : 0u));
    if (r_bss != 0 && r_heap != 0) {
        fork_dbg(dbg_cur, -8, "WARN COW both",
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_free_bytes(),
            (unsigned long long)heap_largest_free());
    }
    return 0;
}

/* Common syscall dispatcher used by both int0x80 and SYSCALL.
   Calling convention follows Linux x86_64: num + up to 6 args. */
uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    /* IMPORTANT:
       current_user can be stale if some subsystem (e.g. tty switching) overwrote it.
       Syscalls must be handled for the *currently running* thread. */
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3) {
        /* fallback */
        cur = thread_get_current_user();
        if (!cur) cur = thread_current();
    }
    if (!cur) return ret_err(EPERM);
    /* Keep global current_user synchronized with the actually running user thread.
       Exec/job-control code reads thread_get_current_user(); stale value here can
       put parent and child into the same pgrp and break Ctrl+C behavior. */
    if (cur->ring == 3) {
        thread_set_current_user(cur);
    }
    cur->sc_a1 = a1;
    cur->sc_a2 = a2;
    cur->sc_a3 = a3;
    cur->sc_a4 = a4;
    cur->sc_a5 = a5;
    cur->sc_a6 = a6;
    /* saved_user_* are normally captured in syscall_entry64 via syscall_snapshot_user_regs().
       If that path wasn't used (fallback/int0x80), fall back to globals once. */
    /* If return RIP wasn't recorded by entry path, dump stack once for diagnosis. */
    if (cur->saved_user_rip == 0) debug_dump_kernel_syscall_stack();

    /* record last syscall for debug logging of ENOSYS */
    last_syscall_debug = num;

    // Uncomment if there is some syscall issue
    /*if (num != 1) kprintf("syscall: num=%llu\n", (unsigned long long)num);*/

    switch (num) {
        case SYS_clone: {
            /* Minimal compatibility: treat clone() without complex flags as fork(). */
            return syscall_do_inner(SYS_fork, 0, 0, 0, 0, 0, 0);
        }
        case SYS_clone3: {
            /* clone3(cl_args, size) - glibc pthreads passes user stack; must use it or advise_stack_range assert fails */
            const void *cl_args_u = (const void*)(uintptr_t)a1;
            size_t cl_size = (size_t)a2;
            if (!cl_args_u || cl_size < 64 || (uintptr_t)cl_args_u + 64 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            uint64_t cl_buf[8];
            if (copy_from_user_raw(cl_buf, cl_args_u, 64) != 0) return ret_err(EFAULT);
            uint64_t flags = cl_buf[0];
            uint64_t child_tid_ptr = cl_buf[2];
            uint64_t parent_tid_ptr = cl_buf[3];
            uint64_t stack = cl_buf[5];
            uint64_t stack_size = cl_buf[6];
            uint64_t tls = cl_buf[7];
            uint64_t saved_rcx = cur->saved_user_rip;
            if (saved_rcx == 0) return ret_err(EINVAL);
            /* clone3 with stack: create thread sharing parent's mm (CLONE_VM). */
            enum { CLONE3_CLONE_THREAD = 0x00010000u };
            int clone3_need_stack_copy = 0;
            if (stack != 0) {
                clone3_dbg(cur, 1, "enter",
                    (unsigned long long)flags,
                    (unsigned long long)stack,
                    (unsigned long long)stack_size);
                /* Linux/glibc clone3 (x86_64): clone_args.stack is the child's initial RSP,
                   i.e. the byte past the high end of the stack mapping (downward-growing stack).
                   stack_size is the span below that pointer, not an offset added to stack. */
                uintptr_t child_rsp = (uintptr_t)stack;
                uintptr_t stack_lo = child_rsp;
                if (stack_size != 0) {
                    if (child_rsp < stack_size) return ret_err(EINVAL);
                    stack_lo = child_rsp - (uintptr_t)stack_size;
                }
                if (child_rsp < 0x1000 || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EINVAL);
                /* Ensure saved_rcx (return site) is user-accessible - otherwise child #PF on first instruction */
                {
                    uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                    if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) != 0) {
                        qemu_debug_printf("clone3: saved return site 0x%llx unmapped/privileged\n", (unsigned long long)saved_rcx);
                        return ret_err(EINVAL);
                    }
                    /* Static/non-PIE harness globals may live below 2MiB; mark() only
                       changes existing PTEs, so explicitly create the low user mapping. */
                    (void)user_map_ensure_present_us_2m(0x10000, 0x200000);
                    (void)mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP);
                }
                /* RSP must be 16-byte aligned per x86-64 ABI (child may use movdqa/call) */
                {
                    uintptr_t aligned = child_rsp & ~(uintptr_t)0xFULL;
                    if (aligned >= stack_lo + 128u)
                        child_rsp = aligned;
                }
                if (child_rsp <= stack_lo || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                    return ret_err(EINVAL);

                uintptr_t map_lo = stack_lo & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t map_hi = (child_rsp + 4096u) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                if (map_hi <= map_lo) map_hi = map_lo + PAGE_SIZE_2M;
                if (map_hi <= map_lo || map_hi >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (mark_user_identity_range_2m_sys((uint64_t)map_lo, (uint64_t)map_hi) != 0) return ret_err(EFAULT);
                {
                    uint64_t saved_rsp = cur->saved_user_rsp;
                    uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(cur->tid ? cur->tid : 1);
                    uintptr_t parent_slot_lo = (parent_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                    uintptr_t child_slot_lo = stack_lo & ~0xFFFULL;
                    /* Stack copy is for glibc pthread (CLONE_THREAD): parent RSP still on the old
                       stack, new stack needs a relocated frame at its high end. axon-harness uses
                       CLONE_VM only with a fresh buffer — never copy (was corrupting parent slot). */
                    clone3_need_stack_copy = 0;
                    if ((flags & CLONE3_CLONE_THREAD) &&
                        saved_rsp >= stack_lo && saved_rsp < child_rsp) {
                        clone3_need_stack_copy = 1;
                    }
                    if (clone3_need_stack_copy) {
                        enum { CLONE3_STACK_COPY_MAX = 8192u };
                        uintptr_t used_tail = 0;
                        if (parent_stack_top > (uintptr_t)saved_rsp)
                            used_tail = parent_stack_top - (uintptr_t)saved_rsp;
                        if (used_tail == 0) used_tail = 4096;
                        if (used_tail < 4096) used_tail = 4096;
                        uintptr_t max_copy = (uintptr_t)CLONE3_STACK_COPY_MAX;
                        if (used_tail < max_copy) max_copy = used_tail;
                        uintptr_t copy_bytes = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
                        if (copy_bytes > max_copy) copy_bytes = max_copy;
                        if (copy_bytes >= 256) {
                            uintptr_t copy_lo = child_rsp - copy_bytes;
                            if (copy_lo < stack_lo)
                                copy_lo = stack_lo;
                            copy_bytes = child_rsp - copy_lo;
                            if (copy_bytes >= 256) {
                                memcpy((void *)copy_lo, (void *)(uintptr_t)saved_rsp, (size_t)copy_bytes);
                                fork_reloc_range_u64(copy_lo, copy_bytes,
                                    (uintptr_t)saved_rsp, (uintptr_t)saved_rsp + copy_bytes, copy_lo,
                                    parent_slot_lo, parent_stack_top, child_slot_lo);
                                clone3_dbg(cur, 5, "stack copy",
                                    (unsigned long long)copy_bytes,
                                    (unsigned long long)saved_rsp,
                                    (unsigned long long)copy_lo);
                            }
                        }
                    } else {
                        clone3_dbg(cur, 5, "fresh stack skip copy",
                            (unsigned long long)stack_lo,
                            (unsigned long long)child_rsp,
                            (unsigned long long)saved_rsp);
                    }
                }
                char child_name[32];
                snprintf(child_name, sizeof(child_name), "%s.child", cur->name);
                thread_t *child = thread_create_blocked(fork_child_return_entry, child_name);
                if (!child) return ret_err(ENOMEM);
                if (child->mm) mm_release(child->mm);
                child->mm = mm_retain(cur->mm ? cur->mm : mm_kernel());
                clone3_dbg(cur, 2, "child created",
                    (unsigned long long)(child->tid ? child->tid : 0),
                    (unsigned long long)saved_rcx,
                    (unsigned long long)saved_rcx);
                child->saved_user_r15 = cur->saved_user_r15;
                child->saved_user_r14 = cur->saved_user_r14;
                child->saved_user_r13 = cur->saved_user_r13;
                child->saved_user_r12 = cur->saved_user_r12;
                child->saved_user_r11 = cur->saved_user_r11;
                child->saved_user_r10 = cur->saved_user_r10;
                child->saved_user_r9 = cur->saved_user_r9;
                child->saved_user_r8 = cur->saved_user_r8;
                child->saved_user_rdi = cur->saved_user_rdi;
                child->saved_user_rsi = cur->saved_user_rsi;
                child->saved_user_rbp = cur->saved_user_rbp;
                child->saved_user_rbx = cur->saved_user_rbx;
                child->saved_user_rdx = cur->saved_user_rdx;
                child->saved_user_rcx = saved_rcx;
                child->saved_user_rip = saved_rcx;
                child->saved_user_rsp = (uint64_t)child_rsp;
                child->user_rip = saved_rcx;
                clone3_dbg(cur, 3, "return-frame",
                    (unsigned long long)saved_rcx,
                    (unsigned long long)child_rsp,
                    (unsigned long long)flags);
                child->user_stack = (uint64_t)child_rsp;
                child->user_stack_base = (uint64_t)stack_lo;
                child->user_stack_limit = (uint64_t)stack;
                child->ring = 3;
                if ((flags & 0x00080000u) && tls != 0 && tls >= 0x1000 && tls < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    child->user_fs_base = tls;
                    /* Ensure TLS region is user-accessible */
                    uintptr_t tls_lo = ((uintptr_t)tls - 0x1000u) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    uintptr_t tls_hi = ((uintptr_t)tls + 0x3000u + PAGE_SIZE_2M - 1) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    (void)mark_user_identity_range_2m_sys((uint64_t)tls_lo, (uint64_t)tls_hi);
                } else {
                    child->user_fs_base = cur->user_fs_base;
                }
                child->uid = cur->uid;
                child->euid = cur->euid;
                child->suid = cur->suid;
                child->gid = cur->gid;
                child->egid = cur->egid;
                child->sgid = cur->sgid;
                child->umask = cur->umask;
                child->attached_tty = cur->attached_tty;
                child->parent_tid = (int)(cur->tid ? cur->tid : 1);
                child->sid = cur->sid;
                child->pgid = cur->pgid;
                strncpy(child->cwd, cur->cwd, sizeof(child->cwd)-1);
                child->cwd[sizeof(child->cwd)-1] = '\0';
                fork_inherit_fd_table(child, cur);
                /* Shared mm (CLONE_VM): inherit brk/mmap state so child mmap doesn't overwrite parent's regions. */
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                /* Parent must not mmap into child's stack; bump parent's user_mmap_next above stack region. */
                {
                    uintptr_t stack_end = child->user_stack_limit;
                    uintptr_t min_next = user_mm_align_up(stack_end, (uintptr_t)PAGE_SIZE_2M);
                    if (cur->user_mmap_next < min_next)
                        cur->user_mmap_next = min_next;
                }
                /* clone3 semantics: touch TID pointers only when the matching flags are set. */
                enum {
                    CLONE_PARENT_SETTID = 0x00100000u,
                    CLONE_CHILD_CLEARTID = 0x00200000u,
                    CLONE_CHILD_SETTID = 0x01000000u
                };
                if ((flags & CLONE_PARENT_SETTID) &&
                    parent_tid_ptr && parent_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    copy_to_user_safe((void*)(uintptr_t)parent_tid_ptr, &child->tid, 4);
                }
                if ((flags & CLONE_CHILD_SETTID) &&
                    child_tid_ptr && child_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    copy_to_user_safe((void*)(uintptr_t)child_tid_ptr, &child->tid, 4);
                }
                if ((flags & CLONE_CHILD_CLEARTID) &&
                    child_tid_ptr && child_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    child->clear_child_tid = child_tid_ptr;
                }
                rebuild_syscall_frame(cur);
                {
                    int ctid = (int)(child->tid ? child->tid : 1);
                    /* CLONE_VM harness path: unblock now (per-thread syscall stacks). */
                    if (flags & CLONE3_CLONE_THREAD) {
                        cur->defer_unblock_tid = ctid;
                        clone3_dbg(cur, 4, "defer child",
                            (unsigned long long)ctid,
                            (unsigned long long)child->user_rip,
                            (unsigned long long)child->user_stack);
                    } else {
                        thread_unblock(ctid);
                        clone3_dbg(cur, 4, "unblock child",
                            (unsigned long long)ctid,
                            (unsigned long long)child->user_rip,
                            (unsigned long long)child->user_stack);
                    }
                }
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            return syscall_do_inner(SYS_fork, 0, 0, 0, 0, 0, 0);
        }
        case SYS_set_tid_address: {
            /* set_tid_address(int *tidptr): used by glibc to set clear_child_tid. */
            uint64_t tidptr = a1;
            if (tidptr != 0) {
                if (tidptr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                cur->clear_child_tid = tidptr;
            }
            return (uint64_t)(cur->tid ? cur->tid : 1);
        }
        case SYS_vfork: {
            /* Minimal vfork semantics:
               - create child thread that shares parent's address space and fds
               - parent is blocked until child calls execve or exit
               - parent returns child's pid, child returns 0
             */
            thread_t *p = cur;
            if (!p) return ret_err(EINVAL);
            /* Read saved return RIP and user RSP saved by syscall_entry64.
               The assembly syscall entry writes the saved return RIP into
               global `syscall_saved_ret_rip` for reliable access from C. */
            /* prefer recorded user return RIP (works for both int0x80 and SYSCALL paths) */
            uint64_t saved_rcx = p->saved_user_rip;
            uint64_t saved_rsp = p->saved_user_rsp;

            /* If we still don't have a valid saved_rcx at this point, fail early. */
            if (saved_rcx == 0) {
                return ret_err(EINVAL);
            }
            /* Try to ensure the user pages around saved_rcx are user-accessible to avoid PF
               when the child enters user mode. This sets PG_US on the containing 2MiB region. */
            if (saved_rcx != 0) {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) == 0) {
                } else {
                    /* If we cannot make the candidate return site user-accessible, refuse vfork
                       rather than heuristically using an unmapped/privileged address which
                       leads to immediate #PF err=0x5 when the child enters user mode. */
                    qemu_debug_printf("vfork: aborting due to unmapped/privileged saved return site\n");
                    return ret_err(EINVAL);
                }
                /* Also try to broadly ensure common user ranges are user-accessible (helps when writes hit elsewhere). */
                (void)user_map_ensure_present_us_2m(0x10000, 0x200000);
                if (mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP) == 0) {
                } else {
                }
            }
            // kprintf("DBG: vfork: syscall_user_return_rip=0x%llx syscall_user_rsp_saved=0x%llx (saved_rcx=0x%llx saved_rsp=0x%llx)\n",
            //         (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved,
            //         (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* vfork semantics for AxonOS (safe variant):
               - create child thread, but do NOT run it on the parent's stack
               - copy active portion of parent's stack into a dedicated child stack
               - parent is NOT blocked in-kernel (avoids returning from a blocked syscall frame)
               This behaves closer to fork(), but avoids the post-exit #GP caused by
               corruption of the parent's syscall frame while it is blocked in-kernel. */
            if (saved_rcx == 0) {
                /* cannot create child if we don't have return site */
                return ret_err(EINVAL);
            }
            /* create child kernel thread that will enter user mode at user_thread_entry.
               Create it BLOCKED first to avoid it running before we finish initializing
               user_rip/user_stack/user_fs_base (race became visible once we added an always-READY idle thread). */
            thread_t *child = thread_create_blocked(user_thread_entry, "vfork-child");
            if (!child) return ret_err(ENOMEM);
            /* initialize child's user context and inherit parent's FDs/credentials */
            /* Create a small user-mode trampoline that zeroes RAX and jumps to saved_rcx.
               This avoids executing user code directly in an unknown register/stack snapshot. */
            {
                /* ---- clone parent's active stack slice into child's own stack ---- */
                uintptr_t parent_fs = (uintptr_t)p->user_fs_base;
                uintptr_t parent_tls_region = (parent_fs >= 0x1000u) ? (parent_fs - 0x1000u) : 0;
                if ((uintptr_t)saved_rsp == 0 || (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    return ret_err(EINVAL);
                }
                uintptr_t max_copy = (uintptr_t)USER_STACK_SIZE;
                if (max_copy > (uintptr_t)(1024 * 1024)) max_copy = (uintptr_t)(1024 * 1024);
                uintptr_t avail = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
                uintptr_t copy_bytes = (avail < max_copy) ? avail : max_copy;
                if (copy_bytes < 256) {
                    return ret_err(EINVAL);
                }

                /* pick child's stack_top based on child tid to avoid overlap */
                uintptr_t child_stack_top = (uintptr_t)USER_STACK_TOP;
                /* reuse the same layout helper as exec uses: stack_top = tls + sizes */
                {
                    extern uintptr_t user_stack_top_for_tid(uint64_t tid); /* in core/elf.c (static), can't call */
                    (void)user_stack_top_for_tid;
                }
                /* We can't call elf.c static helper here, so derive stack_top from parent's
                   canonical layout by using child's tls base region below USER_STACK_TOP:
                   stack_top = USER_STACK_TOP - (tid+1)*stride. Keep stride in sync with elf.c. */
                {
                    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
                    const uint64_t slot = (uint64_t)child->tid + 1ULL;
                    /* Avoid overflow and avoid (off + 0x10000) wrap. If tid is out of range, use top slot. */
                    if (stride != 0 && slot <= (uint64_t)((uintptr_t)-1) / (uint64_t)stride) {
                        const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
                        const uintptr_t top = (uintptr_t)USER_STACK_TOP;
                        const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
                        if (top > min_room && off < (top - min_room)) {
                            child_stack_top = (uintptr_t)USER_STACK_TOP - off;
                        }
                    }
                }
                child_stack_top &= ~((uintptr_t)0xFULL);
                uintptr_t child_rsp = (child_stack_top - copy_bytes);
                uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(p->tid ? p->tid : 1);
                const uintptr_t parent_slot_lo =
                    (parent_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                const uintptr_t child_slot_lo =
                    (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                /* Preserve original stack alignment (SSE movdqa expects this). */
                uintptr_t align_mask = (uintptr_t)0xFULL;
                uintptr_t want = (uintptr_t)saved_rsp & align_mask;
                uintptr_t have = (uintptr_t)child_rsp & align_mask;
                if (have != want) {
                    child_rsp += (want - have) & align_mask;
                }

                /* ensure child stack region is user-accessible */
                {
                    uintptr_t sb = (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                    if (mark_user_identity_range_2m_sys((uint64_t)sb, (uint64_t)child_stack_top) != 0) {
                        return ret_err(EFAULT);
                    }
                }
                /* copy active stack slice */
                memcpy((void*)child_rsp, (void*)(uintptr_t)saved_rsp, (size_t)copy_bytes);
                {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = 0;
                        if (user_read_u64((const void *)(uintptr_t)pp, &v) != 0) return ret_err(EFAULT);
                        uint64_t nv = fork_reloc_user_ptr(v, parent_lo, parent_hi,
                            (uintptr_t)child_rsp, parent_slot_lo, parent_stack_top, child_slot_lo);
                        if (nv != v && user_write_u64((void *)(uintptr_t)pp, nv) != 0)
                            return ret_err(EFAULT);
                    }
                }

                /* ---- set up separate TLS (copy 4KiB from parent) ---- */
                uintptr_t child_tls_region = child_stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
                /* Use same layout as exec: FS base inside region, fake pthread on next page. */
                uintptr_t child_fs = child_tls_region + 0x1000u;
                uintptr_t child_pthread_fake = child_tls_region + 0x2000u;
                if (mark_user_identity_range_2m_sys((uint64_t)child_tls_region, (uint64_t)(child_pthread_fake + 0x1000u)) != 0) {
                    return ret_err(EFAULT);
                }
                /* clear/clone minimal TLS layout (3 pages) */
                memset((void*)child_tls_region, 0, 0x3000u);
                if (parent_tls_region != 0 && parent_tls_region + 0x3000u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy((void*)child_tls_region, (void*)parent_tls_region, 0x3000u);
                } else {
                    /* already zeroed */
                }
                /* Ensure the self pointer slot used by glibc pthread_getspecific is valid. */
                if (user_write_u64((void *)(uintptr_t)(child_fs - 0x78u), (uint64_t)child_pthread_fake) != 0)
                    return ret_err(EFAULT);
                /* Provide default "C" locale string for specifics[5] (see core/elf.c). */
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        if (user_write_u8((void *)(uintptr_t)(c_str + 0), (uint8_t)'C') != 0) return ret_err(EFAULT);
                        if (user_write_u8((void *)(uintptr_t)(c_str + 1), 0) != 0) return ret_err(EFAULT);
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        /* The TLS region may have been cloned from parent and contain garbage/non-canonical
                           pointers in the specifics area. Clear a small window and force slot 5. */
                        for (int si = 0; si < 32; si++) {
                            if (user_write_u64((void *)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)), 0) != 0)
                                return ret_err(EFAULT);
                        }
                        if (user_write_u64((void *)(uintptr_t)specific5_slot, (uint64_t)c_str) != 0)
                            return ret_err(EFAULT);
                    }
                }
                child->user_fs_base = (uint64_t)child_fs;

                uintptr_t tramp = (uintptr_t)USER_VFORK_TRAMP;
                /* ensure tramp region is user-accessible */
                mark_user_identity_range_2m_sys((uint64_t)(tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))),
                                               (uint64_t)((tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))) + PAGE_SIZE_2M));
                if ((uintptr_t)tramp + 64 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    #define VFORK_RELOC(val64) \
                        fork_reloc_user_ptr((uint64_t)(val64), parent_lo, parent_hi, \
                            (uintptr_t)child_rsp, parent_slot_lo, parent_stack_top, child_slot_lo)
                    /* Build a vfork trampoline that restores a full user register snapshot
                       (as if we returned from a real SYSCALL instruction):
                         - restore caller-saved regs: RDI,RSI,RDX,R8,R9,R10,RCX,R11
                         - restore callee-saved regs: RBX,RBP,R12-R15
                         - set RAX=0 (vfork return value in child)
                         - set RSP=saved stack
                         - jump to RCX (return RIP) */
                    unsigned char stub[160];
                    int off = 0;
                    /* movabs rdi, imm64 */
                    uint64_t imm_rdi = VFORK_RELOC(p->saved_user_rdi);
                    stub[off++] = 0x48; stub[off++] = 0xBF; memcpy(&stub[off], &imm_rdi, 8); off += 8;
                    /* movabs rsi, imm64 */
                    uint64_t imm_rsi = VFORK_RELOC(p->saved_user_rsi);
                    stub[off++] = 0x48; stub[off++] = 0xBE; memcpy(&stub[off], &imm_rsi, 8); off += 8;
                    /* movabs rdx, imm64 */
                    uint64_t imm_rdx = VFORK_RELOC(p->saved_user_rdx);
                    stub[off++] = 0x48; stub[off++] = 0xBA; memcpy(&stub[off], &imm_rdx, 8); off += 8;
                    /* movabs r8, imm64 */
                    uint64_t imm_r8 = VFORK_RELOC(p->saved_user_r8);
                    stub[off++] = 0x49; stub[off++] = 0xB8; memcpy(&stub[off], &imm_r8, 8); off += 8;
                    /* movabs r9, imm64 */
                    uint64_t imm_r9 = VFORK_RELOC(p->saved_user_r9);
                    stub[off++] = 0x49; stub[off++] = 0xB9; memcpy(&stub[off], &imm_r9, 8); off += 8;
                    /* movabs r10, imm64 */
                    uint64_t imm_r10 = VFORK_RELOC(p->saved_user_r10);
                    stub[off++] = 0x49; stub[off++] = 0xBA; memcpy(&stub[off], &imm_r10, 8); off += 8;
                    /* movabs rcx, imm64 (return RIP) */
                    uint64_t imm_rcx = (uint64_t)saved_rcx;
                    stub[off++] = 0x48; stub[off++] = 0xB9; memcpy(&stub[off], &imm_rcx, 8); off += 8;
                    /* movabs r11, imm64 (saved RFLAGS from SYSCALL) */
                    uint64_t imm_r11_flags = p->saved_user_r11;
                    stub[off++] = 0x49; stub[off++] = 0xBB; memcpy(&stub[off], &imm_r11_flags, 8); off += 8;
                    /* movabs rbx, imm64 */
                    uint64_t imm_rbx = VFORK_RELOC(p->saved_user_rbx);
                    stub[off++] = 0x48; stub[off++] = 0xBB; memcpy(&stub[off], &imm_rbx, 8); off += 8;
                    /* movabs rbp, imm64 */
                    uint64_t imm_rbp = VFORK_RELOC(p->saved_user_rbp);
                    stub[off++] = 0x48; stub[off++] = 0xBD; memcpy(&stub[off], &imm_rbp, 8); off += 8;
                    /* movabs r12, imm64 */
                    uint64_t imm_r12 = VFORK_RELOC(p->saved_user_r12);
                    stub[off++] = 0x49; stub[off++] = 0xBC; memcpy(&stub[off], &imm_r12, 8); off += 8;
                    /* movabs r13, imm64 */
                    uint64_t imm_r13 = VFORK_RELOC(p->saved_user_r13);
                    stub[off++] = 0x49; stub[off++] = 0xBD; memcpy(&stub[off], &imm_r13, 8); off += 8;
                    /* movabs r14, imm64 */
                    uint64_t imm_r14 = VFORK_RELOC(p->saved_user_r14);
                    stub[off++] = 0x49; stub[off++] = 0xBE; memcpy(&stub[off], &imm_r14, 8); off += 8;
                    /* movabs r15, imm64 */
                    uint64_t imm_r15 = VFORK_RELOC(p->saved_user_r15);
                    stub[off++] = 0x49; stub[off++] = 0xBF; memcpy(&stub[off], &imm_r15, 8); off += 8;
                    /* xor rax, rax -> return value 0 in child */
                    stub[off++] = 0x48; stub[off++] = 0x31; stub[off++] = 0xC0;
                    /* movabs rsp, saved_rsp -> 48 BC imm64 */
                    uint64_t imm_rsp = (uint64_t)child_rsp;
                    stub[off++] = 0x48; stub[off++] = 0xBC; memcpy(&stub[off], &imm_rsp, 8); off += 8;
                    /* jmp rcx -> FF E1 */
                    stub[off++] = 0xFF; stub[off++] = 0xE1;
                    #undef VFORK_RELOC
                    /* pad with NOPs */
                    for (int z = off; z < (int)sizeof(stub); z++) stub[z] = 0x90;
                    memcpy((void*)(uintptr_t)tramp, stub, (size_t)off);
                    /* Read back bytes to verify write succeeded */
                    unsigned char verify[16];
                    memcpy(verify, (void*)(uintptr_t)tramp, sizeof(verify));
                    child->user_rip = (uint64_t)tramp;
                } else {
                    /* fallback: use saved_rcx if tramp can't be used */
                    child->user_rip = saved_rcx;
                }
                child->user_stack = (uint64_t)child_rsp;
                child->user_stack_base = (uint64_t)((child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL);
                child->user_stack_limit = (uint64_t)child_stack_top;
                child->ring = 3;
            }
            child->parent_tid = (int)(p->tid ? p->tid : 1);
            child->sid = p->sid;
            child->pgid = p->pgid;
            child->uid = p->uid; child->euid = p->euid; child->suid = p->suid;
            child->gid = p->gid; child->egid = p->egid; child->sgid = p->sgid;
            child->attached_tty = p->attached_tty;
            strncpy(child->cwd, p->cwd, sizeof(child->cwd) - 1);
            child->cwd[sizeof(child->cwd) - 1] = '\0';
            qemu_debug_printf("vfork: parent=%llu child=%llu saved_rcx=0x%llx saved_rsp=0x%llx\n",
                (unsigned long long)(p->tid ? p->tid : 1),
                (unsigned long long)(child->tid ? child->tid : 1),
                (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* Preserve parent userspace memory across vfork/exec.
               In our shared-address-space model, exec in the child overwrites
               parent memory, so we must snapshot+restore for correctness.
               Optimization: backup only the used region (heap + mmap) instead of
               the full 0x200000..USER_TLS_BASE (~122 MiB). Typical vfork+exec
               (sh, busybox) uses only a few MiB. */
            {
                const uintptr_t base = (uintptr_t)0x00200000u;
                uintptr_t end = (uintptr_t)USER_TLS_BASE;
                if (end < base) end = base;
                /* Backup only up to the end of *heap/program* used memory.
                   IMPORTANT: user_mmap_next can jump high due to large device mmaps
                   (e.g. /dev/fb0 mapping the whole framebuffer). Backing up to that
                   address makes every vfork copy tens/hundreds of MiB and effectively
                   stalls boot. We therefore only extend backup to mmap_next when it is
                   close to brk (heuristic for small anon/file-private mmaps). */
                uintptr_t used_end = (uintptr_t)p->user_brk_cur;
                /* Minimum: cover program load + small heap (busybox ~2MB at 0x400000) */
                const uintptr_t min_backup = base + (8u * 1024u * 1024u);
                if (used_end < min_backup || used_end == 0) used_end = min_backup;
                /* Heuristic: include mmap area only if it's not "far away" (avoid fb0/VRAM-sized mappings). */
                if (p->user_mmap_next != 0) {
                    const uintptr_t mmap_next = (uintptr_t)p->user_mmap_next;
                    const uintptr_t slack = (8u * 1024u * 1024u);
                    if (mmap_next > used_end && mmap_next - used_end <= slack) {
                        used_end = mmap_next;
                    }
                }
                if (used_end > end) used_end = end;
                uint64_t len64 = (uint64_t)(used_end - base);
                qemu_debug_printf("vfork-backup: parent=%llu brk=0x%llx mmap_next=0x%llx used_end=0x%llx len=%llu\n",
                    (unsigned long long)(p->tid ? p->tid : 1),
                    (unsigned long long)p->user_brk_cur,
                    (unsigned long long)p->user_mmap_next,
                    (unsigned long long)used_end,
                    (unsigned long long)len64);
                if (len64 == 0 || len64 > (uint64_t)(256u * 1024u * 1024u)) {
                    qemu_debug_printf("vfork-backup: invalid len=%llu -> ENOMEM\n", (unsigned long long)len64);
                    return ret_err(ENOMEM);
                }
                child->vfork_parent_mem_backup = kmalloc((size_t)len64);
                if (!child->vfork_parent_mem_backup) {
                    qemu_debug_printf("OOM vfork-backup: kmalloc(%llu) failed heap_used=%llu heap_total=%llu\n",
                        (unsigned long long)len64, (unsigned long long)heap_used_bytes(),
                        (unsigned long long)heap_total_bytes());
                    return ret_err(ENOMEM);
                }
                /* Small backup: single copy. Large: chunked memcpy (no thread_yield: still
                 * inside syscall_do on the per-CPU syscall stack — yielding corrupts frame). */
                const size_t chunk = 512u * 1024u;
                if ((size_t)len64 <= chunk) {
                    memcpy(child->vfork_parent_mem_backup, (void*)base, (size_t)len64);
                    qemu_debug_printf("COPIED WHITOUT CHUNKS\n");
                } else {
                    for (size_t off = 0; off < (size_t)len64; off += chunk) {
                        size_t n = chunk;
                        if (off + n > (size_t)len64) n = (size_t)len64 - off;
                        memcpy((char*)child->vfork_parent_mem_backup + off, (void*)(base + off), n);
                    }
                }
                child->vfork_parent_mem_backup_len = len64;
                child->vfork_parent_mem_backup_base = (uint64_t)base;
                child->vfork_parent_brk_saved = (uint64_t)p->user_brk_cur;
                /* Snapshot parent stack from saved RSP to stack top (child shares address space). */
                {
                    uintptr_t parent_top = user_stack_top_for_tid_like_exec(p->tid ? p->tid : 1);
                    uintptr_t lo = (uintptr_t)saved_rsp;
                    if (lo > 0 && lo < parent_top && lo < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        size_t slen = (size_t)(parent_top - lo);
                        if (slen > (size_t)(512u * 1024u))
                            slen = (size_t)(512u * 1024u);
                        child->vfork_parent_stack_backup = kmalloc(slen);
                        if (child->vfork_parent_stack_backup) {
                            memcpy(child->vfork_parent_stack_backup, (void*)lo, slen);
                            child->vfork_parent_saved_rsp = saved_rsp;
                            child->vfork_parent_stack_backup_len = (uint64_t)slen;
                        }
                    }
                }
                child->vfork_parent_tid = (int)(p->tid ? p->tid : 1);
                /* block parent until child exits */
                p->vfork_parent_tid = -1;
                p->state = THREAD_BLOCKED;
                qemu_debug_printf("vfork: parent blocked, child->vfork_parent_tid=%d\n", child->vfork_parent_tid);
            }
            /* duplicate file descriptors (increase refcounts) */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                child->fds[i] = p->fds[i];
                if (child->fds[i]) {
                    if (child->fds[i]->refcount <= 0) child->fds[i]->refcount = 1;
                    else child->fds[i]->refcount++;
                }
            }
            /* If parent was blocked (init backup path), yield to run child now. */
            if (p->state == THREAD_BLOCKED && child->vfork_parent_tid >= 0) {
                qemu_debug_printf("vfork: unblocking child %llu, calling thread_schedule()\n",
                    (unsigned long long)(child->tid ? child->tid : 1));
                thread_unblock((int)(child->tid ? child->tid : 1));
                thread_schedule();
                /* parent resumed after child exit; restore syscall frame */
                qemu_debug_printf("vfork: parent %llu resumed after child exit\n",
                    (unsigned long long)(p->tid ? p->tid : 1));
                rebuild_syscall_frame(p);
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            /* default path: do not block parent; just allow child to run */
            qemu_debug_printf("vfork: default path, unblocking child %llu\n",
                (unsigned long long)(child->tid ? child->tid : 1));
            child->vfork_parent_tid = -1;
            thread_unblock((int)(child->tid ? child->tid : 1));
            /* when parent is unblocked and resumes here, return child's pid to parent */
            return (uint64_t)(child->tid ? child->tid : 1);
        }
        case SYS_set_robust_list:
            /* set_robust_list(head, len): accept (no robust futex handling yet) */
            (void)a1; (void)a2;
            return 0;
        case SYS_futex: {
            /* minimal futex handler: FUTEX_WAIT / FUTEX_WAKE */
            extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
            int res = futex_syscall((uintptr_t)a1, (int)a2, (int)a3, (const void*)(uintptr_t)a4, (uintptr_t)a5, (int)a6);
            if (res < 0) return ret_err(-res);
            return (uint64_t)res;
        }
        case SYS_rseq:
            /* Minimal rseq registration:
               int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig)
               We accept a non-NULL pointer and length (basic validation) and store it
               per-thread so userspace can use rseq registration checks. This is not a
               full rseq implementation but enough for libc compatibility. */
            {
                const void *rseq_ptr = (const void*)(uintptr_t)a1;
                uint32_t rseq_len = (uint32_t)a2;
                int flags = (int)a3;
                (void)flags;
                thread_t *tcur = thread_get_current_user();
                if (!tcur) tcur = thread_current();
                if (rseq_ptr == NULL) {
                    /* unregister */
                    if (tcur) tcur->rseq_ptr = NULL;
                    return 0;
                }
                if ((uintptr_t)rseq_ptr + (uintptr_t)rseq_len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (rseq_len < 16 || rseq_len > 4096) return ret_err(EINVAL);
                if (tcur) tcur->rseq_ptr = (void*)rseq_ptr;
                return 0;
            }
        case SYS_prlimit64: {
            /* prlimit64(pid, resource, new_limit, old_limit)
               Minimal: return conservative limits for current process only (pid==0 or self).
               We ignore new_limit for now. */
            uint64_t pid = a1;
            int resource = (int)a2;
            const void *new_u = (const void*)(uintptr_t)a3;
            void *old_u = (void*)(uintptr_t)a4;
            (void)new_u;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (!(pid == 0 || pid == self)) return ret_err(ESRCH);

            /* Linux rlimit64 */
            struct rlimit64_k { uint64_t rlim_cur; uint64_t rlim_max; } rl;
            enum {
                RLIMIT_STACK = 3,
                RLIMIT_NOFILE = 7,
            };
            if (resource == RLIMIT_STACK) {
                rl.rlim_cur = 8ULL * 1024ULL * 1024ULL;
                rl.rlim_max = 8ULL * 1024ULL * 1024ULL;
            } else if (resource == RLIMIT_NOFILE) {
                rl.rlim_cur = (uint64_t)THREAD_MAX_FD;
                rl.rlim_max = (uint64_t)THREAD_MAX_FD;
            } else {
                /* unknown resource: report "infinite" */
                rl.rlim_cur = ~0ULL;
                rl.rlim_max = ~0ULL;
            }
            if (old_u) {
                if (copy_to_user_safe(old_u, &rl, sizeof(rl)) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_readlink: {
            /* readlink(pathname, buf, bufsiz) */
            const char *path = (const char*)(uintptr_t)a1;
            char *buf = (char*)(uintptr_t)a2;
            size_t bufsiz = (size_t)a3;
            if (!path || !buf) return ret_err(EFAULT);
            if ((uintptr_t)path >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)buf + bufsiz > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);

            char kpath[256];
            resolve_user_path(cur, path, kpath, sizeof(kpath));

            /* Workaround: realpath/canonicalize and Busybox adduser readlink paths to resolve
               them. When a path exists as regular file or dir (not symlink), POSIX readlink
               would fail with EINVAL. Return the path as link target so programs succeed. */
            {
                struct stat st;
                if (vfs_lstat(kpath, &st) == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
                    if (bufsiz == 0) return ret_err(EINVAL);
                    size_t L = strlen(kpath);
                    if (L > bufsiz) L = bufsiz;
                    memcpy(buf, kpath, L);
                    return (uint64_t)L;
                }
            }

            ssize_t rr = vfs_readlink(kpath, buf, bufsiz);
            if (rr >= 0) return (uint64_t)rr;

            /* Fallbacks for common procfs symlinks used by libc/busybox. */
            if (strcmp(kpath, "/proc/self/exe") == 0) {
                const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                size_t L = strlen(target);
                if (bufsiz == 0) return ret_err(EINVAL);
                if (L > bufsiz) L = bufsiz;
                memcpy(buf, target, L);
                return (uint64_t)L; /* no NUL terminator */
            }
            if (strncmp(kpath, "/proc/", 6) == 0) {
                const char *p = kpath + 6;
                int self_ok = 0;
                if (strncmp(p, "self/", 5) == 0) {
                    p += 5;
                    self_ok = 1;
                } else {
                    /* /proc/<pid>/... */
                    int saw_digit = 0;
                    while (*p >= '0' && *p <= '9') { p++; saw_digit = 1; }
                    if (saw_digit && *p == '/') {
                        p++;
                        self_ok = 1; /* best-effort: map any pid to current process view */
                    }
                }
                if (self_ok) {
                    if (strcmp(p, "exe") == 0) {
                        const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                        size_t L = strlen(target);
                        if (bufsiz == 0) return ret_err(EINVAL);
                        if (L > bufsiz) L = bufsiz;
                        memcpy(buf, target, L);
                        return (uint64_t)L;
                    }
                    if (strncmp(p, "fd/", 3) == 0) {
                        int fd = 0;
                        const char *q = p + 3;
                        if (!*q) return ret_err(ENOENT);
                        while (*q >= '0' && *q <= '9') {
                            fd = fd * 10 + (*q - '0');
                            q++;
                        }
                        if (*q == '\0' && fd >= 0 && fd < THREAD_MAX_FD) {
                            struct fs_file *ff = cur->fds[fd];
                            const char *target = (ff && ff->path) ? ff->path : NULL;
                            if (!target) return ret_err(ENOENT);
                            size_t L = strlen(target);
                            if (bufsiz == 0) return ret_err(EINVAL);
                            if (L > bufsiz) L = bufsiz;
                            memcpy(buf, target, L);
                            return (uint64_t)L;
                        }
                    }
                }
            }
            if (cur && cur->name[0]) {
                if (strstr(cur->name, "addgroup") || strstr(cur->name, "adduser") || strstr(cur->name, "wget")) {
                    qemu_debug_printf("READLINK-ENOENT: %s path=%s\n", cur->name, kpath);
                    qemu_debug_printf("READLINK-ENOENT: name=%s path=%s\n", cur->name, kpath);
                }
            }
            return ret_err(ENOENT);
        }
        case SYS_link: {
            /* link(oldpath, newpath) - create hard link */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            int r = fs_link(oldpath, newpath);
            if (r == 0) return 0;
            return ret_err(r < 0 ? -r : EIO);
        }
        case 87: { /* unlink(path) */
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 263: { /* unlinkat(dirfd, path, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)flags; /* we don't support AT_REMOVEDIR etc yet */
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 265: { /* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            int flags = (int)a5;
            (void)flags;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
            int r = fs_link(oldpath, newpath);
            if (r == 0) return 0;
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_rename: {
            /* rename(oldpath, newpath) - syscall 82; rpm needs this for move */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            /* If newpath is a directory, target is newpath/basename(oldpath) (POSIX) */
            {
                struct stat st;
                if (vfs_stat(newpath, &st) == 0 && (st.st_mode & S_IFDIR)) {
                    const char *base = strrchr(oldpath, '/');
                    base = base ? base + 1 : oldpath;
                    size_t nlen = strlen(newpath);
                    size_t blen = strlen(base);
                    if (nlen + 1 + blen + 1 <= sizeof(newpath)) {
                        if (nlen > 0 && newpath[nlen - 1] != '/') {
                            newpath[nlen] = '/';
                            newpath[nlen + 1] = '\0';
                            nlen++;
                        }
                        memcpy(newpath + nlen, base, blen + 1);
                    }
                }
            }
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
            /* Map fs driver internal codes to Linux errno (ramfs uses -1,-2,-3,-5) */
            if (r == -2) return ret_err(ENOENT);
            if (r == -3) return ret_err(ENOTDIR);
            if (r == -5) return ret_err(ENOMEM);
            if (r == -17) return ret_err(EEXIST);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 264: { /* renameat(olddirfd, oldpath, newdirfd, newpath) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
            if (r == -2) return ret_err(ENOENT);
            if (r == -3) return ret_err(ENOTDIR);
            if (r == -5) return ret_err(ENOMEM);
            if (r == -17) return ret_err(EEXIST);
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_umask: {
            /* umask(mask) - syscall 95; returns previous mask, sets new mask */
            unsigned int mask = (unsigned int)(a1 & 07777u);
            unsigned int prev = cur->umask;
            cur->umask = mask;
            return (uint64_t)prev;
        }
        case SYS_mkdir: {
            /* mkdir(path, mode) - syscall 83; init often runs "mkdir -p /dev" before mount */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (path[0] == '\0') return ret_err(EINVAL);
            /* root "/" always exists; rpm may do mkdir -p / and fail with EPERM otherwise */
            if (path[0] == '/' && path[1] == '\0') return 0;
            int r = fs_mkdir(path);
            if (r == 0) {
                (void)fs_chmod(path, (mode & 07777u) | S_IFDIR);
                return 0;
            }
            return ret_err(fs_mkdir_errno(r));
        }
        case 258: { /* mkdirat(dirfd, pathname, mode) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            mode_t mode = (mode_t)(a3 & 0xFFFFu);
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (path[0] == '\0') return ret_err(EINVAL);
            if (path[0] == '/' && path[1] == '\0') return 0;
            int r = fs_mkdir(path);
            if (r == 0) {
                (void)fs_chmod(path, (mode & 07777u) | S_IFDIR);
                return 0;
            }
            return ret_err(fs_mkdir_errno(r));
        }
        case SYS_chmod: {
            /* chmod(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            int r = fs_chmod(path, mode);
            if (r == 0) return 0;
            return ret_err(EPERM);
        }
        case 268: { /* fchmodat(dirfd, pathname, mode, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            mode_t mode = (mode_t)a3;
            int flags = (int)a4;
            (void)flags; /* AT_SYMLINK_NOFOLLOW not supported yet */
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            int r = fs_chmod(path, mode);
            if (r == 0) return 0;
            return ret_err(EPERM);
        }
        case SYS_chown: {
            /* chown(path, uid, gid) - syscall 92; rpm may set ownership; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case 91: { /* fchmod(fd, mode) */
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur ? cur->fds[fd] : NULL;
            if (!f) return ret_err(EBADF);
            if (f->path) {
                int r = fs_chmod(f->path, (mode_t)a2);
                if (r == 0) return 0;
            }
            return 0;
        }
        case 93:  /* fchown(fd, uid, gid) */
        case 94:  /* lchown(path, uid, gid) */
        case 260: /* fchownat(dirfd, pathname, uid, gid, flags) */
            return 0;
        case SYS_utimensat: {
            /* utimensat(dirfd, path, times, flags) - syscall 280; rpm may set mtime; stub success */
            (void)a1; (void)a2; (void)a3; (void)a4;
            return 0;
        }
        case SYS_getrandom: {
            void *bufp = (void*)(uintptr_t)a1;
            size_t len = (size_t)a2;
            (void)a3; /* flags */
            if (!bufp) return ret_err(EFAULT);
            if ((uintptr_t)bufp + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint8_t *p = (uint8_t*)bufp;
            for (size_t i = 0; i < len; i++) {
                /* xorshift32 */
                user_rand_state ^= user_rand_state << 13;
                user_rand_state ^= user_rand_state >> 17;
                user_rand_state ^= user_rand_state << 5;
                p[i] = (uint8_t)(user_rand_state & 0xFF);
            }
            return (uint64_t)len;
        }
        case SYS_clock_gettime: {
            int clk = (int)a1;
            void *tp = (void*)(uintptr_t)a2;
            if (!tp) return ret_err(EFAULT);
            if (!user_range_ok(tp, 16)) return ret_err(EFAULT);
            /* Linux clock ids (glibc wget uses MONOTONIC_RAW, COARSE, BOOTTIME, …). */
            enum {
                CLOCK_REALTIME = 0,
                CLOCK_MONOTONIC = 1,
                CLOCK_PROCESS_CPUTIME_ID = 2,
                CLOCK_THREAD_CPUTIME_ID = 3,
                CLOCK_MONOTONIC_RAW = 4,
                CLOCK_REALTIME_COARSE = 5,
                CLOCK_MONOTONIC_COARSE = 6,
                CLOCK_BOOTTIME = 7
            };
            if (clk < 0 || clk > 15) return ret_err(EINVAL);
            int64_t sec, nsec;
            if (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE) {
                rtc_datetime_t dt;
                rtc_read_datetime(&dt);
                uint64_t secs = rtc_datetime_to_epoch(&dt);
                uint64_t sub = pit_get_time_ms() % 1000ULL;
                sec = (int64_t)secs;
                nsec = (int64_t)(sub * 1000000ULL);
            } else {
                /* Monotonic, raw, coarse, boottime, thread/process CPU: PIT since boot */
                uint64_t ms = pit_get_time_ms();
                sec = (int64_t)(ms / 1000ULL);
                nsec = (int64_t)((ms % 1000ULL) * 1000000ULL);
            }
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            ts.tv_sec = sec;
            ts.tv_nsec = nsec;
            if (copy_to_user_safe(tp, &ts, sizeof(ts)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_gettimeofday: { /* Linux x86_64 nr 96 */
            /* gettimeofday(struct timeval *tv, struct timezone *tz) */
            void *tv_u = (void*)(uintptr_t)a1;
            (void)a2;
            if (!tv_u) return ret_err(EFAULT);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv;
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            uint64_t secs = rtc_datetime_to_epoch(&dt);
            uint64_t usec = (uint64_t)(pit_get_time_ms() % 1000ULL) * 1000ULL;
            tv.tv_sec = (int64_t)secs;
            tv.tv_usec = (int64_t)usec;
            if (copy_to_user_safe(tv_u, &tv, sizeof(tv)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_reboot: {
            /* Linux reboot(magic1, magic2, cmd, arg) — BusyBox reboot/halt/poweroff. */
            enum {
                LINUX_REBOOT_MAGIC1 = 0xFEE1DEADu,
                LINUX_REBOOT_MAGIC2 = 672274793u,  /* 0x28121969 */
                LINUX_REBOOT_MAGIC2A = 0x05121996u,
                LINUX_REBOOT_CMD_RESTART   = 0x01234567u,
                LINUX_REBOOT_CMD_HALT      = 0xCDEF0123u,
                LINUX_REBOOT_CMD_CAD_ON    = 0x89ABCDEFu,
                LINUX_REBOOT_CMD_CAD_OFF   = 0u,
                LINUX_REBOOT_CMD_POWER_OFF = 0x4321FEDCu,
                LINUX_REBOOT_CMD_RESTART2  = 0xA1B2C3D4u,
            };
            uint32_t magic1 = (uint32_t)a1;
            uint32_t magic2 = (uint32_t)a2;
            uint32_t cmd    = (uint32_t)a3;
            const void *arg_u = (const void *)(uintptr_t)a4;
            if (magic1 != LINUX_REBOOT_MAGIC1)
                return ret_err(EINVAL);
            if (magic2 != LINUX_REBOOT_MAGIC2 && magic2 != LINUX_REBOOT_MAGIC2A)
                return ret_err(EINVAL);
            if (cmd == LINUX_REBOOT_CMD_CAD_ON || cmd == LINUX_REBOOT_CMD_CAD_OFF)
                return 0;
            if (cmd == LINUX_REBOOT_CMD_POWER_OFF || cmd == LINUX_REBOOT_CMD_HALT) {
                power_request_shutdown("reboot syscall");
                return 0;
            }
            if (cmd == LINUX_REBOOT_CMD_RESTART2) {
                if (arg_u && !user_range_ok(arg_u, 1))
                    return ret_err(EFAULT);
                power_request_reboot("reboot syscall RESTART2");
                return 0;
            }
            if (cmd == LINUX_REBOOT_CMD_RESTART) {
                power_request_reboot("reboot syscall");
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_clock_nanosleep: {
            /* clock_nanosleep(clockid, flags, req, rem) */
            uintptr_t req_addr = (uintptr_t)a1;
            uint64_t flags = a2;
            const void *req_u = (const void*)(uintptr_t)a3;
            void *rem_u = (void*)(uintptr_t)a4;
            (void)rem_u;
            if (flags != 0) return ret_err(EINVAL);
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)ms);
            return 0;
        }
        case SYS_access: {
            /* access(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            (void)a2;
            if (!path_u) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) == 0) return 0;
            return ret_err(ENOENT);
        }
        case 201: { /* time(time_t *tloc) */
            void *tloc = (void*)(uintptr_t)a1;
            /* If pointer is provided, store seconds since epoch there (time_t is 64-bit) */
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            uint64_t secs = rtc_datetime_to_epoch(&dt);
            if (tloc) {
                if ((uintptr_t)tloc + sizeof(int64_t) > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                int64_t sval = (int64_t)secs;
                if (copy_to_user_safe(tloc, &sval, sizeof(sval)) != 0) return ret_err(EFAULT);
            }
            return (uint64_t)secs;
        }
        case SYS_uname: {
            void *up = (void*)(uintptr_t)a1;
            if (!up) return ret_err(EFAULT);
            /* Linux: struct utsname has 6 fields of 65 bytes each. */
            struct utsname_k {
                char sysname[65];
                char nodename[65];
                char release[65];
                char version[65];
                char machine[65];
                char domainname[65];
            } u;
            memset(&u, 0, sizeof(u));
            /* Keep it simple and stable. */
            snprintf(u.sysname, sizeof(u.sysname), "%s", OS_NAME);
            snprintf(u.nodename, sizeof(u.nodename), "axoniso");
            snprintf(u.release, sizeof(u.release), "%s", OS_VERSION);
            snprintf(u.version, sizeof(u.version), "%s", OS_NAME);
            snprintf(u.machine, sizeof(u.machine), "x86_64");
            snprintf(u.domainname, sizeof(u.domainname), "local");
            if (copy_to_user_safe(up, &u, sizeof(u)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 170: { /* gethostname — BusyBox getty login prompt */
            char *buf = (char *)(uintptr_t)a1;
            size_t len = (size_t)a2;
            if (!buf || len == 0) return ret_err(EINVAL);
            static const char host[] = "axoniso";
            size_t n = sizeof(host) - 1;
            if (n >= len) n = len - 1;
            char k[64];
            memcpy(k, host, n);
            k[n] = '\0';
            if (copy_to_user_safe(buf, k, n + 1) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getcwd: {
            char *bufp = (char*)(uintptr_t)a1;
            size_t size = (size_t)a2;
            const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
            size_t need = strlen(cwd) + 1;
            if (!bufp) return ret_err(EFAULT);
            if (size < need) return ret_err(EINVAL);
            if ((uintptr_t)bufp + need > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            memcpy(bufp, cwd, need);
            return (uint64_t)need;
        }
        case SYS_chdir: {
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct fs_file *f = fs_open(path);
            if (!f) return ret_err(ENOENT);
            /* Don't trust f->type: some drivers don't set it consistently.
               Use stat mode to decide directory-ness so chdir("/") never regresses. */
            struct stat st;
            int is_dir = 0;
            if (vfs_fstat(f, &st) == 0) {
                is_dir = ((st.st_mode & S_IFDIR) == S_IFDIR);
            } else {
                is_dir = (f->type == FS_TYPE_DIR);
            }
            fs_file_free(f);
            if (!is_dir) return ret_err(EINVAL);
            size_t n = strlen(path);
            while (n > 1 && path[n - 1] == '/') path[--n] = '\0';
            strncpy(cur->cwd, path, sizeof(cur->cwd));
            cur->cwd[sizeof(cur->cwd) - 1] = '\0';
            return 0;
        }
        case SYS_syslog: {

            return ENOSYS;
        }
        case SYS_writev: {
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t sum64 = 0;
                for (int i = 0; i < iovcnt; i++) sum64 += (uint64_t)iov[i].len;
                if (sum64 == 0) return 0;
                if (sum64 > 65536u) return ret_err(EINVAL);
                size_t sum = (size_t)sum64;
                uint8_t *flat = (uint8_t *)kmalloc(sum);
                if (!flat) return ret_err(ENOMEM);
                size_t at = 0;
                for (int i = 0; i < iovcnt; i++) {
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    const void *base = (const void *)(uintptr_t)iov[i].base;
                    if (!user_range_ok(base, len)) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    if (copy_from_user_raw(flat + at, base, len) != 0) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    at += len;
                }
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                    if (s->tcp.peer_rst) { kfree(flat); return ret_err(ECONNRESET); }
                    if (s->tcp.peer_fin) { kfree(flat); return ret_err(EPIPE); }
                    if (!s->connected || !s->tcp.established) { kfree(flat); return ret_err(ENOTCONN); }
                    size_t total = 0;
                    net_tcp_ops_t ops;
                    net_make_tcp_ops(&ops, &s->tcp);
                    while (total < sum) {
                        size_t chunk = sum - total;
                        if (chunk > 4096) chunk = 4096;
                        if (total == 0)
                            net_debug_log_tls443_tx(s, flat, chunk, "writev");
                        int wr = net_tcp_send(&s->tcp, &ops, flat + total, chunk, 30000);
                        if (wr < 0) {
                            kfree(flat);
                            return total ? (uint64_t)total : ret_err(EIO);
                        }
                        total += (size_t)wr;
                        if ((size_t)wr < chunk) break;
                    }
                    (void)net_tcp_flush_tx(&s->tcp, &ops, 5000);
                    kfree(flat);
                    return (uint64_t)total;
                }
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                    if (!s->connected) { kfree(flat); return ret_err(EDESTADDRREQ); }
                    if (sum > 2048u) { kfree(flat); return ret_err(EINVAL); }
                    if (s->local_port == 0) s->local_port = net_alloc_ephemeral_port();
                    int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, flat, sum);
                    kfree(flat);
                    if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);
                    return (uint64_t)sum;
                }
                kfree(flat);
                ssize_t wr = net_sock_write_userspace(cur, fd, s, (const void *)(uintptr_t)iov[0].base, (size_t)iov[0].len);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp && chunk > 512) { chunk = 512; tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 512, &copied); }
                    if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                    ssize_t wr;
                    if (f->type == FS_TYPE_PIPE && f->fs_private == (void *)1 && f->driver_private) {
                        wr = pipe_write_bytes((pipe_t *)f->driver_private, tmp, copied, cur);
                    } else {
                        wr = fs_write(f, tmp, copied, f->pos);
                    }
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err((int)(-wr ? -wr : EINVAL));
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_pwritev: {
            /* pwritev(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 296 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp) return (total > 0) ? total : ret_err(EFAULT);
                    ssize_t wr = fs_write(f, tmp, copied, cur_off);
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                    cur_off += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_dup3: {
            /* dup3(oldfd, newfd, flags) — Linux x86_64 292.
               Many tools (including busybox applets) use dup3() internally. */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int flags = (int)a3;
            /* Only allow O_CLOEXEC (ignored) or 0. */
            const int O_CLOEXEC = 02000000;
            if (flags & ~O_CLOEXEC) return ret_err(EINVAL);
            if (oldfd == newfd) return ret_err(EINVAL);
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
        }
        case SYS_getpid:
            if (is_init_user(cur)) return 1;
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getppid:
            if (is_init_user(cur)) return 0;
            if (cur && cur->parent_tid >= 0) return (uint64_t)cur->parent_tid;
            return 1;
        case SYS_gettid:
            if (is_init_user(cur)) return 1;
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getuid:
            return (uint64_t)cur->uid;
        case SYS_geteuid:
            return (uint64_t)cur->euid;
        case SYS_getgid:
            return (uint64_t)cur->gid;
        case SYS_getegid:
            return (uint64_t)cur->egid;
        case SYS_capget:
        case SYS_capset: {
            /* Linux capabilities (htop, libcap). Minimal v1/v2/v3; no per-thread cap storage. */
            enum {
                _CAP_VERSION_1 = 0x19980330u,
                _CAP_VERSION_2 = 0x20071026u,
                _CAP_VERSION_3 = 0x20080522u,
            };
            typedef struct { uint32_t version; int32_t pid; } cap_user_header_t;
            typedef struct { uint32_t effective; uint32_t permitted; uint32_t inheritable; } cap_user_data_t;

            void *hdr_u = (void *)(uintptr_t)a1;
            void *dat_u = (void *)(uintptr_t)a2;
            if (!hdr_u) return ret_err(EFAULT);
            if (!user_range_ok(hdr_u, sizeof(cap_user_header_t))) return ret_err(EFAULT);

            cap_user_header_t hdr;
            if (copy_from_user_raw(&hdr, hdr_u, sizeof(hdr)) != 0) return ret_err(EFAULT);

            int ndata = 0;
            if (hdr.version == _CAP_VERSION_1) ndata = 1;
            else if (hdr.version == _CAP_VERSION_2 || hdr.version == _CAP_VERSION_3) ndata = 2;
            else return ret_err(EINVAL);

            int target_pid = hdr.pid;
            if (target_pid == 0)
                target_pid = (int)(cur->tid ? cur->tid : 1);
            thread_t *target = thread_get(target_pid);
            if (!target || target->state == THREAD_TERMINATED) return ret_err(ESRCH);

            int privileged = (target->euid == 0);
            uint32_t lo = privileged ? 0xFFFFFFFFu : 0u;
            uint32_t hi = privileged ? 0x1FFu : 0u; /* caps 32..40 (CAP_LAST_CAP=40) */

            if (num == SYS_capset) {
                if (cur->euid != 0) return ret_err(EPERM);
                if (!dat_u) return ret_err(EFAULT);
                if (!user_range_ok(dat_u, (size_t)ndata * sizeof(cap_user_data_t))) return ret_err(EFAULT);
                return 0;
            }

            /* capget: datap==NULL probes version/pid only */
            if (!dat_u) return 0;
            if (!user_range_ok(dat_u, (size_t)ndata * sizeof(cap_user_data_t))) return ret_err(EFAULT);

            cap_user_data_t data[2];
            memset(data, 0, sizeof(data));
            data[0].effective = lo;
            data[0].permitted = lo;
            data[0].inheritable = 0;
            if (ndata >= 2) {
                data[1].effective = hi;
                data[1].permitted = hi;
                data[1].inheritable = 0;
            }
            if (copy_to_user_safe(dat_u, data, (size_t)ndata * sizeof(cap_user_data_t)) != 0)
                return ret_err(EFAULT);
            return 0;
        }
        case SYS_setuid: {
            /* setuid(uid): set uid, euid, suid. Root can set any; otherwise uid must equal uid/euid/suid. */
            uid_t uid = (uid_t)a1;
            if (cur->euid == 0) {
                cur->uid = cur->euid = cur->suid = uid;
                return 0;
            }
            if (uid != cur->uid && uid != cur->euid && uid != cur->suid)
                return ret_err(EPERM);
            cur->uid = cur->euid = cur->suid = uid;
            return 0;
        }
        case SYS_setgid: {
            /* setgid(gid): same as setuid for groups. */
            gid_t gid = (gid_t)a1;
            if (cur->euid == 0) {
                cur->gid = cur->egid = cur->sgid = gid;
                return 0;
            }
            if (gid != cur->gid && gid != cur->egid && gid != cur->sgid)
                return ret_err(EPERM);
            cur->gid = cur->egid = cur->sgid = gid;
            return 0;
        }
        case SYS_setreuid: {
            /* setreuid(ruid, euid): -1 means don't change. seteuid(uid) = setreuid(-1, uid). */
            uid_t ruid = (uid_t)(int)a1;
            uid_t euid = (uid_t)(int)a2;
            int do_ruid = (int)a1 != -1;
            int do_euid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_ruid) cur->uid = ruid;
                if (do_euid) cur->euid = euid;
                cur->suid = cur->euid; /* Linux: suid = new euid when euid changed */
                return 0;
            }
            if (do_ruid && ruid != cur->uid && ruid != cur->euid && ruid != cur->suid)
                return ret_err(EPERM);
            if (do_euid && euid != cur->uid && euid != cur->euid && euid != cur->suid)
                return ret_err(EPERM);
            if (do_ruid) cur->uid = ruid;
            if (do_euid) { cur->euid = euid; cur->suid = euid; }
            return 0;
        }
        case SYS_setregid: {
            /* setregid(rgid, egid): -1 means don't change. */
            gid_t rgid = (gid_t)(int)a1;
            gid_t egid = (gid_t)(int)a2;
            int do_rgid = (int)a1 != -1;
            int do_egid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_rgid) cur->gid = rgid;
                if (do_egid) cur->egid = egid;
                cur->sgid = cur->egid;
                return 0;
            }
            if (do_rgid && rgid != cur->gid && rgid != cur->egid && rgid != cur->sgid)
                return ret_err(EPERM);
            if (do_egid && egid != cur->gid && egid != cur->egid && egid != cur->sgid)
                return ret_err(EPERM);
            if (do_rgid) cur->gid = rgid;
            if (do_egid) { cur->egid = egid; cur->sgid = egid; }
            return 0;
        }
        case SYS_setsid:
            if (cur) {
                cur->sid = (int)(cur->tid ? cur->tid : 1);
                cur->pgid = (int)(cur->tid ? cur->tid : 1);
                user_pgrp = (uint64_t)cur->pgid;
            }
            return user_pgrp;
        case 37: /* alarm(seconds) - compatibility shim */
            if (a1 == 0) {
                user_itimer_interval_ms = 0;
            } else {
                uint64_t ms = a1 * 1000ULL;
                if (ms > 0xFFFFFFFFULL) ms = 0xFFFFFFFFULL;
                user_itimer_interval_ms = (uint32_t)ms;
            }
            return 0;
        case SYS_getpgrp:
            if (cur) {
                if (cur->pgid != 0) return (uint64_t)cur->pgid;
            }
            return user_pgrp;
        case SYS_setpgid:
            /* Minimal setpgid implementation:
               If pid==0 use current tid; if pgid==0 use pid.
               Update global user_pgrp for simplicity (single pgrp model). */
            {
                int pid = (int)a1;
                int pgid = (int)a2;
                uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
                if (pid == 0) pid = (int)self;
                if (pgid == 0) pgid = pid;
                /* Allow setting pgid for current process or a child process.
                   If pid refers to another thread, verify it's a child of current (simple permission). */
                if ((uint64_t)pid != self) {
                    thread_t *t = thread_get(pid);
                    if (!t) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> ESRCH (not found)\n", pid, pgid);
                        return ret_err(ESRCH);
                    }
                    /* simple permission: only parent can change child's pgid */
                    if (t->parent_tid != (int)self) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not parent)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid==1 (init) unless
                       caller is pid 1. This avoids user processes mistakenly moving into
                       init's pgrp which later confuses job control and can cause shells to exit. */
                    if (pgid == 1 && (int)self != 1 && !is_init_user(cur)) {
                        //kprintf("sys_setpgid: pid=%d attempted to set pgid=1 -> EPERM (denied)\n", pid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid different from current
                       unless caller is session leader. */
                    int caller_tid = (int)self;
                    int caller_sid = cur ? cur->sid : -1;
                    if ((int)pgid != t->pgid && caller_sid != caller_tid) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not session leader)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    t->pgid = pgid;
                } else {
                    if (cur) cur->pgid = pgid;
                }
                if (pgid != 0) user_pgrp = (uint64_t)pgid;
                //kprintf("sys_setpgid: pid=%d pgid=%d -> OK (user_pgrp=%llu)\n", pid, pgid, (unsigned long long)user_pgrp);
                return 0;
            }
        case SYS_tgkill: {
            /* tgkill(tgid, tid, sig): used by glibc for raise()/pthread_kill()/abort().
               We must make self-targeted SIGABRT actually terminate; otherwise glibc
               falls back to ud2 in userspace -> #GP. */
            uint64_t tgid = a1;
            uint64_t tid  = a2;
            uint64_t sig  = a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (tgid == self && tid == self && sig == 6 /* SIGABRT */) {
                return syscall_do_inner(SYS_exit_group, 134, 0, 0, 0, 0, 0);  /* 134 = 128+SIGABRT */
            }
            if (tgid == self && tid == self) return 0;
            return ret_err(ESRCH);
        }
        case SYS_sched_yield: {
            thread_yield();
            return 0;
        }
        case SYS_select:
        select_common: { /* select / pselect6 (via case 270) */
            /* Minimal but functional select():
               - supports readfds/writefds (exceptfds ignored)
               - readiness model mirrors SYS_poll implementation (TTY/pipe/file/socket)
               - services TCP (net_tcp_service) and polls e1000 while blocking */
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; };
            int nfds = (int)a1;
            void *readfds_u  = (void*)(uintptr_t)a2;
            void *writefds_u = (void*)(uintptr_t)a3;
            (void)a4; /* exceptfds */
            void *timeout_u  = (void*)(uintptr_t)a5;
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);

            /* Linux x86_64 fd_set: 1024 bits = 128 bytes (16 x unsigned long). */
            const size_t fdset_bytes = 128u;

            uint64_t *rin = NULL, *win = NULL;
            uint64_t *rout = NULL, *wout = NULL;
            if (readfds_u) {
                if (!user_range_ok(readfds_u, fdset_bytes)) return ret_err(EFAULT);
                rin  = (uint64_t *)kmalloc(fdset_bytes);
                rout = (uint64_t *)kmalloc(fdset_bytes);
                if (!rin || !rout) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    return ret_err(ENOMEM);
                }
                if (copy_from_user_raw(rin, readfds_u, fdset_bytes) != 0) {
                    kfree(rin); kfree(rout);
                    return ret_err(EFAULT);
                }
            }
            if (writefds_u) {
                if (!user_range_ok(writefds_u, fdset_bytes)) return ret_err(EFAULT);
                win  = (uint64_t *)kmalloc(fdset_bytes);
                wout = (uint64_t *)kmalloc(fdset_bytes);
                if (!win || !wout) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(ENOMEM);
                }
                if (copy_from_user_raw(win, writefds_u, fdset_bytes) != 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    kfree(win); kfree(wout);
                    return ret_err(EFAULT);
                }
            }

            int timeout_ms = -1; /* NULL => infinite */
            if (timeout_u) {
                if (!user_range_ok(timeout_u, sizeof(struct timeval_k))) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EFAULT);
                }
                struct timeval_k tv;
                if (copy_from_user_raw(&tv, timeout_u, sizeof(tv)) != 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EFAULT);
                }
                if (tv.tv_sec < 0 || tv.tv_usec < 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EINVAL);
                }
                uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
                if (ms == 0 && tv.tv_usec > 0) ms = 1;
                if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                timeout_ms = (int)ms;
            }

            thread_t *curth = thread_get_current_user();
            if (!curth) curth = thread_current();

            auto_select_check:
            {
                if (rout) memset(rout, 0, fdset_bytes);
                if (wout) memset(wout, 0, fdset_bytes);
                int ready = 0;
                int has_net_socket = 0;

                for (int fd = 0; fd < nfds; fd++) {
                    int want_r = 0, want_w = 0;
                    if (rin)  want_r = (int)((rin[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (win)  want_w = (int)((win[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (!want_r && !want_w) continue;

                    struct fs_file *f = curth ? curth->fds[fd] : NULL;
                    int can_r = 0, can_w = 0;
                    if (!f) {
                        /* invalid fd: POSIX would error via EBADF; keep it simple for now */
                        continue;
                    }

                    if (want_r) {
                        if (devfs_is_tty_file(f)) {
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_available(tidx) > 0) can_r = 1;
                        } else if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                                has_net_socket = 1;

                            if (s->sock_domain == AF_NETLINK_LOCAL) {
                                if (s->nl_rx_off < s->nl_rx_len) can_r = 1;
                            } else if (s->unix_domain_stub) {
                                if (s->unix_listening) {
                                    if (s->unix_accept_count > 0) can_r = 1;
                                } else if (s->connected) {
                                    if (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s)) can_r = 1;
                                }
                            } else if (s->tcp_listening) {
                                if (s->unix_accept_count > 0) can_r = 1;
                            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                                if (s->rx_has_pending) can_r = 1;
                                else {
                                    uint32_t sip = 0;
                                    uint16_t sport = 0;
                                    int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                                    if (rn > 0) {
                                        ksock_rx_pending_install(s, rn);
                                        s->rx_pending_src_ip_be = sip;
                                        s->rx_pending_src_port = sport;
                                        can_r = 1;
                                    }
                                }
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops, &s->tcp);
                                if (s->tcp.connect_pending)
                                    (void)net_tcp_connect_poll(&s->tcp, &ops, 0);
                                net_pump_tcp_sock(s, 48);
                                if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst || s->tcp.ooo_valid) can_r = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            int is_write_end = (f->fs_private == (void *)1);
                            release_irqrestore(&p->lock, fl);
                            if (!is_write_end && (used > 0 || p->refcount < 2)) can_r = 1;
                        } else {
                            if (f->type == FS_TYPE_DIR) can_r = 1;
                            else if ((size_t)f->pos < (size_t)f->size) can_r = 1;
                        }
                    }

                    if (want_w) {
                        if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                                has_net_socket = 1;
                            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                                can_w = 1;
                            } else if (s->unix_domain_stub) {
                                if (!s->unix_listening && s->connected && !unix_stream_peer_closed(s) && unix_stream_avail_to_write(s) > 0)
                                    can_w = 1;
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops, &s->tcp);
                                if (s->tcp.connect_pending) {
                                    e1000_poll();
                                    if (net_tcp_connect_poll(&s->tcp, &ops, 200) == 0) {
                                        s->connected = 1;
                                        can_w = 1;
                                    } else if (s->tcp.connect_refused) {
                                        can_w = 1;
                                    }
                                } else {
                                    e1000_poll();
                                    (void)net_tcp_service(&s->tcp, &ops, 64);
                                    if (s->tcp.established || s->tcp.peer_rst) can_w = 1;
                                }
                            } else {
                                can_w = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            size_t free = (p->size > 1) ? ((p->size - 1) - used) : 0;
                            int is_write_end = (f->fs_private == (void *)1);
                            release_irqrestore(&p->lock, fl);
                            if (is_write_end && free > 0) can_w = 1;
                        } else {
                            /* regular files: writable */
                            can_w = 1;
                        }
                    }

                    if (can_r && rout) { rout[fd / 64] |= (1ULL << (fd % 64)); ready++; }
                    if (can_w && wout) { wout[fd / 64] |= (1ULL << (fd % 64)); if (!can_r) ready++; }
                }

                if (ready > 0) {
                    if (readfds_u && rout)  { if (copy_to_user_safe(readfds_u,  rout, fdset_bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (writefds_u && wout) { if (copy_to_user_safe(writefds_u, wout, fdset_bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return (uint64_t)ready;
                }

                if (timeout_ms == 0) {
                    if (readfds_u && rout)  (void)copy_to_user_safe(readfds_u,  rout, fdset_bytes);
                    if (writefds_u && wout) (void)copy_to_user_safe(writefds_u, wout, fdset_bytes);
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return 0;
                }

                int step = 10;
                if (timeout_ms > 0 && timeout_ms < step) step = timeout_ms;
                if (has_net_socket)
                    net_pump_all_tcp(curth);
                else
                    e1000_poll();
                thread_sleep((uint32_t)step);
                if (timeout_ms > 0) timeout_ms -= step;
                goto auto_select_check;
            }
        }
        case SYS_nanosleep: { /* nanosleep(req, rem) - Linux 35 */
            const void *req_u = (const void*)(uintptr_t)a1;
            void *rem_u = (void*)(uintptr_t)a2;
            (void)rem_u;
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)(ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (uint32_t)ms));
            return 0;
        }
        case 222: { /* timer_create(clockid, sevp, timerid) - stub for vim E1286 */
            void *tid_u = (void*)(uintptr_t)a3;
            if (!tid_u) return ret_err(EFAULT);
            static int32_t stub_timer_id = 1;
            if (copy_to_user_safe(tid_u, &stub_timer_id, sizeof(stub_timer_id)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 223: { /* timer_settime(timerid, flags, new_value, old_value) - no-op */
            return 0;
        }
        case 226: { /* timer_delete(timerid) - no-op */
            return 0;
        }
        case 38: { /* setitimer(which, new_value, old_value) - compatibility shim */
            const int ITIMER_REAL_LOCAL = 0;
            int which = (int)a1;
            const void *new_u = (const void *)(uintptr_t)a2;
            void *old_u = (void *)(uintptr_t)a3;
            if (which != ITIMER_REAL_LOCAL) return ret_err(EINVAL);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; };
            struct itimerval_k {
                struct timeval_k it_interval;
                struct timeval_k it_value;
            } nv, ov;
            memset(&ov, 0, sizeof(ov));
            ov.it_interval.tv_sec = (int64_t)(user_itimer_interval_ms / 1000u);
            ov.it_interval.tv_usec = (int64_t)((user_itimer_interval_ms % 1000u) * 1000u);
            ov.it_value = ov.it_interval;
            if (old_u && user_range_ok(old_u, sizeof(ov))) {
                (void)copy_to_user_safe(old_u, &ov, sizeof(ov));
            }
            if (!new_u) return 0;
            if (!user_range_ok(new_u, sizeof(nv))) return ret_err(EFAULT);
            if (copy_from_user_raw(&nv, new_u, sizeof(nv)) != 0) return ret_err(EFAULT);
            if (nv.it_interval.tv_sec < 0 || nv.it_interval.tv_usec < 0 ||
                nv.it_value.tv_sec < 0 || nv.it_value.tv_usec < 0) return ret_err(EINVAL);
            uint64_t interval_ms = (uint64_t)nv.it_interval.tv_sec * 1000ULL + (uint64_t)(nv.it_interval.tv_usec / 1000ULL);
            uint64_t value_ms = (uint64_t)nv.it_value.tv_sec * 1000ULL + (uint64_t)(nv.it_value.tv_usec / 1000ULL);
            uint64_t chosen = interval_ms ? interval_ms : value_ms;
            if (chosen > 0xFFFFFFFFULL) chosen = 0xFFFFFFFFULL;
            user_itimer_interval_ms = (uint32_t)chosen;
            return 0;
        }
        case SYS_socket: { /* socket(domain, type, protocol) */
            int domain = (int)a1;
            int type = (int)a2;
            int protocol = (int)a3;
            int unix_stub = 0;
            int ipv6_stub = (domain == AF_INET6);
            int type_base = type & 0x0F; /* mask SOCK_NONBLOCK/CLOEXEC flags */
            if (domain == AF_INET_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL || type_base == SOCK_STREAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (type_base == SOCK_RAW_LOCAL) {
                    if (!(protocol == 0 || protocol == IPPROTO_ICMP_LOCAL)) return ret_err(EPROTONOSUPPORT);
                } else if (type_base == SOCK_DGRAM_LOCAL) {
                    /* Protocol is normalized when storing s->protocol (glibc IPv6 path may pass 41, etc.). */
                } else { /* SOCK_STREAM_LOCAL */
                    if (!(protocol == 0 || protocol == IPPROTO_TCP_LOCAL)) return ret_err(EPROTONOSUPPORT);
                }
            } else if (domain == AF_NETLINK_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (!(protocol == 0 || protocol == NETLINK_ROUTE_LOCAL)) return ret_err(EPROTONOSUPPORT);
                protocol = NETLINK_ROUTE_LOCAL;
            } else if (domain == AF_INET6) {
                /* Stub: create IPv4 socket when tools (wget) request IPv6 */
                domain = AF_INET_LOCAL;
            } else if (domain == AF_UNSPEC) {
                /* getaddrinfo/glibc may pass AF_UNSPEC; treat as IPv4 */
                domain = AF_INET_LOCAL;
            } else if (domain == 1) {
                /* AF_UNIX: stub as AF_INET in the kernel, but emulate connect/send/recv so nss/glibc
                   does not see ECONNREFUSED on nscd-style unix sockets (that breaks getaddrinfo). */
                unix_stub = 1;
                domain = AF_INET_LOCAL;
            } else {
                /* Compatibility: map any other domain to IPv4 (AF_PACKET, odd values from getaddrinfo, etc).
                   Avoids EAFNOSUPPORT causing wget to fail with "out of memory" (fdopen path). */
                domain = AF_INET_LOCAL;
            }
            ksock_net_t *s = (ksock_net_t *)kmalloc(sizeof(*s));
            struct fs_file *f = (struct fs_file *)kmalloc(sizeof(*f));
            char *p = (char *)kmalloc(24);
            if (!s || !f || !p) {
                if (s) kfree(s);
                if (f) kfree(f);
                if (p) kfree(p);
                return ret_err(ENOMEM);
            }
            memset(s, 0, sizeof(*s));
            memset(f, 0, sizeof(*f));
            if (domain == AF_NETLINK_LOCAL) snprintf(p, 24, "socket:[netlink]");
            else snprintf(p, 24, "socket:[icmp]");
            s->sock_domain = domain;
            s->ipv6_stub = ipv6_stub;
            s->unix_domain_stub = unix_stub;
            s->type_base = type_base;
            if (domain == AF_NETLINK_LOCAL) {
                s->protocol = NETLINK_ROUTE_LOCAL;
            } else if (type_base == SOCK_RAW_LOCAL) s->protocol = (protocol == 0) ? IPPROTO_ICMP_LOCAL : protocol;
            else if (type_base == SOCK_DGRAM_LOCAL) {
                /* Only SOCK_DGRAM + IPPROTO_ICMP is ping; everything else is UDP (DNS, resolver IPv6 sockets). */
                s->protocol = (protocol == IPPROTO_ICMP_LOCAL) ? IPPROTO_ICMP_LOCAL : IPPROTO_UDP_LOCAL;
            } else s->protocol = (protocol == 0) ? IPPROTO_TCP_LOCAL : protocol;
            s->connected = 0;
            s->peer_ip_be = 0;
            s->peer_port = 0;
            s->local_port = 0;
            s->next_echo_seq = 0;
            s->nonblock = (type & O_NONBLOCK_LINUX) ? 1 : 0;
            s->kref = 1;
            f->path = p;
            f->type = SYSCALL_FTYPE_SOCKET;
            f->driver_private = s;
            f->refcount = 1;
            int fd = thread_fd_alloc(f);
            if (fd < 0) {
                kfree(s);
                kfree((void *)f->path);
                kfree(f);
                return ret_err(EMFILE);
            }
            return (uint64_t)fd;
        }
        case 49: { /* bind */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_pid = sa.nl_pid ? sa.nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                s->nl_groups = sa.nl_groups;
                return 0;
            }
            if (s->unix_domain_stub) {
                char upath[108];
                int is_abs = 0;
                int pr = unix_sockaddr_path_from_user(addr_u, addrlen, upath, sizeof(upath), &is_abs);
                if (pr != 0) return ret_err(pr);
                if (!is_abs) {
                    /* Maintain a visible socket pathname for userland checks. */
                    (void)fs_unlink(upath);
                    (void)fs_create_file(upath);
                    (void)fs_chmod(upath, S_IFSOCK | 0600);
                }
                memset(s->unix_path, 0, sizeof(s->unix_path));
                strncpy(s->unix_path, upath, sizeof(s->unix_path) - 1);
                s->unix_bound = 1;
                return 0;
            }
            if (s->sock_domain == AF_INET_LOCAL) {
                sockaddr_in_k sa;
                int pr = user_sockaddr_to_ipv4_peer(addr_u, addrlen, &sa);
                if (pr != 0) return ret_err(pr);
                uint16_t port = be16(sa.sin_port);
                if (port == 0) return ret_err(EINVAL);
                if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                    if (net_tcp_find_listener(port)) return ret_err(EADDRINUSE);
                }
                s->local_port = port;
                return 0;
            }
            return 0;
        }
        case 50: { /* listen */
            int fd = (int)a1;
            (void)a2; /* backlog */
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->unix_domain_stub) {
                if (s->type_base != SOCK_STREAM_LOCAL) return ret_err(EOPNOTSUPP);
                if (!s->unix_bound) return ret_err(EINVAL);
                s->unix_listening = 1;
                return 0;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                if (s->local_port == 0) return ret_err(EINVAL);
                if (net_stack_init() != 0) return ret_err(ENETDOWN);
                s->tcp_listening = 1;
                return 0;
            }
            return ret_err(EOPNOTSUPP);
        }
        case 48: { /* shutdown */
            int fd = (int)a1;
            (void)a2;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->unix_domain_stub) return 0;
            return ret_err(EOPNOTSUPP);
        }
        case 43:  /* accept */
        case 288: { /* accept4 */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            (void)a4; /* flags for accept4 */
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            if (!t || fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) return ret_err(EBADF);
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->unix_domain_stub) {
                if (!s->unix_listening) return ret_err(EINVAL);
                struct fs_file *af = unix_acceptq_pop(s);
                while (!af) {
                    if (s->nonblock) return ret_err(EAGAIN);
                    thread_sleep(1);
                    af = unix_acceptq_pop(s);
                }
                int nfd = thread_fd_alloc(af);
                if (nfd < 0) {
                    if (af->driver_private) {
                        ksock_net_t *as = (ksock_net_t *)af->driver_private;
                        if (as->unix_conn) {
                            unix_stream_conn_t *c = as->unix_conn;
                            unsigned long fl = 0;
                            acquire_irqsave(&c->lock, &fl);
                            c->closed[as->unix_end] = 1;
                            c->refs--;
                            int refs = c->refs;
                            release_irqrestore(&c->lock, fl);
                            if (refs <= 0) kfree(c);
                        }
                        kfree(as);
                    }
                    if (af->path) kfree((void *)af->path);
                    kfree(af);
                    return ret_err(EMFILE);
                }
                if (addr_u && addrlen_u && user_range_ok(addrlen_u, 4)) {
                    uint32_t ulen = 0;
                    if (copy_from_user_raw(&ulen, addrlen_u, 4) == 0 && ulen >= 2 && user_range_ok(addr_u, 2)) {
                        uint16_t fam = 1; /* AF_UNIX */
                        (void)copy_to_user_safe(addr_u, &fam, sizeof(fam));
                        ulen = 2;
                        (void)copy_to_user_safe(addrlen_u, &ulen, 4);
                    }
                }
                return (uint64_t)nfd;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                if (!s->tcp_listening) return ret_err(EINVAL);
                (void)thread_reap_unwaited_zombies();
                struct fs_file *af = unix_acceptq_pop(s);
                while (!af) {
                    if (s->nonblock) return ret_err(EAGAIN);
                    net_pump_listen_handshake();
                    af = unix_acceptq_pop(s);
                    if (af) break;
                    thread_yield();
                }
                ksock_net_t *as = (ksock_net_t *)af->driver_private;
                int nfd = thread_fd_alloc(af);
                if (nfd < 0) {
                    net_fs_file_destroy(af);
                    return ret_err(EMFILE);
                }
                if (addr_u && addrlen_u && as && user_range_ok(addrlen_u, 4)) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(as->peer_port);
                    sa.sin_addr = as->peer_ip_be;
                    uint32_t ulen = 0;
                    if (copy_from_user_raw(&ulen, addrlen_u, 4) == 0 && ulen >= sizeof(sa) &&
                        user_range_ok(addr_u, sizeof(sa))) {
                        (void)copy_to_user_safe(addr_u, &sa, sizeof(sa));
                        ulen = (uint32_t)sizeof(sa);
                        (void)copy_to_user_safe(addrlen_u, &ulen, 4);
                    }
                }
                return (uint64_t)nfd;
            }
            return ret_err(EOPNOTSUPP);
        }
        case 42: { /* connect */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_peer_pid = sa.nl_pid;
                s->connected = 1;
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                return 0;
            }
            if (s->unix_domain_stub) {
                char upath[108];
                int is_abs = 0;
                int pr = unix_sockaddr_path_from_user(addr_u, addrlen, upath, sizeof(upath), &is_abs);
                if (pr != 0) return ret_err(pr);
                if (s->type_base != SOCK_STREAM_LOCAL) {
                    s->connected = 1;
                    return 0;
                }
                if (is_abs) return ret_err(ECONNREFUSED);
                ksock_net_t *listener = unix_find_listener_by_path(upath);
                if (!listener || !listener->unix_listening) return ret_err(ECONNREFUSED);
                if (s->connected && s->unix_conn) return ret_err(EISCONN);

                unix_stream_conn_t *conn = (unix_stream_conn_t *)kmalloc(sizeof(*conn));
                ksock_net_t *srv = (ksock_net_t *)kmalloc(sizeof(*srv));
                struct fs_file *srv_f = (struct fs_file *)kmalloc(sizeof(*srv_f));
                char *srv_p = (char *)kmalloc(24);
                if (!conn || !srv || !srv_f || !srv_p) {
                    if (conn) kfree(conn);
                    if (srv) kfree(srv);
                    if (srv_f) kfree(srv_f);
                    if (srv_p) kfree(srv_p);
                    return ret_err(ENOMEM);
                }
                memset(conn, 0, sizeof(*conn));
                conn->refs = 2;
                memset(srv, 0, sizeof(*srv));
                memset(srv_f, 0, sizeof(*srv_f));
                snprintf(srv_p, 24, "socket:[unix]");
                srv->sock_domain = AF_INET_LOCAL;
                srv->unix_domain_stub = 1;
                srv->type_base = SOCK_STREAM_LOCAL;
                srv->protocol = 0;
                srv->connected = 1;
                srv->unix_conn = conn;
                srv->unix_end = 1;
                srv->kref = 1;
                memset(srv->unix_path, 0, sizeof(srv->unix_path));
                strncpy(srv->unix_path, upath, sizeof(srv->unix_path) - 1);
                srv_f->path = srv_p;
                srv_f->type = SYSCALL_FTYPE_SOCKET;
                srv_f->driver_private = srv;
                srv_f->refcount = 1;

                if (unix_acceptq_push(listener, srv_f) != 0) {
                    kfree(srv_p);
                    kfree(srv_f);
                    kfree(srv);
                    kfree(conn);
                    return ret_err(EAGAIN);
                }

                s->connected = 1;
                s->unix_conn = conn;
                s->unix_end = 0;
                memset(s->unix_path, 0, sizeof(s->unix_path));
                strncpy(s->unix_path, upath, sizeof(s->unix_path) - 1);
                return 0;
            }
            sockaddr_in_k to;
            {
                int pa = user_sockaddr_to_ipv4_peer(addr_u, addrlen, &to);
                if (pa != 0) return ret_err(pa);
            }
            /* Inet peer: must not leave unix stub short-circuit in read/write/sendto paths. */
            s->unix_domain_stub = 0;
            if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                s->connected = 1;
                uint32_t pip = be32(to.sin_addr);
                uint16_t pp = be16(to.sin_port);
                /* resolv.conf on Linux often uses 127.0.0.53/127.0.0.1 — redirect to real DNS. */
                if (pp == 53u && (pip & 0xFF000000u) == 0x7F000000u) {
                    if (net_stack_init() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) pip = ns;
                    }
                }
                s->peer_ip_be = pip;
                s->peer_port = pp;
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                return 0;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                /* Linux sockaddr: sin_addr is in_addr (wire octets in LE uint32); be32 -> internal MSB-first. */
                uint32_t dst_ip_be = be32(to.sin_addr);
                uint16_t dport = be16(to.sin_port);
                /* glibc may try TCP to 127.0.0.1/127.0.0.53 :53 first; bridge to real nameserver over UDP. */
                if (dport == 53u) {
                    if (net_stack_init() != 0) return ret_err(ENETDOWN);
                    uint32_t peer = dst_ip_be;
                    if ((dst_ip_be & 0xFF000000u) == 0x7F000000u) {
                        peer = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (peer == 0) return ret_err(ENETDOWN);
                    }
                    s->connected = 1;
                    s->peer_ip_be = peer;
                    s->peer_port = dport;
                    if (s->local_port == 0)
                        s->local_port = net_alloc_ephemeral_port();
                    s->dns_tcp_udp_bridge = 1;
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    return 0;
                }
                /* 127.0.0.1: loopback not implemented; return ECONNREFUSED immediately
                   instead of EIO timeout (no server listens on localhost). */
                if (dst_ip_be == 0x7F000001u)
                    return ret_err(ECONNREFUSED);
                if (net_stack_init() != 0) return ret_err(ENETDOWN);
                if (s->tcp.used) {
                    net_tcp_ops_t close_ops;
                    net_make_tcp_ops(&close_ops, &s->tcp);
                    (void)net_tcp_close(&s->tcp, &close_ops, 500);
                }
                memset(&s->tcp, 0, sizeof(s->tcp));
                s->dns_tcp_udp_bridge = 0;
                s->connected = 0;
                net_rxq_flush();
                s->peer_ip_be = dst_ip_be;
                s->peer_port = dport;
                /* Fresh local port on redirect/reconnect (avoids TIME_WAIT / NAT confusion). */
                s->local_port = net_alloc_ephemeral_port();
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                {
                    uint32_t nh = ip_same_subnet(s->peer_ip_be, g_net.ip_be, g_net.mask_be)
                        ? s->peer_ip_be : g_net.gw_be;
                    uint8_t nh_mac[6];
                    if (nh == g_net.gw_be && g_net.gw_mac_valid) {
                        memcpy(nh_mac, g_net.gw_mac, 6);
                    } else if (net_resolve_mac(nh, nh_mac, 5000) != 0) {
                        return ret_err(ENETUNREACH);
                    } else if (nh == g_net.gw_be) {
                        memcpy(g_net.gw_mac, nh_mac, 6);
                        g_net.gw_mac_valid = 1;
                    }
                    memcpy(g_tcp_xmit_mac, nh_mac, 6);
                    g_tcp_xmit_mac_valid = 1;
                }
                /* ARP wait may have filled RXQ with unrelated frames — clear before SYN. */
                net_rxq_flush();
                net_nic_drain_to_rxq(32);
                klogprintf("tcp: connect2 dst=%u.%u.%u.%u:%u sport=%u nb=%d gwmac=%d nh=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                    (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                    (unsigned)dport, (unsigned)s->local_port, s->nonblock, g_net.gw_mac_valid,
                    g_tcp_xmit_mac[0], g_tcp_xmit_mac[1], g_tcp_xmit_mac[2],
                    g_tcp_xmit_mac[3], g_tcp_xmit_mac[4], g_tcp_xmit_mac[5]);
                net_nic_drain_to_rxq(32);
                g_net_tcp_sniff_left = 32;
                g_net_tcp_connect_active = 1;
                int rc = net_tcp_connect(&s->tcp, &ops, s->peer_ip_be, s->peer_port, s->local_port, 6000);
                g_net_tcp_connect_active = 0;
                g_net_tcp_sniff_left = 0;
                g_tcp_xmit_mac_valid = 0;
                if (rc == -3) {
                    klogprintf("tcp: connect refused dst=%u.%u.%u.%u:%u\n",
                        (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                        (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                        (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(ECONNREFUSED);
                }
                if (rc == -2) {
                    e1000_stats_t est;
                    if (e1000_get_stats(&est) == 0)
                        klogprintf("tcp: timeout dst=%u.%u.%u.%u:%u peer_pkts=%d nic_tx=%u nic_rx=%u\n",
                            (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                            (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                            (unsigned)dport, s->tcp.connect_peer_pkts,
                            (unsigned)est.tx_packets, (unsigned)est.rx_packets);
                    else
                        klogprintf("tcp: connect timeout dst=%u.%u.%u.%u:%u\n",
                            (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                            (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                            (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(ETIMEDOUT);
                }
                if (rc != 0) {
                    klogprintf("tcp: connect failed rc=%d dst=%u.%u.%u.%u:%u\n", rc,
                        (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                        (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                        (unsigned)dport);
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    s->connected = 0;
                    return ret_err(EIO);
                }
                klogprintf("tcp: connected dst=%u.%u.%u.%u:%u\n",
                    (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                    (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                    (unsigned)dport);
                s->connected = 1;
                return 0;
            }
            return 0;
        }
        case 51: { /* getsockname */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->unix_domain_stub) {
                uint16_t fam = 1;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(fam)) ? ulen : (uint32_t)sizeof(fam);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &fam, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(fam);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_pid ? s->nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                sa.nl_groups = s->nl_groups;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            if (s->ipv6_stub) {
                sockaddr_in6_k sa6;
                uint16_t lport = 0;
                if ((s->type_base == SOCK_DGRAM_LOCAL || s->type_base == SOCK_STREAM_LOCAL) && s->local_port)
                    lport = s->local_port;
                sockaddr_in6_v4mapped_fill(&sa6, g_net.ip_be, lport);
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa6)) ? ulen : (uint32_t)sizeof(sa6);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa6, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa6);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_addr = be32(g_net.ip_be);
            if ((s->type_base == SOCK_DGRAM_LOCAL || s->type_base == SOCK_STREAM_LOCAL) && s->local_port) {
                sa.sin_port = be16(s->local_port);
            }

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 52: { /* getpeername */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!s->connected) return ret_err(ENOTCONN);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->unix_domain_stub) {
                uint16_t fam = 1;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(fam)) ? ulen : (uint32_t)sizeof(fam);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &fam, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(fam);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_peer_pid;
                sa.nl_groups = 0;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            if (s->ipv6_stub) {
                sockaddr_in6_k sa6;
                sockaddr_in6_v4mapped_fill(&sa6, s->peer_ip_be, s->peer_port);
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa6)) ? ulen : (uint32_t)sizeof(sa6);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa6, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa6);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_port = be16(s->peer_port);
            sa.sin_addr = be32(s->peer_ip_be);

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 54: { /* setsockopt */
            int fd = (int)a1;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            /* Minimal implementation: accept common ping options. */
            return 0;
        }
        case 55: { /* getsockopt */
            int fd = (int)a1;
            int level = (int)a2;
            int optname = (int)a3;
            void *optval_u = (void *)(uintptr_t)a4;
            void *optlen_u = (void *)(uintptr_t)a5;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!optlen_u || !user_range_ok(optlen_u, 4)) return ret_err(EFAULT);
            uint32_t olen = 0;
            if (copy_from_user_raw(&olen, optlen_u, 4) != 0) return ret_err(EFAULT);
            enum { SOL_SOCKET_LOCAL = 1, SO_ERROR_LOCAL = 4 };
            if (level == SOL_SOCKET_LOCAL && optname == SO_ERROR_LOCAL &&
                s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge &&
                optval_u && olen >= 4) {
                int soerr = 0;
                if (s->tcp.connect_pending)
                    soerr = 0;
                else if (s->tcp.connect_refused)
                    soerr = ECONNREFUSED;
                else if (s->tcp.peer_rst)
                    soerr = ECONNRESET;
                if (copy_to_user_safe(optval_u, &soerr, 4) != 0) return ret_err(EFAULT);
                olen = 4;
                if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (optval_u && olen >= 4) {
                uint32_t zero = 0;
                if (copy_to_user_safe(optval_u, &zero, 4) != 0) return ret_err(EFAULT);
                olen = 4;
            } else {
                olen = 0;
            }
            if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 44: { /* sendto */
            int fd = (int)a1;
            const void *buf_u = (const void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            const void *to_u = (const void *)(uintptr_t)a5;
            size_t tolen = (size_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!buf_u || len == 0) return ret_err(EINVAL);
                if (len < sizeof(nlmsghdr_k) || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                uint8_t pkt[256];
                size_t cp = (len > sizeof(pkt)) ? sizeof(pkt) : len;
                if (copy_from_user_raw(pkt, buf_u, cp) != 0) return ret_err(EFAULT);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > len) return ret_err(EINVAL);
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
                return (uint64_t)len;
            }
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                ssize_t wr = unix_stream_write_from_user(s, buf_u, len);
                if (wr < 0) return ret_err((int)(-wr));
                return (uint64_t)wr;
            }
            /* glibc send(2) -> sendto; OpenSSL wget uses this for TLS on :443. */
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (!buf_u || len == 0) return ret_err(EINVAL);
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->tcp.peer_rst) return ret_err(ECONNRESET);
                if (s->tcp.peer_fin) return ret_err(EPIPE);
                if (!s->connected || !s->tcp.established) return ret_err(ENOTCONN);
                ssize_t wr = net_sock_write_userspace(t, fd, s, buf_u, len);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }
            if (!buf_u || len == 0 || len > 2048) return ret_err(EINVAL);
            if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (to_u) {
                if (tolen < 2u || !user_range_ok(to_u, tolen)) return ret_err(EFAULT);
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(to_u, (size_t)tolen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr); /* user sockaddr stores network-order bytes */
                dst_port = be16(to.sin_port);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                    if (dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_stack_init() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) dst_ip_be = ns;
                    }
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                return ret_err(EDESTADDRREQ);
            }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto fd=%d len=%u dst=%u.%u.%u.%u:%u\n",
                    fd, (unsigned)len,
                    (unsigned)((dst_ip_be >> 24) & 0xFF), (unsigned)((dst_ip_be >> 16) & 0xFF),
                    (unsigned)((dst_ip_be >> 8) & 0xFF), (unsigned)(dst_ip_be & 0xFF),
                    (unsigned)dst_port);
            }
            uint8_t *icmp = (uint8_t *)kmalloc(len);
            if (!icmp) return ret_err(ENOMEM);
            if (copy_from_user_raw(icmp, buf_u, len) != 0) { kfree(icmp); return ret_err(EFAULT); }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u && len >= 12) {
                uint16_t id = (uint16_t)(((uint16_t)icmp[0] << 8) | (uint16_t)icmp[1]);
                uint16_t flags_d = (uint16_t)(((uint16_t)icmp[2] << 8) | (uint16_t)icmp[3]);
                uint16_t qd = (uint16_t)(((uint16_t)icmp[4] << 8) | (uint16_t)icmp[5]);
                uint16_t an = (uint16_t)(((uint16_t)icmp[6] << 8) | (uint16_t)icmp[7]);
                uint16_t ns = (uint16_t)(((uint16_t)icmp[8] << 8) | (uint16_t)icmp[9]);
                uint16_t ar = (uint16_t)(((uint16_t)icmp[10] << 8) | (uint16_t)icmp[11]);
                klogprintf("WGET-DNS: qhdr id=0x%04x flags=0x%04x qd=%u an=%u ns=%u ar=%u\n",
                    (unsigned)id, (unsigned)flags_d,
                    (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
            }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && len > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp + 8, len - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp, len);
                s->last_req_len = len;
                memcpy(s->last_req, icmp, len);
                r = net_send_icmp_echo(s, dst_ip_be, icmp, len);
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, icmp, len);
            }
            kfree(icmp);
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto result r=%d local_port=%u\n", r, (unsigned)s->local_port);
            }
            if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);
            return (uint64_t)len;
        }
        case 45: { /* recvfrom */
            int fd = (int)a1;
            void *buf_u = (void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            int flags = (int)a4;
            void *from_u = (void *)(uintptr_t)a5;
            void *fromlen_u = (void *)(uintptr_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (len == 0) return 0;
                if (!buf_u || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return 0;
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > len) ? len : avail;
                if (copy_to_user_safe(buf_u, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK=0x2 */
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_nl_k) && user_range_ok(from_u, sizeof(sockaddr_nl_k))) {
                        sockaddr_nl_k sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.nl_family = AF_NETLINK_LOCAL;
                        sa.nl_pid = 0; /* kernel */
                        sa.nl_groups = 0;
                        (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                        flen = sizeof(sa);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)ncopy;
            }
            /* Linux-compatible: zero-length recv is valid even with NULL buffer. */
            if (len == 0) return 0;
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                ssize_t rr = unix_stream_read_to_user(s, buf_u, len, (flags & 0x2) ? 1 : 0);
                if (rr < 0) return ret_err((int)(-rr));
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= 2 && user_range_ok(from_u, 2)) {
                        uint16_t fam = 1;
                        (void)copy_to_user_safe(from_u, &fam, sizeof(fam));
                        flen = 2;
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)rr;
            }
            if (!buf_u) {
                if (dbg_wget) qemu_debug_printf("RECVFROM-EFAULT: null buf with len=%llu\n", (unsigned long long)len);
                return ret_err(EFAULT);
            }
            /* glibc recv(2) -> recvfrom; OpenSSL wget uses this for TLS on :443. */
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
                if ((!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) && s->tcp.rx_len == 0) return ret_err(ENOTCONN);
                ssize_t rr = net_sock_read_userspace(t, s, buf_u, len);
                if (rr < 0) return ret_err((int)-rr);
                if (rr == 0) return 0;
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_in_k) && user_range_ok(from_u, sizeof(sockaddr_in_k))) {
                        sockaddr_in_k sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family = AF_INET_LOCAL;
                        sa.sin_port = be16(s->peer_port);
                        sa.sin_addr = be32(s->peer_ip_be);
                        (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                        flen = sizeof(sa);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)rr;
            }
            size_t cap = len;
            if (cap > 8192) cap = 8192; /* defensive cap to avoid huge temporary allocations */
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                    if (n >= 12) {
                        /* DNS header: id, flags, qd, an, ns, ar */
                        uint16_t id = (uint16_t)(((uint16_t)tmp[0] << 8) | (uint16_t)tmp[1]);
                        uint16_t flags_d = (uint16_t)(((uint16_t)tmp[2] << 8) | (uint16_t)tmp[3]);
                        uint8_t rcode = (uint8_t)(flags_d & 0x0Fu);
                        uint16_t qd = (uint16_t)(((uint16_t)tmp[4] << 8) | (uint16_t)tmp[5]);
                        uint16_t an = (uint16_t)(((uint16_t)tmp[6] << 8) | (uint16_t)tmp[7]);
                        uint16_t ns = (uint16_t)(((uint16_t)tmp[8] << 8) | (uint16_t)tmp[9]);
                        uint16_t ar = (uint16_t)(((uint16_t)tmp[10] << 8) | (uint16_t)tmp[11]);
                        klogprintf("WGET-DNS: hdr id=0x%04x flags=0x%04x rcode=%u qd=%u an=%u ns=%u ar=%u\n",
                            (unsigned)id, (unsigned)flags_d, (unsigned)rcode,
                            (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
                        int dump = (n < 32) ? n : 32;
                        klogprintf("WGET-DNS: hex0..%d:", dump - 1);
                        for (int i = 0; i < dump; i++) qemu_debug_printf(" %02x", (unsigned)tmp[i]);
                        qemu_debug_printf("\n");
                    }
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL)
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(buf_u, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)buf_u;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVFROM-EFAULT: copy buf=%p n=%d us=0x%llx ue=0x%llx\n",
                        buf_u, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                uint32_t flen = 0;
                if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_in_k) && user_range_ok(from_u, sizeof(sockaddr_in_k))) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(src_port);
                    sa.sin_addr = be32(src_ip); /* keep sockaddr in network byte order */
                    (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                    uint32_t out_len = sizeof(sa);
                    (void)copy_to_user_safe(fromlen_u, &out_len, 4);
                }
            }
            return (uint64_t)n;
        }
        case 46: { /* sendmsg -> map to sendto for first iov */
            int fd = (int)a1;
            const void *msg_u = (const void *)(uintptr_t)a2;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || m.msg_iovlen > 64 ||
                !user_range_ok(m.msg_iov, (size_t)m.msg_iovlen * 16u))
                return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov[64];
            if (copy_from_user_raw(iov, m.msg_iov, (size_t)m.msg_iovlen * sizeof(iov[0])) != 0)
                return ret_err(EFAULT);
            uint64_t sum64 = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++)
                sum64 += iov[i].len;
            if (sum64 == 0) return 0;
            if (sum64 > 65536u) return ret_err(EINVAL);
            size_t sum = (size_t)sum64;
            uint8_t *flat = (uint8_t *)kmalloc(sum);
            if (!flat) return ret_err(ENOMEM);
            size_t at = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                size_t ilen = (size_t)iov[i].len;
                if (ilen == 0) continue;
                if (!iov[i].base || !user_range_ok(iov[i].base, ilen)) {
                    kfree(flat);
                    return ret_err(EFAULT);
                }
                if (copy_from_user_raw(flat + at, iov[i].base, ilen) != 0) {
                    kfree(flat);
                    return ret_err(EFAULT);
                }
                at += ilen;
            }
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) {
                kfree(flat);
                return ret_err(EBADF);
            }
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                uint8_t pkt[256];
                size_t cp = (sum > sizeof(pkt)) ? sizeof(pkt) : sum;
                memcpy(pkt, flat, cp);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > sum) {
                    kfree(flat);
                    return ret_err(EINVAL);
                }
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
                kfree(flat);
                return (uint64_t)sum;
            }
            if (s->unix_domain_stub) {
                if (!s->connected) { kfree(flat); return ret_err(ENOTCONN); }
                size_t written = 0;
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    ssize_t part = unix_stream_write_from_user(s, iov[i].base, ilen);
                    if (part < 0) {
                        kfree(flat);
                        return written ? (uint64_t)written : ret_err((int)(-part));
                    }
                    written += (size_t)part;
                    if ((size_t)part < ilen)
                        break;
                }
                kfree(flat);
                return (uint64_t)written;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (s->tcp.peer_rst) { kfree(flat); return ret_err(ECONNRESET); }
                if (s->tcp.peer_fin) { kfree(flat); return ret_err(EPIPE); }
                if (!s->connected || !s->tcp.established) { kfree(flat); return ret_err(ENOTCONN); }
                size_t total = 0;
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops, &s->tcp);
                while (total < sum) {
                    size_t chunk = sum - total;
                    if (chunk > 4096) chunk = 4096;
                    if (total == 0)
                        net_debug_log_tls443_tx(s, flat, chunk, "sendmsg");
                    int wr = net_tcp_send(&s->tcp, &ops, flat + total, chunk, 30000);
                    if (wr < 0) {
                        kfree(flat);
                        return total ? (uint64_t)total : ret_err(EIO);
                    }
                    total += (size_t)wr;
                    if ((size_t)wr < chunk)
                        break;
                }
                (void)net_tcp_flush_tx(&s->tcp, &ops, 5000);
                for (int p = 0; p < 64; p++) {
                    e1000_poll();
                    (void)net_tcp_service(&s->tcp, &ops, 128);
                    if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst)
                        break;
                }
                kfree(flat);
                return (uint64_t)total;
            }
            if (sum > 2048) {
                kfree(flat);
                return ret_err(EINVAL);
            }
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (m.msg_name && m.msg_namelen >= 2u && user_range_ok(m.msg_name, (size_t)m.msg_namelen)) {
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(m.msg_name, (size_t)m.msg_namelen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr);
                dst_port = be16(to.sin_port);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) &&
                    dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_stack_init() == 0) {
                    uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                    if (ns) dst_ip_be = ns;
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                kfree(flat);
                return ret_err(EDESTADDRREQ);
            }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && sum > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(flat + 8, sum - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(flat, sum);
                s->last_req_len = sum;
                memcpy(s->last_req, flat, sum);
                r = net_send_icmp_echo(s, dst_ip_be, flat, sum);
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, flat, sum);
            }
            kfree(flat);
            if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);
            return (uint64_t)sum;
        }
        case 307: { /* sendmmsg: minimal, first message only */
            int fd = (int)a1;
            void *mmsg_u = (void *)(uintptr_t)a2;
            uint32_t vlen = (uint32_t)a3;
            int flags = (int)a4;
            if (!mmsg_u || vlen == 0) return ret_err(EFAULT);
            /* struct mmsghdr begins with struct msghdr, so first entry pointer is msg pointer. */
            uint64_t r = syscall_do_inner(46, (uint64_t)fd, (uint64_t)(uintptr_t)mmsg_u, (uint64_t)flags, 0, 0, 0);
            if ((int64_t)r < 0) return r;
            /* mmsghdr.msg_len sits right after msghdr (56 bytes on x86_64 ABI used above). */
            if (user_range_ok((uint8_t *)mmsg_u + 56, 4)) {
                uint32_t mlen = (uint32_t)r;
                (void)copy_to_user_safe((uint8_t *)mmsg_u + 56, &mlen, sizeof(mlen));
            }
            return 1;
        }
        case 47: { /* recvmsg */
            int fd = (int)a1;
            void *msg_u = (void *)(uintptr_t)a2;
            int flags = (int)a3;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || m.msg_iovlen > 64 ||
                !user_range_ok(m.msg_iov, (size_t)m.msg_iovlen * 16u))
                return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov[64];
            if (copy_from_user_raw(iov, m.msg_iov, (size_t)m.msg_iovlen * sizeof(iov[0])) != 0)
                return ret_err(EFAULT);
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (iov[0].len == 0) return 0;
                if (!iov[0].base || !user_range_ok(iov[0].base, (size_t)iov[0].len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return 0;
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > (size_t)iov[0].len) ? (size_t)iov[0].len : avail;
                if (copy_to_user_safe(iov[0].base, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK */
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_nl_k) && user_range_ok(m.msg_name, sizeof(sockaddr_nl_k))) {
                    sockaddr_nl_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.nl_family = AF_NETLINK_LOCAL;
                    sa.nl_pid = 0; /* kernel */
                    (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
                }
                if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                    m.msg_namelen = sizeof(sockaddr_nl_k);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)ncopy;
            }
            /* Linux-compatible: zero-length recvmsg iov is valid. */
            uint64_t want64 = 0;
            for (uint64_t i = 0; i < m.msg_iovlen; i++)
                want64 += iov[i].len;
            if (want64 == 0) return 0;
            if (s->unix_domain_stub) {
                if (!s->connected) return ret_err(ENOTCONN);
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    if (iov[i].len == 0) continue;
                    if (!iov[i].base || !user_range_ok(iov[i].base, (size_t)iov[i].len))
                        return ret_err(EFAULT);
                }
                size_t cap = (want64 > 65536u) ? 65536u : (size_t)want64;
                uint8_t *tmp = (uint8_t *)kmalloc(cap);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = unix_stream_read_to_user(s, tmp, cap, (flags & 0x2) ? 1 : 0);
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err((int)(-rr));
                }
                size_t left = (size_t)rr;
                size_t at = 0;
                for (uint64_t i = 0; i < m.msg_iovlen && left > 0; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    size_t cp = (ilen > left) ? left : ilen;
                    if (copy_to_user_safe(iov[i].base, tmp + at, cp) != 0) {
                        kfree(tmp);
                        return ret_err(EFAULT);
                    }
                    at += cp;
                    left -= cp;
                    if (cp < ilen)
                        break;
                }
                kfree(tmp);
                if (m.msg_name && m.msg_namelen >= 2 && user_range_ok(m.msg_name, 2)) {
                    uint16_t fam = 1;
                    (void)copy_to_user_safe(m.msg_name, &fam, sizeof(fam));
                    m.msg_namelen = 2;
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)rr;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                if (s->tcp.rx_len == 0 && s->tcp.peer_fin) return 0;
                if ((!s->connected || (!s->tcp.established && !s->tcp.peer_rst)) && s->tcp.rx_len == 0) return ret_err(ENOTCONN);
                for (uint64_t i = 0; i < m.msg_iovlen; i++) {
                    if (iov[i].len == 0) continue;
                    if (!iov[i].base || !user_range_ok(iov[i].base, (size_t)iov[i].len))
                        return ret_err(EFAULT);
                }
                size_t cap = (want64 > 65536u) ? 65536u : (size_t)want64;
                uint8_t *tmp = (uint8_t *)kmalloc(cap);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = net_sock_read_userspace(t, s, tmp, cap);
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err((int)-rr);
                }
                if (rr == 0) {
                    kfree(tmp);
                    return 0;
                }
                size_t left = (size_t)rr;
                size_t at = 0;
                for (uint64_t i = 0; i < m.msg_iovlen && left > 0; i++) {
                    size_t ilen = (size_t)iov[i].len;
                    if (ilen == 0) continue;
                    size_t cp = (ilen > left) ? left : ilen;
                    if (copy_to_user_safe(iov[i].base, tmp + at, cp) != 0) {
                        kfree(tmp);
                        return ret_err(EFAULT);
                    }
                    at += cp;
                    left -= cp;
                    if (cp < ilen)
                        break;
                }
                kfree(tmp);
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_in_k) && user_range_ok(m.msg_name, sizeof(sockaddr_in_k))) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(s->peer_port);
                    sa.sin_addr = be32(s->peer_ip_be);
                    (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
                }
                if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                    m.msg_namelen = sizeof(sockaddr_in_k);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)rr;
            }
            if (!iov[0].base) {
                if (dbg_wget) qemu_debug_printf("RECVMSG-EFAULT: null base with len=%llu\n", (unsigned long long)iov[0].len);
                return ret_err(EFAULT);
            }
            size_t cap = (size_t)iov[0].len;
            if (cap > 8192) cap = 8192;
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)iov[0].len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (iov[0].len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (iov[0].len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                    (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge))
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(iov[0].base, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)iov[0].base;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVMSG-EFAULT: copy base=%p n=%d us=0x%llx ue=0x%llx\n",
                        iov[0].base, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            uint32_t fromlen = sizeof(sockaddr_in_k);
            if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_in_k) && user_range_ok(m.msg_name, sizeof(sockaddr_in_k))) {
                sockaddr_in_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET_LOCAL;
                sa.sin_port = be16(src_port);
                sa.sin_addr = be32(src_ip);
                (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
            }
            /* keep msg_namelen in sync */
            if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                m.msg_namelen = fromlen;
                (void)copy_to_user_safe(msg_u, &m, sizeof(m));
            }
            return (uint64_t)n;
        }
        case 299: { /* recvmmsg — Linux x86_64; glibc resolver may batch reads */
            int fd = (int)a1;
            void *mmsg_u = (void *)(uintptr_t)a2;
            unsigned int vlen = (unsigned int)a3;
            int flags = (int)a4;
            (void)a5;
            if (!mmsg_u || vlen == 0) return ret_err(EINVAL);
            /* One struct mmsghdr: msghdr (matches our msghdr_k) + msg_len */
            if (!user_range_ok(mmsg_u, 64)) return ret_err(EFAULT);
            uint64_t r = syscall_do_inner(47, (uint64_t)fd, (uint64_t)mmsg_u, (uint64_t)flags, 0, 0, 0);
            if ((int64_t)r < 0) return r;
            uint32_t mlen = (uint32_t)r;
            /* After Linux struct msghdr (56 bytes on x86_64) */
            if (copy_to_user_safe((uint8_t *)mmsg_u + 56, &mlen, sizeof(mlen)) != 0) return ret_err(EFAULT);
            return 1;
        }
        case SYS_sysinfo: { /* sysinfo(struct sysinfo *) - syscall 99; glibc allocatestack needs sane freeram */
            void *info_u = (void*)(uintptr_t)a1;
            if (!info_u || (uintptr_t)info_u + 112 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* Linux struct sysinfo x86_64: uptime(0), loads[3](8), totalram(32), freeram(40), sharedram(48),
               bufferram(56), totalswap(64), freeswap(72), procs(80), pad(82), totalhigh(84), freehigh(92),
               mem_unit(100). glibc advise_stack_range: freesize from freeram*mem_unit; must be >= stack size. */
            uint8_t buf[128];
            memset(buf, 0, sizeof(buf));
            int64_t uptime_sec = (int64_t)(pit_get_time_ms() / 1000);
            memcpy(buf + 0, &uptime_sec, 8);
            unsigned long loads[3];
            loadavg_get_user(loads);
            memcpy(buf + 8, loads, 24);
            uint64_t totalram = 128 * 1024 * 1024;  /* 128MB */
            uint64_t freeram = 64 * 1024 * 1024;   /* 64MB - enough for stack allocation */
            memcpy(buf + 32, &totalram, 8);
            memcpy(buf + 40, &freeram, 8);
            /* sharedram, bufferram at 48,56 = 0 */
            /* totalswap, freeswap at 64,72 = 0 */
            uint16_t procs = (uint16_t)thread_get_count();
            memcpy(buf + 80, &procs, 2);
            /* totalhigh, freehigh at 84,92 = 0 */
            uint32_t mem_unit = 1;
            memcpy(buf + 100, &mem_unit, 4);
            if (copy_to_user_safe(info_u, buf, 112) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getrlimit: { /* getrlimit(resource, rlim) */
            int resource = (int)a1;
            void *rlim_u = (void*)(uintptr_t)a2;
            if (!rlim_u || (uintptr_t)rlim_u + 16 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; }; rlim_t = 64-bit */
            uint64_t cur_val = 0xFFFFFFFFFFFFFFFFULL, max_val = 0xFFFFFFFFFFFFFFFFULL;
            switch (resource) {
                case 3: /* RLIMIT_STACK */ cur_val = 8 * 1024 * 1024; max_val = cur_val; break;
                case 4: /* RLIMIT_CORE */ cur_val = 0; max_val = 0xFFFFFFFFFFFFFFFFULL; break;
                case 6: /* RLIMIT_NPROC */ cur_val = 4096; max_val = 4096; break;
                case 7: /* RLIMIT_NOFILE */ cur_val = (uint64_t)THREAD_MAX_FD; max_val = cur_val; break;
                case 9: /* RLIMIT_AS */ cur_val = max_val = 0xFFFFFFFFFFFFFFFFULL; break;
                default: cur_val = max_val = 0xFFFFFFFFFFFFFFFFULL; break;
            }
            if (copy_to_user_safe(rlim_u, &cur_val, sizeof(cur_val)) != 0) return ret_err(EFAULT);
            if (copy_to_user_safe((char*)rlim_u + 8, &max_val, sizeof(max_val)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_sched_getaffinity: { /* sched_getaffinity(pid, len, user_mask) */
            int pid = (int)a1;
            size_t len = (size_t)a2;
            void *mask_u = (void*)(uintptr_t)a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            if (!mask_u || len < 8 || (uintptr_t)mask_u + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint64_t mask = smp_default_affinity_mask();
            size_t copy = len < 8 ? len : 8;
            if (copy_to_user_safe(mask_u, &mask, copy) != 0) return ret_err(EFAULT);
            for (size_t i = 8; i < len; i++) {
                char zero = 0;
                if (copy_to_user_safe((char*)mask_u + i, &zero, 1) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
#ifndef PRIO_PROCESS
#define PRIO_PROCESS 0
#endif
        case SYS_getpriority: { /* getpriority(which, who) */
            int which = (int)a1;
            int who = (int)a2;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            thread_t *t = (who == 0) ? cur : thread_get(who);
            if (!t) return ret_err(ESRCH);
            return (uint64_t)(int64_t)t->nice;
        }
        case SYS_setpriority: { /* setpriority(which, who, prio) — Linux nice -20..19 */
            int which = (int)a1;
            int who = (int)a2;
            int nicev = (int)a3;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            if (thread_nice_set(who, nicev) != 0) return ret_err(ESRCH);
            return 0;
        }
        case 62: { /* kill(pid, sig) */
            int pid = (int)a1;
            int sig = (int)a2;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid > 0) {
                thread_t *t = thread_get(pid);
                if (!t) return ret_err(ESRCH);
                /* sig==0 used for existence check */
                if (sig == 0) return 0;
                /* We don't deliver signals yet; accept SIGABRT to exit */
                if (sig == 6 /* SIGABRT */) {
                    qemu_debug_printf("sys_kill: pid=%d sig=SIGABRT received for pid=%d; ignoring auto-exit\n", sig, pid);
                    return 0;
                }
                return 0;
            } else if (pid == 0) {
                /* broadcast to process group: accept */
                (void)sig;
                return 0;
            } else {
                /* other semantics (negative pids) not supported */
                return ret_err(EINVAL);
            }
        }
        case 32: { /* dup(oldfd) */
            int oldfd = (int)a1;
            if (oldfd < 0 || oldfd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[oldfd];
            if (!f) return ret_err(EBADF);
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                if (cur->fds[i] == NULL) {
                    cur->fds[i] = f;
                    if (f->refcount <= 0) f->refcount = 1;
                    else f->refcount++;
                    return (uint64_t)i;
                }
            }
            return ret_err(EMFILE);
        }
        case SYS_dup2: { /* dup2(oldfd, newfd) — Linux 33; getty/nano need this to dup TTY to stdin/stdout/stderr */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
        }
        case 269: /* faccessat(dirfd, pathname, mode, flags) */
        case 439: /* faccessat2(dirfd, pathname, mode, flags, ...) */
        {
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int mode = (int)a3;
            int flags = (int)a4;
            (void)mode; (void)flags;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* build path relative to CWD/dirfd similarly to 269, but only check existence */
            {
                char path[512];
                if (path_u[0] == '/') {
                    strncpy(path, path_u, sizeof(path));
                    path[sizeof(path) - 1] = '\0';
                } else {
                    const int AT_FDCWD = -100;
                    if (dirfd == AT_FDCWD) {
                        resolve_user_path(cur, path_u, path, sizeof(path));
                    } else if (dirfd >= 0 && dirfd < THREAD_MAX_FD && cur->fds[dirfd]) {
                        const char *base = cur->fds[dirfd]->path ? cur->fds[dirfd]->path : "/";
                        size_t bl = strlen(base);
                        if (bl + 1 + strlen(path_u) + 1 > sizeof(path)) return ret_err(ENAMETOOLONG);
                        char basecopy[512]; strncpy(basecopy, base, sizeof(basecopy)); basecopy[sizeof(basecopy)-1] = '\0';
                        if (basecopy[bl-1] != '/') {
                            char *s = strrchr(basecopy, '/');
                            if (s) *(s+1) = '\0';
                            else { basecopy[0] = '/'; basecopy[1] = '\0'; }
                        }
                        snprintf(path, sizeof(path), "%s%s", basecopy, path_u);
                    } else {
                        resolve_user_path(cur, path_u, path, sizeof(path));
                    }
                }
                struct stat st;
                if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
                return 0;
            }
        }
        case 72: { /* fcntl(fd, cmd, arg) - minimal support */
            int fd = (int)a1;
            int cmd = (int)a2;
            int arg = (int)a3;
            enum {
                F_DUPFD = 0,
                F_GETFD = 1,
                F_SETFD = 2,
                F_GETFL = 3,
                F_SETFL = 4,
                F_GETLK = 5,
                F_SETLK = 6,
                F_SETLKW = 7,
                F_DUPFD_CLOEXEC = 1030,
            };
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (cmd == F_DUPFD_CLOEXEC) {
                /* Same as F_DUPFD; we do not track FD_CLOEXEC, accept for compatibility */
                cmd = F_DUPFD;
            }
            if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK) {
                /* File locking: stub as success (no-op). Busybox adduser uses flock on /etc/passwd;
                   without this it gets EINVAL and exits silently. */
                (void)arg;
                if (cmd == F_GETLK && arg) {
                    /* F_GETLK: write flock struct with l_type=F_UNLCK to indicate "not locked" */
                    if (user_range_ok((void*)(uintptr_t)arg, 32)) {
                        uint8_t zeros[32];
                        memset(zeros, 0, sizeof(zeros));
                        copy_to_user_safe((void*)(uintptr_t)arg, zeros, 32);
                    }
                }
                return 0;
            }
            if (cmd == F_GETFD) {
                /* return flags (no FD_CLOEXEC support) */
                return 0;
            } else if (cmd == F_SETFD) {
                /* accept silently */
                (void)arg;
                return 0;
            } else if (cmd == F_GETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    int fl = O_RDWR_LINUX;
                    if (sk->nonblock) fl |= O_NONBLOCK_LINUX;
                    return (uint64_t)(unsigned)fl;
                }
                /* For regular files/dirs/pipes: we don't track flags yet; return accmode only so fdopen() works. */
                return (uint64_t)(unsigned)O_RDWR_LINUX;
            } else if (cmd == F_SETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    sk->nonblock = (arg & O_NONBLOCK_LINUX) ? 1 : 0;
                }
                return 0;
            } else if (cmd == F_DUPFD) {
                /* simple duplicate to next available fd */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i] == NULL) {
                        cur->fds[i] = f;
                        if (f->refcount <= 0) f->refcount = 1;
                        else f->refcount++;
                        return (uint64_t)i;
                    }
                }
                return ret_err(EMFILE);
            }
            return ret_err(EINVAL);
        }
        case 73: { /* flock(fd, operation) - stub as success. Busybox adduser uses flock on /etc/passwd. */
            (void)a1; (void)a2;
            return 0;
        }
        case 74: /* fsync(fd) */
        case 75: { /* fdatasync(fd) - adduser syncs passwd before rename */
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!cur->fds[fd]) return ret_err(EBADF);
            return 0;
        }
        case 162: { /* sync() — drain async block I/O before reboot (BusyBox calls this without -f). */
            iothread_drain();
            return 0;
        }
        case 270: {
            /* pselect6 — musl implements select(2) via this syscall. */
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv_conv;
            void *timeout_u = NULL;
            if ((const void *)(uintptr_t)a5) {
                struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                if (!user_range_ok((const void *)(uintptr_t)a5, sizeof(ts)))
                    return ret_err(EFAULT);
                if (copy_from_user_raw(&ts, (const void *)(uintptr_t)a5, sizeof(ts)) != 0)
                    return ret_err(EFAULT);
                if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                tv_conv.tv_sec = ts.tv_sec;
                tv_conv.tv_usec = ts.tv_nsec / 1000;
                timeout_u = &tv_conv;
            }
            a5 = (uint64_t)(uintptr_t)timeout_u;
            (void)a6;
            goto select_common;
        }
        case 121: { /* getpgid(pid) */
            int pid = (int)a1;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid == 0) {
                return (uint64_t)user_pgrp;
            }
            if ((uint64_t)pid == self) return (uint64_t)user_pgrp;
            /* We only support querying current process for now */
            return ret_err(ESRCH);
        }
        case SYS_rt_sigaction: {
            /* rt_sigaction(int signum, const struct sigaction *act,
                            struct sigaction *oldact, size_t sigsetsize) */
            int signum = (int)a1;
            const void *act_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            if (signum <= 0 || signum >= (int)(sizeof(user_sig_actions)/sizeof(user_sig_actions[0]))) return ret_err(EINVAL);

            /* Linux kernel ABI for rt_sigaction on x86_64:
               struct {
                 void (*handler)(int);
                 unsigned long flags;
                 void (*restorer)(void);
                 sigset_t mask;   // size = sigsetsize (glibc usually passes 8)
               }
               Total size = 24 + sigsetsize.
               Important: do NOT over-copy here; glibc may pass a tiny 32-byte object. */
            if (sigsetsize == 0 || sigsetsize > 128) return ret_err(EINVAL);
            const size_t act_sz = 24 + sigsetsize;
            struct k_sa {
                uint64_t handler;
                uint64_t flags;
                uint64_t restorer;
                uint8_t  mask[128];
            } sa;

            if (old_u) {
                memset(&sa, 0, sizeof(sa));
                sa.handler = (uint64_t)(uintptr_t)user_sig_actions[signum].handler;
                sa.flags = user_sig_actions[signum].flags;
                sa.restorer = user_sig_actions[signum].restorer;
                if (copy_to_user_safe(old_u, &sa, act_sz) != 0) return ret_err(EFAULT);
            }
            if (act_u) {
                memset(&sa, 0, sizeof(sa));
                if (copy_from_user_raw(&sa, act_u, act_sz) != 0) return ret_err(EFAULT);
                user_sig_actions[signum].handler = (user_sighandler_t)(uintptr_t)sa.handler;
                user_sig_actions[signum].flags = sa.flags;
                user_sig_actions[signum].restorer = sa.restorer;
            }
            return 0;
        }
        case SYS_rt_sigtimedwait: {
            /* rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetsize) */
            const void *timeout_u = (const void*)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            void *info_u = (void*)(uintptr_t)a2;
            /* accept 0, 8, or glibc-sized 128-byte sigset; we use lower 64 bits */
            if (!(sigsetsize == 0 || sigsetsize == 8 || sigsetsize == 128)) return ret_err(EINVAL);
            uint64_t mask = 0;
            if (sigsetsize >= 8 && a1) {
                if (copy_from_user_raw(&mask, (const void*)(uintptr_t)a1, sizeof(mask)) != 0) return ret_err(EFAULT);
            }
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            int sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
            if (sig) {
                if (sig == SIGCHLD && info_u) {
                    thread_t *c = find_terminated_child(tcur);
                    struct siginfo_k {
                        int si_signo;
                        int si_errno;
                        int si_code;
                        int si_pid;
                        int si_uid;
                        int si_status;
                        long si_utime;
                        long si_stime;
                    } info;
                    memset(&info, 0, sizeof(info));
                    info.si_signo = SIGCHLD;
                    info.si_code = 1; /* CLD_EXITED */
                    if (c) {
                        info.si_pid = (int)(c->tid ? c->tid : 1);
                        info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                    }
                    copy_to_user_safe(info_u, &info, sizeof(info));
                }
                return (uint64_t)sig;
            }
            if (mask & (1ULL << (SIGCHLD - 1))) {
                thread_t *c = find_terminated_child(tcur);
                if (c) {
                    if (info_u) {
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        info.si_pid = (int)(c->tid ? c->tid : 1);
                        info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)SIGCHLD;
                }
            }
            if (timeout_u) {
                struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                if (copy_from_user_raw(&ts, timeout_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                if (ms > 0) thread_sleep((uint32_t)ms);
                sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
                if (sig) {
                    if (sig == SIGCHLD && info_u) {
                        thread_t *c = find_terminated_child(tcur);
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        if (c) {
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        }
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)sig;
                }
                if (mask & (1ULL << (SIGCHLD - 1))) {
                    thread_t *c = find_terminated_child(tcur);
                    if (c) {
                        if (info_u) {
                            struct siginfo_k {
                                int si_signo;
                                int si_errno;
                                int si_code;
                                int si_pid;
                                int si_uid;
                                int si_status;
                                long si_utime;
                                long si_stime;
                            } info;
                            memset(&info, 0, sizeof(info));
                            info.si_signo = SIGCHLD;
                            info.si_code = 1; /* CLD_EXITED */
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                            copy_to_user_safe(info_u, &info, sizeof(info));
                        }
                        return (uint64_t)SIGCHLD;
                    }
                }
                return ret_err(EAGAIN);
            }
            /* no timeout: block until signal */
            for (;;) {
                thread_sleep(10);
                sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
                if (sig) {
                    if (sig == SIGCHLD && info_u) {
                        thread_t *c = find_terminated_child(tcur);
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        if (c) {
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        }
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)sig;
                }
                if (mask & (1ULL << (SIGCHLD - 1))) {
                    thread_t *c = find_terminated_child(tcur);
                    if (c) {
                        if (info_u) {
                            struct siginfo_k {
                                int si_signo;
                                int si_errno;
                                int si_code;
                                int si_pid;
                                int si_uid;
                                int si_status;
                                long si_utime;
                                long si_stime;
                            } info;
                            memset(&info, 0, sizeof(info));
                            info.si_signo = SIGCHLD;
                            info.si_code = 1; /* CLD_EXITED */
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                            copy_to_user_safe(info_u, &info, sizeof(info));
                        }
                        return (uint64_t)SIGCHLD;
                    }
                }
            }
        }
        case SYS_execve: {
            /* copy path, argv, envp from user and call kernel_execve_from_path */
            const char *path_u = (const char*)(uintptr_t)a1;
            const char *const *argv_u = (const char *const*)(uintptr_t)a2;
            const char *const *envp_u = (const char *const*)(uintptr_t)a3;
            if (!path_u) return ret_err(EFAULT);
            if (!user_range_ok(path_u, 1)) return ret_err(EFAULT);
            /* Copy path */
            size_t plen = user_strnlen_bounded(path_u, 1024);
            if (plen == 0 || plen >= 1024) return ret_err(ENOENT);
            char *path = (char*)kmalloc(plen + 1);
            if (!path) { qemu_debug_printf("OOM execve: path plen=%llu\n", (unsigned long long)(plen+1)); return ret_err(ENOMEM); }
            if (!user_range_ok(path_u, plen + 1) || copy_from_user_raw(path, path_u, plen + 1) != 0) {
                kfree(path);
                return ret_err(EFAULT);
            }
            char resolved_path[512];
            resolve_user_path(cur, path, resolved_path, sizeof(resolved_path));
            /* Copy argv array (NULL-terminated) */
            int argc = 0;
            if (argv_u) {
                /* count args */
                while (argc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&argv_u[argc]), &p) != 0) {
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    argc++;
                }
            }
            const char **kargv = (const char**)kmalloc((size_t)(argc + 1) * sizeof(char*));
            if (!kargv) { qemu_debug_printf("OOM execve: kargv argc=%d\n", argc); kfree(path); return ret_err(ENOMEM); }
            for (int i = 0; i < argc; i++) {
                uint64_t a_up = 0;
                if (user_read_u64((const void*)(uintptr_t)(&argv_u[i]), &a_up) != 0) {
                    kfree((void*)kargv); kfree(path); return ret_err(EFAULT);
                }
                const char *a_u = (const char*)(uintptr_t)a_up;
                if (!a_u || !user_range_ok(a_u, 1)) { kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                size_t L = user_strnlen_bounded(a_u, 4096);
                char *ks = (char*)kmalloc(L + 1);
                if (!ks) { qemu_debug_printf("OOM execve: argv[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                if (!user_range_ok(a_u, L + 1) || copy_from_user_raw(ks, a_u, L + 1) != 0) {
                    kfree(ks);
                    for (int j=0;j<i;j++) kfree((void*)kargv[j]);
                    kfree((void*)kargv);
                    kfree(path);
                    return ret_err(EFAULT);
                }
                kargv[i] = ks;
            }
            kargv[argc] = NULL;
            /* axon-harness execve-dyn: do not run busybox with applet argv[0] (would #PF). */
            {
                const char *bn = strrchr(resolved_path, '/');
                bn = bn ? bn + 1 : resolved_path;
                if (argc >= 1 && kargv[0] && strcmp(bn, "busybox") == 0) {
                    const char *a0 = strrchr(kargv[0], '/');
                    a0 = a0 ? a0 + 1 : kargv[0];
                    if (strcmp(a0, "busybox") != 0) {
                        for (int j = 0; j < argc; j++) kfree((void *)kargv[j]);
                        kfree((void *)kargv);
                        kfree(path);
                        return ret_err(ENOEXEC);
                    }
                }
            }
            /* Copy envp similarly (but allow NULL) */
            int envc = 0;
            const char **kenvp = NULL;
            if (envp_u) {
                while (envc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[envc]), &p) != 0) {
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    envc++;
                }
                kenvp = (const char**)kmalloc((size_t)(envc + 1) * sizeof(char*));
                if (!kenvp) { qemu_debug_printf("OOM execve: kenvp envc=%d\n", envc); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                for (int i = 0; i < envc; i++) {
                    uint64_t e_up = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[i]), &e_up) != 0) {
                        for (int j=0;j<i;j++) kfree((void*)kenvp[j]);
                        kfree(kenvp);
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    const char *e_u = (const char*)(uintptr_t)e_up;
                    if (!e_u || !user_range_ok(e_u, 1)) { for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                    size_t L = user_strnlen_bounded(e_u, 4096);
                    char *ks = (char*)kmalloc(L + 1);
                    if (!ks) { qemu_debug_printf("OOM execve: envp[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                    if (!user_range_ok(e_u, L + 1) || copy_from_user_raw(ks, e_u, L + 1) != 0) { kfree(ks); for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                    kenvp[i] = ks;
                }
                kenvp[envc] = NULL;
            }

            /* call kernel execve (does not return on success) */
            int rc = kernel_execve_from_path(resolved_path, (const char *const *)kargv, (const char *const *)kenvp);
            if (rc == -3) {
                /* One bounded retry for transient tid/layout race in exec path. */
                g_execve_retry_eagain++;
                rc = kernel_execve_from_path(resolved_path, (const char *const *)kargv, (const char *const *)kenvp);
                if (rc == 0) {
                    g_execve_retry_ok++;
                } else {
                    g_execve_retry_fail++;
                    uint64_t now_ms = pit_get_time_ms();
                    if (now_ms - g_execve_retry_last_log_ms >= 2000ULL) {
                        g_execve_retry_last_log_ms = now_ms;
                        klogprintf("execve: retry stats eagain=%llu ok=%llu fail=%llu last_rc=%d path=%s\n",
                                   (unsigned long long)g_execve_retry_eagain,
                                   (unsigned long long)g_execve_retry_ok,
                                   (unsigned long long)g_execve_retry_fail,
                                   rc, resolved_path);
                    }
                }
            }

            /* cleanup on failure */
            if (kenvp) { for (int i=0;i<envc;i++) if (kenvp[i]) kfree((void*)kenvp[i]); kfree(kenvp); }
            for (int i=0;i<argc;i++) if (kargv[i]) kfree((void*)kargv[i]);
            if (kargv) kfree((void*)kargv);
            kfree(path);
            if (rc == 0) {
                sysv_shm_detach_all_for_tid((uint64_t)(cur && cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur && cur->tid ? cur->tid : 1));
                return 0;
            }
            if (rc == -2) return ret_err(ENOEXEC);
            if (rc == -3) return ret_err(EAGAIN);
            return ret_err(ENOENT);
        }
        case SYS_rt_sigprocmask: {
            /* rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize)
               Per-thread signal mask; use cur->saved_sig_mask for user threads. */
            int how = (int)a1;
            const void *set_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            (void)a4;
            uint64_t *p_mask = (cur && cur->ring == 3) ? &cur->saved_sig_mask : &user_sig_mask;

            if (old_u) {
                uint64_t old = *p_mask;
                if (copy_to_user_safe(old_u, &old, sizeof(old)) != 0) return ret_err(EFAULT);
            }
            if (set_u) {
                uint64_t setv = 0;
                if (copy_from_user_raw(&setv, set_u, sizeof(setv)) != 0) return ret_err(EFAULT);
                if (how == 0 /* SIG_BLOCK */) *p_mask |= setv;
                else if (how == 1 /* SIG_UNBLOCK */) *p_mask &= ~setv;
                else if (how == 2 /* SIG_SETMASK */) *p_mask = setv;
                else return ret_err(EINVAL);
            }
            return 0;
        }
        case SYS_fork: {
            uint64_t saved_rcx = cur->saved_user_rip;
            uint64_t saved_rsp = cur->saved_user_rsp;
            fork_dbg(cur, 1, "enter",
                (unsigned long long)(cur->tid ? cur->tid : 0),
                (unsigned long long)saved_rcx,
                (unsigned long long)saved_rsp);
            if (saved_rcx == 0 || saved_rsp == 0 ||
                (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                fork_dbg(cur, -1, "EINVAL args", saved_rcx, saved_rsp, 0);
                return ret_err(EINVAL);
            }
            {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) != 0) {
                    fork_dbg(cur, -2, "EINVAL mark-rip", (unsigned long long)begin,
                        (unsigned long long)end, 0);
                    return ret_err(EINVAL);
                }
            }
            fork_dbg(cur, 2, "mark-rip ok", saved_rcx, saved_rsp, 0);
            (void)thread_reap_unwaited_zombies();
            char child_name[32];
            snprintf(child_name, sizeof(child_name), "%s.child", cur->name);
            thread_t *child = thread_create_blocked(fork_child_return_entry, child_name);
            if (!child) {
                int z = thread_reap_unwaited_zombies();
                child = thread_create_blocked(fork_child_return_entry, child_name);
                if (!child) {
                    fork_dbg(cur, -3, "ENOMEM thread",
                        (unsigned long long)thread_get_count(),
                        (unsigned long long)heap_free_bytes(),
                        (unsigned long long)z);
                    return ret_err(ENOMEM);
                }
            }
            fork_dbg(cur, 3, "child created",
                (unsigned long long)(child->tid ? child->tid : 0), 0, 0);
            child->vfork_parent_tid = -1;
            if (child->mm) mm_release(child->mm);
            child->mm = mm_clone_current();
            if (!child->mm) {
                fork_dbg(cur, -4, "ENOMEM mm", 0, 0, 0);
                fork_stop_child(child);
                return ret_err(ENOMEM);
            }
            fork_dbg(cur, 15, "mm-clone",
                (unsigned long long)(child->mm->cr3 ? child->mm->cr3 : 0),
                (unsigned long long)heap_free_bytes(),
                (unsigned long long)heap_largest_free());
            mm_t *parent_mm = cur->mm ? cur->mm : mm_kernel();
            uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(cur->tid ? cur->tid : 1);
            uintptr_t parent_slot_lo = (parent_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
            if (cur->user_stack_limit > cur->user_stack_base &&
                cur->user_stack_base >= 0x200000u &&
                saved_rsp >= cur->user_stack_base &&
                saved_rsp < cur->user_stack_limit) {
                parent_stack_top = (uintptr_t)cur->user_stack_limit;
                parent_slot_lo = (uintptr_t)cur->user_stack_base;
            }
            enum { FORK_STACK_COPY_MAX = 65536u };
            uintptr_t used_tail = 0;
            if (parent_stack_top > (uintptr_t)saved_rsp)
                used_tail = parent_stack_top - (uintptr_t)saved_rsp;
            if (used_tail == 0) used_tail = 8192;
            if (used_tail < 8192) used_tail = 8192;
            uintptr_t max_copy = (uintptr_t)FORK_STACK_COPY_MAX;
            if (used_tail < max_copy) max_copy = used_tail;
            uintptr_t copy_bytes = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
            if (copy_bytes > max_copy) copy_bytes = max_copy;
            if (copy_bytes < 256) {
                fork_dbg(cur, -5, "EINVAL copy", (unsigned long long)copy_bytes,
                    (unsigned long long)saved_rsp, 0);
                fork_stop_child(child);
                return ret_err(EINVAL);
            }
            /* Linux-like fork: child keeps the same stack VA as the parent (mm_clone + COW).
               Relocating the stack into another per-tid slot breaks frame chains (RBP/RSP)
               and mm_clear_range_private unmaps the parent stack in the child CR3. */
            uintptr_t child_rsp = (uintptr_t)saved_rsp;
            uintptr_t child_stack_top = parent_stack_top;
            uintptr_t child_slot_lo = parent_slot_lo;
            fork_dbg(cur, 4, "stack same-va",
                (unsigned long long)copy_bytes,
                (unsigned long long)child_rsp,
                (unsigned long long)parent_stack_top);
            {
                mm_switch(child->mm);
                if (mark_user_identity_range_2m_sys((uint64_t)parent_slot_lo,
                        (uint64_t)parent_stack_top) != 0) {
                    mm_switch(parent_mm);
                    fork_dbg(cur, -6, "EFAULT stack",
                        (unsigned long long)parent_slot_lo,
                        (unsigned long long)parent_stack_top, 0);
                    fork_stop_child(child);
                    return ret_err(EFAULT);
                }
                {
                    unsigned copied = 0;
                    unsigned max_cow = 48u;
                    if (heap_free_bytes() < (4u << 20))
                        max_cow = 12u;
                    uintptr_t cow_lo = (uintptr_t)saved_rsp;
                    if (cow_lo > 0x20000u) cow_lo -= 0x20000u;
                    else cow_lo = parent_slot_lo;
                    if (cow_lo < parent_slot_lo) cow_lo = parent_slot_lo;
                    (void)mm_cow_fork_pages(child->mm, parent_mm->pml4,
                        (uint64_t)cow_lo, (uint64_t)parent_stack_top, max_cow, &copied);
                    (void)mm_cow_private_writable(child->mm, (uint64_t)cow_lo,
                        (uint64_t)parent_stack_top);
                    fork_dbg(cur, 69, "stack-cow",
                        (unsigned long long)copied,
                        (unsigned long long)cow_lo,
                        (unsigned long long)parent_stack_top);
                }
                mm_switch(parent_mm);
            }
            fork_dbg(cur, 5, "mark-stack ok", 0, 0, 0);
            fork_dbg(cur, 6, "stack shared ok", 0, 0, 0);
            {
                uint64_t parent_fs_base = cur->user_fs_base;
                uintptr_t parent_tls_region = 0, parent_fs = 0, parent_pthread_fake = 0;
                uintptr_t child_tls_region = 0, child_fs = 0, child_pthread_fake = 0;
                fork_tls_layout_for_tid(cur->tid ? cur->tid : 1, parent_stack_top,
                    &parent_tls_region, &parent_fs, &parent_pthread_fake);
                fork_tls_layout_for_tid(child->tid ? child->tid : 1, child_stack_top,
                    &child_tls_region, &child_fs, &child_pthread_fake);
                mm_switch(child->mm);
                if (fork_should_keep_parent_fs(parent_fs_base)) {
                    /* Keep the same FS base VA as parent (glibc expects this after fork). */
                    child->user_fs_base = parent_fs_base;
                    const uint64_t lo = (parent_fs_base >= 0x3000ULL) ? (parent_fs_base - 0x3000ULL) : 0x200000ULL;
                    const uint64_t hi = parent_fs_base + 0x3000ULL;
                    (void)mark_user_identity_range_2m_sys(lo, hi);
                    (void)user_map_ensure_present_us_2m(lo, hi);
                    {
                        uint64_t tcb_self = 0;
                        if (user_read_u64((const void *)(uintptr_t)(parent_fs_base - 0x78u), &tcb_self) == 0)
                            fork_dbg(cur, 66, "tls keep",
                                (unsigned long long)parent_fs_base,
                                (unsigned long long)tcb_self,
                                0);
                        else
                            fork_dbg(cur, 66, "tls keep",
                                (unsigned long long)parent_fs_base,
                                (unsigned long long)-1,
                                0);
                    }
                } else {
                    /* Fallback: per-slot minimal TLS (exec-style). */
                    if (mm_make_private_range(child->mm, (uint64_t)child_tls_region,
                            (uint64_t)(child_pthread_fake + 0x1000u), 0, parent_mm) != 0) {
                        fork_dbg(cur, -7, "WARN tls priv",
                            (unsigned long long)heap_free_bytes(),
                            (unsigned long long)heap_largest_free(), 0);
                    }
                    if (mark_user_identity_range_2m_sys((uint64_t)child_tls_region,
                            (uint64_t)(child_pthread_fake + 0x1000u)) == 0) {
                        (void)user_map_ensure_present_us_2m((uint64_t)child_tls_region,
                            (uint64_t)(child_pthread_fake + 0x1000u));
                        (void)fork_copy_parent_tls(child_tls_region, parent_tls_region, child->mm, parent_mm);
                        fork_seed_glibc_tls(child_tls_region, child_fs, child_pthread_fake);
                        child->user_fs_base = (uint64_t)child_fs;
                        {
                            uint64_t tcb_self = 0;
                            if (user_read_u64((const void *)(uintptr_t)(child_fs - 0x78u), &tcb_self) == 0)
                                fork_dbg(cur, 66, "tls ok",
                                    (unsigned long long)child_tls_region,
                                    (unsigned long long)child_fs,
                                    (unsigned long long)tcb_self);
                            else
                                fork_dbg(cur, 66, "tls ok",
                                    (unsigned long long)child_tls_region,
                                    (unsigned long long)child_fs,
                                    (unsigned long long)-1);
                        }
                    } else {
                        fork_dbg(cur, -7, "WARN skip tls",
                            (unsigned long long)child_tls_region, 0, 0);
                        child->user_fs_base = parent_fs_base;
                    }
                }
                mm_switch(parent_mm);
            }
            child->user_brk_base = cur->user_brk_base;
            child->user_brk_cur = cur->user_brk_cur;
            if (cur->user_mmap_next) child->user_mmap_next = cur->user_mmap_next;
            child->user_mmap_hi = cur->user_mmap_hi;
            {
                uintptr_t stack_end = parent_stack_top;
                uintptr_t min_next = user_mm_align_up(stack_end, (uintptr_t)PAGE_SIZE_2M);
                if (cur->user_mmap_next < min_next)
                    cur->user_mmap_next = min_next;
            }
            child->user_stack_base = cur->user_stack_base ? cur->user_stack_base : (uint64_t)parent_slot_lo;
            child->user_stack_limit = cur->user_stack_limit ? cur->user_stack_limit : (uint64_t)parent_stack_top;
            child->ring = 3;
            (void)fork_privatize_child_mm(child, cur, cur);
            (void)user_vma_fork_privatize_mapped(child->mm,
                    (uint64_t)(cur->tid ? cur->tid : 1));
            fork_dbg(cur, 14, "vma-cow done", 0, 0, 0);
            (void)user_vma_clone_for_tid((uint64_t)(cur->tid ? cur->tid : 1),
                    (uint64_t)(child->tid ? child->tid : 1));
            /* Re-seed TLS only when we did not keep the parent's FS/TCB VA. */
            if (!fork_should_keep_parent_fs(cur->user_fs_base)) {
                uintptr_t ct = 0, cfs = 0, cpf = 0;
                fork_tls_layout_for_tid(child->tid ? child->tid : 1, child_stack_top, &ct, &cfs, &cpf);
                mm_switch(child->mm);
                fork_seed_glibc_tls(ct, cfs, cpf);
                mm_switch(parent_mm);
            }
            child->saved_user_r15 = cur->saved_user_r15;
            child->saved_user_r14 = cur->saved_user_r14;
            child->saved_user_r13 = cur->saved_user_r13;
            child->saved_user_r12 = cur->saved_user_r12;
            child->saved_user_r11 = cur->saved_user_r11;
            child->saved_user_r10 = cur->saved_user_r10;
            child->saved_user_r9 = cur->saved_user_r9;
            child->saved_user_r8 = cur->saved_user_r8;
            child->saved_user_rdi = cur->saved_user_rdi;
            child->saved_user_rsi = cur->saved_user_rsi;
            child->saved_user_rbp = cur->saved_user_rbp;
            child->saved_user_rbx = cur->saved_user_rbx;
            child->saved_user_rdx = cur->saved_user_rdx;
            child->saved_user_rcx = saved_rcx;
            child->saved_user_rip = saved_rcx;
            child->saved_user_rsp = (uint64_t)child_rsp;
            child->user_rip = saved_rcx;
            child->user_stack = (uint64_t)child_rsp;
            fork_dbg(cur, 7, "tramp ready",
                (unsigned long long)child->user_rip,
                (unsigned long long)child->user_stack,
                (unsigned long long)saved_rcx);
            if (child->mm_ptemplate) mm_release(child->mm_ptemplate);
            child->mm_ptemplate = mm_retain(cur->mm);
            child->uid = cur->uid;
            child->euid = cur->euid;
            child->suid = cur->suid;
            child->gid = cur->gid;
            child->egid = cur->egid;
            child->sgid = cur->sgid;
            child->attached_tty = cur->attached_tty;
            child->parent_tid = (int)(cur->tid ? cur->tid : 1);
            child->clear_child_tid = 0;
            child->sid = cur->sid;
            child->pgid = cur->pgid;
            strncpy(child->cwd, cur->cwd, sizeof(child->cwd) - 1);
            child->cwd[sizeof(child->cwd) - 1] = '\0';
            fork_inherit_fd_table(child, cur);
            /* Defer child run until parent leaves syscall (shared per-CPU syscall stack). */
            cur->defer_unblock_tid = (int)(child->tid ? child->tid : 1);
            rebuild_syscall_frame(cur);
            fork_dbg(cur, 8, "unblocked child",
                (unsigned long long)(child->tid ? child->tid : 0), 0, 0);
            fork_dbg(cur, 9, "return pid",
                (unsigned long long)(child->tid ? child->tid : 0), 0, 0);
            return (uint64_t)(child->tid ? child->tid : 1);
        }
        case SYS_wait4: {
            /* waitpid(pid, status*, options, rusage*) minimal implementation
               - pid > 0: wait for specific child pid
               - pid == -1: wait for any child
               We only support blocking wait (options == 0) and ignore rusage.
               Use sc_a* (not a1/a2/a3 locals): another thread's syscall reuses the
               per-CPU syscall kernel stack and clobbers syscall_do_inner's C frame. */
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            if (!tcur) return ret_err(EINVAL);
            (void)a4;
            /* Support WNOHANG (1), WUNTRACED (2), WCONTINUED (8) as no-ops. */
            enum { WNOHANG = 1, WUNTRACED = 2, WCONTINUED = 8 };
            if (((int)tcur->sc_a3) & ~(WNOHANG | WUNTRACED | WCONTINUED)) return ret_err(ENOSYS);

            for (;;) {
                tcur = thread_get_current_user();
                if (!tcur) tcur = thread_current();
                if (!tcur) return ret_err(EINVAL);
                thread_t *found = NULL;
                int has_waitable_child = 0;
                int w4_pid = (int)tcur->sc_a1;
                if (w4_pid > 0) {
                    thread_t *c = thread_get(w4_pid);
                    if (c && c->parent_tid == (int)tcur->tid) {
                        found = c;
                        has_waitable_child = 1;
                    }
                } else if (w4_pid == -1) {
                    /* waitpid(-1) waits for any child. Do not bind the wait to the
                       first live child: init may have multiple gettys and must wake
                       for whichever one exits first. */
                    for (int i = 0; i < thread_get_count(); i++) {
                        thread_t *c = thread_get_by_index(i);
                        if (!c) continue;
                        if (c->parent_tid != (int)tcur->tid) continue;
                        if (c->state == THREAD_TERMINATED && c->exit_status == 0x80000000) continue; /* already reaped */
                        has_waitable_child = 1;
                        if (c->state != THREAD_TERMINATED) continue;
                        if (c->exit_status == 0x80000000) continue; /* already reaped */
                        found = c;
                        break;
                    }
                } else {
                    return ret_err(EINVAL);
                }
                if (!found) {
                    /* Init fallback: if we somehow lost parent linkage, still reap any terminated child. */
                    if (w4_pid == -1 && is_init_user(tcur)) {
                        for (int i = 0; i < thread_get_count(); i++) {
                            thread_t *c = thread_get_by_index(i);
                            if (!c) continue;
                            if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
                                found = c;
                                break;
                            }
                        }
                    }
                    if (!found && !has_waitable_child) {
                        if ((int)tcur->sc_a3 & WNOHANG) {
                            thread_sleep(1);
                            return 0;
                        }
                        return ret_err(ECHILD);
                    }
                    if (!found) {
                        if ((int)tcur->sc_a3 & WNOHANG) {
                            thread_sleep(1);
                            return 0;
                        }
                        thread_yield();
                        continue;
                    }
                }
                /* Trace selection for debugging hangs (limited by global trace budget anyway). */
                if (g_syscall_trace_on && g_syscall_trace_budget > 0 && is_watch_proc(tcur)) {
                    qemu_debug_printf("wait4: parent=%llu name=%s pid_arg=%d -> child=%llu state=%d exit_status=0x%x reaped=%d\n",
                        (unsigned long long)(tcur->tid ? tcur->tid : 1),
                        (tcur->name[0] ? tcur->name : "(noname)"),
                        w4_pid,
                        (unsigned long long)(found->tid ? found->tid : 1),
                        (int)found->state,
                        (unsigned)found->exit_status,
                        (found->exit_status == 0x80000000));
                }
                /* If child was already reaped, behave like Linux: ECHILD */
                if (found->state == THREAD_TERMINATED && found->exit_status == 0x80000000) {
                    if ((int)tcur->sc_a3 & WNOHANG) {
                        thread_sleep(1);
                        return 0;
                    }
                    return ret_err(ECHILD);
                }
                /* If already terminated -> return immediately */
                if (found->state == THREAD_TERMINATED && found->exit_status != 0x80000000) {
                    int st = found->exit_status;
                    int dead_pid = (int)(found->tid ? found->tid : 1);
                    if (tcur->sc_a2) {
                        int *status_u = (int *)(uintptr_t)tcur->sc_a2;
                        if (copy_to_user_safe(status_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
                    }
                    /* mark reaped */
                    found->exit_status = 0x80000000;
                    /* free slot/resources so fork doesn't hit MAX_THREADS */
                    {
                        extern int thread_reap(int pid);
                        (void)thread_reap(dead_pid);
                    }
                    return (uint64_t)dead_pid;
                }
                /* not terminated -> WNOHANG returns immediately */
                if ((int)tcur->sc_a3 & WNOHANG) {
                    thread_sleep(1);
                    return 0;
                }
                /* waitpid(pid>0): wait for that specific child. */
                found->waiter_tid = (int)(tcur->tid ? tcur->tid : 1);
                qemu_debug_printf("wait4: block parent=%llu name=%s child=%llu child_state=%d\n",
                    (unsigned long long)(tcur->tid ? tcur->tid : 1),
                    (tcur->name[0] ? tcur->name : "(noname)"),
                    (unsigned long long)(found->tid ? found->tid : 1),
                    (int)found->state);
                /* Linux-like: stay in syscall (RUNNING), yield so child can run/exit.
                   Do NOT thread_block+thread_schedule here: that resumes via context_switch
                   while syscall_do C stack / entry frame get out of sync. */
                thread_yield();
                /* when child exits, loop to check again */
            }
            return ret_err(EINVAL);
        }
        case SYS_ioctl: {
            int fd = (int)a1;
            uint64_t req = a2;
            void *argp = (void*)(uintptr_t)a3;
            /* Map negative fds to fd 0 (controlling/stdin) to be tolerant of libc behavior. */
            if (fd < 0) {
                fd = 0;
            }
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            /* Common ioctl numbers on Linux x86_64 */
            enum {
                TCGETS    = 0x5401,
                TCSETS    = 0x5402,
                TCSETSW   = 0x5403,
                TCSETSF   = 0x5404,
                TCFLSH    = 0x540B, /* tcflush(3): arg is TCIFLUSH/TCOFLUSH/TCIOFLUSH */
                TIOCSTI   = 0x5412, /* inject byte into tty input queue (terminal ioctls) */
                TIOCGSID  = 0x5429, /* tcgetsid(3) */
                TIOCNOTTY = 0x5423, /* drop controlling tty (getty after setsid) */
                TIOCSCTTY = 0x540E,
                TIOCGPGRP = 0x540F,
                TIOCSPGRP = 0x5410,
                TIOCGWINSZ= 0x5413,
                TIOCSWINSZ= 0x5414,
                TIOCMGET  = 0x5415,
                TIOCMBIS  = 0x5416,
                TIOCMBIC  = 0x5417,
                /* Linux block ioctls commonly used by mkfs/mount utilities */
                BLKGETSIZE   = 0x1260,       /* get device size in 512-byte sectors (unsigned long*) */
                BLKSSZGET    = 0x1268,       /* get logical sector size (int*) */
                BLKBSZGET    = 0x80081270,   /* get block size (int*) */
                BLKGETSIZE64 = 0x80081272,   /* get device size in bytes (uint64_t*) */
                FIONREAD  = 0x541B,
                FIONBIO   = 0x5421,
            };

            /* no ioctl tracing in release builds */

            /* Kernel ABI structs (minimal) */
            struct winsize { uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel; };
            typedef uint32_t tcflag_t;
            typedef uint8_t  cc_t;
            typedef uint32_t speed_t;
            struct termios_k {
                tcflag_t c_iflag;
                tcflag_t c_oflag;
                tcflag_t c_cflag;
                tcflag_t c_lflag;
                cc_t c_line;
                cc_t c_cc[19];
                speed_t c_ispeed;
                speed_t c_ospeed;
            };

            /* usbdevfs subset for /dev/bus/usb/BBB/DDD */
            if (usb_is_devfs_file(f)) {
                const usb_device_t *cd = usb_device_from_file(f);
                usb_device_t *dev = (usb_device_t *)cd;
                if (!dev) return ret_err(ENOENT);

                if (req == USBDEVFS_CLAIMINTERFACE || req == USBDEVFS_RELEASEINTERFACE) {
                    if (!argp) return ret_err(EFAULT);
                    int ifnum = 0;
                    if (copy_from_user_raw(&ifnum, argp, sizeof(ifnum)) != 0) return ret_err(EFAULT);
                    int rc = (req == USBDEVFS_CLAIMINTERFACE) ? usb_claim_interface(dev, ifnum)
                                                               : usb_release_interface(dev, ifnum);
                    return (rc == 0) ? 0 : ret_err(EINVAL);
                }
                if (req == USBDEVFS_RESET) {
                    return (usb_reset_device(dev) == 0) ? 0 : ret_err(EIO);
                }
                if (req == USBDEVFS_CONTROL) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_ctrltransfer_t))) return ret_err(EFAULT);
                    usbdevfs_ctrltransfer_t ctl;
                    if (copy_from_user_raw(&ctl, argp, sizeof(ctl)) != 0) return ret_err(EFAULT);
                    if (ctl.wLength > 4096) return ret_err(EINVAL);
                    void *kbuf = NULL;
                    if (ctl.wLength > 0) {
                        if (!ctl.data || !user_range_ok(ctl.data, ctl.wLength)) return ret_err(EFAULT);
                        kbuf = kmalloc(ctl.wLength);
                        if (!kbuf) return ret_err(ENOMEM);
                        if ((ctl.bRequestType & 0x80) == 0) {
                            if (copy_from_user_raw(kbuf, ctl.data, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                        } else {
                            memset(kbuf, 0, ctl.wLength);
                        }
                    }
                    usb_setup_packet_t s;
                    s.bmRequestType = ctl.bRequestType;
                    s.bRequest = ctl.bRequest;
                    s.wValue = ctl.wValue;
                    s.wIndex = ctl.wIndex;
                    s.wLength = ctl.wLength;
                    int rc = usb_control_transfer(dev, &s, kbuf, ctl.wLength, ctl.timeout ? ctl.timeout : 1000);
                    if (rc >= 0 && (ctl.bRequestType & 0x80) && ctl.wLength > 0) {
                        if (copy_to_user_safe(ctl.data, kbuf, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                if (req == USBDEVFS_BULK) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_bulktransfer_t))) return ret_err(EFAULT);
                    usbdevfs_bulktransfer_t b;
                    if (copy_from_user_raw(&b, argp, sizeof(b)) != 0) return ret_err(EFAULT);
                    if (b.len > 65536u) return ret_err(EINVAL);
                    if (b.len > 0 && (!b.data || !user_range_ok(b.data, b.len))) return ret_err(EFAULT);
                    void *kbuf = NULL;
                    if (b.len > 0) {
                        kbuf = kmalloc(b.len);
                        if (!kbuf) return ret_err(ENOMEM);
                    }
                    int is_in = (b.ep & 0x80u) ? 1 : 0;
                    if (!is_in && b.len > 0) {
                        if (copy_from_user_raw(kbuf, b.data, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    int rc = usb_bulk_transfer(dev, (uint8_t)(b.ep & 0x0Fu), is_in, kbuf, b.len, b.timeout ? b.timeout : 1000);
                    if (rc >= 0 && is_in && b.len > 0) {
                        if (copy_to_user_safe(b.data, kbuf, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                return ret_err(ENOTTY);
            }

            /* Block-device ioctls for /dev/sdX,/dev/hdX (needed by mkfs.vfat and friends). */
            if (req == BLKSSZGET || req == BLKBSZGET || req == BLKGETSIZE || req == BLKGETSIZE64) {
                if (!argp) return ret_err(EFAULT);
                if (!f->path || devfs_get_device_id(f->path) < 0) return ret_err(ENOTTY);
                uint64_t bytes = (uint64_t)f->size;
                if (req == BLKSSZGET || req == BLKBSZGET) {
                    int v = 512;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                if (req == BLKGETSIZE64) {
                    uint64_t v = bytes;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* BLKGETSIZE -> number of 512-byte sectors (unsigned long on x86_64) */
                {
                    uint64_t sectors = bytes / 512u;
                    if (copy_to_user_safe(argp, &sectors, sizeof(sectors)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* Important: libc frequently probes terminal state on stdout/stderr very early
               (e.g. ld.lld does ioctl(TCGETS) on fd=2). Do NOT require tty classification
               for these "query" ioctls; return sensible defaults even if the fd isn't a tty.
               This avoids hangs if a file->path pointer is corrupted and devfs_is_tty_file()
               would fault while doing strcmp(). */
            if (req == TIOCGWINSZ) {
                if (!argp) return ret_err(EFAULT);
                uint16_t rows = (uint16_t)console_max_rows();
                uint16_t cols = (uint16_t)console_max_cols();
                if (rows == 0) rows = 25;
                if (cols == 0) cols = 80;
                struct winsize ws = { .ws_row = rows,
                                      .ws_col = cols,
                                      .ws_xpixel = 0,
                                      .ws_ypixel = 0 };
                if (copy_to_user_safe(argp, &ws, sizeof(ws)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSWINSZ) {
                if (!argp)  return ret_err(EFAULT); /* accept setting window size silently */
                /* optionally we could copy_from_user and store winsize, but accept for now */
                return 0;
            }
            if (req == TIOCSCTTY) {
                /* Attach this thread to the tty as controlling tty. Allow when tty is free
                   so getty (launched by init, often not session leader) can acquire the console. */
                thread_t *curth = thread_current();
                if (!curth) return 0;
                int cur_sid = devfs_get_tty_controlling_sid(f);
                if (cur_sid >= 0 && cur_sid != curth->sid) return ret_err(EPERM);
                devfs_tty_attach_thread(f, curth);
                devfs_set_tty_controlling_sid(f, curth->sid);
                {
                    int tty_idx = devfs_get_tty_index_from_file(f);
                    if (tty_idx >= 0 && curth->pgid >= 0)
                        devfs_set_tty_fg_pgrp(tty_idx, curth->pgid);
                }
                return 0;
            }
            if (req == TIOCGPGRP) {
                if (!argp) return ret_err(EFAULT);
                /* Try to return tty-specific foreground pgrp, fallback to global user_pgrp */
                int pgrp = devfs_tty_get_fg_pgrp(f);
                if (pgrp < 0) pgrp = (int)(user_pgrp);
                uint32_t pu = (uint32_t)pgrp;
                if (copy_to_user_safe(argp, &pu, sizeof(pu)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSPGRP) {
                if (!argp) return ret_err(EFAULT);
                uint32_t p = 0;
                if (copy_from_user_raw(&p, argp, sizeof(p)) != 0) return ret_err(EFAULT);
                /* Be permissive: allow any pgrp for now to avoid shells exiting
                   due to strict job-control checks in this minimal tty model. */
                /* Try to set tty-specific foreground pgrp; fall back to global user_pgrp */
                if (devfs_tty_set_fg_pgrp(f, (int)p) != 0) {
                    if (p != 0) user_pgrp = (uint64_t)p;
                }
                return 0;
            }
            if (req == TCFLSH) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                (void)tty_idx;
                (void)argp;
                return 0;
            }
            if (req == TIOCNOTTY) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                thread_t *ct = thread_current();
                if (ct) {
                    int tty_idx = devfs_get_tty_index_from_file(f);
                    if (tty_idx >= 0 && ct->attached_tty == tty_idx)
                        ct->attached_tty = -1;
                    if (tty_idx >= 0 && devfs_get_tty_by_index(tty_idx) &&
                        devfs_get_tty_by_index(tty_idx)->controlling_sid == ct->sid)
                        devfs_get_tty_by_index(tty_idx)->controlling_sid = -1;
                }
                return 0;
            }
            if (req == TIOCGSID) {
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                thread_t *ct = thread_current();
                int sid = (ct && ct->sid >= 0) ? ct->sid : 0;
                if (copy_to_user_safe(argp, &sid, sizeof(sid)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCMGET) {
                if (!argp) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                /* Virtual consoles: report carrier present so getty proceeds without -L. */
                int bits = (int)(0x40u | 0x100u | 0x04u); /* CAR|DSR|LE */
                if (copy_to_user_safe(argp, &bits, sizeof(bits)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCMBIS || req == TIOCMBIC) {
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                return 0;
            }
            if (req == TCGETS) {
                if (!argp) return ret_err(EFAULT);
                struct termios_k tio;
                memset(&tio, 0, sizeof(tio));
                tio.c_iflag = 0x00000100u /* ICRNL */;
                tio.c_oflag = 0x00000001u /* OPOST */;
                tio.c_cflag = 0x00000CB7u; /* CS8|CREAD|CLOCAL */
                tio.c_lflag = 0x00000002u /* ICANON */ | 0x00000008u /* ECHO */ | 0x00000001u /* ISIG */;
                if (devfs_is_tty_file(f)) {
                    struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_tty_index_from_file(f));
                    if (tty) {
                        tio.c_lflag = tty->term_lflag;
                        tio.c_cc[5] = tty->term_vtime;
                        tio.c_cc[6] = tty->term_vmin;
                    }
                }
                tio.c_ispeed = 9600;
                tio.c_ospeed = 9600;
                /* Never copy full struct termios to userspace: NCCS differs (BusyBox vs glibc)
                 * and a 60-byte write clobbers the stack canary -> "stack smashing detected". */
                size_t safe_sz = 32;
                if (safe_sz > sizeof(tio)) safe_sz = sizeof(tio);
                if (copy_to_user_safe(argp, &tio, safe_sz) != 0) return ret_err(EFAULT);
                return 0;
            }

            /* Socket ioctls often used by wget/getaddrinfo paths. */
            if (f->type == SYSCALL_FTYPE_SOCKET) {
                if (req == FIONBIO) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    uint32_t on = 0;
                    if (copy_from_user_raw(&on, argp, sizeof(on)) != 0) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    if (s) s->nonblock = on ? 1 : 0;
                    return 0;
                }
                if (req == FIONREAD) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    uint32_t nb = 0;
                    if (s) {
                        if (s->sock_domain == AF_NETLINK_LOCAL) {
                            if (s->nl_rx_off < s->nl_rx_len)
                                nb = (uint32_t)(s->nl_rx_len - s->nl_rx_off);
                        } else if (s->unix_domain_stub && s->connected) {
                            size_t a = unix_stream_avail_to_read(s);
                            if (a > 0xFFFFFFFFu) a = 0xFFFFFFFFu;
                            nb = (uint32_t)a;
                        } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL &&
                                   s->dns_tcp_udp_bridge) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                            nb = (s->tcp.rx_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)s->tcp.rx_len;
                        }
                    }
                    if (copy_to_user_safe(argp, &nb, sizeof(nb)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* Network interface ioctls (SIOCxxx) - used by ip, ifconfig, etc. */
                enum {
                    SIOCGIFNAME    = 0x8910,
                    SIOCGIFCONF    = 0x8912,
                    SIOCGIFFLAGS   = 0x8913,
                    SIOCSIFFLAGS   = 0x8914,
                    SIOCGIFADDR    = 0x8915,
                    SIOCSIFADDR    = 0x8916,
                    SIOCGIFDSTADDR = 0x8917,
                    SIOCSIFDSTADDR = 0x8918,
                    SIOCGIFBRDADDR = 0x8919,
                    SIOCSIFBRDADDR = 0x891A,
                    SIOCGIFNETMASK = 0x891B,
                    SIOCSIFNETMASK = 0x891C,
                    SIOCGIFMETRIC  = 0x891D,
                    SIOCSIFMETRIC  = 0x891E,
                    SIOCGIFMTU     = 0x8921,
                    SIOCSIFMTU     = 0x8922,
                    SIOCGIFHWADDR  = 0x8927,
                    SIOCSIFHWADDR  = 0x8928,
                    SIOCGIFINDEX   = 0x8933,
                    SIOCGIFTXQLEN  = 0x8942,
                    SIOCSIFTXQLEN  = 0x8943,
                };
                /* struct ifreq layout (Linux x86_64):
                   char ifr_name[16];
                   union { sockaddr, int, ... } ifr_ifru; (16 bytes typically)
                   Total: 32-40 bytes depending on union member */
                struct ifreq_k {
                    char ifr_name[16];
                    union {
                        struct { uint16_t sa_family; char sa_data[14]; } ifr_addr;
                        struct { uint16_t sa_family; uint8_t sa_data[14]; } ifr_hwaddr;
                        int16_t ifr_flags;
                        int32_t ifr_ifindex;
                        int32_t ifr_metric;
                        int32_t ifr_mtu;
                        int32_t ifr_qlen;
                    };
                };
                /* Check if this is a network interface ioctl */
                if (req == SIOCGIFNAME || req == SIOCGIFINDEX || req == SIOCGIFFLAGS ||
                    req == SIOCGIFADDR || req == SIOCGIFNETMASK || req == SIOCGIFBRDADDR ||
                    req == SIOCGIFHWADDR || req == SIOCGIFMTU || req == SIOCGIFTXQLEN ||
                    req == SIOCGIFMETRIC || req == SIOCGIFDSTADDR ||
                    req == SIOCSIFFLAGS || req == SIOCSIFADDR || req == SIOCSIFNETMASK ||
                    req == SIOCSIFMTU || req == SIOCSIFTXQLEN) {
                    if (!argp || !user_range_ok(argp, sizeof(struct ifreq_k))) return ret_err(EFAULT);
                    struct ifreq_k ifr;
                    memset(&ifr, 0, sizeof(ifr));
                    if (copy_from_user_raw(&ifr, argp, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    /* Determine which interface: lo (index 1) or eth0 (index 2) */
                    int is_lo = 0, is_eth0 = 0;
                    if (strcmp(ifr.ifr_name, "lo") == 0) is_lo = 1;
                    else if (strcmp(ifr.ifr_name, "eth0") == 0 || ifr.ifr_name[0] == '\0') is_eth0 = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 1) is_lo = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 2) is_eth0 = 1;
                    if (!is_lo && !is_eth0) return ret_err(ENODEV);
                    /* Set interface name */
                    if (is_lo) strncpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name));
                    else strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name));
                    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
                    /* Handle specific requests */
                    if (req == SIOCGIFINDEX) {
                        ifr.ifr_ifindex = is_lo ? 1 : 2;
                    } else if (req == SIOCGIFNAME) {
                        /* ifr_name already set above */
                    } else if (req == SIOCGIFFLAGS) {
                        if (is_lo) {
                            /* IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP */
                            ifr.ifr_flags = (int16_t)(0x1 | 0x8 | 0x40);
                        } else {
                            /* IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST */
                            ifr.ifr_flags = (int16_t)(0x1 | 0x2 | 0x40 | 0x1000);
                        }
                    } else if (req == SIOCSIFFLAGS) {
                        /* Accept but ignore - we're always up */
                    } else if (req == SIOCGIFADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t ip = is_lo ? 0x0100007Fu : g_net.ip_be; /* 127.0.0.1 for lo */
                        memcpy(ifr.ifr_addr.sa_data + 2, &ip, 4);
                    } else if (req == SIOCGIFNETMASK) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t mask = is_lo ? 0x000000FFu : g_net.mask_be; /* 255.0.0.0 for lo */
                        memcpy(ifr.ifr_addr.sa_data + 2, &mask, 4);
                    } else if (req == SIOCGIFBRDADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        if (is_lo) {
                            /* lo has no broadcast */
                            return ret_err(ENODEV);
                        }
                        uint32_t brd = (g_net.ip_be & g_net.mask_be) | ~g_net.mask_be;
                        memcpy(ifr.ifr_addr.sa_data + 2, &brd, 4);
                    } else if (req == SIOCGIFDSTADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t dst = is_lo ? 0x0100007Fu : g_net.gw_be;
                        memcpy(ifr.ifr_addr.sa_data + 2, &dst, 4);
                    } else if (req == SIOCGIFHWADDR) {
                        if (is_lo) {
                            ifr.ifr_hwaddr.sa_family = 772; /* ARPHRD_LOOPBACK */
                            memset(ifr.ifr_hwaddr.sa_data, 0, 6);
                        } else {
                            ifr.ifr_hwaddr.sa_family = 1; /* ARPHRD_ETHER */
                            memcpy(ifr.ifr_hwaddr.sa_data, g_net.mac, 6);
                        }
                    } else if (req == SIOCGIFMTU) {
                        ifr.ifr_mtu = is_lo ? 65536 : 1500;
                    } else if (req == SIOCSIFMTU) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFTXQLEN) {
                        ifr.ifr_qlen = is_lo ? 1000 : 1000; /* typical default */
                    } else if (req == SIOCSIFTXQLEN) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFMETRIC) {
                        ifr.ifr_metric = 0;
                    } else if (req == SIOCSIFADDR || req == SIOCSIFNETMASK) {
                        /* Accept but ignore - static config */
                    }
                    if (copy_to_user_safe(argp, &ifr, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* SIOCGIFCONF - list all interfaces */
                if (req == SIOCGIFCONF) {
                    if (!argp) return ret_err(EFAULT);
                    struct ifconf_k {
                        int32_t ifc_len;
                        int32_t __pad;
                        void *ifc_buf;
                    } ifc;
                    if (copy_from_user_raw(&ifc, argp, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    /* We have 2 interfaces: lo and eth0 */
                    struct ifreq_k entries[2];
                    memset(entries, 0, sizeof(entries));
                    /* lo */
                    strncpy(entries[0].ifr_name, "lo", sizeof(entries[0].ifr_name));
                    entries[0].ifr_addr.sa_family = AF_INET_LOCAL;
                    uint32_t lo_ip = 0x0100007Fu; /* 127.0.0.1 in big-endian */
                    memcpy(entries[0].ifr_addr.sa_data + 2, &lo_ip, 4);
                    /* eth0 */
                    strncpy(entries[1].ifr_name, "eth0", sizeof(entries[1].ifr_name));
                    entries[1].ifr_addr.sa_family = AF_INET_LOCAL;
                    memcpy(entries[1].ifr_addr.sa_data + 2, &g_net.ip_be, 4);
                    int32_t needed = (int32_t)(2 * sizeof(struct ifreq_k));
                    if (ifc.ifc_buf && ifc.ifc_len > 0) {
                        int32_t copy_len = (ifc.ifc_len < needed) ? ifc.ifc_len : needed;
                        if (user_range_ok(ifc.ifc_buf, (size_t)copy_len)) {
                            copy_to_user_safe(ifc.ifc_buf, entries, (size_t)copy_len);
                        }
                        ifc.ifc_len = copy_len;
                    } else {
                        ifc.ifc_len = needed;
                    }
                    if (copy_to_user_safe(argp, &ifc, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* KDGKBTYPE (0x4B33): get keyboard type. BusyBox chvt uses this to validate console fd. */
            if (req == 0x4B33) {
                if (argp && user_range_ok(argp, 1)) {
                    char kbd_type = 0; /* 0 = PC/XT style */
                    if (copy_to_user_safe(argp, &kbd_type, 1) == 0 && devfs_is_tty_file(f))
                        return 0;
                }
                return ret_err(ENOTTY);
            }

            /* For the remaining tty-specific ioctls, require a real tty file. */
            if (!devfs_is_tty_file(f)) {
                return ret_err(ENOTTY);
            }
            if (req == 0x5606) { /* VT_ACTIVATE: BusyBox passes vt as value; glibc may pass int* */
                int vt = -1;
                uintptr_t ua = (uintptr_t)argp;
                if (ua >= 1 && ua <= (uintptr_t)DEVFS_TTY_COUNT)
                    vt = (int)ua;
                else if (argp && user_range_ok(argp, sizeof(int))) {
                    if (copy_from_user_raw(&vt, argp, sizeof(vt)) != 0)
                        return ret_err(EFAULT);
                } else
                    return ret_err(EFAULT);
                if (vt >= 1 && vt <= DEVFS_TTY_COUNT) {
                    devfs_switch_tty(vt - 1);
                    return 0;
                }
                return ret_err(ENOTTY);
            }
            if (req == 0x5607) { /* VT_WAITACTIVE: VT_ACTIVATE is synchronous */
                (void)argp;
                return 0;
            }
            if (req == TCSETS || req == TCSETSW || req == TCSETSF) {
                if (!argp) return ret_err(EFAULT);
                struct termios_k tio;
                size_t need = 24; /* through c_cc[6] (VMIN); avoids libc-specific full struct sizes */
                if (copy_from_user_raw(&tio, argp, need) != 0) return ret_err(EFAULT);
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                struct devfs_tty *tty = devfs_get_tty_by_index(tty_idx);
                if (!tty) return ret_err(ENOTTY);
                tty->term_lflag = tio.c_lflag;
                tty->term_vtime = tio.c_cc[5];
                tty->term_vmin = tio.c_cc[6];
                return 0;
            }
            if (req == TIOCSTI) {
                /* Push one byte as if typed on the tty (used by some tools; input path is unchanged). */
                if (!argp) return ret_err(EFAULT);
                unsigned char cbyte;
                if (copy_from_user_raw(&cbyte, argp, 1) != 0) return ret_err(EFAULT);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                devfs_tty_push_input(tty_idx, (char)cbyte);
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_write: {
            int fd = (int)a1;
            const void *bufp = (const void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                ssize_t wr = net_sock_write_userspace(cur, fd, s, bufp, cnt);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }
            if (f->type == FS_TYPE_PIPE && f->fs_private == (void *)1) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                size_t copied = 0;
                void *tmp = copy_from_user_safe(bufp, cnt, PIPE_BUF_SIZE, &copied);
                if (!tmp) return ret_err(EFAULT);
                ssize_t wr = pipe_write_bytes(p, tmp, copied, cur);
                kfree(tmp);
                return (wr >= 0) ? (uint64_t)wr : ret_err((int)-wr);
            }
            size_t total = 0;
            while (total < cnt) {
                size_t chunk = cnt - total;
                if (chunk > 4096) chunk = 4096;
                size_t copied = 0;
                void *tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 4096, &copied);
                if (!tmp && chunk > 512) {
                    chunk = 512;
                    tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 512, &copied);
                }
                if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                ssize_t wr = fs_write(f, tmp, copied, f->pos);
                kfree(tmp);
                if (wr <= 0) return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                f->pos += (size_t)wr;
                total += (size_t)wr;
                if ((size_t)wr < copied) break;
            }
            return (uint64_t)total;
        }
        case SYS_readv: {
            /* readv(fd, const struct iovec *iov, int iovcnt) - scatter read */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t total = 0;
                for (int i = 0; i < iovcnt; i++) {
                    void *base = (void *)(uintptr_t)iov[i].base;
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                    size_t pos = 0;
                    while (pos < len) {
                        size_t chunk = len - pos;
                        if (chunk > 4096) chunk = 4096;
                        ssize_t rr = net_sock_read_userspace(cur, s, (uint8_t *)base + pos, chunk);
                        if (rr < 0) return (total > 0) ? total : ret_err((int)-rr);
                        if (rr == 0) return total;
                        total += (uint64_t)rr;
                        pos += (size_t)rr;
                    }
                }
                return total;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr;
                    if (f->type == FS_TYPE_PIPE && !f->fs_private && f->driver_private) {
                        rr = pipe_read_bytes((pipe_t *)f->driver_private, tmp, chunk, cur);
                    } else {
                        rr = fs_read(f, tmp, chunk, f->pos);
                    }
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err((int)-rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (rr > (ssize_t)chunk) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err(EIO);
                    }
                    if (copy_to_user_safe((uint8_t*)base + off, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)rr;
                    total += (uint64_t)rr;
                    off += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case SYS_preadv: {
            /* preadv(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 295 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t pos = 0;
                while (pos < len) {
                    size_t chunk = len - pos;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr = fs_read(f, tmp, chunk, cur_off);
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err((int)-rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (rr > (ssize_t)chunk) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err(EIO);
                    }
                    if (copy_to_user_safe((uint8_t*)base + pos, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    cur_off += (size_t)rr;
                    total += (uint64_t)rr;
                    pos += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case 17: { /* pread64(fd, buf, count, offset) */
            int fd = (int)a1;
            void *bufp = (void *)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (off_in < 0) return ret_err(EINVAL);
            if (cnt == 0) return 0;
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            /* pread on pipes/sockets is invalid (doesn't use/advance file position). */
            if (f->type == SYSCALL_FTYPE_SOCKET || f->type == FS_TYPE_PIPE) return ret_err(ESPIPE);
            if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            while ((size_t)total < cnt) {
                size_t chunk = cnt - (size_t)total;
                if (chunk > 4096) chunk = 4096;
                void *tmp = kmalloc(chunk);
                if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                ssize_t rr = fs_read(f, tmp, chunk, cur_off);
                if (rr < 0) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_err((int)-rr);
                }
                if (rr == 0) {
                    kfree(tmp);
                    return total;
                }
                if ((size_t)rr > chunk) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_err(EIO);
                }
                if (copy_to_user_safe((uint8_t *)bufp + total, tmp, (size_t)rr) != 0) {
                    kfree(tmp);
                    return (total > 0) ? total : ret_err(EFAULT);
                }
                kfree(tmp);
                total += (uint64_t)rr;
                cur_off += (size_t)rr;
                if ((size_t)rr < chunk) return total;
            }
            return total;
        }
        case 18: { /* pwrite64(fd, buf, count, offset) */
            int fd = (int)a1;
            const void *bufp = (const void *)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (off_in < 0) return ret_err(EINVAL);
            if (cnt == 0) return 0;
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET || f->type == FS_TYPE_PIPE) return ret_err(ESPIPE);
            if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            while ((size_t)total < cnt) {
                size_t chunk = cnt - (size_t)total;
                if (chunk > 4096) chunk = 4096;
                size_t copied = 0;
                void *tmp = copy_from_user_safe((const uint8_t *)bufp + total, chunk, 4096, &copied);
                if (!tmp) return (total > 0) ? total : ret_err(EFAULT);
                ssize_t wr = fs_write(f, tmp, copied, cur_off);
                kfree(tmp);
                if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                total += (uint64_t)wr;
                cur_off += (size_t)wr;
                if ((size_t)wr < copied) return total;
            }
            return total;
        }
        case SYS_read: {
            int fd = (int)a1;
            void *bufp = (void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ssize_t r = net_sock_read_userspace(cur, (ksock_net_t *)f->driver_private, bufp, cnt);
                if (r < 0) return ret_err((int)-r);
                return (uint64_t)r;
            }
            if (f->type == FS_TYPE_PIPE && !f->fs_private) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);
                size_t to_read = cnt < (size_t)PIPE_BUF_SIZE ? cnt : (size_t)PIPE_BUF_SIZE;
                void *tmp = kmalloc(to_read);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = pipe_read_bytes(p, tmp, to_read, cur);
                if (rr > 0) {
                    if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) { kfree(tmp); return ret_err(EFAULT); }
                }
                kfree(tmp);
                return (rr >= 0) ? (uint64_t)rr : ret_err((int)-rr);
            }
            if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);
            size_t to_read = cnt < 4096 ? cnt : 4096;
            void *tmp = kmalloc(to_read);
            if (!tmp) return ret_err(ENOMEM);
            ssize_t rr = fs_read(f, tmp, to_read, f->pos);

            if (rr > 0) {
                if (rr > (ssize_t)to_read) { kfree(tmp); return ret_err(EIO); }
                if (f->path && strcmp(f->path, "/etc/inittab") == 0) {
                    /* Normalize CRLF -> LF for busybox init parser. */
                    for (ssize_t i = 0; i < rr; i++) {
                        if (((char*)tmp)[i] == '\r') ((char*)tmp)[i] = '\n';
                    }
                    if (f->pos == 0) {
                        char preview[129];
                        size_t plen = (rr < 128) ? (size_t)rr : 128;
                        int has_nul = 0;
                        int has_respawn = 0;
                        int has_askfirst = 0;
                        int lines = 0;
                        for (size_t i = 0; i < plen; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\0') has_nul = 1;
                            if (c < 32 || c > 126) c = '.';
                            preview[i] = c;
                        }
                        preview[plen] = '\0';
                        for (ssize_t i = 0; i < rr; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\n') lines++;
                        }
                        if (rr >= 7) {
                            for (ssize_t i = 0; i + 7 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "respawn", 7) == 0) { has_respawn = 1; break; }
                            }
                        }
                        if (rr >= 8) {
                            for (ssize_t i = 0; i + 8 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "askfirst", 8) == 0) { has_askfirst = 1; break; }
                            }
                        }
                        {
                            char hex[3 * 32 + 1];
                            size_t hlen = (rr < 32) ? (size_t)rr : 32;
                            size_t w = 0;
                            for (size_t i = 0; i < hlen && w + 3 < sizeof(hex); i++) {
                                static const char *hx = "0123456789abcdef";
                                unsigned char b = (unsigned char)((char*)tmp)[i];
                                hex[w++] = hx[(b >> 4) & 0xF];
                                hex[w++] = hx[b & 0xF];
                                hex[w++] = ' ';
                            }
                            hex[w] = '\0';
                        }
                    }
                }
                if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) { kfree(tmp); return ret_err(EFAULT); }
                f->pos += (size_t)rr;
                kfree(tmp);
                return (uint64_t)rr;
            }
            if (f->path && strcmp(f->path, "/etc/inittab") == 0 && f->pos == 0) {
            }
            kfree(tmp);
            return (rr >= 0) ? (uint64_t)rr : ret_err((int)-rr);
        }
        case SYS_sendfile: {
            /* ssize_t sendfile(out_fd, in_fd, off_t *offset, size_t count) */
            int out_fd = (int)a1;
            int in_fd = (int)a2;
            off_t *offp = (off_t*)(uintptr_t)a3;
            size_t count = (size_t)a4;
            if (out_fd < 0 || out_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            if (in_fd < 0 || in_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            struct fs_file *fout = cur->fds[out_fd];
            struct fs_file *fin = cur->fds[in_fd];
            if (!fout || !fin) {
                return ret_err(EBADF);
            }
            /* Keep sendfile conservative: tty output is handled better via read/write fallback. */
            if (devfs_is_tty_file(fout)) {
                return ret_err(ENOSYS);
            }
            /* Only support regular file -> write and read via fs_read/fs_write */
            size_t total = 0;
            size_t tocopy = count;
            size_t bufcap = tocopy < 4096 ? tocopy : 4096;
            if (bufcap == 0) return 0;
            uint8_t *tmp = (uint8_t*)kmalloc(bufcap);
            if (!tmp) {
                return ret_err(ENOMEM);
            }
            off_t use_pos = -1;
            if (offp) {
                if (copy_from_user_raw(&use_pos, offp, sizeof(use_pos)) != 0) {
                    kfree(tmp);
                    return ret_err(EFAULT);
                }
            }
            while (tocopy > 0) {
                size_t chunk = tocopy < bufcap ? tocopy : bufcap;
                ssize_t rr;
                if (use_pos >= 0) {
                    rr = fs_read(fin, tmp, chunk, (size_t)use_pos);
                } else {
                    rr = fs_read(fin, tmp, chunk, fin->pos);
                }
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err(EINVAL);
                }
                if (rr == 0) break;
                if (rr > (ssize_t)chunk) {
                    kfree(tmp);
                    return (total > 0) ? (uint64_t)total : ret_err(EIO);
                }
                /* write to fout at its current position */
                ssize_t wr = fs_write(fout, tmp, (size_t)rr, fout->pos);
                if (wr <= 0) {
                    kfree(tmp);
                    return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                }
                if (use_pos >= 0) use_pos += (off_t)rr; else fin->pos += (size_t)rr;
                fout->pos += (size_t)wr;
                total += (size_t)wr;
                tocopy -= (size_t)rr;
                if ((size_t)rr < chunk) break;
            }
            kfree(tmp);
            if (offp) {
                if (copy_to_user_safe(offp, &use_pos, sizeof(use_pos)) != 0) return ret_err(EFAULT);
            }
            return (uint64_t)total;
        }
        case 271: /* ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask, size_t sigsetsize) */
        case SYS_poll: {
            /* int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) */
            const void *ufds = (const void*)(uintptr_t)a1;
            int nfds = (int)a2;
            int timeout;
            thread_t *tcur_poll_cfg = thread_get_current_user();
            if (!tcur_poll_cfg) tcur_poll_cfg = thread_current();
            int is_wget_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "wget")) ? 1 : 0;
            int is_apm_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "apm")) ? 1 : 0;
            int is_git_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "git")) ? 1 : 0;
            if (num == 271) {
                /* Minimal ppoll: ignore sigmask/sigsetsize, translate timespec->ms for poll(). */
                const void *tmo_u = (const void*)(uintptr_t)a3;
                timeout = -1; /* NULL timeout => infinite */
                if (tmo_u) {
                    struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                    if (copy_from_user_raw(&ts, tmo_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                    if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                    uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                    if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                    if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                    timeout = (int)ms;
                } else {
                    /* Cap NULL-timeout ppoll so userland can't block forever on network. */
                    if (is_wget_proc || is_apm_proc || is_git_proc) timeout = 1000;
                }
                } else {
                    timeout = (int)a3; /* milliseconds, -1 means infinite */
                    /* Some tools can block forever on network poll(-1); cap so process can progress. */
                    if (timeout < 0 && (is_wget_proc || is_apm_proc || is_git_proc)) timeout = 1000;
                }
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);
            volatile int elapsed = 0;
            uint64_t poll_t_start = 0;
            int poll_first_entry = 1;
            if (nfds == 0) {
                /* just wait for timeout */
                if (timeout <= 0) return 0;
                if (timeout < 0) {
                    /* block indefinitely but yield */
                    for (;;) { thread_sleep(10); }
                } else {
                    int waited = 0;
                    while (waited < timeout) { thread_sleep(10); waited += 10; }
                    return 0;
                }
            }
            size_t entry_size = 8; /* struct { int fd; short events; short revents; } */
            size_t bytes = (size_t)nfds * entry_size;
            void *kbuf = kmalloc(bytes);
            if (!kbuf) return ret_err(ENOMEM);
            if (copy_from_user_raw(kbuf, ufds, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }

            enum { POLLIN = 0x001, POLLOUT = 0x004, POLLERR = 0x008, POLLHUP = 0x010, POLLNVAL = 0x020 };

            auto_check:
            {
                int ready = 0;
                thread_t *curth = thread_get_current_user();
                if (!curth) curth = thread_current();
                for (int i = 0; i < nfds; i++) {
                    int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                    short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                    short revents = 0;
                    if (fd < 0 || fd >= THREAD_MAX_FD) {
                        revents = POLLNVAL;
                    } else {
                        struct fs_file *f = curth ? curth->fds[fd] : NULL;
                        if (!f) {
                            revents = POLLNVAL;
                        } else {
                            /* tty */
                            if (devfs_is_tty_file(f)) {
                                int tidx = devfs_get_tty_index_from_file(f);
                                if (tidx < 0) tidx = devfs_get_active();
                                if ((events & POLLIN) && devfs_tty_available(tidx) > 0) revents |= POLLIN;
                            } else if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                                if (events & POLLOUT) {
                                    if (s->unix_domain_stub) {
                                        if (!s->unix_listening && s->connected && !unix_stream_peer_closed(s) && unix_stream_avail_to_write(s) > 0)
                                            revents |= POLLOUT;
                                    } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                                        revents |= POLLOUT;
                                    } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                        net_tcp_ops_t ops;
                                        net_make_tcp_ops(&ops, &s->tcp);
                                        if (s->tcp.connect_pending) {
                                            e1000_poll();
                                            if (net_tcp_connect_poll(&s->tcp, &ops, 200) == 0) {
                                                s->connected = 1;
                                                revents |= POLLOUT;
                                            } else if (s->tcp.connect_refused) {
                                                revents |= POLLERR | POLLHUP;
                                            }
                                        } else {
                                            e1000_poll();
                                            (void)net_tcp_service(&s->tcp, &ops, 64);
                                            if (s->tcp.established) revents |= POLLOUT;
                                            if (s->tcp.peer_rst) revents |= POLLERR | POLLHUP;
                                        }
                                    } else {
                                        revents |= POLLOUT;
                                    }
                                }
                                if ((events & POLLIN) && s->sock_domain == AF_NETLINK_LOCAL) {
                                    if (s->nl_rx_off < s->nl_rx_len) revents |= POLLIN;
                                } else if (s->unix_domain_stub) {
                                    if (s->unix_listening) {
                                        if ((events & POLLIN) && s->unix_accept_count > 0) revents |= POLLIN;
                                    } else if (s->connected) {
                                        if ((events & POLLIN) && (unix_stream_avail_to_read(s) > 0 || unix_stream_peer_closed(s))) revents |= POLLIN;
                                        if ((events & POLLOUT) && !unix_stream_peer_closed(s) && unix_stream_avail_to_write(s) > 0) revents |= POLLOUT;
                                    }
                                } else if (s->tcp_listening) {
                                    if ((events & POLLIN) && s->unix_accept_count > 0) revents |= POLLIN;
                                } else if ((events & POLLIN) &&
                                           ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                            (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge))) {
                                    if (s->rx_has_pending) revents |= POLLIN;
                                    else {
                                        uint32_t sip = 0;
                                        uint16_t sport = 0;
                                        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                                        if (rn > 0) {
                                            ksock_rx_pending_install(s, rn);
                                            s->rx_pending_src_ip_be = sip;
                                            s->rx_pending_src_port = sport;
                                            revents |= POLLIN;
                                        }
                                    }
                                } else if ((events & POLLIN) && s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                    if (s->tcp.connect_pending) {
                                        net_tcp_ops_t ops;
                                        net_make_tcp_ops(&ops, &s->tcp);
                                        (void)net_tcp_connect_poll(&s->tcp, &ops, 0);
                                    }
                                    net_pump_tcp_sock(s, 16);
                                    if (s->tcp.rx_len > 0 || s->tcp.peer_fin || s->tcp.peer_rst || s->tcp.ooo_valid) revents |= POLLIN;
                                }
                            } else if (usb_is_devfs_file(f)) {
                                if (events & POLLOUT) revents |= POLLOUT;
                                /* MVP: no async IN queue yet, keep POLLIN clear unless future IRQ path adds data. */
                            } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                                pipe_t *p = (pipe_t *)f->driver_private;
                                unsigned long fl = 0;
                                acquire_irqsave(&p->lock, &fl);
                                size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                                size_t free = (p->size > 1) ? ((p->size - 1) - used) : 0;
                                int is_write_end = (f->fs_private == (void *)1);
                                release_irqrestore(&p->lock, fl);
                                if (is_write_end) {
                                    if ((events & POLLOUT) && free > 0) revents |= POLLOUT;
                                    if (p->refcount < 2) revents |= POLLHUP;
                                } else {
                                    if ((events & POLLIN) && used > 0) revents |= POLLIN;
                                    if (p->refcount < 2) revents |= POLLHUP;
                                }
                            } else {
                                /* regular file: readable if pos < size */
                                if ((events & POLLIN)) {
                                    if (f->type != FS_TYPE_DIR) {
                                        if ((size_t)f->pos < (size_t)f->size) revents |= POLLIN;
                                    } else {
                                        /* directories: indicate readable */
                                        revents |= POLLIN;
                                    }
                                }
                            }
                        }
                    }
                    *(short*)((uint8_t*)kbuf + i * entry_size + 6) = revents; /* revents slot at offset 6 */
                    if (revents) ready++;
                }
                if (ready > 0) {
                    if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    kfree(kbuf);
                    return (uint64_t)ready;
                }
            }

            thread_t *curth_poll = thread_get_current_user();
            if (!curth_poll) curth_poll = thread_current();
            /* Detect if poll set includes network sockets (TCP/UDP) - need e1000_poll */
            int has_net_socket = 0;
            for (int i = 0; i < nfds && !has_net_socket; i++) {
                int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                if (fd < 0 || fd >= THREAD_MAX_FD) continue;
                struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                    (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                    has_net_socket = 1;
            }
            if (timeout == 0) {
                /* Non-blocking poll: service network once so packets get processed. */
                if (has_net_socket)
                    net_pump_all_tcp(curth_poll);
                else
                    thread_sleep(10); /* avoid busy-loop when no network fds */
                kfree(kbuf);
                return 0;
            }
            int step = 10; /* ms */
            int cur_tid = curth_poll ? (int)curth_poll->tid : -1;
            int tty_waiting[16];
            int n_tty_waiting;
            if (timeout < 0) {
                /* block indefinitely: add self as TTY waiter so we wake on keypress.
                   When has_net_socket: must use bounded sleep so we periodically poll e1000 and re-check. */
                for (;;) {
                    if (has_net_socket)
                        net_pump_all_tcp(curth_poll);
                    else
                        e1000_poll();
                    n_tty_waiting = 0;
                    if (cur_tid >= 0) {
                        for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                            int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                            short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                            if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN)) continue;
                            struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                            if (!f || !devfs_is_tty_file(f)) continue;
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                        }
                    }
                    if (n_tty_waiting > 0 && !has_net_socket) {
                        uint32_t redraw_ms = user_itimer_interval_ms;
                        if (redraw_ms > 0)
                            thread_block_with_timeout(cur_tid, redraw_ms);
                        else
                            thread_block(cur_tid);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        if (redraw_ms > 0) {
                            int input_ready = 0;
                            for (int w = 0; w < n_tty_waiting; w++) {
                                if (devfs_tty_available(tty_waiting[w]) > 0) {
                                    input_ready = 1;
                                    break;
                                }
                            }
                            if (!input_ready) {
                                if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                                kfree(kbuf);
                                return 0;
                            }
                        }
                        goto auto_check;
                    }
                    if (n_tty_waiting > 0 && has_net_socket) {
                        thread_block_with_timeout(cur_tid, (uint32_t)step);
                        thread_yield();
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_check;
                    }
                    thread_sleep(step);
                    goto auto_check;
                }
            } else {
                /* timeout > 0: use TTY waiters + block_with_timeout to wake on keypress
                   (Escape) immediately instead of sleeping full timeout */
                n_tty_waiting = 0;
                if (cur_tid >= 0) {
                    for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                        int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                        short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                        if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN)) continue;
                        struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                        if (!f || !devfs_is_tty_file(f)) continue;
                        int tidx = devfs_get_tty_index_from_file(f);
                        if (tidx < 0) tidx = devfs_get_active();
                        if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                    }
                }
                if (n_tty_waiting > 0) {
                    int remain = timeout - elapsed;
                    if (remain > 0) {
                        uint64_t t0 = pit_get_time_ms();
                        thread_block_with_timeout(cur_tid, (uint32_t)remain);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        elapsed += (int)(pit_get_time_ms() - t0);
                        if (elapsed >= timeout) {
                            for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                            kfree(kbuf);
                            return 0; /* timeout expired */
                        }
                    }
                    for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    goto auto_check;
                }
                int step_ms = has_net_socket ? 10 : 2;
                if (poll_first_entry) { poll_t_start = pit_get_time_ms(); poll_first_entry = 0; }
                while (elapsed < timeout) {
                    if (has_net_socket)
                        net_pump_all_tcp(curth_poll);
                    else
                        e1000_poll();
                    uint32_t sleep_ms = (uint32_t)(timeout - elapsed);
                    if (sleep_ms > (uint32_t)step_ms) sleep_ms = (uint32_t)step_ms;
                    thread_sleep(sleep_ms);
                    elapsed = (int)(pit_get_time_ms() - poll_t_start);
                    goto auto_check;
                }
            }
            /* timeout expired */
            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
            kfree(kbuf);
            return 0;
        }
        case SYS_open: {
            const char *path_u = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            (void)a3;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char *path = kmalloc(256);
            if (!path) return ret_err(ENOMEM);
            /* path is a heap buffer; sizeof(path) would be sizeof(char*) (8) and truncate paths */
            resolve_user_path(cur, path_u, path, 256);
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
                else if (strncmp(path, "/tty", 4) == 0 &&
                         path[4] >= '1' && path[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
                         path[5] == '\0') {
                    char dev_tty_path[16];
                    snprintf(dev_tty_path, sizeof(dev_tty_path), "/dev/tty%c", path[4]);
                    f = fs_open(dev_tty_path);
                }
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) { kfree(path); return ret_err(ENOENT); }
                } else {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    kfree(path);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            kfree(path);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case SYS_openat: {
            /* openat(dirfd, pathname, flags, mode) - dirfd=AT_FDCWD(-100) uses cwd */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)a4;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                /* chvt: "console"->/console, "tty"->/tty, "tty0"->/tty0, "vc/0"->/dev/vc/0 (handled by devfs) */
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
                else if (strncmp(path, "/tty", 4) == 0 &&
                         path[4] >= '1' && path[4] <= (char)('0' + DEVFS_TTY_COUNT) &&
                         path[5] == '\0') {
                    char dev_tty_path[16];
                    snprintf(dev_tty_path, sizeof(dev_tty_path), "/dev/tty%c", path[4]);
                    f = fs_open(dev_tty_path);
                }
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) return ret_err(ENOENT);
                } else {
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case 53: { /* socketpair(domain, type, protocol, sv[2]) */
            int domain = (int)a1;
            int type = (int)a2;
            int protocol = (int)a3;
            void *sv_u = (void*)(uintptr_t)a4;
            int type_base = type & ~(O_NONBLOCK_LINUX | 02000000);
            if (domain != 1 || !sv_u || (uintptr_t)sv_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EAFNOSUPPORT);
            if (type_base != SOCK_STREAM_LOCAL || protocol != 0)
                return ret_err(EOPNOTSUPP);
            unix_stream_conn_t *conn = (unix_stream_conn_t *)kmalloc(sizeof(*conn));
            ksock_net_t *s0 = (ksock_net_t *)kmalloc(sizeof(*s0));
            ksock_net_t *s1 = (ksock_net_t *)kmalloc(sizeof(*s1));
            struct fs_file *f0 = (struct fs_file *)kmalloc(sizeof(*f0));
            struct fs_file *f1 = (struct fs_file *)kmalloc(sizeof(*f1));
            char *p0 = (char *)kmalloc(24);
            char *p1 = (char *)kmalloc(24);
            if (!conn || !s0 || !s1 || !f0 || !f1 || !p0 || !p1) {
                if (conn) kfree(conn);
                if (s0) kfree(s0);
                if (s1) kfree(s1);
                if (f0) kfree(f0);
                if (f1) kfree(f1);
                if (p0) kfree(p0);
                if (p1) kfree(p1);
                return ret_err(ENOMEM);
            }
            memset(conn, 0, sizeof(*conn));
            conn->refs = 2;
            conn->lock.lock = 0;
            memset(s0, 0, sizeof(*s0));
            memset(s1, 0, sizeof(*s1));
            memset(f0, 0, sizeof(*f0));
            memset(f1, 0, sizeof(*f1));
            snprintf(p0, 24, "socket:[unix]");
            snprintf(p1, 24, "socket:[unix]");
            s0->sock_domain = AF_INET_LOCAL;
            s1->sock_domain = AF_INET_LOCAL;
            s0->unix_domain_stub = 1;
            s1->unix_domain_stub = 1;
            s0->type_base = SOCK_STREAM_LOCAL;
            s1->type_base = SOCK_STREAM_LOCAL;
            s0->connected = 1;
            s1->connected = 1;
            s0->nonblock = (type & O_NONBLOCK_LINUX) ? 1 : 0;
            s1->nonblock = s0->nonblock;
            s0->unix_conn = conn;
            s1->unix_conn = conn;
            s0->unix_end = 0;
            s1->unix_end = 1;
            s0->kref = 1;
            s1->kref = 1;
            f0->path = p0;
            f1->path = p1;
            f0->type = SYSCALL_FTYPE_SOCKET;
            f1->type = SYSCALL_FTYPE_SOCKET;
            f0->driver_private = s0;
            f1->driver_private = s1;
            f0->refcount = 1;
            f1->refcount = 1;
            int fd0 = thread_fd_alloc(f0);
            int fd1 = thread_fd_alloc(f1);
            if (fd0 < 0 || fd1 < 0) {
                if (fd0 >= 0) thread_fd_close(fd0); else net_fs_file_destroy(f0);
                if (fd1 >= 0) thread_fd_close(fd1); else net_fs_file_destroy(f1);
                return ret_err(EMFILE);
            }
            int fds[2] = { fd0, fd1 };
            if (copy_to_user_safe(sv_u, fds, sizeof(fds)) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_pipe:
        case SYS_pipe2: {
            /* pipe(int pipefd[2]); pipe2(int pipefd[2], int flags). flags (e.g. O_CLOEXEC) ignored for now. */
            void *pipefd_u = (void*)(uintptr_t)a1;
            (void)a2; /* flags for pipe2 */
            if (!pipefd_u || (uintptr_t)pipefd_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            pipe_t *p = (pipe_t *)kmalloc(sizeof(pipe_t));
            if (!p) { qemu_debug_printf("OOM: pipe pipe_t alloc\n"); return ret_err(ENOMEM); }
            p->buf = (uint8_t *)kmalloc(PIPE_BUF_SIZE);
            if (!p->buf) { qemu_debug_printf("OOM: pipe buf alloc %u\n", (unsigned)PIPE_BUF_SIZE); kfree(p); return ret_err(ENOMEM); }
            p->size = PIPE_BUF_SIZE;
            p->head = p->tail = 0;
            p->refcount = 2;
            p->reader_waiter_tid = p->writer_waiter_tid = -1;
            p->lock.lock = 0;

            struct fs_file *r = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            struct fs_file *w = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            if (!r || !w) { kfree(p->buf); kfree(p); if (r) kfree(r); if (w) kfree(w); return ret_err(ENOMEM); }
            memset(r, 0, sizeof(*r)); memset(w, 0, sizeof(*w));
            r->type = w->type = FS_TYPE_PIPE;
            r->driver_private = w->driver_private = p;
            r->fs_private = NULL; w->fs_private = (void *)1; /* 0=read end, 1=write end */
            r->refcount = w->refcount = 1;

            int fd0 = thread_fd_alloc(r);
            int fd1 = thread_fd_alloc(w);
            if (fd0 < 0 || fd1 < 0) {
                if (fd0 >= 0) thread_fd_close(fd0);
                if (fd1 >= 0) thread_fd_close(fd1);
                return ret_err(EMFILE);
            }
            int fds[2] = { fd0, fd1 };
            if (copy_to_user_safe(pipefd_u, fds, 8) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_close: {
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            int r = thread_fd_close(fd);
            return (r == 0) ? 0ULL : ret_err(EBADF);
        }
        case SYS_stat:
        case SYS_lstat: {
            const char *path_u = (const char*)(uintptr_t)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (!path_u || !st_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            int rc_st = (num == SYS_lstat) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
            if (rc_st != 0) return ret_err(ENOENT);
            /* build Linux x86_64 ABI struct stat and copy full layout so vi/busybox S_ISREG works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_fstat: {
            int fd = (int)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            struct stat st;
            if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
            /* build Linux x86_64 ABI struct stat so vi/busybox S_ISREG(st.st_mode) works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_newfstatat: {
            /* newfstatat(dirfd, pathname, statbuf, flags) - use same Linux ABI layout as stat/fstat */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            void *st_u = (void*)(uintptr_t)a3;
            int flags = (int)a4;
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct stat st;
            enum { AT_FDCWD = -100 };
            /* Linux AT_* flags */
            enum { AT_SYMLINK_NOFOLLOW = 0x100 };
            int st_ready = 0;
            /* AT_EMPTY_PATH (0x1000): stat the file given by dirfd when path is empty (or NULL). */
            char first = '\0';
            int empty_path = 0;
            if ((flags & 0x1000) != 0) {
                if (!path_u) {
                    empty_path = 1;
                } else {
                    if (copy_from_user_raw(&first, path_u, 1) != 0) return ret_err(EFAULT);
                    if (first == '\0') empty_path = 1;
                }
            }
            if (empty_path) {
                if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[dirfd];
                if (!f) return ret_err(EBADF);
                if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
                st_ready = 1;
            } else {
                if (!path_u) return ret_err(EFAULT);
                char *kpath = copy_user_cstr(path_u, 256);
                if (!kpath) return ret_err(EFAULT);
                char path[256];
                int rc_resolve = 0;
                if (kpath[0] == '/') {
                    resolve_user_path(cur, kpath, path, sizeof(path));
                } else if (dirfd == AT_FDCWD) {
                    resolve_user_path(cur, kpath, path, sizeof(path));
                } else {
                    if (dirfd < 0 || dirfd >= THREAD_MAX_FD) rc_resolve = -EBADF;
                    else {
                        struct fs_file *df = cur->fds[dirfd];
                        if (!df) rc_resolve = -EBADF;
                        else if (df->type != FS_TYPE_DIR) rc_resolve = -ENOTDIR;
                        else {
                            const char *base = df->path ? df->path : "/";
                            if (strcmp(base, "/") == 0) snprintf(path, sizeof(path), "/%s", kpath);
                            else snprintf(path, sizeof(path), "%s/%s", base, kpath);
                            path[sizeof(path) - 1] = '\0';
                            if (path_needs_normalize(path)) normalize_path(path, sizeof(path));
                        }
                    }
                }
                kfree(kpath);
                if (rc_resolve != 0) {
                    if (rc_resolve == -EBADF) return ret_err(EBADF);
                    if (rc_resolve == -ENOTDIR) return ret_err(ENOTDIR);
                    if (rc_resolve == -ENOENT) return ret_err(ENOENT);
                    return ret_err(EFAULT);
                }
                /* Respect AT_SYMLINK_NOFOLLOW: behave like lstat() when requested. */
                int sr = (flags & AT_SYMLINK_NOFOLLOW) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
                if (sr != 0) return ret_err(ENOENT);
                st_ready = 1;
            }
            if (!st_ready) return ret_err(EFAULT);

            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_lseek: {
            int fd = (int)a1;
            int64_t off = (int64_t)a2;
            int whence = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            off_t newpos = 0;
            /* 0=SET 1=CUR 2=END; 3=SEEK_DATA 4=SEEK_HOLE (Linux) — glibc/wget use 3/4 on regular files */
            if (whence == 0)
                newpos = (off_t)off;
            else if (whence == 1)
                newpos = (off_t)((int64_t)f->pos + off);
            else if (whence == 2)
                newpos = (off_t)((int64_t)f->size + off);
            else if (whence == 3)
                newpos = (off_t)off;
            else if (whence == 4) { /* SEEK_HOLE: no sparse files; hole begins at EOF */
                if ((off_t)off >= (off_t)f->size)
                    newpos = (off_t)off;
                else
                    newpos = (off_t)f->size;
            } else
                return ret_err(EINVAL);
            if (newpos < 0) return ret_err(EINVAL);
            f->pos = newpos;
            return (uint64_t)(uint64_t)f->pos;
        }
        case SYS_ftruncate: {
            int fd = (int)a1;
            int64_t len64 = (int64_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET) return ret_err(EINVAL);
            if (len64 < 0) return ret_err(EINVAL);
            int r = vfs_ftruncate(f, (off_t)len64);
            if (r == 0) return 0;
            if (r < 0) return ret_err(-r);
            return ret_err(EINVAL);
        }
        case SYS_getdents: /* historic getdents syscall (78) */
        case SYS_getdents64: {
            int fd = (int)a1;
            void *dirp_u = (void*)(uintptr_t)a2;
            size_t count = (size_t)a3;
            int want64 = (num == SYS_getdents64);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!dirp_u) return ret_err(EFAULT);
            if (count < 32) return ret_err(EINVAL);
            if ((uintptr_t)dirp_u + count > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type != FS_TYPE_DIR) return ret_err(EINVAL);

            /* Synthesize linux_dirent64 records into a kernel buffer, then copy to userspace.
               This avoids exposing malformed driver records directly to libc. */
            uint8_t kbuf[1024];
            ssize_t rr = fs_readdir_next(f, kbuf, sizeof(kbuf));
            if (rr <= 0) return 0;

            size_t in_off = 0;
            size_t out_off = 0;
            size_t out_cap = count < 4096 ? count : 4096;
            uint8_t *outbuf = (uint8_t*)kmalloc(out_cap);
            if (!outbuf) return ret_err(ENOMEM);

            while (in_off + 8 <= (size_t)rr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)(kbuf + in_off);
                if (de->rec_len < 8) break;
                size_t rem = (size_t)rr - in_off;
                size_t entry_rec = (size_t)de->rec_len;
                if (entry_rec == 0) break;
                /* Do not parse a partial entry at buffer end — would corrupt next name */
                if (entry_rec > rem) break;
                size_t max_name = (entry_rec > 8) ? entry_rec - 8 : 0;
                size_t name_len_use = (size_t)de->name_len;
                if (name_len_use > max_name) name_len_use = max_name;
                /* Never read past this record — avoids "+" or garbage from next entry. */
                if (name_len_use > 255) name_len_use = 255;

                const char *nm_raw = (const char*)(kbuf + in_off + 8);
                char namebuf_local[256];
                size_t copy_n = (name_len_use < sizeof(namebuf_local)-1) ? name_len_use : (sizeof(namebuf_local)-1);
                if (copy_n > 0) memcpy(namebuf_local, nm_raw, copy_n);
                namebuf_local[copy_n] = '\0';
                for (size_t _i = 0; _i < copy_n; _i++) {
                    unsigned char ch = (unsigned char)namebuf_local[_i];
                    if (ch < 32 || ch > 126) namebuf_local[_i] = '?';
                }
                const char *nm = namebuf_local;
                size_t nlen = copy_n;

                /* Determine inode/type by stat'ing the full path if possible.
                   IMPORTANT: some virtual filesystems don't provide st_ino (0).
                   Userspace tools often treat d_ino==0 as "absent" and skip it,
                   which makes mountpoints like /dev invisible. */
                uint64_t out_ino = (uint64_t)de->inode;
                uint8_t out_type = (uint8_t)de->file_type;
                if (f->path && nlen > 0) {
                    char fullpath[512];
                    size_t plen = strlen(f->path);
                    if (plen + 1 + nlen + 1 < sizeof(fullpath)) {
                        memcpy(fullpath, f->path, plen);
                        if (plen == 0 || fullpath[plen-1] != '/') fullpath[plen++] = '/';
                        memcpy(fullpath + plen, nm, nlen);
                        fullpath[plen + nlen] = '\0';
                        struct fs_file *ef = fs_open(fullpath);
                        if (ef) {
                            struct stat st;
                            if (vfs_fstat(ef, &st) == 0) {
                                if ((uint64_t)st.st_ino != 0) {
                                    out_ino = (uint64_t)st.st_ino;
                                }
                                if ((st.st_mode & S_IFDIR) == S_IFDIR) out_type = EXT2_FT_DIR;
                                else out_type = EXT2_FT_REG_FILE;
                            }
                            fs_file_free(ef);
                        }
                    }
                }

                uint8_t dtype = 0; /* DT_UNKNOWN */
                if (out_type == EXT2_FT_DIR) dtype = 4;       /* DT_DIR */
                else if (out_type == EXT2_FT_REG_FILE) dtype = 8; /* DT_REG */
                else if (out_type == EXT2_FT_SYMLINK) dtype = 10; /* DT_LNK */

                size_t reclen;
                if (want64) {
                    /* linux_dirent64: ino(8), off(8), reclen(2), type(1), name[] */
                    reclen = 19 + nlen + 1;
                } else {
                    /* linux_dirent: ino(8), off(8), reclen(2), name[], ..., type at last byte */
                    reclen = 18 + nlen + 1 + 1;
                }
                reclen = (reclen + 7) & ~7u;
                if (out_off + reclen > out_cap) break;

                uint8_t *outp = outbuf + out_off;
                *(uint64_t*)(outp + 0) = (uint64_t)out_ino;
                *(int64_t*)(outp + 8) = (int64_t)f->pos;
                *(uint16_t*)(outp + 16) = (uint16_t)reclen;
                if (want64) {
                    outp[18] = dtype;
                    memcpy(outp + 19, nm, nlen);
                    outp[19 + nlen] = '\0';
                    for (size_t z = 19 + nlen + 1; z < reclen; z++) outp[z] = 0;
                } else {
                    memcpy(outp + 18, nm, nlen);
                    outp[18 + nlen] = '\0';
                    for (size_t z = 19 + nlen; z + 1 < reclen; z++) outp[z] = 0;
                    outp[reclen - 1] = dtype;
                }

                out_off += reclen;
                in_off += entry_rec;
            }

            /* Rewind directory position so next getdents64 re-reads the partial entry */
            if (in_off < (size_t)rr)
                f->pos -= (rr - (off_t)in_off);

            /* copy synthesized data to user buffer per-record (safer) */
            size_t wrote = 0;
            size_t scan = 0;
            while (scan + 18 < out_off) {
                uint16_t recl = *(uint16_t*)(outbuf + scan + 16);
                if (recl == 0) break;
                if (scan + recl > out_off) break;
                /* bounds check user destination */
                if ((uintptr_t)dirp_u + wrote + recl > (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    break;
                }
                int rc = copy_to_user_safe((uint8_t*)dirp_u + wrote, outbuf + scan, recl);
                if (rc != 0) {
                    kfree(outbuf);
                    return ret_err(EFAULT);
                }
                wrote += recl;
                scan += recl;
            }
            kfree(outbuf);
            return (uint64_t)wrote;
        }
        case SYS_arch_prctl: {
            /* Linux x86_64 arch_prctl(code, addr) — rdi=code, rsi=addr */
            enum { ARCH_SET_GS = 0x1001, ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ARCH_GET_GS = 0x1004 };
            uint64_t code = a1;
            uint64_t addr = a2;
            /* Defensive: some callers have been seen with code/addr swapped. */
            if (code >= 0x200000ULL && code < (uint64_t)USER_STACK_TOP &&
                (addr == ARCH_SET_FS || addr == ARCH_SET_GS || addr == ARCH_GET_FS || addr == ARCH_GET_GS)) {
                uint64_t t = code;
                code = addr;
                addr = t;
            }
            if (code == ARCH_SET_FS || code == ARCH_SET_GS) {
                if (code == ARCH_SET_GS)
                    code = ARCH_SET_FS;
                if (addr < 0x200000ULL || addr >= (uint64_t)USER_STACK_TOP) {
                    kprintf("arch_prctl SET_FS: bad addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                {
                    uint64_t map_lo = addr & ~((uint64_t)PAGE_SIZE_2M - 1);
                    uint64_t map_hi = (addr + 0x4000ULL + PAGE_SIZE_2M - 1) & ~((uint64_t)PAGE_SIZE_2M - 1);
                    if (map_hi > (uint64_t)USER_STACK_TOP) map_hi = (uint64_t)USER_STACK_TOP;
                    if (user_map_ensure_present_us_2m(map_lo, map_hi) != 0) {
                        kprintf("arch_prctl SET_FS: map fail addr=0x%llx lo=0x%llx hi=0x%llx\n",
                            (unsigned long long)addr,
                            (unsigned long long)map_lo, (unsigned long long)map_hi);
                        return ret_err(EFAULT);
                    }
                }
                /* Fix for early "stack smashing detected" in glibc:
                   If userspace executed stack-protected frames BEFORE TLS (FS base) was set,
                   then changing FS base later makes the epilogue compare against a different
                   guard at fs:0x28 -> abort().
                   Keep the guard stable by copying old fs:0x28 into new TLS fs:0x28. */
                uint64_t old_fs = msr_read_u64(MSR_FS_BASE);
                uint64_t old_guard = 0;
                if (old_fs >= 0x200000ULL && old_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    (void)copy_from_user_raw(&old_guard, (const void *)(uintptr_t)(old_fs + 0x28), sizeof(old_guard));
                } else {
                    old_guard = 0x8b13f00d2a11c000ULL;
                }

                cur->user_fs_base = addr;
                set_user_fs_base(addr);

                if (addr + 0x30 <= (uint64_t)USER_STACK_TOP) {
                    (void)copy_to_user_safe((void *)(uintptr_t)(addr + 0x28), &old_guard, sizeof(old_guard));
                }
                return 0;
            } else if (code == ARCH_GET_FS) {
                if (addr < 0x200000ULL || addr >= (uint64_t)MMIO_IDENTITY_LIMIT) {
                    kprintf("arch_prctl GET_FS: bad addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                if (copy_to_user_safe((void *)(uintptr_t)addr, &cur->user_fs_base, sizeof(cur->user_fs_base)) != 0) {
                    kprintf("arch_prctl GET_FS: copy fail addr=0x%llx\n", (unsigned long long)addr);
                    return ret_err(EFAULT);
                }
                return 0;
            } else if (code == ARCH_GET_GS) {
                kprintf("arch_prctl GET_GS: ENOSYS\n");
                return ret_err(ENOSYS);
            }
            kprintf("arch_prctl: EINVAL code=0x%llx addr=0x%llx\n",
                (unsigned long long)code, (unsigned long long)addr);
            return ret_err(EINVAL);
        }
        case SYS_mount: {
            /* mount(source, target, fstype, flags, data) */
            const char *src_u = (const char*)(uintptr_t)a1;
            const char *tgt_u = (const char*)(uintptr_t)a2;
            const char *type_u = (const char*)(uintptr_t)a3;
            (void)a4; (void)a5;
            if (!tgt_u || !type_u) return ret_err(EINVAL);
            char *k_type = copy_user_cstr(type_u, 64);
            if (!k_type) return ret_err(EFAULT);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) { kfree(k_type); return ret_err(EFAULT); }
            char target[256];
            resolve_user_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') { kfree(k_type); return ret_err(EINVAL); }

            int rc = -1;
            int errno_out = EINVAL;
            if (strcmp(k_type, "proc") == 0 || strcmp(k_type, "procfs") == 0) {
                (void)procfs_register();
                ramfs_mkdir(target);
                rc = procfs_mount(target);
                if (rc != 0) errno_out = EBUSY;
            } else if (strcmp(k_type, "sysfs") == 0) {
                if (sysfs_register() == 0) {
                    ramfs_mkdir(target);
                    rc = sysfs_mount(target);
                    if (rc == 0)
                        kernel_sysfs_populate_default();
                    else
                        errno_out = EBUSY;
                } else {
                    errno_out = EBUSY;
                }
            } else if (strcmp(k_type, "devfs") == 0 || strcmp(k_type, "devtmpfs") == 0 || strcmp(k_type, "tmpfs") == 0) {
                /* tmpfs as mount type for /dev: treat same as devtmpfs (init inittab fallback) */
                ramfs_mkdir(target);
                rc = devfs_mount(target);
                if (rc != 0) errno_out = EBUSY;
            } else if (strcmp(k_type, "fat32") == 0 || strcmp(k_type, "vfat") == 0 || strcmp(k_type, "msdos") == 0 || strcmp(k_type, "auto") == 0) {
                if (!src_u) { kfree(k_type); return ret_err(EINVAL); }
                char *k_src_raw = copy_user_cstr(src_u, 256);
                if (!k_src_raw) { kfree(k_type); return ret_err(EFAULT); }
                char source[256];
                resolve_user_path(cur, k_src_raw, source, sizeof(source));
                kfree(k_src_raw);
                if (source[0] == '\0') { kfree(k_type); return ret_err(EINVAL); }

                int dev_id = devfs_get_device_id(source);
                if (dev_id < 0) { kfree(k_type); return ret_err(ENOENT); }

                /* Ensure FAT32 state is initialized for this device. */
                if (fat32_probe_and_mount(dev_id) != 0) { kfree(k_type); return ret_err(EINVAL); }
                struct fs_driver *drv = fat32_get_driver();
                if (!drv) { kfree(k_type); return ret_err(EINVAL); }

                ramfs_mkdir(target);
                rc = fs_mount(target, drv);
                if (rc != 0) errno_out = EBUSY;
            } else {
                rc = -1;
                errno_out = EINVAL;
            }

            kfree(k_type);
            return (rc == 0) ? 0 : ret_err(errno_out);
        }
        case SYS_umount2: {
            /* umount2(target, flags) */
            const char *tgt_u = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            /* Support only the common case flags==0; ignore MNT_DETACH etc for now. */
            if (flags != 0) return ret_err(ENOSYS);
            if (!tgt_u) return ret_err(EINVAL);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) return ret_err(EFAULT);
            char target[256];
            resolve_user_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') return ret_err(EINVAL);
            /* normalize: strip trailing slashes except root */
            size_t n = strlen(target);
            while (n > 1 && target[n - 1] == '/') target[--n] = '\0';

            struct fs_driver *drv = fs_get_mount_driver(target);
            int rc = fs_unmount(target);
            if (rc != 0) return ret_err(EINVAL);

            /* driver-specific cleanup */
            if (drv && drv->ops && drv->ops->name) {
                if (strcmp(drv->ops->name, "fat32") == 0) {
                    fat32_unmount_cleanup();
                }
            }
            return 0;
        }
        case SYS_brk:
            return user_syscall_brk(a1);
        case SYS_shmget: {
            int key = (int)a1;
            size_t size = (size_t)a2;
            int shmflg = (int)a3;
            enum { IPC_PRIVATE_LOCAL = 0, IPC_CREAT_LOCAL = 01000, IPC_EXCL_LOCAL = 02000 };
            if (size == 0) return ret_err(EINVAL);
            size = (size_t)user_mm_align_up((uintptr_t)size, 4096);
            if (size < 4096) size = 4096;

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uid_t uid = tcur ? tcur->euid : 0;
            gid_t gid = tcur ? tcur->egid : 0;
            uint32_t pid = (uint32_t)((tcur && tcur->tid) ? tcur->tid : 1);

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            if (key != IPC_PRIVATE_LOCAL) {
                sysv_shm_seg_t *seg = sysv_shm_find_by_key_nolock(key);
                if (seg) {
                    if ((shmflg & IPC_CREAT_LOCAL) && (shmflg & IPC_EXCL_LOCAL)) {
                        release_irqrestore(&g_sysv_shm_lock, fl);
                        return ret_err(EEXIST);
                    }
                    if (size > seg->size) {
                        release_irqrestore(&g_sysv_shm_lock, fl);
                        return ret_err(EINVAL);
                    }
                    int id = seg->shmid;
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return (uint64_t)id;
                }
                if (!(shmflg & IPC_CREAT_LOCAL)) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(ENOENT);
                }
            }

            int slot = -1;
            for (int i = 0; i < SYSV_SHM_MAX_SEGMENTS; i++) {
                if (!g_sysv_shm[i].used) { slot = i; break; }
            }
            if (slot < 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            uintptr_t base = sysv_shm_alloc_va_nolock(size);
            if (base == 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOMEM);
            }

            sysv_shm_seg_t *seg = &g_sysv_shm[slot];
            memset(seg, 0, sizeof(*seg));
            seg->used = 1;
            seg->shmid = g_sysv_shm_next_id++;
            if (g_sysv_shm_next_id < 1) g_sysv_shm_next_id = 1;
            seg->key = key;
            seg->size = size;
            seg->base = base;
            seg->mode = (uint32_t)(shmflg & 0777);
            seg->uid = uid;
            seg->gid = gid;
            seg->cuid = uid;
            seg->cgid = gid;
            seg->cpid = pid;
            seg->lpid = 0;
            seg->atime = 0;
            seg->dtime = 0;
            seg->ctime = sysv_shm_now_secs();
            seg->nattch = 0;
            seg->removed = 0;
            int shmid = seg->shmid;
            release_irqrestore(&g_sysv_shm_lock, fl);

            if (mark_user_identity_range_2m_sys((uint64_t)base, (uint64_t)(base + size)) != 0) {
                acquire_irqsave(&g_sysv_shm_lock, &fl);
                seg->used = 0;
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EFAULT);
            }
            memset((void *)base, 0, size);
            return (uint64_t)shmid;
        }
        case SYS_shmat: {
            int shmid = (int)a1;
            uintptr_t req_addr = (uintptr_t)a2;
            int shmflg = (int)a3;
            enum { SHM_RDONLY_LOCAL = 010000, SHM_RND_LOCAL = 020000 };
            (void)req_addr;
            (void)shmflg;

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);
            uid_t uid = tcur ? tcur->euid : 0;

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            if (!seg || seg->removed) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            if (req_addr != 0) {
                uintptr_t want = req_addr;
                if (shmflg & SHM_RND_LOCAL) want &= ~0xFFFu;
                if (want != seg->base) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EINVAL);
                }
            }
            if ((shmflg & SHM_RDONLY_LOCAL) == 0) {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid && (seg->mode & 0222u) == 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EACCES);
                }
            } else {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid && (seg->mode & 0444u) == 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EACCES);
                }
            }
            if (sysv_shm_register_attach_nolock(shmid, tid, seg->base, (shmflg & SHM_RDONLY_LOCAL) ? 1 : 0) != 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            seg->nattch++;
            seg->lpid = (uint32_t)tid;
            seg->atime = sysv_shm_now_secs();
            uintptr_t addr = seg->base;
            size_t seg_size = seg->size;
            release_irqrestore(&g_sysv_shm_lock, fl);
            if (user_vma_add(tid, addr, seg_size, (shmflg & SHM_RDONLY_LOCAL) ? 1 : 3, USER_VMA_KIND_SHM) != 0) {
                acquire_irqsave(&g_sysv_shm_lock, &fl);
                int dshmid = -1;
                (void)sysv_shm_detach_one_by_tid_addr_nolock(tid, addr, &dshmid);
                sysv_shm_seg_t *dseg = sysv_shm_find_by_id_nolock(shmid);
                if (dseg) {
                    if (dseg->nattch > 0) dseg->nattch--;
                    dseg->dtime = sysv_shm_now_secs();
                    dseg->lpid = (uint32_t)tid;
                    sysv_shm_cleanup_removed_nolock(dseg);
                }
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(ENOSPC);
            }
            return (uint64_t)addr;
        }
        case SYS_shmdt: {
            uintptr_t addr = (uintptr_t)a1;
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            int shmid = -1;
            if (sysv_shm_detach_one_by_tid_addr_nolock(tid, addr, &shmid) != 0) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            size_t seg_size = seg ? seg->size : 0;
            if (seg) {
                if (seg->nattch > 0) seg->nattch--;
                seg->dtime = sysv_shm_now_secs();
                seg->lpid = (uint32_t)tid;
                sysv_shm_cleanup_removed_nolock(seg);
            }
            release_irqrestore(&g_sysv_shm_lock, fl);
            if (seg_size > 0)
                user_vma_unmap_range(tid, addr, seg_size);
            return 0;
        }
        case SYS_shmctl: {
            int shmid = (int)a1;
            int cmd = (int)a2;
            void *buf_u = (void *)(uintptr_t)a3;
            enum { IPC_RMID_LOCAL = 0, IPC_SET_LOCAL = 1, IPC_STAT_LOCAL = 2 };

            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uint64_t tid = (uint64_t)((tcur && tcur->tid) ? tcur->tid : 1);
            uid_t uid = tcur ? tcur->euid : 0;

            unsigned long fl = 0;
            acquire_irqsave(&g_sysv_shm_lock, &fl);
            sysv_shm_seg_t *seg = sysv_shm_find_by_id_nolock(shmid);
            if (!seg) {
                release_irqrestore(&g_sysv_shm_lock, fl);
                return ret_err(EINVAL);
            }
            if (cmd == IPC_RMID_LOCAL) {
                if (uid != 0 && uid != seg->uid && uid != seg->cuid) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EPERM);
                }
                seg->removed = 1;
                seg->key = 0;
                seg->lpid = (uint32_t)tid;
                seg->dtime = sysv_shm_now_secs();
                sysv_shm_cleanup_removed_nolock(seg);
                release_irqrestore(&g_sysv_shm_lock, fl);
                return 0;
            }
            if (cmd == IPC_SET_LOCAL) {
                if (!buf_u || !user_range_ok(buf_u, sizeof(struct sysv_shmid_ds_compat))) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                if (uid != 0 && uid != seg->uid && uid != seg->cuid) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EPERM);
                }
                struct sysv_shmid_ds_compat ds;
                if (copy_from_user_raw(&ds, buf_u, sizeof(ds)) != 0) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                seg->mode = (seg->mode & ~0777u) | (uint32_t)(ds.shm_perm.mode & 0777u);
                seg->uid = (uid_t)ds.shm_perm.uid;
                seg->gid = (gid_t)ds.shm_perm.gid;
                seg->ctime = sysv_shm_now_secs();
                release_irqrestore(&g_sysv_shm_lock, fl);
                return 0;
            }
            if (cmd == IPC_STAT_LOCAL) {
                if (!buf_u || !user_range_ok(buf_u, sizeof(struct sysv_shmid_ds_compat))) {
                    release_irqrestore(&g_sysv_shm_lock, fl);
                    return ret_err(EFAULT);
                }
                struct sysv_shmid_ds_compat ds;
                memset(&ds, 0, sizeof(ds));
                ds.shm_perm.key = (uint32_t)seg->key;
                ds.shm_perm.uid = (uint32_t)seg->uid;
                ds.shm_perm.gid = (uint32_t)seg->gid;
                ds.shm_perm.cuid = (uint32_t)seg->cuid;
                ds.shm_perm.cgid = (uint32_t)seg->cgid;
                ds.shm_perm.mode = (uint16_t)(seg->mode & 0777u);
                ds.shm_segsz = (uint64_t)seg->size;
                ds.shm_atime = (int64_t)seg->atime;
                ds.shm_dtime = (int64_t)seg->dtime;
                ds.shm_ctime = (int64_t)seg->ctime;
                ds.shm_cpid = (int32_t)seg->cpid;
                ds.shm_lpid = (int32_t)seg->lpid;
                ds.shm_nattch = (uint64_t)seg->nattch;
                release_irqrestore(&g_sysv_shm_lock, fl);
                if (copy_to_user_safe(buf_u, &ds, sizeof(ds)) != 0) return ret_err(EFAULT);
                return 0;
            }
            release_irqrestore(&g_sysv_shm_lock, fl);
            return ret_err(EINVAL);
        }
        case SYS_mmap:
            return user_syscall_mmap(cur, a1, a2, a3, a4, a5, a6);
        case SYS_munmap:
            return user_syscall_munmap(a1, a2);
        case SYS_madvise: {
            /* madvise(addr, length, advice) - syscall 28; glibc/apm uses MADV_DONTNEED etc.; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case SYS_mprotect:
            return user_syscall_mprotect(a1, a2, a3);
        case SYS_exit: {
            (void)a1;
            qemu_debug_printf("sys_exit: pid=%llu name=%s called exit(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            /* store exit status in wait format (status << 8) */
            if (cur) {
                int ignore_sigchld = (user_sig_actions[SIGCHLD].handler == SIG_IGN) ||
                    ((user_sig_actions[SIGCHLD].flags & SA_NOCLDWAIT) != 0);
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                sysv_shm_detach_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i]) {
                        struct fs_file *f = cur->fds[i];
                        cur->fds[i] = NULL;
                        fs_file_free(f);
                    }
                }
                /* wake vfork parent if any (restore parent's stack snapshot first) */
                int vfork_pt = cur->vfork_parent_tid;
                if (vfork_pt >= 0) {
                    qemu_debug_printf("sys_exit: waking vfork parent %d from child %llu\n",
                        vfork_pt, (unsigned long long)(cur->tid ? cur->tid : 1));
                    vfork_restore_parent_memory(cur);
                    vfork_restore_parent_stack(cur);
                    cur->vfork_parent_tid = -1;
                }
                /* glibc pthread_join waits on clear_child_tid; write 0 and FUTEX_WAKE so parent wakes */
                if (cur->clear_child_tid != 0 && cur->clear_child_tid < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    {
                        extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                        futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0);
                    }
                    cur->clear_child_tid = 0;
                }
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                if (cur->user_stack_base != 0 && cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        if (pt->user_brk_cur < cur->user_brk_cur)
                            pt->user_brk_cur = cur->user_brk_cur;
                        if (pt->user_mmap_next < cur->user_mmap_next)
                            pt->user_mmap_next = cur->user_mmap_next;
                    }
                }
                /* Mark zombie BEFORE waking wait4/vfork waiters: thread_schedule() below
                   may run the parent while this thread is still in SYS_exit. */
                cur->state = THREAD_TERMINATED;
                if (ignore_sigchld) {
                    /* No zombie: allow scheduler to free this slot. */
                    cur->exit_status = 0x80000000;
                }
                if (is_watch_proc(cur)) {
                    qemu_debug_printf("exit: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                if (vfork_pt >= 0)
                    thread_unblock(vfork_pt);
                if (cur->parent_tid >= 0 && !ignore_sigchld) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        thread_unblock((int)(pt->tid ? pt->tid : 1));
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
                }
                if (cur->waiter_tid >= 0) {
                    if (is_watch_proc(cur)) {
                        qemu_debug_printf("exit: pid=%llu (%s) waking waiter=%d\n",
                            (unsigned long long)(cur->tid ? cur->tid : 1),
                            cur->name,
                            cur->waiter_tid);
                    }
                    thread_unblock(cur->waiter_tid);
                }
                if (cur->mm_ptemplate) {
                    mm_release(cur->mm_ptemplate);
                    cur->mm_ptemplate = NULL;
                }
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_release(cur->mm);
                    cur->mm = mm_kernel();
                }
            }
            /* IMPORTANT:
               If this is a scheduled kernel thread (tid!=0), do not drop into ring0 shell.
               Run other READY threads (e.g. parent in wait4) once, then halt this task. */
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_schedule();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_exit_group: {
            (void)a1;
            qemu_debug_printf("sys_exit_group: pid=%llu name=%s called exit_group(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            if (cur) {
                devfs_tty_remove_waiter_from_all_ttys((int)(cur->tid ? cur->tid : 1));
                exit_group_reap_peer_threads(cur);
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                sysv_shm_detach_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                user_vma_remove_all_for_tid((uint64_t)(cur->tid ? cur->tid : 1));
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i]) {
                        struct fs_file *f = cur->fds[i];
                        cur->fds[i] = NULL;
                        fs_file_free(f);
                    }
                }
                thread_yield(); /* let pipe reader run and see EOF before we wake vfork parent */
                if (cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        /* Parent may be blocked outside wait4 path (pipe/poll/read). */
                        thread_unblock((int)(pt->tid ? pt->tid : 1));
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
                }
                if (cur->vfork_parent_tid >= 0) {
                    qemu_debug_printf("sys_exit_group: waking vfork parent %d from child %llu\n",
                        cur->vfork_parent_tid, (unsigned long long)(cur->tid ? cur->tid : 1));
                    vfork_restore_parent_memory(cur);
                    vfork_restore_parent_stack(cur);
                    thread_unblock(cur->vfork_parent_tid);
                    cur->vfork_parent_tid = -1;
                } else {
                    qemu_debug_printf("sys_exit_group: child %llu has no vfork_parent_tid (was %d)\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1), cur->vfork_parent_tid);
                }
                if (cur->waiter_tid >= 0) thread_unblock(cur->waiter_tid);
                if (cur->clear_child_tid != 0 && cur->clear_child_tid < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    { extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                      futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0); }
                    cur->clear_child_tid = 0;
                }
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                if (cur->user_stack_base != 0 && cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        if (pt->user_brk_cur < cur->user_brk_cur)
                            pt->user_brk_cur = cur->user_brk_cur;
                        if (pt->user_mmap_next < cur->user_mmap_next)
                            pt->user_mmap_next = cur->user_mmap_next;
                    }
                }
                cur->state = THREAD_TERMINATED;
                if (is_watch_proc(cur)) {
                    qemu_debug_printf("exit_group: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                if (cur->mm_ptemplate) {
                    mm_release(cur->mm_ptemplate);
                    cur->mm_ptemplate = NULL;
                }
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_release(cur->mm);
                    cur->mm = mm_kernel();
                }
            }
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_yield();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_rt_sigreturn: {
            /* rt_sigreturn: restore from ucontext on user stack. RSP at entry = ucontext. */
            uintptr_t uc_ptr = (uintptr_t)syscall_user_rsp_saved;
            if (uc_ptr < 0x200000 || uc_ptr + sizeof(k_ucontext_t) > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            k_ucontext_t uc;
            if (copy_from_user_raw(&uc, (const void *)uc_ptr, sizeof(uc)) != 0)
                return ret_err(EFAULT);
            k_sigcontext_t *sc = &uc.uc_mcontext;
            cur->saved_user_r8  = sc->r8;
            cur->saved_user_r9  = sc->r9;
            cur->saved_user_r10 = sc->r10;
            cur->saved_user_r11 = sc->r11;
            cur->saved_user_r12 = sc->r12;
            cur->saved_user_r13 = sc->r13;
            cur->saved_user_r14 = sc->r14;
            cur->saved_user_r15 = sc->r15;
            cur->saved_user_rdi = sc->rdi;
            cur->saved_user_rsi = sc->rsi;
            cur->saved_user_rbp = sc->rbp;
            cur->saved_user_rbx = sc->rbx;
            cur->saved_user_rdx = sc->rdx;
            cur->saved_user_rcx = sc->rcx;
            cur->saved_user_rip = sc->rip;
            cur->saved_user_rsp = sc->rsp;
            cur->saved_sig_mask = uc.uc_sigmask[0];
            rebuild_syscall_frame(cur);
            syscall_user_rsp_saved = sc->rsp;
            return sc->rax;
        }
        case SYS_resolve: { /* resolve(hostname, out_ip_be) - full resolver: hosts then DNS; hostname user ptr, out_ip_be user ptr to uint32_t */
            const char *host_u = (const char *)(uintptr_t)a1;
            uint32_t *out_u = (uint32_t *)(uintptr_t)a2;
            if (!host_u || !out_u || !user_range_ok(host_u, 1) || !user_range_ok(out_u, 4))
                return ret_err(EFAULT);
            static int resolve_dbg_left = 8;
            char host[256];
            size_t i = 0;
            for (; i < sizeof(host) - 1; i++) {
                char c;
                if (copy_from_user_raw(&c, host_u + i, 1) != 0) return ret_err(EFAULT);
                host[i] = c;
                if (c == '\0') break;
            }
            host[sizeof(host) - 1] = '\0';
            if (i >= sizeof(host) - 1) return ret_err(ENAMETOOLONG);

            /* Ensure net stack is initialized before reading dns/gw fields.
               Otherwise g_net.{dns_be,gw_be} can be 0 and resolver returns EIO. */
            if (net_stack_init() != 0) return ret_err(ENETDOWN);
            uint32_t dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
            if (!dns_be) return ret_err(ENETDOWN);
            if (resolve_dbg_left-- > 0) {
                klogprintf("resolve: host=%s ip=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u use_dns=%u.%u.%u.%u\n",
                    host,
                    (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                    (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                    (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                    (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF),
                    (unsigned)((g_net.dns_be >> 24) & 0xFF), (unsigned)((g_net.dns_be >> 16) & 0xFF),
                    (unsigned)((g_net.dns_be >> 8) & 0xFF), (unsigned)(g_net.dns_be & 0xFF),
                    (unsigned)((dns_be >> 24) & 0xFF), (unsigned)((dns_be >> 16) & 0xFF),
                    (unsigned)((dns_be >> 8) & 0xFF), (unsigned)(dns_be & 0xFF));
            }
            /* No 10.0.2.3 fallback: bridged/NAT would use wrong DNS */
            uint32_t ip_be;
            if (kernel_resolve_full(host, dns_be, &ip_be) != 0) return ret_err(EIO);
            /* User ABI: same as sockaddr_in.sin_addr / in_addr_t on x86_64 (LE memory = wire order). */
            {
                uint32_t ip_user = be32(ip_be);
                if (copy_to_user_safe(out_u, &ip_user, 4) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        default:
            /* Keep unknown syscalls silent to avoid console stalls under heavy userland probing. */
            (void)a4; (void)a5; (void)a6;
            return ret_err(ENOSYS);
    }
}
