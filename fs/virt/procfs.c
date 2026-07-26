#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <fs.h>
#include <procfs.h>
#include <heap.h>
#include <ext2.h>
#include <stat.h>
#include <spinlock.h>
#include <thread.h>
#include <process.h>
#include <rtc.h>
#include <sysinfo.h>
#include <axonos.h>
#include <smp.h>
#include <usb.h>
#include <scsi.h>
#include <pci.h>
#include <devfs.h>
#include <vga.h>
#include <pit.h>
#include <loadavg.h>
#include <exec.h>
#include <user_vma.h>
#include <syscall.h>

struct procfs_handle {
	int kind; /* 1=root, 2=pid_dir, 3=pid_file, 4=symlink, 5=pid_fd_dir, 6=pid_fd_link, 7=plain, 8=proc_sys_dir, 9=proc_sys_file */
	int pid;
	int file_id; /* pid_file: 0=cmdline,1=stat,2=status,3=statm; sys/plain: ids; pid_fd_link: fd number */
	size_t pos;
	int is_task;
	char *cache;
	size_t cache_len;
};

static struct fs_driver procfs_driver;
static struct fs_driver_ops procfs_ops;
static spinlock_t procfs_lock = { 0 };

/* Linux /proc/<pid>: pid is TGID. Resolve process leader, else fall back to tid. */
static thread_t *procfs_thread_by_id(int id) {
    if (id <= 0) return NULL;
    process_t *p = process_find((uint64_t)(unsigned)id);
    if (p && p->leader) {
        if (p->leader->state != THREAD_TERMINATED)
            return p->leader;
        if (p->state == PROCESS_ZOMBIE)
            return p->leader;
    }
    thread_t *t = thread_get(id);
    if (!t || t->ring != 3) return NULL;
    if (t->state == THREAD_TERMINATED) {
        if (!t->process || t->process->state != PROCESS_ZOMBIE)
            return NULL;
    }
    return t;
}

static int procfs_tgid(const thread_t *t) {
    if (!t) return 0;
    if (t->process)
        return (int)t->process->pid;
    return (int)(t->tid ? t->tid : 0);
}

/* True if this thread should appear as /proc/<tgid> (one entry per TGID). */
static int procfs_is_tgid_dir(const thread_t *t) {
    if (!t || t->tid == 0 || t->ring != 3)
        return 0;
    if (t->state == THREAD_TERMINATED) {
        if (!t->process || t->process->state != PROCESS_ZOMBIE)
            return 0;
    }
    if (t->process) {
        if (t->process->leader)
            return t->process->leader == t;
        /* No leader pointer: only the lowest-tid member of the group. */
        int cnt = thread_get_count();
        for (int i = 0; i < cnt; i++) {
            thread_t *o = thread_get_by_index(i);
            if (!o || o->process != t->process)
                continue;
            if (o->tid && o->tid < t->tid)
                return 0;
        }
        return 1;
    }
    /* Orphan ring-3 thread: publish by tid, unless a real process owns that pid. */
    if (process_find((uint64_t)(unsigned)t->tid))
        return 0;
    return 1;
}

static int procfs_append_dirent(char **buf, size_t *len, size_t *cap,
                                const char *name, uint32_t ino, uint8_t ftype) {
    if (!buf || !len || !cap || !name)
        return -1;
    size_t namelen = strlen(name);
    if (namelen == 0 || namelen > 255)
        return -1;
    size_t rec_len = (8 + namelen + 3) & ~3u;
    if (*len + rec_len > *cap) {
        size_t ncap = *cap ? *cap * 2 : 4096;
        while (ncap < *len + rec_len)
            ncap *= 2;
        char *nbuf = (char *)kmalloc(ncap);
        if (!nbuf)
            return -1;
        if (*buf && *len)
            memcpy(nbuf, *buf, *len);
        if (*buf)
            kfree(*buf);
        *buf = nbuf;
        *cap = ncap;
    }
    uint8_t *out = (uint8_t *)(*buf + *len);
    memset(out, 0, rec_len);
    struct ext2_dir_entry de;
    de.inode = ino;
    de.rec_len = (uint16_t)rec_len;
    de.name_len = (uint8_t)namelen;
    de.file_type = ftype;
    memcpy(out, &de, 8);
    memcpy(out + 8, name, namelen);
    *len += rec_len;
    return 0;
}

/* Snapshot /proc root so getdents byte offsets stay stable (no duplicate PIDs). */
static int procfs_build_root_dir(struct procfs_handle *h) {
    if (!h)
        return -1;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    static const char *top[] = {
        "meminfo", "cpuinfo", "uptime", "loadavg", "mounts", "filesystems",
        "stat", "partitions", "sys", "bus", "tty", "ttydebug", "net", "scsi"
    };
    for (size_t ti = 0; ti < sizeof(top) / sizeof(top[0]); ti++) {
        const char *name = top[ti];
        uint8_t ft = (strcmp(name, "sys") == 0 || strcmp(name, "bus") == 0 ||
                      strcmp(name, "tty") == 0 || strcmp(name, "net") == 0 ||
                      strcmp(name, "scsi") == 0)
                         ? EXT2_FT_DIR
                         : EXT2_FT_REG_FILE;
        if (procfs_append_dirent(&buf, &len, &cap, name,
                                 (uint32_t)(1000 + (uint32_t)ti), ft) != 0) {
            if (buf)
                kfree(buf);
            return -1;
        }
    }

    /* Dedup by TGID — bitmap covers typical userspace pid space. */
    enum { SEEN_MAX = 4096 };
    uint8_t seen[(SEEN_MAX + 7) / 8];
    memset(seen, 0, sizeof(seen));
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!procfs_is_tgid_dir(t))
            continue;
        int tgid = procfs_tgid(t);
        if (tgid <= 0)
            continue;
        if (tgid < SEEN_MAX) {
            unsigned bi = (unsigned)tgid;
            if (seen[bi >> 3] & (uint8_t)(1u << (bi & 7)))
                continue;
            seen[bi >> 3] |= (uint8_t)(1u << (bi & 7));
        } else {
            /* Rare high pid: linear check against already-emitted numeric names. */
            char needle[32];
            int nl = snprintf(needle, sizeof(needle), "%d", tgid);
            if (nl <= 0)
                continue;
            int dup = 0;
            size_t off = 0;
            while (off + 8 <= len) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry *)(buf + off);
                if (de->rec_len < 8)
                    break;
                if (de->name_len == (uint8_t)nl &&
                    memcmp(buf + off + 8, needle, (size_t)nl) == 0) {
                    dup = 1;
                    break;
                }
                off += de->rec_len;
            }
            if (dup)
                continue;
        }
        char namebuf[32];
        int nlen = snprintf(namebuf, sizeof(namebuf), "%d", tgid);
        if (nlen <= 0)
            continue;
        if (procfs_append_dirent(&buf, &len, &cap, namebuf,
                                 (uint32_t)((uint32_t)(tgid + 1) & 0xffffffffu),
                                 EXT2_FT_DIR) != 0) {
            if (buf)
                kfree(buf);
            return -1;
        }
    }
    h->cache = buf;
    h->cache_len = len;
    return 0;
}

static void procfs_sanitize_comm(char *comm, size_t cap) {
    if (!comm || cap == 0) return;
    /* Linux get_task_comm / proc_task_name: '(' ')' never appear raw in (comm). */
    for (size_t i = 0; i < cap && comm[i]; i++) {
        if (comm[i] == '(' || comm[i] == ')' || comm[i] == ' ' ||
            comm[i] == '\n' || comm[i] == '\t')
            comm[i] = '_';
    }
    if (!comm[0]) {
        comm[0] = '?';
        if (cap > 1) comm[1] = '\0';
    }
}

static ssize_t procfs_show_cmdline(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = procfs_thread_by_id(pid);
    if (!t) {
        /* Empty cmdline is OK; never leave parsers with garbage. */
        if (size > 0) buf[0] = '\0';
        return (size > 0) ? 1 : 0;
    }
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    size_t len = strlen(comm);
    if (len + 1 > size) len = (size > 0) ? (size - 1) : 0;
    memcpy(buf, comm, len);
    if (len < size) buf[len++] = '\0';
    return (ssize_t)len;
}

static char procfs_state_char(const thread_t *t) {
    if (!t) return 'Z';
    switch (t->state) {
        case THREAD_RUNNING:
        case THREAD_READY: return 'R';
        case THREAD_BLOCKED:
        case THREAD_SLEEPING: return 'S';
        case THREAD_TERMINATED: return 'Z';
        default: return 'S';
    }
}

struct procfs_proc_mem {
    uint64_t vsize_bytes;
    unsigned long size_pages;
    unsigned long rss_pages;
    unsigned long data_pages;
    unsigned long stack_pages;
};

static unsigned long procfs_bytes_to_pages(uint64_t bytes) {
    return (unsigned long)((bytes + 4095ull) / 4096ull);
}

static void procfs_calc_proc_mem(thread_t *t, struct procfs_proc_mem *m) {
    memset(m, 0, sizeof(*m));
    if (!t)
        return;

    uint64_t vma_bytes = (uint64_t)user_vma_total_size_for_mm(t);
    uint64_t bytes = vma_bytes;
    uint64_t data_bytes = 0;
    if (t->user_brk_cur > t->user_brk_base)
        data_bytes = (uint64_t)(t->user_brk_cur - t->user_brk_base);

    uint64_t stack_bytes = 0;
    if (t->user_stack_limit > t->user_stack_base)
        stack_bytes = t->user_stack_limit - t->user_stack_base;
    else if (t->ring == 3)
        stack_bytes = USER_STACK_SIZE;

    uint64_t tls_bytes = (t->ring == 3 && t->user_fs_base != 0) ? USER_TLS_SIZE : 0;
    bytes += data_bytes + stack_bytes + tls_bytes;
    if (bytes == 0 && t->ring == 3)
        bytes = 16ull * 4096ull;

    uint64_t rss_bytes = 0;
    if (t->ring == 3) {
        uint64_t resident_vma = vma_bytes;
        if (resident_vma > (4ull * 1024ull * 1024ull))
            resident_vma = 4ull * 1024ull * 1024ull;
        uint64_t resident_stack = stack_bytes;
        if (resident_stack > (256ull * 1024ull))
            resident_stack = 256ull * 1024ull;
        uint64_t resident_tls = tls_bytes ? (64ull * 1024ull) : 0;
        rss_bytes = resident_vma + data_bytes + resident_stack + resident_tls;
        if (rss_bytes < 16ull * 1024ull)
            rss_bytes = 16ull * 1024ull;
        if (rss_bytes > bytes)
            rss_bytes = bytes;
    }

    m->vsize_bytes = bytes;
    m->size_pages = procfs_bytes_to_pages(bytes);
    m->rss_pages = procfs_bytes_to_pages(rss_bytes);
    m->data_pages = procfs_bytes_to_pages(data_bytes + tls_bytes);
    m->stack_pages = procfs_bytes_to_pages(stack_bytes);
}

static uint64_t procfs_sum_unique_user_rss_kb(void) {
    void *seen_mm[128];
    int seen_count = 0;
    uint64_t rss_kb = 0;
    int n = thread_get_count();

    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3 || t->state == THREAD_TERMINATED)
            continue;

        void *key = t->mm ? (void *)t->mm : (void *)t;
        int seen = 0;
        for (int j = 0; j < seen_count; j++) {
            if (seen_mm[j] == key) {
                seen = 1;
                break;
            }
        }
        if (seen)
            continue;
        if (seen_count < (int)(sizeof(seen_mm) / sizeof(seen_mm[0])))
            seen_mm[seen_count++] = key;

        struct procfs_proc_mem mem;
        procfs_calc_proc_mem(t, &mem);
        rss_kb += ((uint64_t)mem.rss_pages * 4096ull) / 1024ull;
    }

    return rss_kb;
}

static ssize_t procfs_show_stat(char *buf, size_t size, void *priv) {
    struct procfs_handle *h = (struct procfs_handle *)priv;
    int pid = h ? h->pid : 0;
    if (!buf || size == 0) return 0;
    thread_t *t = procfs_thread_by_id(pid);
    /*
     * BusyBox ps does strchr(buf, ')') then *p = 0 with no NULL check.
     * An empty / missing-paren line → #PF at cr2=0. Always emit Linux form.
     */
    if (!t) {
        int written = snprintf(buf, size,
            "%d (unknown) Z 0 0 0 0 0 "
            "0 0 0 0 0 0 0 0 0 "
            "0 0 0 0 0 0 0 "
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
            "0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            pid);
        if (written < 0) return 0;
        size_t w = (size_t)written;
        if (w > size) w = size;
        return (ssize_t)w;
    }
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    {
        char *slash = strrchr(comm, '/');
        if (slash && slash[1]) memmove(comm, slash + 1, strlen(slash + 1) + 1);
        if (strlen(comm) > 15) comm[15] = '\0';
        procfs_sanitize_comm(comm, sizeof(comm));
    }
    int ppid = (t->parent_tid >= 0) ? t->parent_tid : 0;
    int pgrp = (t->pgid >= 0) ? t->pgid : (int)t->tid;
    int sid = (t->sid >= 0) ? t->sid : pgrp;
    int tty_nr = 0;
    int tpgid = pgrp;
    int prio = 20 + t->nice;
    if (prio < 1) prio = 1;
    if (prio > 39) prio = 39;
    uint64_t hz = pit_get_frequency();
    if (hz == 0) hz = 1000;
    /* /proc/<pid>/stat expects USER_HZ units (typically 100). */
    uint64_t utime = 0;
    uint64_t stime = 0;
    if (t->process && h && !h->is_task) {
        /* Linux: /proc/<tgid>/stat utime/stime are thread-group totals. */
        int cnt = thread_get_count();
        for (int i = 0; i < cnt; i++) {
            thread_t *th = thread_get_by_index(i);
            if (!th || th->process != t->process) continue;
            utime += (th->utime_ticks * 100ull) / hz;
            stime += (th->stime_ticks * 100ull) / hz;
        }
    } else {
        utime = (t->utime_ticks * 100ull) / hz;
        stime = (t->stime_ticks * 100ull) / hz;
    }
    uint64_t starttime = (t->start_ticks * 100ull) / hz;
    struct procfs_proc_mem mem;
    procfs_calc_proc_mem(t, &mem);
    int written = snprintf(
        buf, size,
        "%d (%s) %c %d %d %d %d %d "
        "%u %llu %llu %llu %llu %llu %llu %lld %lld "
        "%d %d %d %d %llu %llu %lu "
        "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu "
        "%d %d %llu %llu %lld %llu %llu %llu %llu %llu %llu %llu %d\n",
        procfs_tgid(t), comm, procfs_state_char(t), ppid, pgrp, sid, tty_nr, tpgid,
        0u,
        0ull, 0ull, 0ull, 0ull,
        (unsigned long long)utime,
        (unsigned long long)stime,
        0ll, 0ll,
        prio, t->nice,
        (t->process && h && !h->is_task) ? ({ int _n=0, _c=thread_get_count(); for(int _i=0;_i<_c;_i++){ thread_t *_th=thread_get_by_index(_i); if(_th && _th->process==t->process) _n++; } _n; }) : 1, 0,
        (unsigned long long)starttime,
        (unsigned long long)mem.vsize_bytes,
        mem.rss_pages,
        ~0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull,
        17, 0,
        0ull, 0ull, 0ll,
        0ull, 0ull,
        (unsigned long long)t->user_brk_base,
        0ull, 0ull, 0ull, 0ull, 0
    );
    if (written < 0) return 0;
    /* Truncation must not drop the closing ')' or BusyBox ps #PF's. */
    if ((size_t)written >= size || !strchr(buf, ')')) {
        int stub = snprintf(buf, size, "%d (%s) %c %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            procfs_tgid(t), comm[0] ? comm : "?", procfs_state_char(t), ppid);
        if (stub < 0) return 0;
        written = stub;
    }
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_status(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = procfs_thread_by_id(pid);
    if (!t) return 0;
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    {
        char *slash = strrchr(comm, '/');
        if (slash && slash[1]) memmove(comm, slash + 1, strlen(slash + 1) + 1);
        if (strlen(comm) > 15) comm[15] = '\0';
        procfs_sanitize_comm(comm, sizeof(comm));
    }
    int ppid = (t->parent_tid >= 0) ? t->parent_tid : 0;
    int pgrp = (t->pgid >= 0) ? t->pgid : (int)t->tid;
    int sid = (t->sid >= 0) ? t->sid : pgrp;
    const char *cap_hex = (t->euid == 0) ? "000001ffffffffff" : "0000000000000000";
    struct procfs_proc_mem mem;
    procfs_calc_proc_mem(t, &mem);
    unsigned long vm_size_kb = (unsigned long)(mem.vsize_bytes / 1024ull);
    unsigned long vm_rss_kb = (unsigned long)(((uint64_t)mem.rss_pages * 4096ull) / 1024ull);
    unsigned long vm_data_kb = (unsigned long)(((uint64_t)mem.data_pages * 4096ull) / 1024ull);
    unsigned long vm_stk_kb = (unsigned long)(((uint64_t)mem.stack_pages * 4096ull) / 1024ull);
    int written = snprintf(
        buf, size,
        "Name:\t%s\n"
        "State:\t%c\n"
        "Pid:\t%d\n"
        "PPid:\t%d\n"
        "VmPeak:\t%lu kB\n"
        "VmSize:\t%lu kB\n"
        "VmRSS:\t%lu kB\n"
        "VmData:\t%lu kB\n"
        "VmStk:\t%lu kB\n"
        "Uid:\t%u\t%u\t%u\t%u\n"
        "Gid:\t%u\t%u\t%u\t%u\n"
        "CapInh:\t%s\n"
        "CapPrm:\t%s\n"
        "CapEff:\t%s\n"
        "CapBnd:\t%s\n"
        "CapAmb:\t0000000000000000\n"
        "Threads:\t1\n"
        "NSpgid:\t%d\n"
        "NSsid:\t%d\n",
        comm, procfs_state_char(t), procfs_tgid(t), ppid,
        vm_size_kb, vm_size_kb, vm_rss_kb, vm_data_kb, vm_stk_kb,
        (unsigned)t->uid, (unsigned)t->euid, (unsigned)t->suid, (unsigned)t->euid,
        (unsigned)t->gid, (unsigned)t->egid, (unsigned)t->sgid, (unsigned)t->egid,
        cap_hex, cap_hex, cap_hex, cap_hex,
        pgrp, sid
    );
    if (written < 0) return 0;
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_statm(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = procfs_thread_by_id(pid);
    if (!t) return 0;
    struct procfs_proc_mem mem;
    procfs_calc_proc_mem(t, &mem);
    /* size resident shared text lib data dt (pages) */
    int written = snprintf(buf, size, "%lu %lu 0 0 0 %lu 0\n",
                           mem.size_pages, mem.rss_pages, mem.data_pages);
    if (written < 0) return 0;
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_meminfo(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	int mb = sysinfo_ram_mb();
	if (mb < 0) mb = 0;
	int total_kb = mb * 1024;
	uint64_t user_rss_kb = procfs_sum_unique_user_rss_kb();
	uint64_t heap_kb = heap_used_bytes() / 1024u;
	uint64_t kernel_visible_kb = heap_kb;
	if (kernel_visible_kb > 16u * 1024u)
		kernel_visible_kb = 16u * 1024u;
	uint64_t used64 = user_rss_kb + kernel_visible_kb;
	if (used64 > (uint64_t)total_kb) used64 = (uint64_t)total_kb;
	int used_kb = (int)used64;
	int free_kb = total_kb - used_kb;
	int written = snprintf(buf, size,
		"MemTotal:       %d kB\n"
		"MemFree:        %d kB\n"
		"MemAvailable:   %d kB\n"
		"Buffers:          0 kB\n"
		"Cached:           0 kB\n"
		"SwapCached:       0 kB\n"
		"Active:        %llu kB\n"
		"Inactive:         0 kB\n"
		"Shmem:            0 kB\n"
		"Slab:          %llu kB\n"
		"SReclaimable:     0 kB\n"
		"SUnreclaim:    %llu kB\n"
		"KernelStack:      0 kB\n"
		"PageTables:       0 kB\n"
		"SwapTotal:        0 kB\n"
		"SwapFree:         0 kB\n",
		total_kb, free_kb, free_kb,
		(unsigned long long)user_rss_kb,
		(unsigned long long)heap_kb,
		(unsigned long long)heap_kb);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Kernel snprintf has no floating-point; use fixed-point text. */
static void procfs_fmt_centiseconds(uint64_t ms_whole, char *out, size_t cap) {
	uint64_t sec = ms_whole / 1000ull;
	unsigned cent = (unsigned)((ms_whole % 1000ull) * 100ull / 1000ull);
	if (cent > 99u) cent = 99u;
	snprintf(out, cap, "%llu.%02u", (unsigned long long)sec, cent);
}

static void procfs_fmt_load_scaled(unsigned long scaled, char *out, size_t cap) {
	unsigned long whole = scaled / 65536ul;
	unsigned long cent = (scaled % 65536ul) * 100ul / 65536ul;
	if (cent > 99ul) cent = 99ul;
	snprintf(out, cap, "%lu.%02lu", whole, cent);
}

static ssize_t procfs_show_uptime(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	uint64_t ms = (uint64_t)pit_get_time_ms();
	char up[32];
	procfs_fmt_centiseconds(ms, up, sizeof(up));
	int written = snprintf(buf, size, "%s 0.00\n", up);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Linux /proc/loadavg — busybox uptime uses this for "load average" */
static ssize_t procfs_show_loadavg(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	unsigned long av[3];
	loadavg_get_user(av);
	char s1[24], s2[24], s3[24];
	procfs_fmt_load_scaled(av[0], s1, sizeof(s1));
	procfs_fmt_load_scaled(av[1], s2, sizeof(s2));
	procfs_fmt_load_scaled(av[2], s3, sizeof(s3));
	int run = thread_runnable_nonidle_count();
	if (run < 0)
		run = 0;
	int nthr = thread_get_count();
	if (nthr < 1)
		nthr = 1;
	int written = snprintf(buf, size, "%s %s %s %d/%d %d\n", s1, s2, s3, run, nthr, nthr);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Minimal /proc/stat — nproc and some tools count cpu0..cpuN-1 lines */
static ssize_t procfs_show_kernel_stat(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	int n = smp_cpu_count();
	if (n < 1)
		n = 1;
	uint64_t user = 0, nice = 0, system = 0, idle = 0;
	thread_cpu_times_user_hz(&user, &nice, &system, &idle);
	/* Linux btime: seconds since Epoch at boot. CMOS→unix is optional; 0 is valid. */
	uint64_t btime = 0;
	size_t w = 0;
	int wr = snprintf(buf + w, (w < size) ? (size - w) : 0,
			  "cpu  %llu %llu %llu %llu 0 0 0 0 0 0\n",
			  (unsigned long long)user,
			  (unsigned long long)nice,
			  (unsigned long long)system,
			  (unsigned long long)idle);
	if (wr < 0) return 0;
	w += (size_t)wr;
	for (int i = 0; i < n && w < size; i++) {
		uint64_t cu = 0, cn = 0, cs = 0, ci = 0;
		thread_cpu_times_user_hz_cpu(i, &cu, &cn, &cs, &ci);
		wr = snprintf(buf + w, (w < size) ? (size - w) : 0,
			      "cpu%d %llu %llu %llu %llu 0 0 0 0 0 0\n", i,
			      (unsigned long long)cu,
			      (unsigned long long)cn,
			      (unsigned long long)cs,
			      (unsigned long long)ci);
		if (wr < 0)
			break;
		w += (size_t)wr;
	}
	/* Always emit the trailer htop/glibc expect — even if cpu lines filled the buf. */
	{
		char trailer[160];
		int tl = snprintf(trailer, sizeof(trailer),
				  "intr 0\nctxt 0\nbtime %llu\nprocesses %d\nprocs_running %d\nprocs_blocked 0\n",
				  (unsigned long long)btime,
				  thread_get_count(), thread_runnable_nonidle_count());
		if (tl > 0) {
			size_t need = (size_t)tl;
			if (w + need > size) {
				/* Prefer keeping btime over the last per-cpu lines. */
				if (need < size) {
					w = size - need;
					memcpy(buf + w, trailer, need);
					w = size;
				}
			} else {
				memcpy(buf + w, trailer, need);
				w += need;
			}
		}
	}
	if (w > size)
		w = size;
	return (ssize_t)w;
}

static ssize_t procfs_show_partitions(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	/* Linux-like /proc/partitions format (minimal). */
	size_t w = 0;
	w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0, "major minor  #blocks  name\n");
	int n = devfs_block_count();
	for (int i = 0; i < n; i++) {
		char name[64];
		int did = -1;
		uint32_t sectors = 0;
		if (devfs_block_get(i, name, sizeof(name), &did, &sectors) != 0) continue;
		/* Show both SATA-like sdX and legacy IDE-like hdN nodes. */
		int is_sd = (name[0] == 's' && name[1] == 'd');
		int is_hd = (name[0] == 'h' && name[1] == 'd');
		if (!is_sd && !is_hd) continue;
		/* blocks in 1K units like Linux: sectors * 512 / 1024 == sectors/2 */
		uint32_t blocks = sectors / 2;
		/* fake major/minor; enough for userland tools that just parse size+name */
		int major = is_hd ? 3 : 8;
		int minor = did >= 0 ? did * 16 : i * 16;
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
							   "%5d %5d %8u %s\n", major, minor, (unsigned)blocks, name);
		if (written < 0) break;
		w += (size_t)written;
		if (w >= size) { w = size; break; }
	}
	return (ssize_t)w;
}

/* Map internal driver names to Linux /proc/mounts fstype strings. */
static const char *procfs_mount_fstype(const char *drv_name, int is_root) {
    if (is_root)
        return "rootfs";
    if (!drv_name)
        return "unknown";
    if (strcmp(drv_name, "procfs") == 0)
        return "proc";
    if (strcmp(drv_name, "devfs") == 0)
        return "devtmpfs";
    if (strcmp(drv_name, "sysfs") == 0)
        return "sysfs";
    if (strcmp(drv_name, "ramfs") == 0)
        return "ramfs";
    return drv_name;
}

/* Linux-like /proc/mounts backed by VFS mount table */
static ssize_t procfs_show_mounts(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    size_t w = 0;
    int n = fs_mount_count();
    int have_root = 0;
    for (int i = 0; i < n; i++) {
        char mpath[64];
        char drv[32];
        if (fs_mount_get(i, mpath, sizeof(mpath), drv, sizeof(drv)) != 0) continue;
        int is_root = (mpath[0] == '/' && mpath[1] == '\0');
        if (is_root)
            have_root = 1;
        const char *fstype = procfs_mount_fstype(drv, is_root);
        /* Linux: source mountpoint fstype options dump pass */
        const char *src = is_root ? "rootfs" : fstype;
        int wr = snprintf(buf + w, (w < size) ? (size - w) : 0,
                          "%s %s %s rw,relatime 0 0\n",
                          src, mpath, fstype);
        if (wr < 0) break;
        w += (size_t)wr;
        if (w >= size) { w = size; break; }
    }
    /* BusyBox mount(1) requires a "/" line in /proc/mounts. */
    if (!have_root && w < size) {
        int wr = snprintf(buf + w, size - w, "rootfs / rootfs rw 0 0\n");
        if (wr > 0)
            w += (size_t)wr;
    }
    if (w > size)
        w = size;
    return (ssize_t)w;
}

/* Linux /proc/filesystems — OpenRC sysfs init greps for "sysfs" here. */
static ssize_t procfs_show_filesystems(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    static const char text[] =
        "nodev\tsysfs\n"
        "nodev\tproc\n"
        "nodev\tdevtmpfs\n"
        "nodev\ttmpfs\n"
        "nodev\tramfs\n"
        "\tvfat\n"
        "\tmsdos\n"
        "\text2\n";
    size_t len = sizeof(text) - 1;
    if (len > size) len = size;
    memcpy(buf, text, len);
    return (ssize_t)len;
}

/* Linux-like /proc/scsi/scsi: Host, Channel, Id, Lun, Type, Vendor, Model, Rev */
static ssize_t procfs_show_scsi(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	size_t w = 0;
	int n = scsi_lun_count();
	for (int i = 0; i < n; i++) {
		char vendor[32], product[32], revision[16];
		uint32_t sectors;
		int disk_id;
		char dev_letter;
		if (scsi_lun_get_info(i, vendor, sizeof(vendor), product, sizeof(product),
		                      revision, sizeof(revision), &sectors, &disk_id, &dev_letter) != 0)
			continue;
		uint32_t size_mb = sectors / 2048;
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
			"Host: scsi Channel: 00 Id: %02d Lun: 00\n  Vendor: %-8s Model: %-16s Rev: %-4s\n  Type:   Direct-Access    ANSI SCSI revision: 05\n  /dev/sd%c: %u sectors (%u MiB)\n",
			disk_id, vendor, product, revision, dev_letter, (unsigned)sectors, size_mb);
		if (written < 0) break;
		w += (size_t)written;
		if (w >= size) { w = size; break; }
	}
	if (n == 0)
		w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0, "(no SCSI disks)\n");
	return (ssize_t)w;
}

/* Linux /proc/bus/pci/devices (legacy alias: /proc/pci) */
static ssize_t procfs_show_pci(char *buf, size_t size, void *priv) {
	(void)priv;
	return pci_show_proc_devices(buf, size);
}

/* CPU info */
static ssize_t procfs_show_cpuinfo(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	int ncpu = smp_cpu_count();
	if (ncpu < 1)
		ncpu = 1;
	const char *model = sysinfo_cpu_name();
	size_t w = 0;
	for (int i = 0; i < ncpu && w < size; i++) {
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
			"processor\t: %d\n"
			"model name\t: %s\n"
			"cpu cores\t: %d\n",
			i, model ? model : "Unknown", ncpu);
		if (written < 0)
			break;
		w += (size_t)written;
		if (w >= size) {
			w = size;
			break;
		}
		if (i + 1 < ncpu && w + 1 < size)
			buf[w++] = '\n';
	}
	return (ssize_t)w;
}

/* Simple proc/sys storage: kernel.hostname */
static char proc_hostname[64] = OS_NAME;
static ssize_t procfs_show_hostname(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	size_t len = strlen(proc_hostname);
	if (len > size) len = size;
	memcpy(buf, proc_hostname, len);
	if (len < size) buf[len++] = '\n';
	return (ssize_t)len;
}

static ssize_t procfs_store_hostname(const char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return -1;
	/* copy up to capacity-1 and trim newline */
	size_t copy_len = size;
	if (copy_len >= sizeof(proc_hostname)) copy_len = sizeof(proc_hostname) - 1;
	memcpy(proc_hostname, buf, copy_len);
	proc_hostname[copy_len] = '\0';
	/* trim trailing newline */
	if (copy_len > 0 && proc_hostname[copy_len-1] == '\n') proc_hostname[copy_len-1] = '\0';
	return (ssize_t)size;
}

static ssize_t procfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
	if (!file || !file->driver_private || !buf) return -1;
	struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
	if (!h) return -1;
	if (h->kind == 9 && h->file_id == 20) {
		/* permission: only root */
		thread_t *ct = thread_current();
		if (!ct || ct->euid != 0) return -1;
		/* accept whole buffer (ignore offset semantics for simplicity) */
		return procfs_store_hostname((const char*)buf, size, NULL);
	}
	if (h->kind == 7 && h->file_id == 60) {
		thread_t *ct = thread_current();
		if (!ct || ct->euid != 0 || offset != 0) return -1;
		return procfs_net_store_dhcp((const char *)buf, size);
	}
	return -1;
}

/* Generate /proc plain-file body for file_id (meminfo/stat/mounts/...). */
static ssize_t procfs_generate_plain(int file_id, char *buf, size_t cap) {
	if (!buf || cap == 0) return 0;
	if (file_id == 10) return procfs_show_meminfo(buf, cap, NULL);
	if (file_id == 11) return procfs_show_uptime(buf, cap, NULL);
	if (file_id == 12) return procfs_show_cpuinfo(buf, cap, NULL);
	if (file_id == 13) return procfs_show_partitions(buf, cap, NULL);
	if (file_id == 14) return procfs_show_loadavg(buf, cap, NULL);
	if (file_id == 15) return procfs_show_kernel_stat(buf, cap, NULL);
	if (file_id == 16) return procfs_show_mounts(buf, cap, NULL);
	if (file_id == 17) return procfs_show_filesystems(buf, cap, NULL);
	if (file_id == 40) return procfs_show_scsi(buf, cap, NULL);
	if (file_id == 41 || file_id == 42) return procfs_show_pci(buf, cap, NULL);
	if (file_id == 30) return usb_proc_bus_devices_show(buf, cap, NULL);
	if (file_id == 31) return devfs_tty_debug_dump(buf, cap);
	if (file_id == 50) return procfs_net_snap_tcp(buf, cap);
	if (file_id == 51) return procfs_net_snap_udp(buf, cap);
	if (file_id == 52) return procfs_net_snap_tcp6(buf, cap);
	if (file_id == 53) return procfs_net_snap_udp6(buf, cap);
	if (file_id == 54) return procfs_net_snap_raw(buf, cap);
	if (file_id == 55) return procfs_net_snap_raw6(buf, cap);
	if (file_id == 56) return procfs_net_snap_unix(buf, cap);
	if (file_id == 57) return procfs_net_snap_arp(buf, cap);
	if (file_id == 58) return procfs_net_snap_dev(buf, cap);
	if (file_id == 59) return procfs_net_snap_route(buf, cap);
	if (file_id == 60) return procfs_net_snap_dhcp(buf, cap);
	return 0;
}

/* Snapshot plain /proc file at open (or lazily on first read). */
static void procfs_fill_kind7_cache(struct procfs_handle *h, struct fs_file *f) {
	if (!h || !f || h->kind != 7 || h->cache)
		return;
	size_t cap = 4096;
	if (h->file_id >= 50 && h->file_id <= 56)
		cap = 65536;
	else if (h->file_id == 15)
		cap = 8192; /* cpu + cpu0..N + btime trailer */
	h->cache = (char *)kmalloc(cap);
	if (!h->cache)
		return;
	ssize_t full = procfs_generate_plain(h->file_id, h->cache, cap);
	if (full > 0) {
		f->size = (size_t)full;
		h->cache_len = f->size;
	} else {
		/* Keep empty snapshot (len 0) so read returns EOF, not "missing". */
		h->cache_len = 0;
		f->size = 0;
	}
}

static int procfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    return -1;
}

static int procfs_open(const char *path, struct fs_file **out_file) {
    if (!path || !out_file) return -1;
    char npath[512];
    strncpy(npath, path, sizeof(npath) - 1);
    npath[sizeof(npath) - 1] = '\0';
    size_t nlen = strlen(npath);
    while (nlen > 5 && npath[nlen - 1] == '/') {
        npath[nlen - 1] = '\0';
        nlen--;
    }
    path = npath;
    if (!(strcmp(path, "/proc") == 0 || strncmp(path, "/proc/", 6) == 0)) return -1;
    int rc = -1;
    struct fs_file *f = NULL;
    char *pp = NULL;
    struct procfs_handle *h = NULL;

    /* allocate fs_file early */
    f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -1;
    memset(f, 0, sizeof(*f));
    pp = (char*)kmalloc(strlen(path) + 1);
    if (!pp) { kfree(f); return -1; }
    memcpy(pp, path, strlen(path) + 1);
    f->path = pp;
    f->fs_private = procfs_driver.driver_data;

    /* prepare handle */
    h = (struct procfs_handle*)kmalloc(sizeof(struct procfs_handle));
    if (!h) { kfree(pp); kfree(f); return -1; }
    memset(h, 0, sizeof(*h));

    /* Determine type */
    if (strcmp(path, "/proc") == 0) {
        h->kind = 1; /* root */
        f->type = FS_TYPE_DIR;
        f->size = 0;
        if (procfs_build_root_dir(h) == 0)
            f->size = h->cache_len;
    } else {
		/* parse /proc/<id>[/name...] */
		const char *p = path + 6; /* after "/proc/" */
		const char *slash = strchr(p, '/');
		size_t first_len = slash ? (size_t)(slash - p) : strlen(p);
		if (first_len == 0) { kfree(h); kfree(pp); kfree(f); return -1; }
		/* handle 'self' */
		int pid = -1;
		if (first_len == 4 && strncmp(p, "self", 4) == 0) {
			thread_t *ct = thread_get_current_user();
			if (!ct) ct = thread_current();
			pid = ct ? (int)ct->tid : -1;
		} else {
			/* numeric pid? */
			char tmp[32];
			if (first_len >= sizeof(tmp)) { kfree(h); kfree(pp); kfree(f); return -1; }
			memcpy(tmp, p, first_len); tmp[first_len] = '\0';
			int ok = 1;
			for (size_t i = 0; i < first_len; i++) if (tmp[i] < '0' || tmp[i] > '9') { ok = 0; break; }
			if (ok) pid = atoi(tmp);
		}
		/* special subtree: /proc/sys/... */
		if (first_len == 3 && strncmp(p, "sys", 3) == 0) {
			if (!slash) {
				h->kind = 8; h->file_id = 0; f->type = FS_TYPE_DIR; f->size = 0;
				f->driver_private = h;
				*out_file = f;
				return 0;
			} else {
				/* parse second component */
				const char *q = slash + 1;
				const char *slash2 = strchr(q, '/');
				size_t qlen = slash2 ? (size_t)(slash2 - q) : strlen(q);
				if (qlen == 0) { kfree(h); kfree(pp); kfree(f); return -1; }
				/* only 'kernel' namespace supported */
				if (qlen == 6 && strncmp(q, "kernel", 6) == 0) {
					if (!slash2) {
						/* /proc/sys/kernel */
						h->kind = 8; h->file_id = 1; f->type = FS_TYPE_DIR; f->size = 0;
						f->driver_private = h;
						*out_file = f;
						return 0;
					} else {
						/* /proc/sys/kernel/<name> */
						const char *name = slash2 + 1;
						if (strcmp(name, "hostname") == 0) {
							h->kind = 9; h->file_id = 20; f->type = FS_TYPE_REG;
							/* size = strlen + newline */
							f->size = strlen(proc_hostname) + 1;
							f->driver_private = h;
							*out_file = f;
							return 0;
						}
					}
				}
				kfree(h); kfree(pp); kfree(f); return -1;
			}
		}
		/* top-level file: /proc/partitions (file_id 13 — 12 is cpuinfo) */
		if (first_len == 10 && strncmp(p, "partitions", 10) == 0) {
			h->kind = 7;
			h->file_id = 13;
			f->type = FS_TYPE_REG;
			f->size = 0;
			f->driver_private = h;
			procfs_fill_kind7_cache(h, f);
			*out_file = f;
			return 0;
		}
		/* /proc/scsi (directory) and /proc/scsi/scsi (file) */
		if (first_len == 4 && strncmp(p, "scsi", 4) == 0) {
			if (!slash) {
				h->kind = 13;
				f->type = FS_TYPE_DIR;
				f->size = 0;
				f->driver_private = h;
				*out_file = f;
				return 0;
			}
			if (strcmp(slash + 1, "scsi") == 0) {
				h->kind = 7;
				h->file_id = 40;
				f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			kfree(h); kfree(pp); kfree(f); return -1;
		}
		/* if path is exactly /proc/<something> and something is not a pid -> special files like /proc/meminfo or directories like sys/bus */
		if (!slash) {
			/* Could be pid dir or top-level file like meminfo/uptime */
			/* Check for meminfo/uptime */
			if (first_len == 7 && strncmp(p, "meminfo", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 10; /* meminfo */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			if (first_len == 6 && strncmp(p, "uptime", 6) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 11; /* uptime */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			if (first_len == 7 && strncmp(p, "cpuinfo", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 12; /* cpuinfo */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			if (first_len == 3 && strncmp(p, "pci", 3) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 41; /* pci */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			if (first_len == 7 && strncmp(p, "loadavg", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 14; /* loadavg */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
            if (first_len == 6 && strncmp(p, "mounts", 6) == 0) {
                h->kind = 7; f->type = FS_TYPE_REG;
                f->size = 0;
                f->driver_private = h;
                h->file_id = 16; /* mounts */
                procfs_fill_kind7_cache(h, f);
                *out_file = f;
                return 0;
            }
            if (first_len == 11 && strncmp(p, "filesystems", 11) == 0) {
                h->kind = 7; f->type = FS_TYPE_REG;
                f->size = 0;
                f->driver_private = h;
                h->file_id = 17; /* filesystems */
                procfs_fill_kind7_cache(h, f);
                *out_file = f;
                return 0;
            }
			if (first_len == 4 && strncmp(p, "stat", 4) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 15; /* kernel stat (cpu lines) */
				procfs_fill_kind7_cache(h, f);
				*out_file = f;
				return 0;
			}
			if (first_len == 3 && strncmp(p, "sys", 3) == 0) {
				/* /proc/sys root directory */
				h->kind = 8; h->file_id = 0; f->type = FS_TYPE_DIR; f->size = 0;
				*out_file = f;
				return 0;
			}
            if (first_len == 3 && strncmp(p, "tty", 3) == 0) {
                /* /proc/tty root directory (minimal) */
                h->kind = 12; f->type = FS_TYPE_DIR; f->size = 0;
                f->driver_private = h;
                *out_file = f;
                return 0;
            }
            if (first_len == 8 && strncmp(p, "ttydebug", 8) == 0) {
                h->kind = 7; h->file_id = 31; f->type = FS_TYPE_REG; f->size = 4096;
                f->driver_private = h;
                *out_file = f;
                return 0;
            }
            if (first_len == 3 && strncmp(p, "bus", 3) == 0) {
                /* /proc/bus root directory */
                h->kind = 10; f->type = FS_TYPE_DIR; f->size = 0;
                *out_file = f;
                return 0;
            }
            if (first_len == 3 && strncmp(p, "net", 3) == 0) {
                /* /proc/net — netstat, ss */
                h->kind = 14; f->type = FS_TYPE_DIR; f->size = 0;
                f->driver_private = h;
                *out_file = f;
                return 0;
            }
			if (pid < 0) { kfree(h); kfree(pp); kfree(f); return -1; }
			/* pid directory */
			h->kind = 2;
			h->pid = pid;
			f->type = FS_TYPE_DIR;
			f->size = 0;
		} else {
			/* deeper paths: could be /proc/<pid>/cmdline, /proc/<pid>/stat, /proc/<pid>/fd, /proc/<pid>/fd/<n> */
			const char *rest = slash + 1;
            /* /proc/bus/... */
            if (first_len == 3 && strncmp(p, "bus", 3) == 0) {
                if (strncmp(rest, "usb", 3) == 0 && (rest[3] == '\0' || rest[3] == '/')) {
                    if (rest[3] == '\0') {
                        h->kind = 11; f->type = FS_TYPE_DIR; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                    const char *rest2 = rest + 4; /* after usb/ */
                    if (strncmp(rest2, "devices", 7) == 0 && rest2[7] == '\0') {
                        h->kind = 7; h->file_id = 30; f->type = FS_TYPE_REG; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                }
                if (strncmp(rest, "pci", 3) == 0 && (rest[3] == '\0' || rest[3] == '/')) {
                    if (rest[3] == '\0') {
                        h->kind = 16; f->type = FS_TYPE_DIR; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                    const char *rest2 = rest + 4; /* after pci/ */
                    if (strncmp(rest2, "devices", 7) == 0 && rest2[7] == '\0') {
                        h->kind = 7; h->file_id = 42; f->type = FS_TYPE_REG; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
            /* /proc/tty/... */
            if (first_len == 3 && strncmp(p, "tty", 3) == 0) {
                if (strcmp(rest, "drivers") == 0) {
                    h->kind = 7; h->file_id = 31; f->type = FS_TYPE_REG; f->size = 4096;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                if (*rest == '\0') {
                    h->kind = 12; f->type = FS_TYPE_DIR; f->size = 0;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
            /* /proc/net/{tcp,udp,...} */
            if (first_len == 3 && strncmp(p, "net", 3) == 0) {
                if (strchr(rest, '/')) { kfree(h); kfree(pp); kfree(f); return -1; }
                int fid = -1;
                if (strcmp(rest, "tcp") == 0) fid = 50;
                else if (strcmp(rest, "udp") == 0) fid = 51;
                else if (strcmp(rest, "tcp6") == 0) fid = 52;
                else if (strcmp(rest, "udp6") == 0) fid = 53;
                else if (strcmp(rest, "raw") == 0) fid = 54;
                else if (strcmp(rest, "raw6") == 0) fid = 55;
                else if (strcmp(rest, "unix") == 0) fid = 56;
                else if (strcmp(rest, "arp") == 0) fid = 57;
                else if (strcmp(rest, "dev") == 0) fid = 58;
                else if (strcmp(rest, "route") == 0) fid = 59;
                else if (strcmp(rest, "dhcp") == 0) fid = 60;
                if (fid >= 0) {
                    h->kind = 7;
                    h->file_id = fid;
                    f->type = FS_TYPE_REG;
                    f->size = 65536;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
			if (pid < 0) { kfree(h); kfree(pp); kfree(f); return -1; }
			/* check for fd directory */
			if (strncmp(rest, "task", 4) == 0 && (rest[4] == '\0' || rest[4] == '/')) {
				if (rest[4] == '\0') {
					h->kind = 15;
					h->pid = pid;
					f->type = FS_TYPE_DIR;
					f->size = 0;
				} else {
					const char *tidp = rest + 5;
					char tmp[32];
					size_t tl = strlen(tidp);
					if (tl == 0 || tl >= sizeof(tmp)) {
						kfree(h); kfree(pp); kfree(f); return -1;
					}
					memcpy(tmp, tidp, tl);
					tmp[tl] = '\0';
					char *slash3 = strchr(tmp, '/');
					int tid = -1;
					if (slash3) *slash3 = '\0';
					int ok = 1;
					for (size_t i = 0; tmp[i]; i++)
						if (tmp[i] < '0' || tmp[i] > '9') { ok = 0; break; }
					if (!ok) { kfree(h); kfree(pp); kfree(f); return -1; }
					tid = atoi(tmp);
					if (!slash3) {
						h->kind = 16;
						h->pid = tid;
						f->type = FS_TYPE_DIR;
						f->size = 0;
					} else {
						const char *trest = tidp + (slash3 - tmp) + 1;
						if (strncmp(trest, "stat", 4) == 0 && trest[4] == '\0')
							h->file_id = 1;
						else if (strncmp(trest, "status", 6) == 0 && trest[6] == '\0')
							h->file_id = 2;
						else if (strncmp(trest, "statm", 5) == 0 && trest[5] == '\0')
							h->file_id = 3;
						else if (strncmp(trest, "cmdline", 7) == 0 && trest[7] == '\0')
							h->file_id = 0;
						else { kfree(h); kfree(pp); kfree(f); return -1; }
						h->kind = 3;
						h->pid = tid;
						h->is_task = 1;
						f->type = FS_TYPE_REG;
					}
				}
				if (h->kind == 3 && f->type == FS_TYPE_REG) {
					size_t cap = 4096;
					h->cache = (char *)kmalloc(cap);
					if (h->cache) {
						ssize_t full = 0;
						if (h->file_id == 0)
							full = procfs_show_cmdline(h->cache, cap, (void *)(uintptr_t)h->pid);
						else if (h->file_id == 1)
							full = procfs_show_stat(h->cache, cap, h);
						else if (h->file_id == 2)
							full = procfs_show_status(h->cache, cap, (void *)(uintptr_t)h->pid);
						else if (h->file_id == 3)
							full = procfs_show_statm(h->cache, cap, (void *)(uintptr_t)h->pid);
						if (full > 0) {
							f->size = (size_t)full;
							h->cache_len = f->size;
						} else {
							kfree(h->cache);
							h->cache = NULL;
						}
					}
				}
			} else if (strncmp(rest, "fd", 2) == 0 && (rest[2] == '\0' || rest[2] == '/')) {
				if (rest[2] == '\0') {
					h->kind = 5; h->pid = pid; f->type = FS_TYPE_DIR; f->size = 0;
				} else {
					/* /proc/<pid>/fd/<n> */
					const char *rest2 = rest + 3; /* after 'fd/' */
					if (!rest2) { kfree(h); kfree(pp); kfree(f); return -1; }
					/* parse fd number */
					char tmp[16];
					size_t l = strlen(rest2);
					if (l == 0 || l >= sizeof(tmp)) { kfree(h); kfree(pp); kfree(f); return -1; }
					memcpy(tmp, rest2, l); tmp[l] = '\0';
					int ok = 1;
					for (size_t i = 0; i < l; i++) if (tmp[i] < '0' || tmp[i] > '9') { ok = 0; break; }
					if (!ok) { kfree(h); kfree(pp); kfree(f); return -1; }
					int fdnum = atoi(tmp);
					h->kind = 6; h->pid = pid; h->file_id = fdnum;
					/* represent as symlink */
					f->type = FS_TYPE_REG;
					/* compute symlink size below */
					size_t cap = 512;
					char *tmpbuf = (char*)kmalloc(cap);
					if (tmpbuf) {
						/* build link target */
						thread_t *t = procfs_thread_by_id(pid);
						if (t && fdnum >= 0 && fdnum < THREAD_MAX_FD && t->fds[fdnum]) {
							const char *target = t->fds[fdnum]->path ? t->fds[fdnum]->path : "(anon)";
							size_t tlen = strlen(target);
							if (tlen >= cap) tlen = cap - 1;
							memcpy(tmpbuf, target, tlen);
							f->size = tlen;
						} else {
							const char *not = "(invalid)";
							size_t tlen = strlen(not);
							if (tlen >= cap) tlen = cap - 1;
							memcpy(tmpbuf, not, tlen);
							f->size = tlen;
						}
						kfree(tmpbuf);
					}
				}
			} else {
				/* other pid children: cmdline, stat, status, statm, mounts */
			if (strncmp(rest, "cmdline", 7) == 0 && rest[7] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 0; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "stat", 4) == 0 && rest[4] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 1; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "status", 6) == 0 && rest[6] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 2; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "statm", 5) == 0 && rest[5] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 3; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "mounts", 6) == 0 && rest[6] == '\0') {
					/* /proc/self/mounts == /proc/mounts (Linux) */
					h->kind = 7; h->file_id = 16; f->type = FS_TYPE_REG; f->size = 0;
					f->driver_private = h;
					procfs_fill_kind7_cache(h, f);
					*out_file = f;
					return 0;
				} else {
					kfree(h); kfree(pp); kfree(f); return -1;
				}
				/* compute size */
				size_t cap = 4096;
				h->cache = (char*)kmalloc(cap);
				if (h->cache) {
					ssize_t full = 0;
					if (h->file_id == 0) full = procfs_show_cmdline(h->cache, cap, (void*)(uintptr_t)h->pid);
					else if (h->file_id == 1) full = procfs_show_stat(h->cache, cap, h);
					else if (h->file_id == 2) full = procfs_show_status(h->cache, cap, (void*)(uintptr_t)h->pid);
					else if (h->file_id == 3) full = procfs_show_statm(h->cache, cap, (void*)(uintptr_t)h->pid);
					if (full > 0) {
						f->size = (size_t)full;
						h->cache_len = f->size;
					} else {
						kfree(h->cache);
						h->cache = NULL;
					}
				}
			}
		}
    }

    /* Plain /proc files: snapshot once so multi-read/getdents offsets stay stable. */
    if (h->kind == 7)
        procfs_fill_kind7_cache(h, f);

    f->driver_private = h;
    *out_file = f;
    return 0;
}

static ssize_t procfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
    if (!h) return -1;

    /* /proc root — stable snapshot built at open (byte-offset safe for getdents). */
    if (h->kind == 1) {
        if (!h->cache)
            return 0;
        if ((size_t)offset >= h->cache_len)
            return 0;
        size_t to_copy = h->cache_len - (size_t)offset;
        if (to_copy > size)
            to_copy = size;
        memcpy(buf, h->cache + offset, to_copy);
        return (ssize_t)to_copy;
    }

    if (h->kind == 2) {
        /* /proc/<pid> dir: entries cmdline/stat/status/statm */
        const char *names[5] = { "task", "cmdline", "stat", "status", "statm" };
        const uint8_t types[5] = { EXT2_FT_DIR, EXT2_FT_REG_FILE, EXT2_FT_REG_FILE, EXT2_FT_REG_FILE, EXT2_FT_REG_FILE };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        /* if pid has fd dir, include 'fd' as directory entry first */
        thread_t *ttmp = procfs_thread_by_id(h->pid);
        int include_fd = (ttmp != NULL);
        int start_idx = 0;
        if (include_fd) {
            /* add fd entry before others */
            const char *fname = "fd";
            size_t namelen = strlen(fname);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; }
            else {
                if (written < size) {
                    size_t entry_off = 0;
                    if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
                    uint8_t tmpent[512];
                    if (rec_len <= sizeof(tmpent)) {
                        for (size_t zi = 0; zi < sizeof(tmpent); zi++) tmpent[zi] = 0;
                        struct ext2_dir_entry de;
                        de.inode = 2;
                        de.rec_len = (uint16_t)rec_len;
                        de.name_len = (uint8_t)namelen;
                        de.file_type = EXT2_FT_DIR;
                        memcpy(tmpent, &de, 8);
                        memcpy(tmpent + 8, fname, namelen);
                        size_t avail = size - written;
                        size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                        if (tocopy > avail) tocopy = avail;
                        if (tocopy > 0) memcpy(out + written, tmpent + entry_off, tocopy);
                        written += tocopy;
                    }
                }
            }
            pos += rec_len;
        }
        for (int idx = 0; idx < 5; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) { pos += rec_len; continue; }
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(idx + 1);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = types[idx];
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

	/* /proc/sys directory listing */
	if (h->kind == 8) {
        const char *names_root[] = { "kernel" };
        const char *names_kernel[] = { "hostname" };
        const char *const *names = (h->file_id == 1) ? names_kernel : names_root;
        int ncount = 1;
		size_t pos = 0;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int idx = 0; idx < ncount; idx++) {
			size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
			if (written >= size) break;
			size_t entry_off = 0;
			if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
			uint8_t tmp[256];
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(2000 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = (h->file_id == 1) ? EXT2_FT_REG_FILE : EXT2_FT_DIR;
            for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
			size_t avail = size - written;
			size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
			if (tocopy > avail) tocopy = avail;
			if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
			written += tocopy;
			pos += rec_len;
		}
		return (ssize_t)written;
	}

    /* /proc/tty directory listing */
    if (h->kind == 12) {
        const char *names[] = { "drivers" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3100 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    /* /proc/net directory listing */
    if (h->kind == 14) {
        static const char *names[] = { "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "unix", "arp", "dev", "route", "dhcp" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t *)buf;
        for (size_t idx = 0; idx < sizeof(names) / sizeof(names[0]); idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) {
                pos += rec_len;
                continue;
            }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(4000u + (uint32_t)idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    /* /proc/bus directory listing */
    if (h->kind == 10) {
        const char *names[] = { "usb", "pci" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 2; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3000 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    /* /proc/bus/pci directory listing */
    if (h->kind == 16) {
        const char *names[] = { "devices" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3100 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    /* /proc/scsi directory listing */
    if (h->kind == 13) {
        /* /proc/scsi: list file "scsi" */
        const char *names[] = { "scsi" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3200 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
        }
        return (ssize_t)written;
    }
    if (h->kind == 11) {
        const char *names[] = { "devices" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3010 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    /* regular file */
    if (h->kind == 3) {
        if (!h->cache) return 0;
        if ((size_t)offset >= h->cache_len) return 0;
        size_t to_copy = h->cache_len - (size_t)offset;
        if (to_copy > size) to_copy = size;
        memcpy(buf, h->cache + offset, to_copy);
        return (ssize_t)to_copy;
    }

	/* /proc/<pid>/task — list thread ids */
	if (h->kind == 15) {
        if (offset == 0) h->file_id = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        
        int cnt = thread_get_count();
        for (int i = h->file_id; i < cnt; i++) {
            thread_t *t = thread_get_by_index(i);
            if (!t || t->process == NULL || t->process->pid != (uint64_t)(unsigned)h->pid) {
                h->file_id = i + 1;
                continue;
            }
            char namebuf[32];
            int nlen = snprintf(namebuf, sizeof(namebuf), "%d", (int)t->tid);
            if (nlen <= 0) {
                h->file_id = i + 1;
                continue;
            }
            size_t namelen = (size_t)nlen;
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (written + rec_len > size) break;
            
            struct ext2_dir_entry de;
            de.inode = (uint32_t)t->tid;
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            memcpy(out + written, &de, 8);
            memcpy(out + written + 8, namebuf, namelen);
            for (size_t z = 8 + namelen; z < rec_len; z++) out[written + z] = 0;
            
            written += rec_len;
            h->file_id = i + 1;
        }
        return (ssize_t)written;
	}
	/* /proc/<pid>/task/<tid> — same files as pid dir */
	if (h->kind == 16) {
		const char *tnames[4] = { "cmdline", "stat", "status", "statm" };
		size_t pos = 0;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int idx = 0; idx < 4; idx++) {
			size_t namelen = strlen(tnames[idx]);
			size_t rec_len = 8 + namelen;
			rec_len = (rec_len + 3) & ~3u;
			if (pos + rec_len <= offset) { pos += rec_len; continue; }
			if (written >= size) break;
			size_t entry_off = (offset > pos) ? (size_t)(offset - pos) : 0;
			uint8_t tmp[256];
			struct ext2_dir_entry de;
			de.inode = (uint32_t)(idx + 1);
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = EXT2_FT_REG_FILE;
			memset(tmp, 0, sizeof(tmp));
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, tnames[idx], namelen);
			size_t tocopy = rec_len - entry_off;
			if (tocopy > size - written) tocopy = size - written;
			if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
			written += tocopy;
			pos += rec_len;
		}
		return (ssize_t)written;
	}

	/* pid fd directory listing */
	if (h->kind == 5) {
        if (offset == 0) h->file_id = 0;
		thread_t *t = procfs_thread_by_id(h->pid);
		if (!t) return -1;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int i = h->file_id; i < THREAD_MAX_FD; i++) {
			char namebuf[16];
			int nlen = snprintf(namebuf, sizeof(namebuf), "%d", i);
			if (nlen <= 0) { h->file_id = i + 1; continue; }
			size_t namelen = (size_t)nlen;
			size_t rec_len = 8 + namelen;
			rec_len = (rec_len + 3) & ~3u;
            if (written + rec_len > size) break;
            
			uint8_t tmp[256];
            memset(tmp, 0, sizeof(tmp));
			struct ext2_dir_entry de;
			de.inode = (uint32_t)(i + 1);
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = (t->fds[i] ? EXT2_FT_REG_FILE : EXT2_FT_UNKNOWN);
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, namebuf, namelen);
            memcpy(out + written, tmp, rec_len);
			written += rec_len;
            h->file_id = i + 1;
		}
		return (ssize_t)written;
	}
	/* pid fd symlink target */
	if (h->kind == 6) {
		thread_t *t = procfs_thread_by_id(h->pid);
		if (!t) return 0;
		int fdnum = h->file_id;
		const char *target = "(invalid)";
		if (fdnum >= 0 && fdnum < THREAD_MAX_FD && t->fds[fdnum]) {
			if (t->fds[fdnum]->path) target = t->fds[fdnum]->path;
			else target = "(anon)";
		}
		size_t tlen = strlen(target);
		if ((size_t)offset >= tlen) return 0;
		size_t tocopy = tlen - (size_t)offset;
		if (tocopy > size) tocopy = size;
		memcpy(buf, target + offset, tocopy);
		return (ssize_t)tocopy;
	}

	/* top-level files like meminfo/uptime/stat/mounts */
	if (h->kind == 7) {
        /* Open has many early-return paths that skip cache fill — generate now. */
        if (!h->cache)
            procfs_fill_kind7_cache(h, file);
        if (!h->cache) return 0;
        if ((size_t)offset >= h->cache_len) return 0;
        size_t to_copy = h->cache_len - (size_t)offset;
        if (to_copy > size) to_copy = size;
        memcpy(buf, h->cache + offset, to_copy);
        return (ssize_t)to_copy;
	}

	/* proc/sys files (hostname etc) */
	if (h->kind == 9) {
		/* only hostname supported (file_id == 20) */
		if (h->file_id == 20) {
			size_t tcap = 256;
			if (tcap < size + offset) tcap = size + offset;
			char *tmpbuf = (char*)kmalloc(tcap);
			if (!tmpbuf) return -1;
			ssize_t full = procfs_show_hostname(tmpbuf, tcap, NULL);
			if (full < 0) { kfree(tmpbuf); return -1; }
			size_t len = (size_t)full;
			if ((size_t)offset >= len) { kfree(tmpbuf); return 0; }
			size_t tocopy = len - (size_t)offset;
			if (tocopy > size) tocopy = size;
			memcpy(buf, tmpbuf + offset, tocopy);
			kfree(tmpbuf);
			return (ssize_t)tocopy;
		}
		return -1;
	}

    return -1;
}

static void procfs_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) {
        struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
        if (h->cache) kfree(h->cache);
        kfree(h);
    }
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int procfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st || !file->driver_private) return -1;
    struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
    if (!h) return -1;
    if (h->kind == 1 || h->kind == 2 || h->kind == 5 || h->kind == 8 || h->kind == 10 ||
        h->kind == 11 || h->kind == 12 || h->kind == 13 || h->kind == 14 || h->kind == 15 ||
        h->kind == 16) {
        st->st_ino = (h->kind == 2 && h->pid > 0) ? (ino_t)((unsigned)h->pid + 100u) : 0;
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2;
        if (h->kind == 2) {
            thread_t *pt = procfs_thread_by_id(h->pid);
            if (pt) {
                st->st_uid = (uid_t)pt->euid;
                st->st_gid = (gid_t)pt->egid;
            }
        }
    } else if (h->kind == 6) {
        /* fd links are symlinks */
        st->st_ino = 0;
        st->st_mode = S_IFLNK | 0777;
        st->st_nlink = 1;
        st->st_size = (off_t)file->size;
    } else {
        st->st_ino = 0;
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = (off_t)file->size;
    }
    if (h->kind != 2) {
        st->st_uid = 0;
        st->st_gid = 0;
    }
    st->st_atime = st->st_mtime = st->st_ctime = (time_t)rtc_ticks;
    return 0;
}

int procfs_register(void) {
    procfs_ops.name = "procfs";
    procfs_ops.create = procfs_create;
    procfs_ops.open = procfs_open;
    procfs_ops.read = procfs_read;
    procfs_ops.write = procfs_write;
    procfs_ops.release = procfs_release;
    procfs_ops.chmod = NULL;
    procfs_driver.ops = &procfs_ops;
    procfs_driver.driver_data = NULL;
    procfs_lock.lock = 0;
    return fs_register_driver(&procfs_driver);
}

int procfs_unregister(void) {
    return fs_unregister_driver(&procfs_driver);
}

int procfs_mount(const char *path) {
    if (!path) return -1;
    return fs_mount(path, &procfs_driver);
}


