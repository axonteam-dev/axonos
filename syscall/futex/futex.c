#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <thread.h>
#include <heap.h>
#include <spinlock.h>
#include <mmio.h>
#include <syscall.h>
#include <string.h>
#include <vga.h>
#include <mm.h>
#include <klog.h>
#include <timekeeping.h>

#define FUTEX_WAIT           0
#define FUTEX_WAKE           1
#define FUTEX_REQUEUE        3
#define FUTEX_CMP_REQUEUE    4
#define FUTEX_WAIT_BITSET    9
#define FUTEX_WAKE_BITSET   10
#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_CLOCK_REALTIME    256

/* Minimal errno set (same values as used by syscall dispatcher) */
#define EPERM   1
#define ENOENT  2
#define EFAULT  14
#define EINVAL  22
#define ENOMEM  12
#define EAGAIN  11
#define EINTR   4
#define ENOSYS  38
#define ETIMEDOUT 110

#define FUTEX_BUCKETS 256

typedef struct futex_waiter {
    int tid;
    uint32_t bitset;
    int woken;
    struct futex_node *node;
    struct futex_waiter *next;
} futex_waiter_t;

typedef struct futex_node {
    uintptr_t key;
    mm_t *owner;
    futex_waiter_t *waiters;
    struct futex_node *next;
} futex_node_t;

static futex_node_t *futex_table[FUTEX_BUCKETS];
static spinlock_t futex_lock = { 0 };

static inline int futex_hash(uintptr_t key, mm_t *owner) {
    return (int)(((key >> 3) ^ ((uintptr_t)owner >> 4)) & (FUTEX_BUCKETS - 1));
}

static futex_node_t *futex_find_node(uintptr_t key, mm_t *owner, int create) {
    int h = futex_hash(key, owner);
    futex_node_t *n = futex_table[h];
    while (n) {
        if (n->key == key && n->owner == owner) return n;
        n = n->next;
    }
    if (!create) return NULL;
    n = (futex_node_t*)kmalloc(sizeof(futex_node_t));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->key = key;
    n->owner = owner;
    n->next = futex_table[h];
    futex_table[h] = n;
    return n;
}

/* Copy 32-bit value from user; return 0 on success, -EFAULT on error. */
static int read_u32_user(uint32_t *out, uintptr_t uaddr) {
    if (!out) return -EINVAL;
    if (uaddr + sizeof(uint32_t) > (uintptr_t)MMIO_IDENTITY_LIMIT) return -EFAULT;
    thread_t *cur = thread_current();
    return cur && cur->mm && mm_copy_from_user(cur->mm, out, uaddr, sizeof(*out)) == 0 ? 0 : -EFAULT;
}

static void futex_drop_empty(futex_node_t *node) {
    if (!node || node->waiters) return;
    int h = futex_hash(node->key, node->owner);
    futex_node_t **link = &futex_table[h];
    while (*link && *link != node) link = &(*link)->next;
    if (*link) { *link = node->next; kfree(node); }
}

static void futex_unlink_waiter(futex_waiter_t *w) {
    if (!w->node) return;
    futex_waiter_t **link = &w->node->waiters;
    while (*link && *link != w) link = &(*link)->next;
    if (*link) *link = w->next;
    w->node = NULL;
    w->next = NULL;
}

void futex_cancel_thread(thread_t *thread) {
    if (!thread || !thread->active_futex_waiter) return;
    unsigned long flags;
    acquire_irqsave(&futex_lock, &flags);
    futex_waiter_t *w = thread->active_futex_waiter;
    if (w) {
        futex_node_t *node = w->node;
        futex_unlink_waiter(w);
        futex_drop_empty(node);
        thread->active_futex_waiter = NULL;
        kfree(w);
    }
    release_irqrestore(&futex_lock, flags);
}

static uint64_t futex_now_ns(int realtime) {
    if (!realtime) return time_monotonic_us() * 1000ULL;
    int64_t sec, ns;
    ktime_get_real_ts64(&sec, &ns);
    return (uint64_t)sec * 1000000000ULL + (uint64_t)ns;
}

static int futex_key(thread_t *cur, uintptr_t address, int private,
                     uintptr_t *key, mm_t **owner) {
    if (address & 3) return -EINVAL;
    if (address < 0x1000 || address > (uintptr_t)MMIO_IDENTITY_LIMIT - 4 || !cur->mm)
        return -EFAULT;
    if (private) { *owner = cur->mm; *key = address; return 0; }
    uint64_t pa;
    if (mm_user_leaf_pa(cur->mm, address, 0, &pa) != 0) return -EFAULT;
    *owner = NULL; *key = (uintptr_t)pa;
    return 0;
}

static int futex_wake_locked(futex_node_t *node, int count, uint32_t bitset) {
    int woke = 0;
    for (futex_waiter_t *w = node ? node->waiters : NULL; w && woke < count;) {
        futex_waiter_t *next = w->next;
        if (w->bitset & bitset) {
            futex_unlink_waiter(w);
            w->woken = 1;
            thread_t *t = thread_get(w->tid);
            if (t && t->active_futex_waiter == w && t->state != THREAD_TERMINATED) {
                thread_unblock(w->tid);
                woke++;
            }
        }
        w = next;
    }
    return woke;
}

/* Minimal futex syscall backend.
   Returns 0..n on success or negative errno on failure.
   For FUTEX_REQUEUE/CMP_REQUEUE: val2 (nr_requeue) is passed via timeout ptr. */
int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3) {
    int val2 = (int)(uintptr_t)timeout; /* repurposed for nr_requeue in REQUEUE ops */
    int cmd = op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME); /* strip flags, get base op */
    thread_t *cur = thread_current();
    if (!cur) return -EPERM;
    if (cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAKE &&
        cmd != FUTEX_WAKE_BITSET && cmd != FUTEX_REQUEUE && cmd != FUTEX_CMP_REQUEUE)
        return -ENOSYS;
    int private = !!(op & FUTEX_PRIVATE_FLAG), realtime = !!(op & FUTEX_CLOCK_REALTIME);
    if (realtime && cmd != FUTEX_WAIT_BITSET) return -ENOSYS;
    uintptr_t key; mm_t *owner;
    int key_error = futex_key(cur, uaddr, private, &key, &owner);
    if (key_error) return key_error;

    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) {
        uint32_t bitset = cmd == FUTEX_WAIT ? UINT32_MAX : (uint32_t)val3;
        if (!bitset) return -EINVAL;
        uint64_t deadline = 0;
        if (timeout) {
            struct { int64_t sec, ns; } ts;
            if (!cur->mm || mm_copy_from_user(cur->mm, &ts, (uintptr_t)timeout, sizeof(ts)) != 0)
                return -EFAULT;
            if (ts.sec < 0 || ts.ns < 0 || ts.ns >= 1000000000LL ||
                (uint64_t)ts.sec > (UINT64_MAX - (uint64_t)ts.ns) / 1000000000ULL)
                return -EINVAL;
            deadline = (uint64_t)ts.sec * 1000000000ULL + (uint64_t)ts.ns;
            if (cmd == FUTEX_WAIT) {
                uint64_t now = futex_now_ns(0);
                deadline = deadline > UINT64_MAX - now ? UINT64_MAX : deadline + now;
            }
        }
        futex_waiter_t *w = (futex_waiter_t*)kmalloc(sizeof(futex_waiter_t));
        if (!w) return -ENOMEM;
        memset(w, 0, sizeof(*w));
        w->tid = (int)(cur->tid ? cur->tid : 1);
        w->bitset = bitset;
        unsigned long flags;
        acquire_irqsave(&futex_lock, &flags);
        uint32_t value;
        /* Recheck under the same lock as WAKE and queue publication. */
        int result = read_u32_user(&value, uaddr);
        if (!result && value != (uint32_t)val) result = -EAGAIN;
        if (result) { release_irqrestore(&futex_lock, flags); kfree(w); return result; }
        futex_node_t *node = futex_find_node(key, owner, 1);
        if (!node) { release_irqrestore(&futex_lock, flags); kfree(w); return -ENOMEM; }
        w->node = node; w->next = node->waiters; node->waiters = w;
        cur->active_futex_waiter = w;
        for (;;) {
            if (w->woken) { result = 0; break; }
            if (cur->pending_signals & ~cur->saved_sig_mask) { result = -EINTR; break; }
            uint64_t now = timeout ? futex_now_ns(realtime) : 0;
            if (timeout && now >= deadline) { result = -ETIMEDOUT; break; }
            if (timeout) {
                uint64_t remaining = deadline - now;
                uint64_t ms = remaining / 1000000ULL + (remaining % 1000000ULL != 0);
                if (ms > 0x7fffffffULL) ms = 0x7fffffffULL;
                thread_block_with_timeout(w->tid, (uint32_t)ms);
            } else {
                thread_block(w->tid);
            }
            release_irqrestore(&futex_lock, flags);
            if (cur->state == THREAD_BLOCKED) thread_yield();
            acquire_irqsave(&futex_lock, &flags);
        }
        node = w->node;
        futex_unlink_waiter(w); futex_drop_empty(node);
        cur->active_futex_waiter = NULL;
        release_irqrestore(&futex_lock, flags);
        kfree(w);
        return result;
    } else if (cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET) {
        uint32_t bitset = cmd == FUTEX_WAKE ? UINT32_MAX : (uint32_t)val3;
        if (val < 0 || !bitset) return -EINVAL;
        unsigned long flags;
        acquire_irqsave(&futex_lock, &flags);
        futex_node_t *node = futex_find_node(key, owner, 0);
        int woke = futex_wake_locked(node, val, bitset);
        futex_drop_empty(node);
        release_irqrestore(&futex_lock, flags);
        return woke;
    } else if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE) {
        int nr_wake = val;
        int nr_requeue = val2;
        if (nr_wake < 0 || nr_requeue < 0) return -EINVAL;
        uintptr_t key2; mm_t *owner2;
        key_error = futex_key(cur, uaddr2, private, &key2, &owner2);
        if (key_error) return key_error;
        if (key == key2 && owner == owner2) return -EINVAL;
        unsigned long flags;
        acquire_irqsave(&futex_lock, &flags);
        if (cmd == FUTEX_CMP_REQUEUE) {
            uint32_t curv = 0;
            if (read_u32_user(&curv, uaddr) < 0) { release_irqrestore(&futex_lock, flags); return -EFAULT; }
            if (curv != (uint32_t)val3) { release_irqrestore(&futex_lock, flags); return -EAGAIN; }
        }
        futex_node_t *src = futex_find_node(key, owner, 0);
        int woke = futex_wake_locked(src, nr_wake, UINT32_MAX), requeued = 0;
        if (src && src->waiters && nr_requeue) {
            futex_node_t *dst = futex_find_node(key2, owner2, 1);
            if (!dst) { release_irqrestore(&futex_lock, flags); return woke ? woke : -ENOMEM; }
            while (src->waiters && requeued < nr_requeue) {
                futex_waiter_t *w = src->waiters;
                src->waiters = w->next;
                w->node = dst; w->next = dst->waiters; dst->waiters = w;
                requeued++;
            }
        }
        futex_drop_empty(src);
        release_irqrestore(&futex_lock, flags);
        return woke + requeued;
    } else {
        return -ENOSYS;
    }
}
