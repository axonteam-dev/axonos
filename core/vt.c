#include <vt.h>
#include <devfs.h>
#include <process.h>
#include <thread.h>
#include <spinlock.h>
#include <errno.h>
#include <string.h>
#include <video.h>

/* PIDs are monotonic in this kernel. Do not retain process/thread pointers:
 * process_signal_targets still has its own process-exit lifetime limitations. */
struct vt_control {
    struct vt_mode_k mode;
    uint64_t owner;
    int pending;                 /* destination + 1, or zero */
    int acquiring;
    int released;                /* owner accepted; display switch may be retried */
};
static struct vt_control controls[DEVFS_TTY_COUNT];
static spinlock_t vt_lock;
static int irq_request;          /* last keyboard request, destination + 1 */

static int valid(int index) { return index >= 0 && index < DEVFS_TTY_COUNT; }
static int alive(struct vt_control *c) {
    return c->owner && process_signal_targets(NULL, (int)c->owner, 0) > 0;
}
static void reset(struct vt_control *c) { memset(c, 0, sizeof(*c)); }

int vt_get_mode(int index, struct vt_mode_k *mode) {
    if (!valid(index)) return -ENOTTY;
    acquire(&vt_lock);
    *mode = controls[index].mode;
    release(&vt_lock);
    return 0;
}

int vt_set_mode(int index, const struct vt_mode_k *mode, uint64_t pid) {
    if (!valid(index)) return -ENOTTY;
    if ((mode->mode != 0 && mode->mode != 1) ||
        mode->relsig < 0 || mode->relsig > 64 ||
        mode->acqsig < 0 || mode->acqsig > 64 ||
        mode->frsig < 0 || mode->frsig > 64 || !pid) return -EINVAL;
    acquire(&vt_lock);
    struct vt_control *c = &controls[index];
    int pending = c->pending;
    reset(c);
    c->mode = *mode;
    if (mode->mode == 1) c->owner = pid;
    /* Switching back to AUTO must not strand an already requested switch. */
    if (pending) __atomic_store_n(&irq_request, pending, __ATOMIC_RELEASE);
    release(&vt_lock);
    return 0;
}

/* Called with vt_lock held, only from process context. */
static int switch_locked(int index) {
    int old = devfs_get_active();
    if (index == old) return 0;
    struct vt_control *src = &controls[old];
    if (src->mode.mode == 1) {
        if (!alive(src)) reset(src);
        else {
            if (src->released) return 0;
            /* Like Linux, each switch request notifies the owner again. */
            src->pending = index + 1;
            if (src->mode.relsig &&
                !process_signal_targets(NULL, (int)src->owner, src->mode.relsig))
                reset(src);
            else return 0;
        }
    }
    else if (video_vt_graphics(old)) return -EBUSY;
    if (devfs_switch_tty(index) != 0) return -EBUSY;
    struct vt_control *dst = &controls[index];
    if (dst->mode.mode == 1) {
        if (!alive(dst)) reset(dst);
        else {
            dst->acquiring = 1;
            if (dst->mode.acqsig &&
                !process_signal_targets(NULL, (int)dst->owner, dst->mode.acqsig))
                reset(dst);
        }
    }
    return 0;
}

int vt_request_switch(int index) {
    if (!valid(index)) return -EINVAL;
    acquire(&vt_lock);
    int rc = switch_locked(index);
    release(&vt_lock);
    return rc;
}

int vt_release(int index, int action, uint64_t pid) {
    if (!valid(index)) return -ENOTTY;
    /* Linux checks tty permission, not the identity of the VT signal owner. */
    (void)pid;
    acquire(&vt_lock);
    struct vt_control *c = &controls[index];
    int rc = 0;
    if (c->mode.mode != 1) rc = -EINVAL;
    else if (c->pending && index == devfs_get_active()) {
        int target = c->pending - 1;
        c->pending = 0;
        c->released = 0;
        if (action != 0) {
            /* Bypass release negotiation, but still notify the new owner. */
            if (devfs_switch_tty(target) != 0) {
                c->pending = target + 1;
                c->released = 1;
            }
            else {
                struct vt_control *dst = &controls[target];
                if (dst->mode.mode == 1) {
                    if (!alive(dst)) reset(dst);
                    else {
                        dst->acquiring = 1;
                        if (dst->mode.acqsig && !process_signal_targets(NULL, (int)dst->owner, dst->mode.acqsig)) reset(dst);
                    }
                }
            }
        }
    } else if (action == 2) c->acquiring = 0;
    else rc = -EINVAL;
    release(&vt_lock);
    return rc;
}

void vt_request_switch_irq(int index) {
    if (valid(index)) __atomic_store_n(&irq_request, index + 1, __ATOMIC_RELEASE);
}

void vt_worker(void) {
    for (;;) {
        int request = __atomic_exchange_n(&irq_request, 0, __ATOMIC_ACQ_REL);
        if (request && vt_request_switch(request - 1) == -EBUSY) {
            int empty = 0;
            __atomic_compare_exchange_n(&irq_request, &empty, request, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
        /* Recover a switch if its release owner died while userspace held it. */
        acquire(&vt_lock);
        int active = devfs_get_active();
        struct vt_control *c = &controls[active];
        if (c->pending && c->released) {
            int target = c->pending - 1;
            if (devfs_switch_tty(target) == 0) {
                c->pending = 0;
                c->released = 0;
                struct vt_control *dst = &controls[target];
                if (dst->mode.mode == 1) {
                    if (!alive(dst)) reset(dst);
                    else {
                        dst->acquiring = 1;
                        if (dst->mode.acqsig && !process_signal_targets(NULL, (int)dst->owner, dst->mode.acqsig)) reset(dst);
                    }
                }
            }
        } else if (c->pending && !alive(c)) {
            int target = c->pending;
            reset(c);
            int empty = 0;
            __atomic_compare_exchange_n(&irq_request, &empty, target, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
        release(&vt_lock);
        thread_sleep(10);
    }
}
