#include <user_vma.h>
#include <user_as.h>
#include <user_mm.h>
#include <user_map.h>
#include <exec.h>
#include <mm.h>
#include <mmio.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>
#include <thread.h>
#include <heap.h>
#include <fs.h>
#include <pagecache.h>
#include <frame.h>

static user_vma_t g_user_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;

static void user_vma_drop_file_nolock(user_vma_t *v) {
    if (!v || !v->file)
        return;
    struct fs_file *f = v->file;
    v->file = NULL;
    v->file_off = 0;
    fs_file_free(f);
}

static void user_vma_clear_nolock(user_vma_t *v) {
    if (!v || !v->used)
        return;
    user_vma_drop_file_nolock(v);
    v->used = 0;
}

static user_vma_t *user_vma_mm_storage(mm_t *mm, int create) {
    if (!mm)
        return NULL;
    if (!mm->vma_storage && create) {
        /* Allocate under live CR3 — g_kernel_mm L3 may be a stale boot snapshot. */
        user_vma_t *storage =
            (user_vma_t *)kmalloc(sizeof(user_vma_t) * USER_VMA_MAX);
        if (storage)
            memset(storage, 0, sizeof(user_vma_t) * USER_VMA_MAX);
        mm->vma_storage = storage;
    }
    return (user_vma_t *)mm->vma_storage;
}

int user_vma_add_mm(mm_t *mm, uintptr_t addr, size_t len, int prot, int kind) {
    user_vma_t *vmas = user_vma_mm_storage(mm, 1);
    if (!vmas)
        return -1;
    unsigned long fl;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; ++i) {
        if (vmas[i].used && vmas[i].addr == addr && vmas[i].len == len &&
            vmas[i].kind == kind) {
            vmas[i].prot = prot;
            release_irqrestore(&g_user_vma_lock, fl);
            return 0;
        }
    }
    for (int i = 0; i < USER_VMA_MAX; ++i) {
        if (!vmas[i].used) {
            vmas[i].used = 1;
            vmas[i].tid = 0;
            vmas[i].addr = addr;
            vmas[i].len = len;
            vmas[i].prot = prot;
            vmas[i].kind = kind;
            vmas[i].file = NULL;
            vmas[i].file_off = 0;
            release_irqrestore(&g_user_vma_lock, fl);
            return 0;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return -1;
}

int user_vma_is_shared_page_mm(mm_t *mm, uintptr_t va) {
    user_vma_t *vmas = user_vma_mm_storage(mm, 0);
    if (!vmas)
        return 0;
    unsigned long fl;
    int shared = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; ++i) {
        if (!vmas[i].used || vmas[i].kind != USER_VMA_KIND_SHM)
            continue;
        if (va >= vmas[i].addr && va < vmas[i].addr + vmas[i].len) {
            shared = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return shared;
}

int user_vma_clone_mm(mm_t *dst, mm_t *src) {
    user_vma_t *source = user_vma_mm_storage(src, 0);
    if (!source)
        return 0;
    user_vma_t *target = user_vma_mm_storage(dst, 1);
    if (!target)
        return -1;
    unsigned long fl;
    acquire_irqsave(&g_user_vma_lock, &fl);
    memcpy(target, source, sizeof(user_vma_t) * USER_VMA_MAX);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (target[i].used && target[i].file)
            fs_file_get(target[i].file);
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return 0;
}

static int user_vma_kind_is_mmap_like(int kind) {
    return kind == USER_VMA_KIND_MMAP ||
           kind == USER_VMA_KIND_MMAP_LAZY ||
           kind == USER_VMA_KIND_SHM ||
           kind == USER_VMA_KIND_ELF_LOAD;
}

/* File-backed mapping whose identity leftover is not file bytes (Linux filemap). */
static int user_vma_is_filemap(const user_vma_t *v) {
    if (!v || !v->file)
        return 0;
    return v->kind == USER_VMA_KIND_MMAP_LAZY ||
           v->kind == USER_VMA_KIND_ELF_LOAD ||
           v->kind == USER_VMA_KIND_MMAP ||
           v->kind == USER_VMA_KIND_SHM;
}

static user_vma_t *user_vma_find_containing_nolock(uint64_t tid, uintptr_t va) {
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) return &g_user_vmas[i];
    }
    return NULL;
}

static int user_vma_add_nolock(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind) {
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        if (g_user_vmas[i].addr == addr && g_user_vmas[i].len == len && g_user_vmas[i].kind == kind) {
            g_user_vmas[i].prot = prot;
            return 0;
        }
    }
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) {
            g_user_vmas[i].used = 1;
            g_user_vmas[i].tid = tid;
            g_user_vmas[i].addr = addr;
            g_user_vmas[i].len = len;
            g_user_vmas[i].prot = prot;
            g_user_vmas[i].kind = kind;
            g_user_vmas[i].file = NULL;
            g_user_vmas[i].file_off = 0;
            return 0;
        }
    }
    return -1;
}

static int user_vma_split_at_nolock(uint64_t tid, uintptr_t split_va) {
    user_vma_t *v = user_vma_find_containing_nolock(tid, split_va);
    if (!v) return 0;
    if (split_va == v->addr || split_va >= v->addr + v->len) return 0;
    size_t left_len = (size_t)(split_va - v->addr);
    size_t right_len = v->len - left_len;
    uintptr_t right_addr = split_va;
    int prot = v->prot;
    int kind = v->kind;
    struct fs_file *file = v->file;
    uint64_t file_off = v->file_off;
    if (user_vma_add_nolock(tid, right_addr, right_len, prot, kind) != 0) return -1;
    user_vma_t *right = user_vma_find_containing_nolock(tid, right_addr);
    if (right && file) {
        fs_file_get(file);
        right->file = file;
        right->file_off = file_off + (uint64_t)left_len;
    }
    v->len = left_len;
    return 0;
}

static int user_vma_tid_matches_runner_mm_nolock(thread_t *runner, uint64_t record_tid) {
    if (!runner)
        return record_tid == 1u;
    if (!runner->mm)
        return (uint64_t)(runner->tid ? runner->tid : 1) == record_tid;
    int n = thread_get_count();
    for (int j = 0; j < n; j++) {
        thread_t *u = thread_get_by_index(j);
        if (!u || u->ring != 3) continue;
        if (u->mm != runner->mm) continue;
        if ((uint64_t)(u->tid ? u->tid : 1) == record_tid)
            return 1;
    }
    return 0;
}

static int user_vma_split_runner_at_nolock(thread_t *runner,
                                            uintptr_t split_va) {
    if (!runner)
        return -1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        user_vma_t *v = &g_user_vmas[i];
        if (!v->used ||
            !user_vma_tid_matches_runner_mm_nolock(runner, v->tid))
            continue;
        uintptr_t end = v->addr + v->len;
        if (split_va <= v->addr || split_va >= end)
            continue;
        int free_i = -1;
        for (int j = 0; j < USER_VMA_MAX; j++) {
            if (!g_user_vmas[j].used) {
                free_i = j;
                break;
            }
        }
        if (free_i < 0)
            return -1;
        g_user_vmas[free_i] = *v;
        g_user_vmas[free_i].addr = split_va;
        g_user_vmas[free_i].len = (size_t)(end - split_va);
        if (g_user_vmas[free_i].file) {
            fs_file_get(g_user_vmas[free_i].file);
            g_user_vmas[free_i].file_off =
                v->file_off + (uint64_t)(split_va - v->addr);
        }
        v->len = (size_t)(split_va - v->addr);
    }
    return 0;
}

static int user_vma_split_mm_at_nolock(user_vma_t *vmas,
                                        uintptr_t split_va) {
    if (!vmas)
        return 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        user_vma_t *v = &vmas[i];
        if (!v->used)
            continue;
        uintptr_t end = v->addr + v->len;
        if (split_va <= v->addr || split_va >= end)
            continue;
        int free_i = -1;
        for (int j = 0; j < USER_VMA_MAX; j++) {
            if (!vmas[j].used) {
                free_i = j;
                break;
            }
        }
        if (free_i < 0)
            return -1;
        vmas[free_i] = *v;
        vmas[free_i].addr = split_va;
        vmas[free_i].len = (size_t)(end - split_va);
        if (vmas[free_i].file) {
            fs_file_get(vmas[free_i].file);
            vmas[free_i].file_off =
                v->file_off + (uint64_t)(split_va - v->addr);
        }
        v->len = (size_t)(split_va - v->addr);
    }
    return 0;
}

static int user_vma_unmap_capacity_nolock(thread_t *owner,
                                           uintptr_t addr, uintptr_t end) {
    int global_free = 0;
    int global_need = 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        user_vma_t *v = &g_user_vmas[i];
        if (!v->used) {
            global_free++;
            continue;
        }
        if (owner) {
            if (!user_vma_tid_matches_runner_mm_nolock(owner, v->tid))
                continue;
        } else {
            continue;
        }
        uintptr_t ve = v->addr + v->len;
        if (addr > v->addr && addr < ve) global_need++;
        if (end > v->addr && end < ve) global_need++;
    }
    if (global_need > global_free)
        return -1;

    user_vma_t *mm_vmas = owner && owner->mm ?
        user_vma_mm_storage(owner->mm, 0) : NULL;
    if (mm_vmas) {
        int mm_free = 0;
        int mm_need = 0;
        for (int i = 0; i < USER_VMA_MAX; i++) {
            user_vma_t *v = &mm_vmas[i];
            if (!v->used) {
                mm_free++;
                continue;
            }
            uintptr_t ve = v->addr + v->len;
            if (addr > v->addr && addr < ve) mm_need++;
            if (end > v->addr && end < ve) mm_need++;
        }
        if (mm_need > mm_free)
            return -1;
    }
    return 0;
}

int user_vma_add(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind) {
    unsigned long fl = 0;
    int rc;
    acquire_irqsave(&g_user_vma_lock, &fl);
    rc = user_vma_add_nolock(tid, addr, len, prot, kind);
    release_irqrestore(&g_user_vma_lock, fl);
    thread_t *owner = thread_get((int)tid);
    if (owner && owner->mm)
        (void)user_vma_add_mm(owner->mm, addr, len, prot, kind);
    return rc;
}

int user_vma_can_unmap_range(uint64_t tid, uintptr_t addr, size_t len) {
    if (len == 0 || addr + len < addr)
        return -1;
    thread_t *owner = thread_get((int)tid);
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    int rc = owner ?
        user_vma_unmap_capacity_nolock(owner, addr, addr + len) : 0;
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_unmap_range(uint64_t tid, uintptr_t addr, size_t len) {
    uintptr_t end = addr + len;
    thread_t *owner = thread_get((int)tid);
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    if (owner && owner->mm) {
        if (user_vma_unmap_capacity_nolock(owner, addr, end) != 0) {
            release_irqrestore(&g_user_vma_lock, fl);
            return -1;
        }
        user_vma_t *mm_vmas = user_vma_mm_storage(owner->mm, 0);
        if (user_vma_split_runner_at_nolock(owner, addr) != 0 ||
            user_vma_split_runner_at_nolock(owner, end) != 0 ||
            user_vma_split_mm_at_nolock(mm_vmas, addr) != 0 ||
            user_vma_split_mm_at_nolock(mm_vmas, end) != 0) {
            release_irqrestore(&g_user_vma_lock, fl);
            return -1;
        }
        for (int i = 0; i < USER_VMA_MAX; i++) {
            if (g_user_vmas[i].used &&
                user_vma_tid_matches_runner_mm_nolock(owner,
                                                       g_user_vmas[i].tid)) {
                uintptr_t a = g_user_vmas[i].addr;
                uintptr_t e = a + g_user_vmas[i].len;
                if (!(e <= addr || a >= end))
                    user_vma_clear_nolock(&g_user_vmas[i]);
            }
            if (mm_vmas && mm_vmas[i].used) {
                uintptr_t a = mm_vmas[i].addr;
                uintptr_t e = a + mm_vmas[i].len;
                if (!(e <= addr || a >= end))
                    user_vma_clear_nolock(&mm_vmas[i]);
            }
        }
    } else {
        (void)user_vma_split_at_nolock(tid, addr);
        (void)user_vma_split_at_nolock(tid, end);
        for (int i = 0; i < USER_VMA_MAX; i++) {
            if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
            uintptr_t a = g_user_vmas[i].addr;
            uintptr_t e = a + g_user_vmas[i].len;
            if (e <= addr || a >= end) continue;
            user_vma_clear_nolock(&g_user_vmas[i]);
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return 0;
}

int user_vma_set_prot(uint64_t tid, uintptr_t addr, size_t len, int prot) {
    unsigned long fl = 0;
    int rc = 0;
    uintptr_t end = addr + len;
    acquire_irqsave(&g_user_vma_lock, &fl);
    if (user_vma_split_at_nolock(tid, addr) != 0) rc = -1;
    else if (user_vma_split_at_nolock(tid, end) != 0) rc = -1;
    else {
        for (int i = 0; i < USER_VMA_MAX; i++) {
            if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
            uintptr_t a = g_user_vmas[i].addr;
            uintptr_t e = a + g_user_vmas[i].len;
            if (e <= addr || a >= end) continue;
            g_user_vmas[i].prot = prot;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_is_fully_mapped(uint64_t tid, uintptr_t addr, size_t len) {
    uintptr_t end = addr + len;
    uintptr_t cur = addr;
    unsigned long fl = 0;
    int ok = 1;
    acquire_irqsave(&g_user_vma_lock, &fl);
    while (cur < end) {
        user_vma_t *v = user_vma_find_containing_nolock(tid, cur);
        if (!v) { ok = 0; break; }
        uintptr_t ve = v->addr + v->len;
        if (ve <= cur) { ok = 0; break; }
        cur = ve;
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return ok;
}

uintptr_t user_vma_max_mmap_like_end_nolock(uint64_t tid) {
    uintptr_t mx = 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        if (!user_vma_kind_is_mmap_like(g_user_vmas[i].kind)) continue;
        uintptr_t e = g_user_vmas[i].addr + g_user_vmas[i].len;
        if (e > mx) mx = e;
    }
    return mx;
}

uintptr_t user_vma_max_mmap_like_end(uint64_t tid) {
    unsigned long fl = 0;
    uintptr_t mx;
    acquire_irqsave(&g_user_vma_lock, &fl);
    mx = user_vma_max_mmap_like_end_nolock(tid);
    release_irqrestore(&g_user_vma_lock, fl);
    return mx;
}

uintptr_t user_vma_max_mmap_like_end_for_mm_nolock(thread_t *runner) {
    uintptr_t mx = 0;
    if (!runner) return 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_kind_is_mmap_like(g_user_vmas[i].kind)) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uintptr_t e = g_user_vmas[i].addr + g_user_vmas[i].len;
        if (e > mx) mx = e;
    }
    return mx;
}

uintptr_t user_vma_max_mmap_like_end_for_mm(thread_t *runner) {
    unsigned long fl = 0;
    uintptr_t mx;
    acquire_irqsave(&g_user_vma_lock, &fl);
    mx = user_vma_max_mmap_like_end_for_mm_nolock(runner);
    release_irqrestore(&g_user_vma_lock, fl);
    return mx;
}

size_t user_vma_total_size_for_mm(thread_t *runner) {
    if (!runner)
        return 0;
    unsigned long fl = 0;
    size_t total = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used)
            continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        if ((size_t)-1 - total < g_user_vmas[i].len) {
            total = (size_t)-1;
            break;
        }
        total += g_user_vmas[i].len;
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return total;
}

uintptr_t user_vma_min_mmap_like_for_thread_nolock(thread_t *tcur, uintptr_t brk_base) {
    uintptr_t best = (uintptr_t)-1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_kind_is_mmap_like(g_user_vmas[i].kind)) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(tcur, (uint64_t)g_user_vmas[i].tid)) continue;
        uintptr_t a = g_user_vmas[i].addr;
        if (a < 0x200000u) continue;
        if (a >= brk_base && a < best) best = a;
    }
    return best;
}

uintptr_t user_vma_min_mmap_like_for_thread(thread_t *tcur, uintptr_t brk_base) {
    unsigned long fl = 0;
    uintptr_t v;
    acquire_irqsave(&g_user_vma_lock, &fl);
    v = user_vma_min_mmap_like_for_thread_nolock(tcur, brk_base);
    release_irqrestore(&g_user_vma_lock, fl);
    return v;
}

int user_vma_overlaps_thread_range(thread_t *runner, uintptr_t addr, size_t len) {
    if (len == 0 || !runner) return 0;
    unsigned long fl = 0;
    int rc = 0;
    uint64_t a0 = (uint64_t)addr;
    uint64_t a1 = a0 + (uint64_t)len;
    if (a1 < a0) return 1;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uint64_t b0 = (uint64_t)g_user_vmas[i].addr;
        uint64_t b1 = b0 + (uint64_t)g_user_vmas[i].len;
        if (b1 < b0) continue;
        if (!(a1 <= b0 || a0 >= b1)) {
            rc = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_mmap_range_overlaps_nolock(thread_t *runner, uintptr_t addr, size_t len) {
    if (len == 0 || !runner) return 0;
    uint64_t a0 = (uint64_t)addr;
    uint64_t a1 = a0 + (uint64_t)len;
    if (a1 < a0) return 1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_kind_is_mmap_like(g_user_vmas[i].kind)) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uint64_t b0 = (uint64_t)g_user_vmas[i].addr;
        uint64_t b1 = b0 + (uint64_t)g_user_vmas[i].len;
        if (b1 < b0) continue;
        if (!(a1 <= b0 || a0 >= b1)) return 1;
    }
    return 0;
}

int user_vma_mmap_range_overlaps(thread_t *runner, uintptr_t addr, size_t len) {
    unsigned long fl = 0;
    int rc;
    acquire_irqsave(&g_user_vma_lock, &fl);
    rc = user_vma_mmap_range_overlaps_nolock(runner, addr, len);
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

/* Lowest exclusive end of any runner VMA intersecting [addr, addr+len), or 0. */
static uintptr_t user_vma_overlap_end_nolock(thread_t *runner, uintptr_t addr, uint64_t len) {
    uint64_t a0 = (uint64_t)addr;
    uint64_t a1 = a0 + len;
    uintptr_t end = 0;
    if (a1 < a0) return (uintptr_t)-1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uint64_t b0 = (uint64_t)g_user_vmas[i].addr;
        uint64_t b1 = b0 + (uint64_t)g_user_vmas[i].len;
        if (b1 < b0) continue;
        if (a1 <= b0 || a0 >= b1) continue;
        if ((uintptr_t)b1 > end) end = (uintptr_t)b1;
    }
    return end;
}

uintptr_t user_vma_find_unmapped(thread_t *runner, uintptr_t floor, uintptr_t ceil,
                                 uint64_t len, uintptr_t hint, uintptr_t align) {
    if (!runner || len == 0 || floor >= ceil)
        return 0;
    if (align < 4096u)
        align = 4096u;
    /* Require power-of-two align. */
    if ((align & (align - 1u)) != 0)
        align = 4096u;
    if (len > (uint64_t)(ceil - floor))
        return 0;

    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);

    if (hint != 0) {
        uintptr_t h = user_mm_align_up(hint, align);
        if (h >= floor && (uint64_t)h + len <= (uint64_t)ceil &&
            (uint64_t)h + len >= (uint64_t)h &&
            user_vma_overlap_end_nolock(runner, h, len) == 0) {
            release_irqrestore(&g_user_vma_lock, fl);
            return h;
        }
    }

    uintptr_t cand = user_mm_align_up(floor, align);
    for (int iter = 0; iter < USER_VMA_MAX + 16; iter++) {
        if (cand >= ceil || (uint64_t)cand + len > (uint64_t)ceil ||
            (uint64_t)cand + len < (uint64_t)cand)
            break;
        uintptr_t block = user_vma_overlap_end_nolock(runner, cand, len);
        if (block == 0) {
            release_irqrestore(&g_user_vma_lock, fl);
            return cand;
        }
        if (block == (uintptr_t)-1)
            break;
        uintptr_t next = user_mm_align_up(block, align);
        if (next <= cand)
            next = cand + align;
        cand = next;
    }

    release_irqrestore(&g_user_vma_lock, fl);
    return 0;
}

/* Lowest start of any VMA overlapping [addr, addr+len), or 0 if none. */
static uintptr_t user_vma_overlap_start_nolock(thread_t *runner, uintptr_t addr, uint64_t len) {
    uint64_t a0 = (uint64_t)addr;
    uint64_t a1 = a0 + len;
    uintptr_t start = 0;
    int hit = 0;
    if (a1 < a0) return (uintptr_t)-1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uint64_t b0 = (uint64_t)g_user_vmas[i].addr;
        uint64_t b1 = b0 + (uint64_t)g_user_vmas[i].len;
        if (b1 < b0) continue;
        if (a1 <= b0 || a0 >= b1) continue;
        if (!hit || (uintptr_t)b0 < start) {
            start = (uintptr_t)b0;
            hit = 1;
        }
    }
    return hit ? start : 0;
}

uintptr_t user_vma_find_unmapped_topdown(thread_t *runner, uintptr_t floor,
                                         uintptr_t ceil, uint64_t len,
                                         uintptr_t align) {
    if (!runner || len == 0 || floor >= ceil)
        return 0;
    if (align < 4096u)
        align = 4096u;
    if ((align & (align - 1u)) != 0)
        align = 4096u;
    if (len > (uint64_t)(ceil - floor))
        return 0;

    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);

    /* Highest aligned start where start+len <= ceil. */
    uintptr_t cand = user_mm_align_down(ceil - (uintptr_t)len, align);
    if (cand + (uintptr_t)len > ceil) {
        if (cand < align) {
            release_irqrestore(&g_user_vma_lock, fl);
            return 0;
        }
        cand -= align;
    }

    for (int iter = 0; iter < USER_VMA_MAX + 16; iter++) {
        if (cand < floor || (uint64_t)cand + len > (uint64_t)ceil)
            break;
        uintptr_t ov_start = user_vma_overlap_start_nolock(runner, cand, len);
        if (ov_start == 0) {
            release_irqrestore(&g_user_vma_lock, fl);
            return cand;
        }
        if (ov_start == (uintptr_t)-1)
            break;
        /* Sit just below the blocking VMA. */
        if (ov_start < floor + (uintptr_t)len)
            break;
        uintptr_t next = user_mm_align_down(ov_start - (uintptr_t)len, align);
        if (next >= cand) {
            if (cand < align + floor)
                break;
            next = cand - align;
        }
        cand = next;
    }

    release_irqrestore(&g_user_vma_lock, fl);
    return 0;
}

void user_vma_remove_all_for_tid(uint64_t tid) {
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (g_user_vmas[i].used && g_user_vmas[i].tid == tid)
            user_vma_clear_nolock(&g_user_vmas[i]);
    }
    release_irqrestore(&g_user_vma_lock, fl);
}

void user_vma_teardown_unmap_for_exec(thread_t *runner) {
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (runner && !user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (e > a && a >= 0x200000u && e <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            mm_t *k = mm_kernel();
            int priv = runner && runner->mm && k && runner->mm->pml4 && k->pml4 &&
                       runner->mm->pml4 != k->pml4;
            if (priv) {
                /* Do not map_page_2m: that collapses private ELF pages to identity. */
                (void)mm_make_private_range(runner->mm, (uint64_t)a, (uint64_t)e, 0, k);
            } else {
                (void)user_map_ensure_present_us_2m((uint64_t)a, (uint64_t)e);
                user_as_mmap_memset_zero_chunked(a, (size_t)(e - a));
            }
        }
        user_vma_clear_nolock(&g_user_vmas[i]);
    }
    release_irqrestore(&g_user_vma_lock, fl);
}

int user_vma_allows_write(thread_t *runner, uintptr_t va) {
    if (!runner || va < 0x200000u || va >= (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    unsigned long fl = 0;
    int allow = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used)
            continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner,
                                                   (uint64_t)g_user_vmas[i].tid))
            continue;
        if ((g_user_vmas[i].prot & 2) == 0)
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            allow = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return allow;
}

int user_vma_covers_page(uint64_t tid, uintptr_t va) {
    if (va < 0x200000u || va >= (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    unsigned long fl = 0;
    int hit = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid)
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            hit = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return hit;
}

int user_vma_is_lazy_file_page(uint64_t tid, uintptr_t va) {
    if (va < 0x200000u || va >= (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    unsigned long fl = 0;
    int hit = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid)
            continue;
        if (!g_user_vmas[i].file)
            continue;
        if (!user_vma_is_filemap(&g_user_vmas[i]))
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            hit = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return hit;
}

int user_vma_is_lazy_anon_page(uint64_t tid, uintptr_t va) {
    if (va < 0x200000u || va >= (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    unsigned long fl = 0;
    int hit = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid)
            continue;
        if (g_user_vmas[i].kind != USER_VMA_KIND_MMAP_LAZY)
            continue;
        if (g_user_vmas[i].file)
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            hit = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return hit;
}

int user_vma_is_lazy_file_page_for(thread_t *runner, uintptr_t va) {
    if (!runner || va < 0x200000u || va >= (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    unsigned long fl = 0;
    int hit = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used)
            continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, g_user_vmas[i].tid))
            continue;
        if (!g_user_vmas[i].file)
            continue;
        if (!user_vma_is_filemap(&g_user_vmas[i]))
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            hit = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return hit;
}

int user_vma_fork_scrub_lazy_file(mm_t *child_mm, uint64_t from_tid) {
    mm_t *k;
    uint64_t *share_l4;
    unsigned long fl = 0;
    int rc = 0;

    if (!child_mm || !child_mm->pml4)
        return -1;
    k = mm_kernel();
    if (!k || !k->pml4)
        return -1;
    share_l4 = k->pml4;

    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        uintptr_t a, e, va;
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != from_tid)
            continue;
        if (g_user_vmas[i].file) {
            if (!user_vma_is_filemap(&g_user_vmas[i]))
                continue;
        } else if (g_user_vmas[i].kind != USER_VMA_KIND_MMAP_LAZY) {
            continue;
        }
        a = g_user_vmas[i].addr;
        e = a + g_user_vmas[i].len;
        if (e <= a || a < 0x200000u)
            continue;
        if (e > (uintptr_t)MMIO_IDENTITY_LIMIT)
            e = (uintptr_t)MMIO_IDENTITY_LIMIT;
        /* Drop the lock across unmap (may allocate PT pages). */
        release_irqrestore(&g_user_vma_lock, fl);
        for (va = a & ~((uintptr_t)0xFFFu); va < e; va += 0x1000u) {
            uint64_t pa = 0;
            if (mm_va_leaf_pa(child_mm, (uint64_t)va, &pa) != 0)
                continue;
            /* Private Soft_OWNED frames have pa != va — keep those. */
            if ((pa & ~0xFFFULL) != ((uint64_t)va & ~0xFFFULL))
                continue;
            /* Identity leftover: punch a hole so filemap_fault can run. */
            if (mm_unmap_user_range(child_mm, share_l4, (uint64_t)va,
                                    (uint64_t)va + 0x1000ULL) != 0) {
                rc = -1;
                break;
            }
        }
        acquire_irqsave(&g_user_vma_lock, &fl);
        if (rc != 0)
            break;
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_is_shared_page(uint64_t tid, uintptr_t va) {
    unsigned long fl = 0;
    int shared = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        if (g_user_vmas[i].kind != USER_VMA_KIND_SHM) continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) {
            shared = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return shared;
}

/* Snapshot the VMAs the fork-COW walk needs, under one lock grab:
 * - g_user_vmas entries for `tid` (authoritative for covers/lazy/shared)
 * - the per-mm storage of `mm` (authoritative for mm-scoped SHM)
 * Entries are plain struct copies; the frozen parent guarantees lifetime.
 * Returns entry count (both stores, duplicates possible when in sync). */
int user_vma_snapshot(uint64_t tid, mm_t *mm, user_vma_t *dst, size_t max,
                      int *mm_only_out) {
    if (!dst || max == 0)
        return 0;
    size_t n = 0;
    unsigned long fl;
    int mm_only = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX && n < max; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid)
            continue;
        dst[n++] = g_user_vmas[i];
    }
    if (n < max && mm) {
        user_vma_t *vmas = user_vma_mm_storage(mm, 0);
        if (vmas) {
            for (int i = 0; i < USER_VMA_MAX && n < max; i++) {
                if (!vmas[i].used)
                    continue;
                dst[n++] = vmas[i];
                mm_only++;
            }
        }
    }
    if (mm_only_out)
        *mm_only_out = mm_only;
    release_irqrestore(&g_user_vma_lock, fl);
    return (int)n;
}

int user_vma_fork_privatize_mapped(mm_t *child_mm, mm_t *parent_mm,
                                   uint64_t *parent_l4, uint64_t from_tid) {
    if (!child_mm || !parent_mm || !parent_l4) return -1;
    unsigned long fl = 0;
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != from_tid) continue;
        if (g_user_vmas[i].kind == USER_VMA_KIND_SHM ||
            g_user_vmas[i].kind == USER_VMA_KIND_MMAP_LAZY)
            continue;
        if ((g_user_vmas[i].prot & 2) == 0)
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (e <= a || e > (uintptr_t)MMIO_IDENTITY_LIMIT) {
            rc = -1;
            break;
        }
        /*
         * Linux fork applies COW to every writable private mapping regardless
         * of size. This includes ELF .data/.bss and 2 MiB-backed mappings;
         * skipping either leaves libc globals writable in both processes.
         */
        if (mm_cow_mark_user_readonly_pair_l4(child_mm, parent_mm, parent_l4,
                                              (uint64_t)a, (uint64_t)e) != 0) {
            rc = -1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_clone_for_tid(uint64_t from_tid, uint64_t to_tid) {
    unsigned long fl = 0;
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != from_tid) continue;
        if (user_vma_add_nolock(to_tid, g_user_vmas[i].addr, g_user_vmas[i].len,
                g_user_vmas[i].prot, g_user_vmas[i].kind) != 0) {
            for (int j = 0; j < USER_VMA_MAX; j++) {
                if (g_user_vmas[j].used && g_user_vmas[j].tid == to_tid)
                    user_vma_clear_nolock(&g_user_vmas[j]);
            }
            rc = -1;
            break;
        }
        user_vma_t *dst = user_vma_find_containing_nolock(to_tid, g_user_vmas[i].addr);
        if (dst && g_user_vmas[i].file) {
            fs_file_get(g_user_vmas[i].file);
            dst->file = g_user_vmas[i].file;
            dst->file_off = g_user_vmas[i].file_off;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_lookup_after(thread_t *runner, uintptr_t addr,
    uintptr_t *vm_start, uintptr_t *vm_end, int *kind, int *prot,
    struct fs_file **file, uint64_t *file_off) {
    unsigned long fl = 0;
    user_vma_t *best = NULL;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used)
            continue;
        if (runner) {
            if (!user_vma_tid_matches_runner_mm_nolock(runner, g_user_vmas[i].tid))
                continue;
        } else if (g_user_vmas[i].tid != 1)
            continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (e <= addr)
            continue;
        if (!best || a < best->addr)
            best = &g_user_vmas[i];
    }
    if (!best) {
        release_irqrestore(&g_user_vma_lock, fl);
        return -1;
    }
    if (vm_start)
        *vm_start = best->addr;
    if (vm_end)
        *vm_end = best->addr + best->len;
    if (kind)
        *kind = best->kind;
    if (prot)
        *prot = best->prot;
    if (file_off)
        *file_off = best->file_off;
    if (file) {
        *file = best->file;
        if (best->file)
            fs_file_get(best->file);
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return 0;
}

int user_vma_grow(thread_t *runner, uintptr_t addr, size_t old_len, size_t new_len) {
    if (!runner || old_len == 0 || new_len < old_len)
        return -1;
    unsigned long fl = 0;
    int rc = -1;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used)
            continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, g_user_vmas[i].tid))
            continue;
        if (g_user_vmas[i].addr != addr || g_user_vmas[i].len != old_len)
            continue;
        g_user_vmas[i].len = new_len;
        rc = 0;
        break;
    }
    if (rc == 0 && runner->mm) {
        user_vma_t *vmas = user_vma_mm_storage(runner->mm, 0);
        if (vmas) {
            for (int i = 0; i < USER_VMA_MAX; i++) {
                if (!vmas[i].used)
                    continue;
                if (vmas[i].addr != addr || vmas[i].len != old_len)
                    continue;
                vmas[i].len = new_len;
                break;
            }
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_add_file(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind,
                      struct fs_file *file, uint64_t file_off) {
    if (!file || len == 0)
        return -1;
    if (kind != USER_VMA_KIND_MMAP_LAZY && kind != USER_VMA_KIND_ELF_LOAD &&
        kind != USER_VMA_KIND_MMAP && kind != USER_VMA_KIND_SHM)
        kind = USER_VMA_KIND_MMAP_LAZY;
    unsigned long fl = 0;
    int rc;
    acquire_irqsave(&g_user_vma_lock, &fl);
    rc = user_vma_add_nolock(tid, addr, len, prot, kind);
    if (rc == 0) {
        user_vma_t *v = user_vma_find_containing_nolock(tid, addr);
        if (!v) {
            rc = -1;
        } else {
            if (v->file)
                user_vma_drop_file_nolock(v);
            fs_file_get(file);
            v->file = file;
            v->file_off = file_off;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    if (rc == 0) {
        thread_t *owner = thread_get((int)tid);
        if (owner && owner->mm) {
            (void)user_vma_add_mm(owner->mm, addr, len, prot, kind);
            user_vma_t *vmas = user_vma_mm_storage(owner->mm, 0);
            if (vmas) {
                unsigned long fl2 = 0;
                acquire_irqsave(&g_user_vma_lock, &fl2);
                for (int i = 0; i < USER_VMA_MAX; i++) {
                    if (!vmas[i].used || vmas[i].addr != addr || vmas[i].len != len)
                        continue;
                    if (vmas[i].file)
                        user_vma_drop_file_nolock(&vmas[i]);
                    fs_file_get(file);
                    vmas[i].file = file;
                    vmas[i].file_off = file_off;
                    break;
                }
                release_irqrestore(&g_user_vma_lock, fl2);
            }
        }
    }
    return rc;
}

/*
 * Linux filemap_fault for MAP_SHARED: install the page-cache frame so every
 * attach (fork or a later mmap of the same file) sees the same PA.
 * MAP_PRIVATE still uses user_vma_fill_file_page (private copies).
 */
static int user_vma_map_shared_file_page(thread_t *t, const user_vma_t *hit, uint64_t lo)
{
    uint64_t pa;
    uint64_t foff;
    uint64_t flags;
    mm_t *k;

    if (!t || !t->mm || !hit || !hit->file)
        return 0;
    k = mm_kernel();
    if (!k || !t->mm->pml4 || t->mm->pml4 == k->pml4)
        return 0;
    if (lo < (uint64_t)hit->addr)
        return 0;
    foff = hit->file_off + (lo - (uint64_t)hit->addr);
    if (pagecache_get(hit->file, foff, &pa) != 0)
        return 0;
    flags = PG_PRESENT | PG_US | PG_SOFT_OWNED;
    if (hit->prot & 2)
        flags |= PG_RW;
    if (!(hit->prot & 4))
        flags |= PG_NX;
    if (mm_map_user_page(t->mm, lo, pa, flags) != 0) {
        frame_release(pa);
        return 0;
    }
    invlpg((void *)(uintptr_t)lo);
    return 1;
}

/*
 * Linux filemap_fault: copy one page through a kernel bounce buffer.
 * Never fs_read into a physical frame address, and never skip fill when
 * leaf PA equals VA (identity leftover) — that left zeros so glibc intern
 * treated LC_COLLATE file offsets as pointers (fnmatch #GP, rdi=0x11).
 */
static int user_vma_fill_file_page(thread_t *t, const user_vma_t *hit, uint64_t lo)
{
    uint8_t kbuf[4096];
    uint64_t foff;
    size_t n;
    ssize_t nr;
    mm_t *share;

    if (!hit || !hit->file)
        return 1;
    if (lo < (uint64_t)hit->addr)
        return 0;
    foff = hit->file_off + (lo - (uint64_t)hit->addr);
    memset(kbuf, 0, sizeof(kbuf));
    n = 0x1000u;
    if (foff < (uint64_t)hit->file->size) {
        uint64_t avail = (uint64_t)hit->file->size - foff;
        if (avail < n)
            n = (size_t)avail;
        nr = fs_read(hit->file, kbuf, n, (size_t)foff);
        if (nr < 0)
            return 0;
        if ((size_t)nr < 0x1000u)
            memset(kbuf + (size_t)nr, 0, 0x1000u - (size_t)nr);
    }
    /* Process mm (not swapper): copy via PA like user_mmap_copyin_file. */
    if (t && t->mm && t->mm->pml4 && t->mm != mm_kernel()) {
        share = t->mm_ptemplate ? t->mm_ptemplate : mm_kernel();
        if (mm_copy_to_user(t->mm, share, lo, kbuf, 0x1000u) != 0)
            return 0;
        return 1;
    }
    memcpy((void *)(uintptr_t)lo, kbuf, 0x1000u);
    return 1;
}

int user_vma_fault_lazy_anon(uint64_t cr2) {
    if (cr2 < 0x200000ULL || cr2 >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return 0;
    thread_t *t = thread_current();
    if (!t || t->ring != 3) {
        t = thread_get_current_user();
        if (!t) return 0;
    }
    unsigned long fl = 0;
    uintptr_t va2m = (uintptr_t)(cr2 & ~(uint64_t)(PAGE_SIZE_2M - 1));
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    user_vma_t *hit = NULL;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(t, (uint64_t)g_user_vmas[i].tid)) continue;
        if (g_user_vmas[i].kind != USER_VMA_KIND_MMAP_LAZY &&
            g_user_vmas[i].kind != USER_VMA_KIND_ELF_LOAD &&
            !user_vma_is_filemap(&g_user_vmas[i]))
            continue;
        uint64_t a64 = (uint64_t)g_user_vmas[i].addr;
        uint64_t end64 = a64 + (uint64_t)g_user_vmas[i].len;
        if (end64 < a64) continue;
        if ((uint64_t)cr2 >= a64 && (uint64_t)cr2 < end64) {
            hit = &g_user_vmas[i];
            break;
        }
    }
    if (!hit) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    /* PROT_NONE reservation: access must fault, not demand-fill. */
    if (hit->prot == 0) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    user_vma_t hit_copy = *hit;
    uint64_t hit_end = (uint64_t)hit->addr + (uint64_t)hit->len;
    uint64_t page_lo = (uint64_t)cr2 & ~0xFFFULL;
    if (hit_end < (uint64_t)hit->addr || (uint64_t)cr2 >= hit_end ||
        page_lo < (uint64_t)hit->addr) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    uintptr_t mmap_cap = user_as_mmap_brk_top_limit(t);
    uint64_t cap64 = (uint64_t)mmap_cap;
    if (cap64 > (uint64_t)USER_STACK_TOP)
        cap64 = (uint64_t)USER_STACK_TOP;
    if (page_lo >= cap64 || page_lo >= hit_end) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    release_irqrestore(&g_user_vma_lock, fl);

    uint64_t lo = (uint64_t)cr2 & ~0xFFFULL;
    uint64_t hi = lo + 0x1000ULL;
    if (hit_copy.kind == USER_VMA_KIND_SHM && hit_copy.file)
        return user_vma_map_shared_file_page(t, &hit_copy, lo);
    mm_t *k = mm_kernel();
    if (!(t->mm && k && t->mm->pml4 && k->pml4 && t->mm->pml4 != k->pml4)) {
        if (map_page_2m((uint64_t)va2m, (uint64_t)va2m, PG_PRESENT | PG_RW | PG_US) != 0)
            return 0;
        memset((void *)(uintptr_t)lo, 0, 0x1000u);
        if (!user_vma_fill_file_page(t, &hit_copy, lo))
            return 0;
        return 1;
    }
    mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : k;
    if (mm_privatize_identity_range_blank(t->mm, lo, hi) != 0)
        return 0;
    if (mm_make_private_range_noyield(t->mm, lo, hi, 0, share) != 0)
        return 0;

    if (!user_vma_fill_file_page(t, &hit_copy, lo))
        return 0;
    (void)user_map_mprotect_range(lo, hi, hit_copy.prot);
    return 1;
}

int user_vma_fault_nonpresent(uint64_t cr2, uint64_t err) {
    /*
     * Linux: only !present faults are demand-fill. A present write-protect
     * fault (err bit0=1, bit1=1) is do_wp_page / Soft_COW. Claiming those
     * here returned "handled" without making the leaf writable and livelocked
     * the glibc _Fork child on the first .bss store after set_robust_list.
     */
    if (err & 1u)
        return 0;
    if (cr2 < 0x200000ULL || cr2 >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return 0;
    thread_t *t = thread_current();
    if (!t || t->ring != 3) {
        t = thread_get_current_user();
        if (!t) return 0;
    }

    unsigned long fl = 0;
    uintptr_t va2m = (uintptr_t)(cr2 & ~(uint64_t)(PAGE_SIZE_2M - 1));
    user_vma_t hit_copy;
    int found = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(t, (uint64_t)g_user_vmas[i].tid)) continue;
        uint64_t a64 = (uint64_t)g_user_vmas[i].addr;
        uint64_t end64 = a64 + (uint64_t)g_user_vmas[i].len;
        if (end64 < a64) continue;
        if ((uint64_t)cr2 >= a64 && (uint64_t)cr2 < end64) {
            hit_copy = g_user_vmas[i];
            found = 1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    if (!found) return 0;

    int is_write = (err & 2u) != 0;
    int is_exec = (err & 16u) != 0;
    if (hit_copy.prot == 0) return 0;
    if (is_write && !(hit_copy.prot & 2)) return 0;
    if (is_exec && !(hit_copy.prot & 4) && hit_copy.kind != USER_VMA_KIND_ELF_LOAD) return 0;

    {
        mm_t *k = mm_kernel();
        if (t->mm && k && t->mm->pml4 && k->pml4 && t->mm->pml4 != k->pml4) {
            mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : k;
            uint64_t lo = (uint64_t)(cr2 & ~0xFFFULL);
            uint64_t hi = lo + 0x1000ULL;
            if (hit_copy.kind == USER_VMA_KIND_SHM && hit_copy.file)
                return user_vma_map_shared_file_page(t, &hit_copy, lo);
            if (hit_copy.kind == USER_VMA_KIND_SHM && !hit_copy.file) {
                /*
                 * MAP_SHARED anon uses identity VA==PA. Do not privatize/blank —
                 * that breaks nginx master↔worker shared zones. Install the same
                 * identity leaf into this mm so writers stay coherent.
                 */
                if (mm_clear_range_private(t->mm, share->pml4, lo, hi) != 0)
                    return 0;
                /* map_page_2m updates live CR3 (already this process after #PF). */
                if (map_page_2m((uint64_t)(lo & ~((uint64_t)PAGE_SIZE_2M - 1)),
                                (uint64_t)(lo & ~((uint64_t)PAGE_SIZE_2M - 1)),
                                PG_PRESENT | PG_RW | PG_US) != 0)
                    return 0;
                return 1;
            }
            /* Linux do_anonymous_page / filemap_fault: one 4K page. */
            if (mm_privatize_identity_range_blank(t->mm, lo, hi) != 0)
                return 0;
            if (mm_make_private_range_noyield(t->mm, lo, hi, 0, share) != 0)
                return 0;
            if (!user_vma_fill_file_page(t, &hit_copy, lo))
                return 0;
            /* Apply VMA prot (PROT_EXEC clears NX for libc text pages). */
            (void)user_map_mprotect_range(lo, hi, hit_copy.prot);
            return 1;
        }
    }
    if (err & 1u) {
        if (user_map_mark_identity_2m((uint64_t)va2m, (uint64_t)(va2m + PAGE_SIZE_2M)) != 0)
            return 0;
    } else {
        if (map_page_2m((uint64_t)va2m, (uint64_t)va2m, PG_PRESENT | PG_RW | PG_US) != 0)
            return 0;
    }
    if (hit_copy.file) {
        uint64_t flo = (uint64_t)cr2 & ~0xFFFULL;
        memset((void *)(uintptr_t)flo, 0, 0x1000u);
        if (!user_vma_fill_file_page(t, &hit_copy, flo))
            return 0;
    } else if (hit_copy.kind == USER_VMA_KIND_MMAP_LAZY) {
        uint64_t hit_end = (uint64_t)hit_copy.addr + (uint64_t)hit_copy.len;
        uint64_t chunk_end = (uint64_t)va2m + (uint64_t)PAGE_SIZE_2M;
        size_t zlen = (size_t)PAGE_SIZE_2M;
        if (chunk_end > hit_end) {
            if (hit_end <= (uint64_t)va2m) return 1;
            zlen = (size_t)(hit_end - (uint64_t)va2m);
        }
        memset((void *)(uintptr_t)va2m, 0, zlen);
    }
    return 1;
}

/* axonos.h / idt.c */
int fault_try_mmap_lazy_anon(uint64_t cr2) {
    return user_vma_fault_lazy_anon(cr2);
}

int fault_try_user_vma_nonpresent(uint64_t cr2, uint64_t err) {
    return user_vma_fault_nonpresent(cr2, err);
}
