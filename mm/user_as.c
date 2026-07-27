#include <user_as.h>
#include <mm.h>
#include <user_map.h>
#include <user_mm.h>
#include <user_vma.h>
#include <axonos.h>
#include <exec.h>
#include <heap.h>
#include <klog.h>
#include <mmio.h>
#include <paging.h>
#include <string.h>
#include <thread.h>

extern void kprintf(const char *fmt, ...);

uintptr_t user_as_mmap_next = 0;
uintptr_t user_as_mmap_hi = 0;
uintptr_t user_as_brk_base = 0;
uintptr_t user_as_brk_cur = 0;

/* True when the thread owns a distinct page-table root (not the shared kernel L4). */
static int user_as_has_private_mm(thread_t *t) {
    mm_t *k = mm_kernel();
    return t && t->mm && k && t->mm->pml4 && k->pml4 && t->mm->pml4 != k->pml4;
}

/* Map [lo,hi) for brk/teardown without collapsing private 4K ELF pages back to
 * identity 2MiB (that stomped openrc back to busybox at 0x4030d0).
 * Returns 0 on success, -1 if private anon install failed (fail closed). */
static int user_as_ensure_range_for_exec(thread_t *tcur, uintptr_t lo, uintptr_t hi) {
    if (hi <= lo || lo < 0x200000u || hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
        return 0;
    if (user_as_has_private_mm(tcur)) {
        /* Linux do_brk_flags: identity→anon zero; share baseline = oldmm. */
        mm_t *share = tcur->mm_ptemplate ? tcur->mm_ptemplate : mm_kernel();
        if (mm_privatize_identity_range_blank(tcur->mm, (uint64_t)lo, (uint64_t)hi) != 0)
            return -1;
        if (mm_make_private_range(tcur->mm, (uint64_t)lo, (uint64_t)hi, 0, share) != 0)
            return -1;
        return 0;
    }
    if (user_map_ensure_present_us_2m((uint64_t)lo, (uint64_t)hi) != 0)
        return -1;
    user_as_mmap_memset_zero_chunked(lo, (size_t)(hi - lo));
    return 0;
}

uintptr_t user_as_stack_top_for_tid(uint64_t tid) {
    const uintptr_t top = (uintptr_t)USER_STACK_TOP;
    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
    const uint64_t slot = tid + 1ULL;
    if (stride == 0) return top;
    if (slot > (uint64_t)((uintptr_t)-1) / (uint64_t)stride) return top;
    const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
    const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
    if (top <= min_room) return top;
    if (off >= (top - min_room)) return top;
    return top - off;
}

uintptr_t user_as_mmap_brk_top_limit(thread_t *tcur) {
    /*
     * Linux get_unmapped_area is process-wide. Do NOT clamp to the calling
     * thread's pthread stack_base (Go workers sit mid-VA around 0x31xxxxxx):
     * that made mmap for the next ~8MiB stack see top≈0x318a0000 after arenas
     * filled [MMAP_BASE..pthread_stack) and fail with ENOMEM / EAGAIN.
     * Pthread stacks are normal mmap VMAs — find_unmapped skips them.
     */
    uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
    (void)tcur;
    if (top_limit > (uintptr_t)USER_STACK_TOP)
        top_limit = (uintptr_t)USER_STACK_TOP;
    {
        uintptr_t hlo = (uintptr_t)heap_base_addr();
        if (hlo > 0x200000u && hlo < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            uintptr_t guard = 0x20000u;
            uintptr_t heap_cap = (hlo > guard) ? (hlo - guard) : hlo;
            if (heap_cap < top_limit)
                top_limit = heap_cap;
        }
    }
    return top_limit;
}

uintptr_t user_as_shared_max_mmap_next(thread_t *cur, uintptr_t fallback) {
    uintptr_t cap = (uintptr_t)USER_STACK_TOP;
    if (cur) {
        uintptr_t tl = user_as_mmap_brk_top_limit(cur);
        if (tl < cap)
            cap = tl;
    }
    uintptr_t v = (fallback < cap) ? fallback : 0;
    if (!cur || !cur->mm)
        return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        uintptr_t nx = t->user_mmap_next;
        if (nx >= cap) continue;
        if (nx > v) v = nx;
    }
    return v;
}

uintptr_t user_as_shared_max_brk_cur(thread_t *cur, uintptr_t fallback) {
    uintptr_t v = fallback;
    if (!cur || !cur->mm) return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_cur > v) v = t->user_brk_cur;
    }
    return v;
}

uintptr_t user_as_shared_pick_brk_base(thread_t *cur, uintptr_t fallback) {
    uintptr_t v = fallback;
    if (!cur || !cur->mm) return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_base > 0 && (v == 0 || t->user_brk_base < v))
            v = t->user_brk_base;
    }
    return v;
}

void user_as_shared_publish_brk(thread_t *cur, uintptr_t base, uintptr_t cur_brk) {
    if (!cur || !cur->mm) return;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_base == 0) t->user_brk_base = base;
        if (t->user_brk_cur < cur_brk) t->user_brk_cur = cur_brk;
    }
}

void user_as_shared_publish_mmap(thread_t *cur, uintptr_t next, uintptr_t hi) {
    if (!cur || !cur->mm) return;
    uintptr_t cap = user_as_mmap_brk_top_limit(cur);
    if (cap > (uintptr_t)USER_STACK_TOP)
        cap = (uintptr_t)USER_STACK_TOP;
    if (next > cap || hi > cap) {
        klogprintf("user_as: drop corrupt mmap cursor next=0x%llx hi=0x%llx cap=0x%llx\n",
            (unsigned long long)next, (unsigned long long)hi, (unsigned long long)cap);
        return;
    }
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_mmap_next < next) t->user_mmap_next = next;
        if (t->user_mmap_hi < hi) t->user_mmap_hi = hi;
    }
}

int user_as_mmap_overlaps_user_stack(thread_t *t, uintptr_t addr, uintptr_t len,
    uintptr_t *above_stack_out) {
    if (above_stack_out)
        *above_stack_out = 0;
    uintptr_t map_end = addr + len;
    if (len && map_end < addr)
        return 1;

    /*
     * Only the high primary stack (near USER_STACK_TOP) is a hard reserved
     * band. Mid-VA pthread stacks are mmap VMAs and must not be treated as a
     * process-wide ceiling here.
     */
    uintptr_t lo = 0;
    uintptr_t hi = 0;
    const uintptr_t primary_floor = (uintptr_t)USER_STACK_TOP / 2u;
    if (t && t->user_stack_limit > t->user_stack_base &&
        t->user_stack_base >= primary_floor) {
        lo = (uintptr_t)t->user_stack_base;
        hi = (uintptr_t)t->user_stack_limit;
    }
    if (lo == 0 || hi <= lo)
        return 0;
    if (map_end <= lo || addr >= hi)
        return 0;
    if (above_stack_out)
        *above_stack_out = user_mm_align_up(hi, (uintptr_t)PAGE_SIZE_2M);
    return 1;
}

int user_as_mmap_overlaps_kernel_heap(uintptr_t addr, uintptr_t len) {
    uintptr_t map_end = addr + len;
    if (len && map_end < addr)
        return 1;
    uintptr_t hlo = (uintptr_t)heap_base_addr();
    uintptr_t hhi = heap_region_end_exclusive();
    if (hlo <= 0x200000 || !(hhi > hlo))
        return 0;
    if (map_end <= hlo || addr >= hhi)
        return 0;
    return 1;
}

void user_as_mmap_memset_zero_chunked(uintptr_t addr, size_t len) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (user_as_mmap_overlaps_kernel_heap(addr, len)) {
        klogprintf("user_as: refuse memset on kernel region addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)(uint64_t)len);
        return;
    }
    if (addr >= (uintptr_t)USER_TLS_BASE) {
        klogprintf("user_as: refuse memset above TLS addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)(uint64_t)len);
        return;
    }
    if (t && user_as_mmap_overlaps_user_stack(t, addr, len, NULL)) {
        klogprintf("user_as: refuse memset on stack overlap addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)(uint64_t)len);
        return;
    }
    /*
     * Private mm: pages were installed as anon zero via do_brk_flags /
     * do_anonymous_page. VA memset would hit identity phys while CR3 is still
     * oldmm (vfork-exec load) or smash a sibling that still shares that PA.
     */
    if (user_as_has_private_mm(t))
        return;
    const size_t chunk = 4u * 1024u * 1024u;
    if (len <= chunk) {
        memset((void *)addr, 0, len);
        return;
    }
    for (size_t off = 0; off < len; off += chunk) {
        size_t now = (len - off < chunk) ? (len - off) : chunk;
        memset((void *)(addr + off), 0, now);
    }
}

void user_as_mmap_lazy_drop_present_pages(uintptr_t addr, size_t len) {
    /*
     * Do NOT call unmap_page_2m() here: that clears the same VA in the kernel
     * mm identity map. Page-table pages are accessed via VA==PA; punching a
     * 128MiB+ hole under USER_MMAP_BASE then makes unmap_page_2m_on_l4 fault
     * in the kernel (seen as Oops CR2=0x8117000 while dropping Go PROT_NONE).
     *
     * Private mm: unmap only in the process tables.
     * Shared CR3: leave leaves present; PROT_NONE is enforced by VMA prot==0
     * in the fault path (no demand-fill).
     */
    thread_t *t = thread_get_current_user();
    if (!t)
        t = thread_current();
    mm_t *k = mm_kernel();
    if (!t || !t->mm || !k || !t->mm->pml4 || t->mm->pml4 == k->pml4)
        return;
    mm_t *share = (t->mm_ptemplate && t->mm_ptemplate->pml4) ?
        t->mm_ptemplate : k;
    if (!share || !share->pml4)
        return;
    (void)mm_unmap_user_range(t->mm, share->pml4,
                              (uint64_t)addr,
                              (uint64_t)addr + (uint64_t)len);
}

void user_as_reset_on_exec(thread_t *tcur, uintptr_t brk_base) {
    if (brk_base < (8u * 1024u * 1024u)) brk_base = 8u * 1024u * 1024u;
    brk_base = user_mm_align_up(brk_base, 4096);
    if (tcur) {
        tcur->user_brk_base = brk_base;
        tcur->user_brk_cur = brk_base;
        tcur->user_mmap_next = 0;
        tcur->user_mmap_hi = 0;
    } else {
        user_as_brk_base = brk_base;
        user_as_brk_cur = brk_base;
        user_as_mmap_next = 0;
        user_as_mmap_hi = 0;
    }
}

void user_as_set_brk_after_load(thread_t *tcur, uintptr_t elf_brk, uintptr_t image_hi) {
    const uintptr_t floor = 8u * 1024u * 1024u;
    /* Static glibc __libc_setup_tls places the TCB in the brk slab (~fs:0x8003c0). */
    const uintptr_t tls_window = 64u * 1024u;
    uintptr_t orig = elf_brk;
    uintptr_t brk = elf_brk;
    if (brk < floor) brk = floor;
    brk = user_mm_align_up(brk, 4096);
    /*
     * Legacy shared-CR3: zero image→brk gap.
     * Private mm (Linux do_brk_flags): install anon zero pages for the initial
     * brk/TLS window so identity leaves are never user backing for SET_FS.
     * Do not prefault multi-MiB — further growth uses user_brk_ensure_range.
     */
    if (!user_as_has_private_mm(tcur)) {
        uintptr_t zero_lo = 0;
        if (image_hi > 0x200000u && brk > image_hi)
            zero_lo = image_hi;
        else if (orig > 0x200000u && brk > orig)
            zero_lo = orig;
        if (zero_lo != 0 && brk > zero_lo && brk <= (uintptr_t)MMIO_IDENTITY_LIMIT)
            (void)user_as_ensure_range_for_exec(tcur, zero_lo, brk);
    } else {
        /*
         * Raise brk to 8MiB for glibc TLS, but also materialize [elf_end, brk).
         * Musl-static bash uses the classic &_end heap in that gap (fopen
         * /etc/passwd → malloc); if those pages are missing, getpwuid fails
         * and the prompt becomes "I have no name!".
         */
        uintptr_t gap_lo = orig;
        if (image_hi > gap_lo)
            gap_lo = image_hi;
        gap_lo = user_mm_align_up(gap_lo, 4096);
        if (gap_lo < brk && gap_lo > 0x200000u &&
            user_as_ensure_range_for_exec(tcur, gap_lo, brk) != 0)
            kprintf("exec-brk: anon gap failed lo=0x%llx brk=0x%llx\n",
                (unsigned long long)gap_lo, (unsigned long long)brk);
        uintptr_t hi = brk + tls_window;
        if (hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
            hi = (uintptr_t)MMIO_IDENTITY_LIMIT;
        if (hi > brk && user_as_ensure_range_for_exec(tcur, brk, hi) != 0)
            kprintf("exec-brk: anon TLS window failed brk=0x%llx hi=0x%llx\n",
                (unsigned long long)brk, (unsigned long long)hi);
    }
    if (tcur) {
        tcur->user_brk_base = brk;
        tcur->user_brk_cur = brk;
        if (tcur->mm) {
            tcur->mm->brk_base = brk;
            tcur->mm->brk_current = brk;
        }
        user_as_shared_publish_brk(tcur, brk, brk);
    } else {
        user_as_brk_base = brk;
        user_as_brk_cur = brk;
    }
}

void user_as_teardown_for_exec(thread_t *tcur, uintptr_t new_brk_base) {
    /*
     * Linux execve replaces the mm. When kernel_execve_from_path() already
     * installed a fresh private mm, the old brk/mmap/heap live only in the
     * discarded tree — do NOT scrub those VAs into the new mm.
     *
     * The old scrub (make_private_range / memset over [brk_lo,brk_hi)) walked
     * still-shared identity leaves and zeroed/remapped the vfork parent's
     * heap (fs≈0x8003c0, command name "ls" @ 0x801738 → parent #GP). It also
     * stalled syscall 59 for many seconds on a grown ash heap.
     */
    if (user_as_has_private_mm(tcur)) {
        uint64_t tid = (uint64_t)(tcur->tid ? tcur->tid : 1);
        user_vma_remove_all_for_tid(tid);
        user_as_reset_on_exec(tcur, new_brk_base);
        user_as_reset_on_exec(NULL, new_brk_base);
        return;
    }

    /* Legacy shared-CR3 boot path (no per-task mm yet). */
    uintptr_t brk_lo = (uintptr_t)-1;
    uintptr_t brk_hi = 0;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (tcur && tcur->mm && t->mm != tcur->mm && t->ring == 3) continue;
        if (t->user_brk_base != 0) {
            if (t->user_brk_base < brk_lo) brk_lo = t->user_brk_base;
            if (t->user_brk_cur > brk_hi) brk_hi = t->user_brk_cur;
        } else if (t->user_brk_cur > brk_hi) {
            brk_hi = t->user_brk_cur;
        }
    }
    if (user_as_brk_cur > brk_hi) brk_hi = user_as_brk_cur;
    if (user_as_brk_base != 0 && user_as_brk_base < brk_lo) brk_lo = user_as_brk_base;
    if (brk_lo == (uintptr_t)-1)
        brk_lo = 8u * 1024u * 1024u;
    if (brk_hi < brk_lo)
        brk_hi = brk_lo;

    user_vma_teardown_unmap_for_exec(tcur);

    if (brk_hi > brk_lo && brk_lo >= 0x200000u && brk_hi <= (uintptr_t)MMIO_IDENTITY_LIMIT)
        user_as_ensure_range_for_exec(tcur, brk_lo, brk_hi);

    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->ring == 3 && tcur && tcur->mm && t->mm != tcur->mm) continue;
        user_as_reset_on_exec(t, new_brk_base);
    }
    user_as_reset_on_exec(NULL, new_brk_base);
}
