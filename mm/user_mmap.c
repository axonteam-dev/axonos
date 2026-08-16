#include <user_mmap.h>
#include <mm.h>
#include <user_vma.h>
#include <user_as.h>
#include <user_map.h>
#include <user_mm.h>
#include <user_layout.h>
#include <exec.h>
#include <fs.h>
#include <thread.h>
#include <heap.h>
#include <mmio.h>
#include <paging.h>
#include <debug.h>
#include <klog.h>
#include <fbdev.h>
#include <string.h>
#include <axonos.h>

extern void kprintf(const char *fmt, ...);

static int user_mmap_watch(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    return (strstr(t->name, "linuxrc") || strstr(t->name, "busybox") ||
            strstr(t->name, "wget") || strstr(t->name, "uget") ||
            strstr(t->name, "adduser") || strstr(t->name, "addgroup")) ? 1 : 0;
}

enum {
    MAP_FIXED = 0x10,
    MAP_ANONYMOUS = 0x20,
    MAP_PRIVATE = 0x02,
    MAP_SHARED = 0x01,
    MAP_GROWSDOWN = 0x0100,
    MAP_DENYWRITE = 0x0800,
    MAP_EXECUTABLE = 0x1000,
    MAP_LOCKED = 0x2000,
    MAP_NORESERVE = 0x4000,
    MAP_POPULATE = 0x8000,
    MAP_NONBLOCK = 0x10000,
    MAP_STACK = 0x20000,
    MAP_HUGETLB = 0x40000,
    MAP_SYNC = 0x80000,
    MAP_FIXED_NOREPLACE = 0x100000,
};

/* Linux treats these as hints / bookkeeping; ignore after anon install. */
enum {
    MAP_IGNORABLE = MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE |
                    MAP_LOCKED | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK |
                    MAP_STACK | MAP_HUGETLB | MAP_SYNC
};

static int user_mmap_unmap_pages(thread_t *t, uintptr_t addr, size_t len) {
    if (!t || !t->mm)
        return user_map_unmap_range((uint64_t)addr,
                                    (uint64_t)addr + (uint64_t)len);
    mm_t *kernel_mm = mm_kernel();
    if (t->mm == kernel_mm || !t->mm->pml4)
        return user_map_unmap_range((uint64_t)addr,
                                    (uint64_t)addr + (uint64_t)len);
    mm_t *share = (t->mm_ptemplate && t->mm_ptemplate != t->mm &&
                   t->mm_ptemplate->pml4) ?
        t->mm_ptemplate : kernel_mm;
    if (!share || !share->pml4)
        return -1;
    return mm_unmap_user_range(t->mm, share->pml4,
                               (uint64_t)addr,
                               (uint64_t)addr + (uint64_t)len);
}

static int user_mmap_install_pages(uintptr_t addr, size_t len, uintptr_t top_limit,
                                   int shared_mapping) {
    if ((uint64_t)addr + (uint64_t)len > (uint64_t)top_limit)
        return -1;
    uint64_t req_lo = (uint64_t)addr & ~0xFFFULL;
    uint64_t req_hi = ((uint64_t)addr + (uint64_t)len + 0xFFFULL) & ~0xFFFULL;
    if (req_hi > (uint64_t)top_limit)
        req_hi = (uint64_t)top_limit;
    if (req_lo >= req_hi)
        return -1;
    /*
     * MAP_SHARED anon must stay coherent across fork (nginx accept mutex /
     * slab zones). Use identity VA==PA leaves; fork + #PF keep them shared.
     * MAP_PRIVATE: never identity-map into a private mm (ash GPF after fork).
     */
    if (shared_mapping) {
        uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
        uintptr_t map_end = (uintptr_t)(((uint64_t)addr + (uint64_t)len + PAGE_SIZE_2M - 1) &
                                        ~((uint64_t)PAGE_SIZE_2M - 1));
        if (map_begin >= map_end || map_end > top_limit)
            return -1;
        for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
            if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
                return -1;
        }
        return 0;
    }
    {
        thread_t *t = thread_get_current_user();
        if (!t)
            t = thread_current();
        mm_t *k = mm_kernel();
        if (t && t->mm && k && t->mm->pml4 && k->pml4 &&
            t->mm->pml4 != k->pml4) {
            mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : k;
            if (!share || !share->pml4)
                return -1;
            /*
             * Linux do_mmap/do_anonymous_page: private anon → fresh zero pages.
             * mm_demote_user_identity leaves !US identity; unmap must see those
             * (mm_va_leaf_pa). Only clear [req_lo,req_hi) — wiping the whole
             * covering 2MiB destroyed sibling anon maps (curl body buffer) so
             * the later write(stdout) copy_from_user EFAULT'd → curl error 23.
             */
            if (mm_unmap_user_range(t->mm, share->pml4, req_lo, req_hi) != 0)
                return -1;
            if (mm_make_private_range_bulk_zero_force(t->mm, req_lo, req_hi,
                                                     share) != 0)
                return -1;
            return 0;
        }
    }
    uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
    uintptr_t map_end = (uintptr_t)(((uint64_t)addr + (uint64_t)len + PAGE_SIZE_2M - 1) &
                                    ~((uint64_t)PAGE_SIZE_2M - 1));
    if (map_begin >= map_end || map_end > top_limit)
        return -1;
    for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
        if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
            return -1;
    }
    return 0;
}

uint64_t user_syscall_mmap(thread_t *cur, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6) {
    uintptr_t req_addr = (uintptr_t)a1;
    uint64_t len_u64 = (uint64_t)a2;
    int prot = (int)a3;
    int flags = (int)a4;
    int shared_mapping = (flags & MAP_SHARED) != 0;
    /* Linux: PROT_NONE (prot==0) is a pure VA reservation — no phys commit. */
    int prot_none = ((prot & 7) == 0);

    if (len_u64 == 0) return user_mm_ret_err(USER_MM_EINVAL);
    if (user_mm_len_exceeds_cap(len_u64)) {
        kprintf("mmap: ENOMEM raw len 0x%llx >= cap 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)USER_MM_SINGLE_MAP_CAP);
        klogprintf("mmap: ENOMEM raw len 0x%llx >= cap 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)USER_MM_SINGLE_MAP_CAP);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    len_u64 = (len_u64 + 4095ull) & ~4095ull;
    if (len_u64 > (uint64_t)((size_t)-1)) return user_mm_ret_err(USER_MM_EINVAL);
    if (user_mm_len_exceeds_cap(len_u64)) {
        kprintf("mmap: ENOMEM len 0x%llx >= cap 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)USER_MM_SINGLE_MAP_CAP);
        klogprintf("mmap: ENOMEM len 0x%llx >= cap 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)USER_MM_SINGLE_MAP_CAP);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    size_t len = (size_t)len_u64;

    int fixed_mapping = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) ? 1 : 0;
    if (!(flags & (MAP_PRIVATE | MAP_SHARED))) return user_mm_ret_err(USER_MM_ENOSYS);

    /* Go runtime sysReserve uses high arena hints (e.g. 0xc0<<32). Fail fast —
     * do not walk install/zero paths for addresses we can never map. */
    if (fixed_mapping &&
        (req_addr >= (uintptr_t)USER_STACK_TOP ||
         req_addr >= (uintptr_t)MMIO_IDENTITY_LIMIT ||
         (uint64_t)req_addr + len_u64 < (uint64_t)req_addr ||
         (uint64_t)req_addr + len_u64 > (uint64_t)USER_STACK_TOP))
        return user_mm_ret_err(USER_MM_ENOMEM);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();

    uintptr_t top_limit = user_as_mmap_brk_top_limit(tcur);
    if (top_limit > (uintptr_t)USER_STACK_TOP)
        top_limit = (uintptr_t)USER_STACK_TOP;

    uintptr_t *p_mmap_next = (tcur && tcur->mm) ? &tcur->mm->mmap_cursor :
        (tcur ? &tcur->user_mmap_next : &user_as_mmap_next);
    uintptr_t shared_next = tcur ? user_as_shared_max_mmap_next(tcur, *p_mmap_next) : *p_mmap_next;
    if (shared_next > *p_mmap_next) *p_mmap_next = shared_next;
    if (*p_mmap_next >= top_limit) *p_mmap_next = 0;

    if (tcur) {
        uintptr_t vma_hi = user_vma_max_mmap_like_end_for_mm(tcur);
        /* ELF_LOAD ends near &_end / TLS (e.g. 0x14xxxxx). Do not start the
         * next anon mmap there — PROT_NONE reserve would unmap Go's fs TLS. */
        if (vma_hi < (uintptr_t)USER_MMAP_BASE)
            vma_hi = 0;
        if (vma_hi > *p_mmap_next) {
            if (vma_hi < top_limit) *p_mmap_next = vma_hi;
            else *p_mmap_next = 0;
        }
    }

    uintptr_t brk_cur_for_mmap = tcur ? user_as_shared_max_brk_cur(tcur, tcur->user_brk_cur) : user_as_brk_cur;
    if (brk_cur_for_mmap == 0) brk_cur_for_mmap = 8u * 1024u * 1024u;
    uintptr_t brk_guard_floor = user_mm_align_up(brk_cur_for_mmap + 0x10000u, 4096);
    /* Never place/punch anon mmap through the ELF image, brk gap, or TLS. */
    uintptr_t anon_floor = (uintptr_t)USER_MMAP_BASE;
    if (brk_guard_floor > anon_floor)
        anon_floor = brk_guard_floor;
    /*
     * Leave a permanent low band for glibc brk + small mmap arenas.
     * Go PROT_NONE / large anon are placed TOP-DOWN above this band so they
     * cannot starve libc malloc (x_cgo_thread_start malloc(24)).
     */
    const uintptr_t libc_zone = 128u * 1024u * 1024u;
    /* pthread MAP_STACK stays in the low libc band (bottom-up). Go arenas don't. */
    int is_stack = (flags & MAP_STACK) != 0;
    int large_or_reserve = (flags & MAP_ANONYMOUS) && !shared_mapping &&
        !fixed_mapping && !is_stack && (prot_none || len_u64 > (1ull << 20));
    if (large_or_reserve) {
        uintptr_t prefer = (uintptr_t)USER_MMAP_BASE + libc_zone;
        if (brk_guard_floor + libc_zone > prefer)
            prefer = brk_guard_floor + libc_zone;
        prefer = user_mm_align_up(prefer, (uintptr_t)PAGE_SIZE_2M);
        if (prefer > anon_floor && prefer < top_limit &&
            prefer + len_u64 <= top_limit)
            anon_floor = prefer;
    }
    /*
     * Guard only low TLS (glibc TCB near brk/image). Go keeps FS near the
     * stack; raising anon_floor to that tip made anon_floor >= top_limit and
     * the reset below collapsed the search floor to ~brk (0x26xxxxx) — then
     * 128MiB arenas hit "no free VA" despite a free window under the stack.
     */
    if (tcur && tcur->user_fs_base >= 0x200000u &&
        tcur->user_fs_base < (uintptr_t)USER_MMAP_BASE) {
        uintptr_t tls_hi = user_mm_align_up(
            (uintptr_t)tcur->user_fs_base + 0x10000u, (uintptr_t)PAGE_SIZE_2M);
        if (tls_hi > anon_floor && tls_hi < top_limit)
            anon_floor = tls_hi;
    }
    if (anon_floor >= top_limit) {
        anon_floor = brk_guard_floor;
        if (anon_floor < (uintptr_t)USER_MMAP_BASE &&
            (uintptr_t)USER_MMAP_BASE < top_limit)
            anon_floor = (uintptr_t)USER_MMAP_BASE;
        if (anon_floor >= top_limit)
            anon_floor = brk_guard_floor < top_limit ? brk_guard_floor : 0;
    }

    if (len_u64 > (uint64_t)top_limit) {
        kprintf("mmap: ENOMEM len 0x%llx > top_limit 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)top_limit);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    if (*p_mmap_next == 0) {
        /* Prefer the reserved user mmap window (see user_layout.h), not 32MiB
         * which collides with early brk growth and used to sit under the heap. */
        uintptr_t def = anon_floor;
        if (def >= top_limit && top_limit > (8u * 1024u * 1024u)) {
            def = user_mm_align_up(top_limit / 2u, 4096);
            if (def < (8u * 1024u * 1024u)) def = 8u * 1024u * 1024u;
            if (def < anon_floor && anon_floor < top_limit)
                def = anon_floor;
        }
        *p_mmap_next = def;
    }
    if (*p_mmap_next < anon_floor) *p_mmap_next = anon_floor;
    if (*p_mmap_next < brk_guard_floor) *p_mmap_next = brk_guard_floor;

    /*
     * Stack occupies [base, limit). top_limit already stops below that VMA —
     * do not bump mmap_next above the stack tip (that left no room for Go).
     */
    if (tcur && tcur->user_stack_base != 0 &&
        tcur->user_stack_limit > tcur->user_stack_base &&
        *p_mmap_next >= top_limit) {
        *p_mmap_next = anon_floor < top_limit ? anon_floor : brk_guard_floor;
    }

    /*
     * Large Go arenas (dockerd) are 2MiB-aligned PROT_NONE reserves. Keep the
     * chosen VA 2MiB-aligned so reserve_only applies and we do not eagerly
     * commit 128MiB of frames.
     */
    uintptr_t map_align = 4096u;
    if ((flags & MAP_ANONYMOUS) && !shared_mapping &&
        len_u64 > (96ull << 20) &&
        (len_u64 & ((uint64_t)PAGE_SIZE_2M - 1)) == 0)
        map_align = (uintptr_t)PAGE_SIZE_2M;

    uintptr_t addr = fixed_mapping ? req_addr : user_mm_align_up(*p_mmap_next, map_align);
    if (fixed_mapping && (addr & 0xFFFu) != 0) return user_mm_ret_err(USER_MM_EINVAL);
    if (fixed_mapping && user_as_mmap_overlaps_kernel_heap(addr, len))
        return user_mm_ret_err(USER_MM_EINVAL);

    if (!fixed_mapping) {
        uintptr_t floor = anon_floor;
        if (brk_guard_floor > floor)
            floor = brk_guard_floor;
        if (addr < floor)
            addr = floor;
        /*
         * Linux do_mmap / get_unmapped_area: without MAP_FIXED a busy hint or a
         * stale mmap cursor that sits under an existing VMA (holes after
         * munmap / MAP_FIXED arenas) must not ENOMEM — search for a free gap.
         */
        uintptr_t search = user_mm_align_up(addr, map_align);
        uintptr_t soft_hint = 0;
        if (req_addr != 0) {
            uintptr_t h = user_mm_align_up(req_addr, map_align);
            if (h >= floor && user_mm_range_fits(h, len_u64, top_limit) &&
                h < (uintptr_t)USER_TLS_BASE &&
                (uint64_t)h + len_u64 <= (uint64_t)USER_TLS_BASE)
                soft_hint = h;
        }
        /* Large Go arenas: top-down so the libc zone below anon_floor stays free. */
        int use_topdown = large_or_reserve && tcur &&
            (prot_none || len_u64 > (32ull << 20));
        addr = 0;
        if (use_topdown) {
            uintptr_t cand = user_vma_find_unmapped_topdown(tcur, floor, top_limit,
                                                           len_u64, map_align);
            if (cand != 0 && !user_as_mmap_overlaps_kernel_heap(cand, len) &&
                !(tcur && user_as_mmap_overlaps_user_stack(tcur, cand,
                                                          (uintptr_t)len_u64, NULL)) &&
                user_mm_range_fits(cand, len_u64, top_limit) &&
                cand >= brk_guard_floor) {
                addr = cand;
            }
        }
        if (addr == 0) {
        int retried_from_floor = 0;
        for (int attempt = 0; attempt < 64; attempt++) {
            if (search < floor)
                search = floor;
            search = user_mm_align_up(search, map_align);
            uintptr_t cand = tcur ?
                user_vma_find_unmapped(tcur, search, top_limit, len_u64,
                                       attempt == 0 ? soft_hint : 0, map_align) :
                search;
            if (!tcur) {
                /* No VMA owner: accept cursor if it fits. */
                if (!user_mm_range_fits(search, len_u64, top_limit))
                    cand = 0;
                else
                    cand = search;
            }
            if (cand == 0) {
                /*
                 * Cursor may sit near top_limit so (ceil-search) < len even
                 * though a free gap exists at anon_floor (Linux bottom-up
                 * fallback after vm_unmapped_area fails the hint/cursor).
                 */
                if (!retried_from_floor && search > floor) {
                    search = floor;
                    retried_from_floor = 1;
                    continue;
                }
                break;
            }
            if (user_as_mmap_overlaps_kernel_heap(cand, len)) {
                const uintptr_t hgap = 0x10000u;
                uintptr_t hhi = heap_region_end_exclusive();
                uintptr_t skip = user_mm_align_up(hhi + hgap, map_align);
                if (skip <= search || skip >= top_limit) {
                    if (!retried_from_floor && search > floor) {
                        search = floor;
                        retried_from_floor = 1;
                        continue;
                    }
                    break;
                }
                search = skip;
                continue;
            }
            if (tcur && user_as_mmap_overlaps_user_stack(tcur, cand, (uintptr_t)len_u64, NULL)) {
                uintptr_t above_stack = 0;
                (void)user_as_mmap_overlaps_user_stack(tcur, cand, (uintptr_t)len_u64, &above_stack);
                if (above_stack > cand && above_stack < top_limit) {
                    search = user_mm_align_up(above_stack, map_align);
                    continue;
                }
                if (!retried_from_floor && search > floor) {
                    search = floor;
                    retried_from_floor = 1;
                    continue;
                }
                break;
            }
            if (!user_mm_range_fits(cand, len_u64, top_limit) ||
                cand >= (uintptr_t)USER_TLS_BASE ||
                (uint64_t)cand + len_u64 > (uint64_t)USER_TLS_BASE ||
                cand < brk_guard_floor) {
                search = cand + map_align;
                continue;
            }
            addr = cand;
            break;
        }
        } /* bottom-up (or topdown miss) */
        if (addr == 0) {
            kprintf("mmap: ENOMEM no free VA len=0x%llx floor=0x%llx top=0x%llx\n",
                (unsigned long long)len_u64,
                (unsigned long long)floor,
                (unsigned long long)top_limit);
            return user_mm_ret_err(USER_MM_ENOMEM);
        }
        *p_mmap_next = addr;
    }
    if (addr < brk_guard_floor) return user_mm_ret_err(USER_MM_EINVAL);
    /* MAP_FIXED must not punch through TLS/brk/image below the anon floor. */
    if (fixed_mapping && addr < anon_floor)
        return user_mm_ret_err(USER_MM_ENOMEM);
    if ((uint64_t)addr + len_u64 < (uint64_t)addr)
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (addr >= (uintptr_t)USER_TLS_BASE ||
        (uint64_t)addr + len_u64 > (uint64_t)USER_TLS_BASE) {
        kprintf("mmap: ENOMEM outside user mmap cap addr=0x%llx len=0x%llx cap=0x%llx fixed=%d\n",
            (unsigned long long)addr,
            (unsigned long long)len_u64,
            (unsigned long long)(uint64_t)USER_TLS_BASE,
            fixed_mapping);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    if (!user_mm_range_fits(addr, len_u64, top_limit)) {
        kprintf("mmap: ENOMEM span_end=0x%llx cap=0x%llx\n",
            (unsigned long long)((uint64_t)addr + len_u64), (unsigned long long)top_limit);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    if (user_mm_len_exceeds_cap(len_u64)) return user_mm_ret_err(USER_MM_ENOMEM);

    if (tcur && user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, NULL)) {
        kprintf("mmap: ENOMEM still overlaps user stack addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)len_u64);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    uint64_t vtid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    if (fixed_mapping) {
        if ((flags & MAP_FIXED_NOREPLACE) && user_vma_mmap_range_overlaps(tcur, addr, len))
            return user_mm_ret_err(USER_MM_ENOMEM);
        if (!(flags & MAP_FIXED_NOREPLACE)) {
            if (user_vma_can_unmap_range(vtid, addr, len) != 0 ||
                user_mmap_unmap_pages(tcur, addr, len) != 0 ||
                user_vma_unmap_range(vtid, addr, len) != 0)
                return user_mm_ret_err(USER_MM_ENOMEM);
        }
    }

    if (addr < 0x200000 ||
        user_as_mmap_overlaps_kernel_heap(addr, len)) {
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    /*
     * PROT_NONE / large anon: Linux reserves VA without allocating frames.
     * Private file maps (libc.so via ld.so): same — demand-fill on #PF
     * (filemap_fault). Eager fs_read of ~2MiB + frame_alloc made every
     * dynamic execve feel like ~1s.
     */
    int mmap_vma_kind = (flags & MAP_SHARED) ?
        USER_VMA_KIND_SHM : USER_VMA_KIND_MMAP;
    int reserve_only = 0;
    int file_lazy = 0;
    struct fs_file *file_lazy_f = NULL;
    uint64_t file_lazy_off = 0;
    if ((flags & MAP_ANONYMOUS) && !shared_mapping) {
        /*
         * Linux demand-pages anonymous memory unless MAP_POPULATE.
         * Eager install of every RW page (pthread 8MiB stacks, glibc arenas)
         * burned kmalloc via frame_alloc(8KiB/page) until libc malloc(24) in
         * x_cgo_thread_start failed → "runtime/cgo: out of memory in thread_start".
         * PROT_NONE / large 2MiB-aligned arenas stay lazy as before.
         */
        if (prot_none || !(flags & MAP_POPULATE))
            reserve_only = 1;
    } else if (!(flags & MAP_ANONYMOUS) && !shared_mapping &&
               !(flags & MAP_POPULATE)) {
        int fd = (int)(int64_t)a5;
        off_t file_off = (off_t)(int64_t)a6;
        if (fd >= 0 && fd < THREAD_MAX_FD && file_off >= 0) {
            struct fs_file *f = tcur ? tcur->fds[fd] : cur->fds[fd];
            if (!f) f = cur->fds[fd];
            if (f && f->type == FS_TYPE_REG && f->size > 0 &&
                !fbdev_is_fb0_file(f) &&
                /*
                 * Entware's glibc loader remaps PT_LOAD ranges and changes
                 * protections before touching every page. Keep /opt runtime
                 * objects eager until lazy file VMAs preserve backing data
                 * across all of those split/remap operations.
                 */
                !(f->path && strncmp(f->path, "/opt/", 5) == 0)) {
                file_lazy = 1;
                file_lazy_f = f;
                file_lazy_off = (uint64_t)file_off;
            }
        }
    }

    if (reserve_only || file_lazy) {
        if (reserve_only && addr < anon_floor)
            return user_mm_ret_err(USER_MM_ENOMEM);
        /* Unmap in the process mm only — never punch kernel identity. */
        if (user_mmap_unmap_pages(tcur, addr, len) != 0)
            return user_mm_ret_err(USER_MM_EFAULT);
        mmap_vma_kind = USER_VMA_KIND_MMAP_LAZY;
    } else if (user_mmap_install_pages(addr, len, top_limit, shared_mapping) != 0) {
        return user_mm_ret_err(USER_MM_EFAULT);
    }

    if (flags & MAP_ANONYMOUS) {
        /* pthread stack uses MAP_STACK|MAP_ANONYMOUS|MAP_PRIVATE (0x20022).
         * Stripping only the core bits left MAP_STACK set → spurious ENOSYS
         * and docker's pthread_create never reached clone. */
        flags &= ~(MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED | MAP_FIXED |
                   MAP_FIXED_NOREPLACE | MAP_IGNORABLE);
        if (flags != 0) return user_mm_ret_err(USER_MM_ENOSYS);
        if (!reserve_only)
            user_as_mmap_memset_zero_chunked(addr, len);
    } else if (!file_lazy) {
        int fd = (int)(int64_t)a5;
        off_t file_off = (off_t)(int64_t)a6;
        if (fd < 0 || fd >= THREAD_MAX_FD) return user_mm_ret_err(USER_MM_EBADF);
        struct fs_file *f = tcur ? tcur->fds[fd] : cur->fds[fd];
        if (!f) f = cur->fds[fd];
        if (!f) return user_mm_ret_err(USER_MM_EBADF);
        if (f->type != FS_TYPE_REG) return user_mm_ret_err(USER_MM_EBADF);
        if (file_off < 0) return user_mm_ret_err(USER_MM_EINVAL);
        if (fbdev_is_fb0_file(f)) {
            if (!fbdev_is_active()) return user_mm_ret_err(USER_MM_ENODEV);
            size_t fo = (size_t)file_off;
            if (fo > f->size) return user_mm_ret_err(USER_MM_EINVAL);
            size_t maxl = f->size - fo;
            size_t maplen = len < maxl ? len : maxl;
            if (maplen > 0 && fbdev_mmap_user(addr, maplen, fo) != 0)
                return user_mm_ret_err(USER_MM_EFAULT);
        } else {
            if (f->size == 0) {
                klogprintf("mmap: empty file fd=%d addr=0x%llx path=%s\n",
                    fd, (unsigned long long)addr, f->path ? f->path : "(null)");
                return user_mm_ret_err(USER_MM_EINVAL);
            }
            size_t pg_off = (size_t)((uint64_t)file_off & ~4095ULL);
            uintptr_t inpage = (uintptr_t)((uint64_t)file_off - (uint64_t)pg_off);
            uintptr_t map_lo = addr - inpage;
            size_t file_avail = 0;
            if (pg_off < f->size) file_avail = f->size - pg_off;
            size_t want = inpage + len;
            size_t to_read = want < file_avail ? want : file_avail;
            if (to_read > 0) {
                ssize_t nr = fs_read(f, (void *)map_lo, to_read, pg_off);
                if (nr != (ssize_t)to_read) {
                    klogprintf("mmap: fs_read fail fd=%d map=0x%llx off=0x%zx want=0x%zx got=%zd path=%s\n",
                        fd, (unsigned long long)map_lo, pg_off, to_read, (long long)nr,
                        f->path ? f->path : "(null)");
                    return user_mm_ret_err(USER_MM_EFAULT);
                }
            } else if ((size_t)file_off < f->size) {
                klogprintf("mmap: no bytes read fd=%d addr=0x%llx off=0x%llx len=0x%zx size=%zu path=%s\n",
                    fd, (unsigned long long)addr, (unsigned long long)(uint64_t)file_off, len,
                    (size_t)f->size, f->path ? f->path : "(null)");
                return user_mm_ret_err(USER_MM_EFAULT);
            }
            {
                uintptr_t map_end = addr + len;
                uintptr_t zlo = map_lo + to_read;
                if (map_end > zlo)
                    user_as_mmap_memset_zero_chunked(zlo, (size_t)(map_end - zlo));
            }
            if (fixed_mapping && pg_off == 0 && to_read >= 4) {
                const unsigned char *eh = (const unsigned char *)(uintptr_t)map_lo;
                if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F') {
                    klogprintf("mmap: missing ELF magic map=0x%llx path=%s\n",
                        (unsigned long long)map_lo, f->path ? f->path : "(null)");
                    return user_mm_ret_err(USER_MM_EFAULT);
                }
            }
            if (user_mmap_watch(tcur) && fixed_mapping) {
                const unsigned char *p = (const unsigned char *)(uintptr_t)addr;
                klogprintf("mmap-fixed: addr=0x%llx len=0x%zx off=0x%llx map=0x%llx read=0x%zx path=%s b0=%02x%02x%02x%02x\n",
                    (unsigned long long)addr, len, (unsigned long long)(uint64_t)file_off,
                    (unsigned long long)map_lo, to_read, f->path ? f->path : "(null)",
                    to_read >= 4 ? p[0] : 0, to_read >= 4 ? p[1] : 0,
                    to_read >= 4 ? p[2] : 0, to_read >= 4 ? p[3] : 0);
            }
        }
    }

    /* Non-FIXED: address was chosen free via user_vma_find_unmapped. */
    if (file_lazy) {
        if (user_vma_add_file(vtid, addr, len, prot & 7, USER_VMA_KIND_MMAP_LAZY,
                              file_lazy_f, file_lazy_off) != 0)
            return user_mm_ret_err(USER_MM_ENOSPC);
    } else if (user_vma_add(vtid, addr, len, prot & 7, mmap_vma_kind) != 0) {
        return user_mm_ret_err(USER_MM_ENOSPC);
    }

    uint64_t sum_next = (uint64_t)addr + len_u64;
    if (sum_next < (uint64_t)addr || sum_next > (uint64_t)top_limit)
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (!fixed_mapping)
        *p_mmap_next = (uintptr_t)sum_next;

    uint64_t he64 = (uint64_t)addr + len_u64;
    if (tcur) {
        if (he64 > tcur->user_mmap_hi) tcur->user_mmap_hi = (uintptr_t)he64;
        user_as_shared_publish_mmap(tcur, *p_mmap_next, (uintptr_t)he64);
    } else if (he64 > user_as_mmap_hi) {
        user_as_mmap_hi = (uintptr_t)he64;
    }

    if (!user_mm_range_fits(addr, len_u64, top_limit))
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (user_as_mmap_overlaps_kernel_heap(addr, len))
        return user_mm_ret_err(USER_MM_EFAULT);
    return (uint64_t)addr;
}

uint64_t user_syscall_munmap(uint64_t a1, uint64_t a2) {
    uintptr_t addr = (uintptr_t)a1;
    size_t len = (size_t)a2;
    if (len == 0) return user_mm_ret_err(USER_MM_EINVAL);
    if ((uint64_t)len > UINT64_MAX - 4095ULL)
        return user_mm_ret_err(USER_MM_EINVAL);
    len = (size_t)user_mm_align_up((uintptr_t)len, 4096);
    if (addr < 0x200000) return user_mm_ret_err(USER_MM_EINVAL);
    if ((uint64_t)addr + (uint64_t)len < (uint64_t)addr ||
        (uint64_t)addr + (uint64_t)len > (uint64_t)MMIO_IDENTITY_LIMIT)
        return user_mm_ret_err(USER_MM_EINVAL);
    if ((addr & 0xFFF) != 0) return user_mm_ret_err(USER_MM_EINVAL);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    uint64_t tid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    if (user_vma_can_unmap_range(tid, addr, len) != 0 ||
        user_mmap_unmap_pages(tcur, addr, len) != 0)
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (user_vma_unmap_range(tid, addr, len) != 0)
        return user_mm_ret_err(USER_MM_ENOMEM);
    uintptr_t max_end = tcur ? user_vma_max_mmap_like_end_for_mm(tcur) : user_vma_max_mmap_like_end(tid);
    if (tcur) {
        uintptr_t floor = user_mm_align_up(
            (tcur->user_brk_cur ? tcur->user_brk_cur : (8u * 1024u * 1024u)) + 0x10000u, 4096);
        if (max_end < floor) max_end = floor;
        if (tcur->mm) {
            int n = thread_get_count();
            for (int i = 0; i < n; i++) {
                thread_t *pt = thread_get_by_index(i);
                if (!pt || pt->ring != 3 || pt->mm != tcur->mm) continue;
                if (pt->user_mmap_next > max_end) pt->user_mmap_next = max_end;
                if (pt->user_mmap_hi > pt->user_mmap_next) pt->user_mmap_hi = pt->user_mmap_next;
            }
            if (tcur->mm->mmap_cursor > max_end)
                tcur->mm->mmap_cursor = max_end;
        } else {
            if (tcur->user_mmap_next > max_end) tcur->user_mmap_next = max_end;
            if (tcur->user_mmap_hi > tcur->user_mmap_next) tcur->user_mmap_hi = tcur->user_mmap_next;
        }
    }
    return 0;
}

uint64_t user_syscall_mprotect(uint64_t a1, uint64_t a2, uint64_t a3) {
    uintptr_t addr = (uintptr_t)a1;
    size_t len = (size_t)a2;
    int prot = (int)a3;
    if (len == 0) return 0;
    len = (size_t)user_mm_align_up((uintptr_t)len, 4096);
    if (addr < 0x200000) return user_mm_ret_err(USER_MM_EINVAL);
    if (addr + len >= (uintptr_t)MMIO_IDENTITY_LIMIT) return user_mm_ret_err(USER_MM_EINVAL);
    if ((addr & 0xFFF) != 0) return user_mm_ret_err(USER_MM_EINVAL);
    if ((prot & ~7) != 0) return user_mm_ret_err(USER_MM_EINVAL);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    uint64_t tid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    if ((prot & 2) && tcur && tcur->mm) {
        mm_t *share = tcur->mm_ptemplate ?
            tcur->mm_ptemplate : mm_kernel();
        if (mm_break_cow_range_for_write(tcur->mm, share,
                                         (uint64_t)addr,
                                         (uint64_t)addr + len) != 0)
            return user_mm_ret_err(USER_MM_ENOMEM);
    }
    if (!user_vma_is_fully_mapped(tid, addr, len)) {
        if (user_map_ensure_present_us_2m((uint64_t)addr, (uint64_t)addr + len) != 0)
            return user_mm_ret_err(USER_MM_EFAULT);
        if (user_vma_unmap_range(tid, addr, len) != 0)
            return user_mm_ret_err(USER_MM_ENOSPC);
        if (user_vma_add(tid, addr, len, prot & 7, USER_VMA_KIND_MMAP) != 0)
            return user_mm_ret_err(USER_MM_ENOSPC);
    } else if (user_vma_set_prot(tid, addr, len, prot & 7) != 0) {
        return user_mm_ret_err(USER_MM_ENOSPC);
    }
    if (user_map_mprotect_range((uint64_t)addr, (uint64_t)addr + len, prot & 7) != 0)
        return user_mm_ret_err(USER_MM_EFAULT);
    return 0;
}
