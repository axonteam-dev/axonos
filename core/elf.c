/*
 * ELF file parser
*/

#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <exec.h>
#include <heap.h>
#include <mmio.h>
#include <thread.h>
#include <process.h>

static int kernel_execve_into_mm(const char *path, const char *const argv[],
                                 const char *const envp[]);
#include <devfs.h>
#include <gdt.h>
#include <paging.h>
#include <mm.h>
#include <user_vma.h>
#include <user_as.h>
#include <user_map.h>
#include <elf.h>
#include <vga.h>
#include <debug.h>
#include <syscall.h>

extern uint8_t _end[]; /* kernel end symbol from linker */

static int exec_stdio_is_dev_null(const struct fs_file *f) {
    if (!f || !f->path)
        return 0;
    return strcmp(f->path, "/dev/null") == 0 ||
           strcmp(f->path, "null") == 0;
}

/* Intentional redirects (pipes, sockets, regular files) must survive exec.
 * Only closed fds or /dev/null need the boot console rebind. */
static int exec_stdio_needs_console(const struct fs_file *f) {
    if (!f)
        return 1;
    if (f->type == FS_TYPE_PIPE || f->type == FS_TYPE_SOCKET)
        return 0;
    if (devfs_is_tty_file((struct fs_file *)f))
        return 0;
    if (exec_stdio_is_dev_null(f))
        return 1;
    /* Keep open non-tty files (redirections to regular paths). */
    return 0;
}

void exec_boot_ensure_stdio(thread_t *ut) {
    if (!ut)
        return;

    /*
     * Linux starts init with descriptors 0, 1 and 2 already open. Use one
     * shared open-file description for the console, like dup2(0, 1/2).
     *
     * BusyBox bb_sanitize_stdio() opens /dev/null when stdio is closed. With
     * an empty inittab console id, spawn never reopens a real tty — ash then
     * sees EOF on stdin and exits, and ::respawn loops forever.
     *
     * Only rebind closed /dev/null stdio. Never replace pipes/sockets: that
     * destroyed `echo test | cat` (stdin pipe freed on execve → no "test").
     *
     * fds 0/1/2 often alias the same fs_file; free each unique pointer once
     * per aliased slot (refcount may be wrong after fork/exec).
     */
    int need_console = 0;
    for (int fd = 0; fd <= 2; fd++) {
        if (exec_stdio_needs_console(ut->fds[fd])) {
            need_console = 1;
            break;
        }
    }
    if (need_console) {
        struct fs_file *console = devfs_open_direct("/dev/console");
        if (!console)
            return;
        struct fs_file *old[3] = { ut->fds[0], ut->fds[1], ut->fds[2] };
        /* Replace only slots that need a console; keep pipes/redirections. */
        for (int fd = 0; fd <= 2; fd++) {
            if (exec_stdio_needs_console(old[fd]))
                ut->fds[fd] = NULL;
        }
        for (int i = 0; i < 3; i++) {
            struct fs_file *f = old[i];
            if (!f || f == console)
                continue;
            if (!exec_stdio_needs_console(f))
                continue;
            int first = 1;
            for (int j = 0; j < i; j++) {
                if (old[j] == f) {
                    first = 0;
                    break;
                }
            }
            if (!first)
                continue;
            int n = 0;
            for (int j = 0; j < 3; j++) {
                if (old[j] == f && exec_stdio_needs_console(f))
                    n++;
            }
            for (int k = 0; k < n; k++)
                fs_file_free(f);
        }
        int adopted = 0;
        for (int fd = 0; fd <= 2; fd++) {
            if (!ut->fds[fd]) {
                ut->fds[fd] = console;
                adopted++;
            }
        }
        if (adopted == 0)
            fs_file_free(console);
        else
            console->refcount = adopted;
    } else {
        for (int fd = 1; fd <= 2; fd++) {
            if (!ut->fds[fd]) {
                ut->fds[fd] = ut->fds[0];
                if (ut->fds[fd])
                    ut->fds[fd]->refcount++;
            }
        }
    }

    if (ut->fds[0] && devfs_is_tty_file(ut->fds[0])) {
        int tty = devfs_get_tty_index_from_file(ut->fds[0]);
        if (tty < 0)
            tty = devfs_get_active();
        ut->attached_tty = tty;
        /* Do not invent sid/pgid here — getty must call setsid() itself. */
        if (ut->sid > 0)
            (void)devfs_set_tty_controlling_sid(ut->fds[0], ut->sid);
        (void)devfs_tty_attach_thread(ut->fds[0], ut);
        if (ut->pgid > 0)
            devfs_set_tty_fg_pgrp(tty, ut->pgid);
        devel_printf("stdio-console: tid=%llu path=%s tty=%d sid=%d pgid=%d\n",
            (unsigned long long)(ut->tid ? ut->tid : 1),
            ut->fds[0]->path ? ut->fds[0]->path : "?",
            tty, ut->sid, ut->pgid);
    }

    process_sync_from_thread(ut->process, ut);
}

uint64_t elf_et_dyn_base(void) {
    uintptr_t ke = (uintptr_t)_end;
    uint64_t base = ((uint64_t)ke + (uint64_t)(PAGE_SIZE_2M - 1)) & ~((uint64_t)PAGE_SIZE_2M - 1);
    /* Conventional Linux x86-64 ET_EXEC/PIE low load address. Must stay at
     * USER_IMAGE_BASE (0x400000) so a new PIE replaces busybox in-place;
     * flooring to 0x800000 left a ghost busybox image that openrc then
     * jumped into (RIP=0x4030d0 AVX / 0x63e2c0 .bss zeros). */
    if (base < (uint64_t)USER_IMAGE_BASE)
        base = (uint64_t)USER_IMAGE_BASE;
    return base;
}

uint64_t elf_interp_base(void) {
    uint64_t base = elf_et_dyn_base() + 16ULL * 1024ULL * 1024ULL;
    base = (base + (uint64_t)(PAGE_SIZE_2M - 1)) & ~((uint64_t)PAGE_SIZE_2M - 1);
    if (base < 0x02000000ULL)
        base = 0x02000000ULL;
    return base;
}

/*
 * ET_EXEC has fixed virtual addresses and must never be slid: its machine code
 * may contain absolute references. Only PIE/shared-object images (ET_DYN) are
 * position independent. Overlapping ET_EXEC segments are rejected by the
 * loader's kernel-range check below.
 */
static uint64_t elf_load_base_for_image(const Elf64_Ehdr *eh, const Elf64_Phdr *phdrs, int nph) {
    (void)phdrs;
    (void)nph;
    if (eh->e_type == 3)
        return elf_et_dyn_base();
    return 0;
}

static int elf_needs_private_user_pages(thread_t *tc);
static int mark_user_identity_range_2m(uint64_t va_begin, uint64_t va_end);

/*
 * Copy into the target mm by physical leaf address. Writing through a user VA
 * while CR3 is the kernel tree (or a stale TLB) fills identity phys and leaves
 * the private exec pages zero — user then runs `00 00` at entry (add [rax],al
 * → #PF cr2=0). Linux load_elf_binary writes the destination VMA backing;
 * with identity-mapped phys we store to the leaf PA directly.
 */
static int elf_copy_into_mm(mm_t *mm, uint64_t va, const void *src, size_t n) {
    if (!mm || (!src && n) || n == 0)
        return n == 0 ? 0 : -1;
    const uint8_t *s = (const uint8_t *)src;
    while (n) {
        uint64_t leaf = 0;
        if (mm_va_leaf_pa(mm, va, &leaf) != 0)
            return -1;
        uint64_t page = leaf & ~0xFFFULL;
        /* Identity leaf (pa==va): store hits the frozen vfork parent's phys
         * BusyBox image — BSS wipe / PT_LOAD rewrite → parent #PF at junk RIP. */
        if (page == (va & ~0xFFFULL)) {
            kprintf("elf_copy: refuse identity leaf va=0x%llx\n",
                    (unsigned long long)va);
            return -1;
        }
        uint64_t off = va & 0xFFFULL;
        size_t chunk = (size_t)(0x1000ULL - off);
        if (chunk > n)
            chunk = n;
        memcpy((void *)(uintptr_t)(page + off), s, chunk);
        invlpg((void *)(uintptr_t)va);
        va += chunk;
        s += chunk;
        n -= chunk;
    }
    return 0;
}

static int elf_zero_into_mm(mm_t *mm, uint64_t va, size_t n) {
    if (!mm || n == 0)
        return 0;
    while (n) {
        uint64_t leaf = 0;
        if (mm_va_leaf_pa(mm, va, &leaf) != 0)
            return -1;
        uint64_t page = leaf & ~0xFFFULL;
        if (page == (va & ~0xFFFULL)) {
            kprintf("elf_zero: refuse identity leaf va=0x%llx\n",
                    (unsigned long long)va);
            return -1;
        }
        uint64_t off = va & 0xFFFULL;
        size_t chunk = (size_t)(0x1000ULL - off);
        if (chunk > n)
            chunk = n;
        memset((void *)(uintptr_t)(page + off), 0, chunk);
        va += chunk;
        n -= chunk;
    }
    return 0;
}

/*
 * Linux process-local layout: every mm uses the same stack VA
 * (USER_STACK_TOP). Separate page tables make that safe across tasks.
 * Per-tid descending slots used to walk into the kernel heap arena
 * (e.g. 0x8050e000), so execve's kmalloc backing collided with the stack VA
 * (priv-map-bug want==got==va) and burned ~8MiB heap per getty.
 */
static uintptr_t user_stack_top_for_tid(uint64_t tid) {
    (void)tid;
    return (uintptr_t)USER_STACK_TOP;
}

/* Linux execve: map only the argv/env tip; the rest of RLIMIT_STACK is demand-zero. */
static int exec_map_stack_tip(thread_t *tc, uintptr_t tip_lo, uintptr_t tip_hi) {
    if (!tc || !tc->mm || tip_hi <= tip_lo)
        return -1;
    tip_lo &= ~0xFFFULL;
    tip_hi = (tip_hi + 0xFFFULL) & ~0xFFFULL;
    /* Cap tip — never prefault the whole 8MiB slot. */
    if (tip_hi - tip_lo > 256u * 1024u)
        tip_lo = tip_hi - 256u * 1024u;
    /*
     * Linux get_arg_page(bprm->mm): install the tip only in the nascent mm.
     * The old mm is consulted solely to reject accidental frame sharing.
     */
    mm_t *oldmm = tc->mm_ptemplate ? tc->mm_ptemplate : NULL;
    if (!oldmm && tc->exec_discard_mm &&
        tc->exec_discard_mm->pml4 && tc->exec_discard_mm != tc->mm)
        oldmm = tc->exec_discard_mm;
    mm_t *map_share = mm_kernel();
    if (!map_share || !map_share->pml4 || map_share == tc->mm)
        return -1;

    /* Map tip vs swapper only — never pass oldmm into sharedaware. */
    if (mm_make_private_range_bulk_zero_force(tc->mm, (uint64_t)tip_lo,
                                              (uint64_t)tip_hi, map_share) != 0)
        return -1;
    for (uint64_t va = (uint64_t)tip_lo; va < (uint64_t)tip_hi; va += 0x1000ULL) {
        uint64_t cpa = 0, ppa = 0;
        if (mm_va_leaf_pa(tc->mm, va, &cpa) != 0)
            return -1;
        cpa &= ~0xFFFULL;
        if (cpa == (va & ~0xFFFULL)) {
            devel_printf("exec-tip: still identity va=0x%llx\n",
                    (unsigned long long)va);
            return -1;
        }
        if (oldmm && oldmm->pml4 &&
            mm_va_leaf_pa(oldmm, va, &ppa) == 0 &&
            (ppa & ~0xFFFULL) == cpa) {
            devel_printf("exec-tip: shares oldmm va=0x%llx pa=0x%llx\n",
                    (unsigned long long)va, (unsigned long long)cpa);
            return -1;
        }
    }
    return 0;
}

static inline uintptr_t user_tls_base_for_stack_top(uintptr_t stack_top) {
    return (uintptr_t)stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
}

static inline uintptr_t exec_align_up_ptr(uintptr_t v, uintptr_t a) {
    if (a == 0) return v;
    return (v + (a - 1u)) & ~(a - 1u);
}

static int exec_seed_static_tls(uintptr_t stack_top, uintptr_t random_addr,
                                const elf_tls_info_t *tls, uintptr_t *out_fs_base) {
    if (!out_fs_base) return -1;
    const uintptr_t tls_region_base = user_tls_base_for_stack_top(stack_top);
    uintptr_t tls_align = (tls && tls->align) ? (uintptr_t)tls->align : 16u;
    if (tls_align < 16u) tls_align = 16u;
    uintptr_t tls_memsz = (tls && tls->memsz) ? (uintptr_t)tls->memsz : 0;
    uintptr_t tls_filesz = (tls && tls->filesz) ? (uintptr_t)tls->filesz : 0;
    if (tls_filesz > tls_memsz) return -1;
    uintptr_t tls_block_size = exec_align_up_ptr(tls_memsz, tls_align);
    uintptr_t fs_base = tls_region_base + exec_align_up_ptr(tls_block_size + 0x1000u, 16u);
    if (fs_base < tls_region_base + 0x1000u)
        fs_base = tls_region_base + 0x1000u;
    const uintptr_t tls_block = fs_base - tls_block_size;
    const uintptr_t used_hi = fs_base + 0x3000u;

    if (tls_block < tls_region_base) return -1;
    if (used_hi <= fs_base || used_hi >= (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    if (used_hi > tls_region_base + (uintptr_t)USER_TLS_SIZE) return -1;

    thread_t *tc = thread_current();
    if (elf_needs_private_user_pages(tc)) {
        mm_t *share = mm_kernel();
        if (mm_make_private_range_bulk_zero(tc->mm, (uint64_t)tls_region_base,
                (uint64_t)used_hi, share) != 0)
            return -1;
        /* Private TLS already PG_US from bulk_zero — no identity mark. */
    } else {
        (void)mark_user_identity_range_2m((uint64_t)tls_region_base, (uint64_t)used_hi);
    }

    /* Publish through leaf PAs — VA memset under kernel CR3 hits identity PFNs. */
    if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
        if (elf_zero_into_mm(tc->mm, (uint64_t)tls_region_base,
                             (size_t)(used_hi - tls_region_base)) != 0)
            return -1;
        if (tls_block_size != 0) {
            if (!tls || tls->vaddr + tls_filesz > (uint64_t)MMIO_IDENTITY_LIMIT)
                return -1;
            if (tls_filesz &&
                elf_copy_into_mm(tc->mm, (uint64_t)tls_block,
                                 (const void *)(uintptr_t)tls->vaddr,
                                 (size_t)tls_filesz) != 0)
                return -1;
        }
    } else {
        memset((void *)tls_region_base, 0, (size_t)(used_hi - tls_region_base));
        if (tls_block_size != 0) {
            if (!tls || tls->vaddr + tls_filesz > (uint64_t)MMIO_IDENTITY_LIMIT)
                return -1;
            if (tls_filesz)
                memcpy((void *)tls_block, (const void *)(uintptr_t)tls->vaddr,
                       (size_t)tls_filesz);
        }
    }

    uint64_t guard = 0;
    if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
        uint64_t rpa = 0;
        if (mm_va_leaf_pa(tc->mm, (uint64_t)random_addr, &rpa) == 0)
            guard = *(uint64_t *)(uintptr_t)(rpa + (random_addr & 0xFFFULL));
        else
            guard = 0x8b13f00d2a11c0deULL;
    } else if (random_addr + 16 <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
        guard = *(uint64_t *)(uintptr_t)random_addr;
    } else {
        guard = 0x8b13f00d2a11c0deULL;
    }
    guard &= ~0xFFULL;

    /* glibc x86_64 static TLS uses variant II: TLS lives below the TCB,
       and helpers like __errno_location compute from %fs:0. */
    {
        uint64_t tcb[6];
        tcb[0] = (uint64_t)fs_base;
        tcb[1] = (uint64_t)(fs_base + 0x800u);
        tcb[2] = (uint64_t)fs_base;
        tcb[3] = 0;
        tcb[4] = 0;
        tcb[5] = guard; /* placed at fs_base+0x28 via separate writes below */
        if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
            uint64_t words[2];
            words[0] = (uint64_t)fs_base;
            words[1] = (uint64_t)(fs_base + 0x800u);
            if (elf_copy_into_mm(tc->mm, (uint64_t)fs_base, words, 16) != 0)
                return -1;
            words[0] = (uint64_t)fs_base;
            if (elf_copy_into_mm(tc->mm, (uint64_t)fs_base + 0x10u, words, 8) != 0)
                return -1;
            words[0] = guard;
            if (elf_copy_into_mm(tc->mm, (uint64_t)fs_base + 0x28u, words, 8) != 0)
                return -1;
            words[0] = guard ^ 0x5a5a5a5a5a5a5a5aULL;
            if (elf_copy_into_mm(tc->mm, (uint64_t)fs_base + 0x30u, words, 8) != 0)
                return -1;
            (void)tcb;
        } else {
            *(volatile uint64_t *)(uintptr_t)(fs_base + 0x00u) = (uint64_t)fs_base;
            *(volatile uint64_t *)(uintptr_t)(fs_base + 0x08u) = (uint64_t)(fs_base + 0x800u);
            *(volatile uint64_t *)(uintptr_t)(fs_base + 0x10u) = (uint64_t)fs_base;
            *(volatile uint64_t *)(uintptr_t)(fs_base + 0x28u) = guard;
            *(volatile uint64_t *)(uintptr_t)(fs_base + 0x30u) =
                guard ^ 0x5a5a5a5a5a5a5a5aULL;
        }
    }

    {
        const uintptr_t fake_locale = fs_base + 0x1800u;
        if (fake_locale + 0x100u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
                uint8_t cbuf[2] = { (uint8_t)'C', 0 };
                if (elf_copy_into_mm(tc->mm, (uint64_t)fake_locale, cbuf, 2) != 0)
                    return -1;
                for (uintptr_t key = 0; key < 32; key++) {
                    uint64_t slot_val = (uint64_t)fake_locale;
                    if (elf_copy_into_mm(tc->mm,
                            (uint64_t)(fs_base + 0x80u + key * sizeof(uint64_t)),
                            &slot_val, sizeof(slot_val)) != 0)
                        return -1;
                }
            } else {
                *(volatile uint8_t *)(uintptr_t)(fake_locale + 0) = (uint8_t)'C';
                *(volatile uint8_t *)(uintptr_t)(fake_locale + 1) = 0;
                for (uintptr_t key = 0; key < 32; key++) {
                    const uintptr_t slot = fs_base + 0x80u + key * sizeof(uint64_t);
                    *(volatile uint64_t *)(uintptr_t)slot = (uint64_t)fake_locale;
                }
            }
        }
    }

    *out_fs_base = fs_base;
    return 0;
}

static inline uint64_t msr_read_u64_local(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void msr_write_u64_local(uint32_t msr, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(v >> 32);
    asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

/* Helpers for per-process page table creation.
   We allocate 4KiB-aligned tables via kmalloc and build a new PML4 for the process,
   copying kernel entries and installing per-segment leaf entries with PG_US.
*/
static void *alloc_page_table(void) {
    void *p = kmalloc(PAGE_SIZE_4K);
    if (!p) return NULL;
    memset(p, 0, PAGE_SIZE_4K);
    return p;
}

/* Duplicate an existing page table page (virtual pointer assumed identity-mapped). */
static void *dup_page_table(void *old) {
    void *n = alloc_page_table();
    if (!n) return NULL;
    memcpy(n, old, PAGE_SIZE_4K);
    return n;
}

/* Translate virtual address to physical by walking active CR3 page tables.
   Returns physical base (frame) or 0 on failure. Works only while current
   page tables are active and mapping exists. */
uint64_t virt_to_phys(uint64_t va) {
    /* Kernel and userspace in AxonOS are identity-mapped for the low 4GiB.
       Many subsystems (AHCI DMA buffers, boot modules, early heap) allocate from
       this region. Walking page tables here is unnecessary and can fail once we
       start splitting bootstrap 1GiB mappings into 2MiB tables (virtual/physical
       pointer confusion). */
    if (va < 0x100000000ULL) return va;

    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return 0;
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;
    uint64_t l1i = (va >> 12) & 0x1FF;
    if (!(l4[l4i] & PG_PRESENT)) return 0;
    uint64_t l3e = l4[l4i];
    if (l3e & PG_PS_2M) {
        /* 1GiB page */
        return (l3e & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    }
    uint64_t *l3 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
    if (!(l3[l3i] & PG_PRESENT)) return 0;
    uint64_t l2e = l3[l3i];
    if (l2e & PG_PS_2M) {
        /* 2MiB page */
        return (l2e & ~(PAGE_SIZE_2M - 1)) | (va & (PAGE_SIZE_2M - 1));
    }
    uint64_t *l2 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
    if (!(l2[l2i] & PG_PRESENT)) return 0;
    uint64_t l1e = l2[l2i];
    uint64_t *l1 = (uint64_t*)(uintptr_t)(l1e & ~0xFFFULL);
    if (!(l1[l1i] & PG_PRESENT)) return 0;
    return (l1[l1i] & ~0xFFFULL) | (va & 0xFFFULL);
}

/* Create new PML4 by cloning current active CR3 contents. */
static void *create_process_pml4(void) {
    uint64_t cr3 = paging_read_cr3();
    uint64_t *src_l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!src_l4) return NULL;
    void *newpml4 = alloc_page_table();
    if (!newpml4) return NULL;
    memcpy(newpml4, (void*)src_l4, PAGE_SIZE_4K);
    return newpml4;
}

/* Ensure a table exists at given entry (level pointer) and return pointer to it.
   parent_entry_ptr points to the 64-bit entry in parent table. If entry is not present,
   allocate new table and update parent entry. Returns pointer to child table. */
static uint64_t *ensure_child_table(uint64_t *parent_entries, int idx) {
    uint64_t ent = parent_entries[idx];
    if (ent & PG_PRESENT) {
        /* existing */
        return (uint64_t*)(uintptr_t)(ent & ~0xFFFULL);
    }
    void *nt = alloc_page_table();
    if (!nt) return NULL;
    uint64_t newent = ((uint64_t)(uintptr_t)nt) | PG_PRESENT | PG_RW;
    parent_entries[idx] = newent;
    return (uint64_t*)nt;
}

/* Map one VA->PA into provided pml4 (virtual pointer) with flags. Doesn't split large pages.
   flags should include PG_PRESENT|PG_RW|PG_US and optionally PG_NX omitted for executable.
*/
static int pml4_map_one(void *pml4_ptr, uint64_t va, uint64_t pa, uint64_t flags) {
    uint64_t *l4 = (uint64_t*)pml4_ptr;
    int l4i = (va >> 39) & 0x1FF;
    int l3i = (va >> 30) & 0x1FF;
    int l2i = (va >> 21) & 0x1FF;
    int l1i = (va >> 12) & 0x1FF;

    uint64_t ent4 = l4[l4i];
    /* allocate l3 if missing or clone if present and shared with kernel */
    uint64_t *l3;
    if (ent4 & PG_PRESENT) {
        l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
        /* clone to avoid modifying kernel tables */
        l3 = dup_page_table(l3);
        if (!l3) return -1;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFF);
    } else {
        l3 = alloc_page_table();
        if (!l3) return -1;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t ent3 = l3[l3i];
    /* check for large 1GiB mapping */
    if (ent3 & PG_PS_2M) {
        /* convert not supported; return error if large page present */
        return -1;
    }
    uint64_t *l2;
    if (ent3 & PG_PRESENT) {
        l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
        l2 = dup_page_table(l2);
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFF);
    } else {
        l2 = alloc_page_table();
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t ent2 = l2[l2i];
    if (ent2 & PG_PS_2M) {
        /* 2MiB large page exists; replace with new 2MiB mapping */
        l2[l2i] = (pa & ~(PAGE_SIZE_2M - 1)) | (flags & ~PG_PS_2M) | PG_PS_2M;
        return 0;
    }
    uint64_t *l1;
    if (ent2 & PG_PRESENT) {
        l1 = (uint64_t*)(uintptr_t)(ent2 & ~0xFFFULL);
        l1 = dup_page_table(l1);
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ent2 & 0xFFF);
    } else {
        l1 = alloc_page_table();
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | PG_PRESENT | PG_RW | PG_US;
    }

    /* set final L1 entry */
    l1[l1i] = (pa & ~0xFFFULL) | (flags & ~PG_PS_2M) | PG_PRESENT;
    return 0;
}

/* Validate minimal ELF64 header */
static int elf_validate_header(const Elf64_Ehdr *eh, size_t len) {
    if (!eh) return 0;
    if (len < sizeof(Elf64_Ehdr)) return 0;
    /* magic 0x7F 'E' 'L' 'F' */
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') return 0;
    /* class must be ELFCLASS64 (2) */
    if (eh->e_ident[4] != 2) return 0;
    /* data encoding little endian */
    if (eh->e_ident[5] != 1) return 0;
    /* ELF type/executable */
    /* Accept both ET_EXEC and ET_DYN (PIE). ET_DYN will be loaded at a fixed
       base address to support position-independent executables; full dynamic
       loader/relocations are still not implemented. */
    if (eh->e_type != 2 && eh->e_type != 3) {
        return 0;
    }
    return 1;
}

/* User images are loaded into the low identity-mapped region by copying to p_vaddr.
   To avoid corrupting the kernel heap (which is also identity-mapped), keep user
   segments strictly below the heap base. */
static uint64_t user_image_limit_bytes(void) {
    uintptr_t hb = heap_base_addr();
    /* If heap isn't initialized for some reason, fall back to 64MiB. */
    if (hb == 0) return 64ULL * 1024ULL * 1024ULL;
    return (uint64_t)hb;
}

static int elf_ptr_identity_ok(const void *p, size_t sz) {
    uintptr_t a = (uintptr_t)p;
    if (a < 0x1000u) return 0;
    if (a >= (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    if (sz > 0 && a > ((uintptr_t)MMIO_IDENTITY_LIMIT - sz)) return 0;
    return 1;
}

/* Fork gives a new mm_t with a copied PML4; boot/init on BSP shares the kernel root.
 * Compare page-table roots — not mm struct pointers — so early exec never takes the
 * private-mm path when still on the kernel address space. */
static int elf_needs_private_user_pages(thread_t *tc) {
    mm_t *k = mm_kernel();
    if (!tc || !k) return 0;
    if (!elf_ptr_identity_ok(tc, sizeof(*tc))) return 0;
    if (!elf_ptr_identity_ok(k, sizeof(*k))) return 0;
    if (!tc->mm) return 0;
    if (!elf_ptr_identity_ok(tc->mm, sizeof(mm_t))) return 0;
    if (!tc->mm->pml4 || !k->pml4) return 0;
    if (!elf_ptr_identity_ok(tc->mm->pml4, PAGE_SIZE_4K)) return 0;
    if (!elf_ptr_identity_ok(k->pml4, PAGE_SIZE_4K)) return 0;
    return tc->mm->pml4 != k->pml4;
}

/* Linux applies R_X86_64_RELATIVE for ET_DYN (PIE + ld.so) before user entry.
 * IRELATIVE for ET_EXEC static binaries is applied by glibc CRT before main —
 * do not invoke IFUNC resolvers from the kernel. */
static int elf_apply_rela_relative(uint64_t load_base, const Elf64_Phdr *phdrs, int phnum) {
    if (!phdrs || phnum <= 0 || load_base == 0) return 0;
    const Elf64_Rela *rela = NULL;
    size_t relasz = 0;
    size_t relaent = sizeof(Elf64_Rela);

    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type != ELF_PT_DYNAMIC) continue;
        if (phdrs[i].p_memsz < sizeof(Elf64_Dyn)) return -1;
        const Elf64_Dyn *dyn = (const Elf64_Dyn *)(uintptr_t)(load_base + phdrs[i].p_vaddr);
        size_t n = (size_t)(phdrs[i].p_memsz / sizeof(Elf64_Dyn));
        for (size_t j = 0; j < n; j++) {
            if (dyn[j].d_tag == ELF_DT_NULL) break;
            if (dyn[j].d_tag == ELF_DT_RELA)
                rela = (const Elf64_Rela *)(uintptr_t)(load_base + dyn[j].d_un);
            else if (dyn[j].d_tag == ELF_DT_RELASZ)
                relasz = (size_t)dyn[j].d_un;
            else if (dyn[j].d_tag == ELF_DT_RELAENT && dyn[j].d_un != 0)
                relaent = (size_t)dyn[j].d_un;
        }
        break;
    }
    if (!rela || relasz == 0 || relaent < sizeof(Elf64_Rela))
        return 0;
    size_t nrel = relasz / relaent;
    for (size_t i = 0; i < nrel; i++) {
        const Elf64_Rela *r = (const Elf64_Rela *)((const char *)rela + i * relaent);
        uint32_t rtype = (uint32_t)ELF64_R_TYPE(r->r_info);
        uint64_t *where = (uint64_t *)(uintptr_t)(load_base + r->r_offset);
        if ((uintptr_t)where < load_base || (uintptr_t)where >= (uintptr_t)MMIO_IDENTITY_LIMIT)
            return -1;
        if (rtype == ELF_R_X86_64_RELATIVE) {
            *where = load_base + (uint64_t)r->r_addend;
        } else if (rtype == ELF_R_X86_64_IRELATIVE) {
            typedef uint64_t (*irel_fn_t)(void);
            irel_fn_t resolver = (irel_fn_t)(uintptr_t)(load_base + (uint64_t)r->r_addend);
            if ((uintptr_t)resolver < load_base ||
                (uintptr_t)resolver >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                return -1;
            *where = resolver();
        }
    }
    return 0;
}

/*
 * Legacy shared-CR3 only: stamp PG_US on the active page tables.
 * Never call this for a private mm while CR3 is still oldmm (vfork-exec load):
 * that mutates the frozen parent's tables (ash GPF at RIP=="ls" @ 0x801738).
 * Private exec leaves already have PG_US from mm_make_private_range / bulk_zero.
 */
static int mark_user_range_exec(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_end > MMIO_IDENTITY_LIMIT) va_end = MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    {
        thread_t *tc = thread_current();
        if (!tc || tc->ring != 3)
            tc = thread_get_current_user();
        if (tc && elf_needs_private_user_pages(tc))
            return 0;
    }
    uint64_t cr3 = paging_read_cr3();
    uint64_t *active_l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!active_l4) return -1;

    uint64_t begin = va_begin & ~(PAGE_SIZE_2M - 1);
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = active_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US | PG_RW;
        l4[l4i] &= ~PG_NX;

        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        /* Do not OR flags onto a 1GiB leaf — that would publish the whole GB. */
        if (l3[l3i] & PG_PS_2M)
            return -1;
        l3[l3i] |= PG_US | PG_RW;
        l3[l3i] &= ~PG_NX;
        uint64_t l3e = l3[l3i];

        uint64_t *l2 = (uint64_t *)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            l2[l2i] |= PG_US | PG_RW;
            l2[l2i] &= ~PG_NX;
            /* Never grant RW on Soft_COW — that bypasses mm_cow_fault_page. */
            if (l2[l2i] & PG_SOFT_COW)
                l2[l2i] &= ~PG_RW;
            invlpg((void *)(uintptr_t)va);
            continue;
        }

        uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
        uint64_t chunk_end = va + PAGE_SIZE_2M;
        if (chunk_end > end) chunk_end = end;
        for (uint64_t p = va; p < chunk_end; p += PAGE_SIZE_4K) {
            uint64_t idx = (p >> 12) & 0x1FF;
            if (!(l1[idx] & PG_PRESENT))
                continue;
            l1[idx] |= PG_US;
            l1[idx] &= ~PG_NX;
            if (l1[idx] & PG_SOFT_COW)
                l1[idx] &= ~PG_RW;
            else
                l1[idx] |= PG_RW;
            invlpg((void *)(uintptr_t)p);
        }
    }
    return 0;
}

int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry) {
    if (!buf || len < sizeof(Elf64_Ehdr)) {kprintf("!buf || len < sizeof(Elf64_Ehdr)\n");return -1;}
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)buf;
    if (!elf_validate_header(eh, len)) return -2;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return -3;

    const Elf64_Phdr *phdrs_mem = (const Elf64_Phdr*)((const char*)buf + eh->e_phoff);
    uint64_t load_base = elf_load_base_for_image(eh, phdrs_mem, (int)eh->e_phnum);

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    uint64_t brk_end = 0;
    const uint64_t image_entry = eh->e_entry + load_base;
    /* Pass 1: copy all PT_LOAD; pass 2: mark PTE flags (see elf_load_from_path). */
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs_mem[i];
        if ((const char*)ph + sizeof(Elf64_Phdr) > (const char*)buf + len) return -4;
        if (ph->p_type != 1) continue; /* PT_LOAD */

        /* Check bounds */
        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (vend < vstart) return -5;
        /* Hard limit for user image virtual range.
           We currently load user binaries into the low identity-mapped region by copying to p_vaddr.
           Keep them below the heap floor (64MiB) to prevent corrupting kernel heap. */
        const uint64_t USER_IMAGE_LIMIT = user_image_limit_bytes();
        if (vend > USER_IMAGE_LIMIT) {
            kprintf("elf: user image too high (segment 0x%llx..0x%llx, limit 0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)USER_IMAGE_LIMIT);
            return -6;
        }
        if (vstart < kernel_end && vend > kernel_start) {
            kprintf("elf: segment overlaps kernel (vaddr 0x%llx..0x%llx kernel 0x%llx..0x%llx)\n",
                (unsigned long long)vstart, (unsigned long long)vend,
                (unsigned long long)kernel_start, (unsigned long long)kernel_end);
            return -7;
        }
        if (vstart + ph->p_filesz > MMIO_IDENTITY_LIMIT) {
            /* avoid writing above identity-mapped region for now */
            kprintf("elf: segment outside identity-mapped range, unsupported vaddr=0x%llx\n", (unsigned long long)vstart);
            return -8;
        }

        /* Copy file data into target vaddr (assumes identity mapping) */
        if (ph->p_offset + ph->p_filesz > len) return -12;
        void *dst = (void*)(uintptr_t)(ph->p_vaddr + load_base);
        const void *src = (const char*)buf + ph->p_offset;
        /* copy filesz bytes */
        if (ph->p_filesz > 0) memcpy(dst, src, (size_t)ph->p_filesz);
        /* zero remaining (bss) */
        if (ph->p_memsz > ph->p_filesz) {
            memset((char*)dst + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));
        }
        if (vend > brk_end) brk_end = vend;
    }

    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs_mem[i];
        if (ph->p_type != 1) continue;
        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (mark_user_range_exec(vstart, vend) != 0) return -9;
    }

    if (brk_end) {
        thread_t *tc = thread_current();
        user_as_set_brk_after_load(tc, (uintptr_t)brk_end, (uintptr_t)brk_end);
    }
    if (out_entry) *out_entry = image_entry;
    return 0;
}

/* Mark an identity-mapped VA range as user-accessible by setting PG_US
   on all relevant paging structure levels. This is required for both
   instruction fetch and stack/data access in ring3. */
static int mark_user_identity_range_2m(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_end > MMIO_IDENTITY_LIMIT) va_end = MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *active_l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!active_l4) return -1;
    uint64_t begin = va_begin & ~(PAGE_SIZE_2M - 1);
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = active_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) {
            l3[l3i] |= PG_US;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            l2[l2i] |= PG_US;
        } else {
            l2[l2i] |= PG_US;
            uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
            uint64_t chunk_end = va + PAGE_SIZE_2M;
            if (chunk_end > end) chunk_end = end;
            for (uint64_t p = va; p < chunk_end; p += PAGE_SIZE_4K) {
                uint64_t idx = (p >> 12) & 0x1FF;
                if (l1[idx] & PG_PRESENT)
                    l1[idx] |= PG_US;
                invlpg((void*)(uintptr_t)p);
            }
            continue;
        }
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

static void mark_broad_user_ranges_for_exec(void) {
    uintptr_t begin = 0x200000;
    uintptr_t end = 0x80000000ULL; /* low 2GiB identity — covers stack AVX overruns */
    if (end > (uintptr_t)MMIO_IDENTITY_LIMIT) end = (uintptr_t)MMIO_IDENTITY_LIMIT;
    /*
     * Never stamp PG_US onto identity-mapped kernel-heap pages. Per-tid stacks
     * live in the same VA window as the heap arena; after privatize their PTEs
     * point at distinct PAs (safe to mark). Raw identity heap leaves must stay
     * supervisor-only or ring3 scribbles zero kmalloc headers (magic=0 flood).
     */
    uintptr_t hlo = heap_base_addr();
    uintptr_t hhi = heap_region_end_exclusive();
    if (hlo == 0 || hhi <= hlo || hlo >= end) {
        (void)mark_user_identity_range_2m((uint64_t)begin, (uint64_t)end);
        return;
    }
    if (begin < hlo)
        (void)mark_user_identity_range_2m((uint64_t)begin, (uint64_t)hlo);
    /* Skip [hlo, hhi): privatized stack/TLS pages are marked by exec stack setup. */
    if (hhi < end)
        (void)mark_user_identity_range_2m((uint64_t)hhi, (uint64_t)end);
}

void exec_ensure_user_mappings(void) {
    /*
     * Linux has no identity-map PG_US stamp. On a private mm from
     * mm_alloc() the L4 is a shallow clone of swapper — L3/L2/L1
     * are still shared. Walking ~2GiB here and doing `l3[i] |= PG_US` mutates
     * the kernel page tables (and the frozen vfork parent's) and hangs boot
     * at openrc-exec-enter. Only the legacy shared-CR3 path needs this.
     */
    thread_t *tc = thread_current();
    if (!tc || tc->ring != 3)
        tc = thread_get_current_user();
    if (tc && elf_needs_private_user_pages(tc))
        return;
    mark_broad_user_ranges_for_exec();
}

/* After replacing an ET_EXEC (busybox @ 0x400000) with a small PIE (openrc),
 * leftover .text/.data from the previous image stays identity-mapped and
 * executable. Scrub the tail so RIP cannot land in stale busybox or zeroed
 * .bss (double-kill: #PF then #UD at 0x63e2c0).
 *
 * Do NOT scrub on busybox→busybox re-exec (/bin/mount, /bin/sh): keep_hi is
 * already ~0x63f000 and zeroing 0x63f000..0x800000 via still-shared fork page
 * tables wipes the parent's brk/heap. Init then dies right after wait4-reap
 * of the first sysinit child. */
static void exec_scrub_stale_image_tail(uint64_t keep_hi) {
    /* Always cover the classic busybox ET_EXEC window. */
    uint64_t scrub_lo = 0x400000ULL;
    uint64_t scrub_end = 8ULL * 1024ULL * 1024ULL;
    uintptr_t hb = heap_base_addr();
    if (hb != 0 && (uint64_t)hb < scrub_end)
        scrub_end = (uint64_t)hb;
    /* Large ET_EXEC still occupies the busybox window — nothing stale to clear. */
    if (keep_hi >= 0x600000ULL)
        return;
    /* Keep the newly loaded image; scrub only above it within the window. */
    uint64_t begin = scrub_lo;
    if (keep_hi > scrub_lo)
        begin = (keep_hi + 0xFFFULL) & ~0xFFFULL;
    if (begin >= scrub_end)
        return;
    thread_t *tc = thread_current();
    if (!tc || tc->ring != 3)
        tc = thread_get_current_user();
    if (!tc || !elf_needs_private_user_pages(tc))
        return;
    mm_t *share = mm_kernel();
    if (mm_make_private_range(tc->mm, begin, scrub_end, 0, share) != 0)
        return;
    (void)user_map_mprotect_range(begin, scrub_end, 3 /* PROT_READ|PROT_WRITE */);
    {
        static int scrub_log_left = 4;
        if (scrub_log_left-- > 0)
            devel_printf("exec-scrub: cleared stale image 0x%llx..0x%llx\n",
                    (unsigned long long)begin, (unsigned long long)scrub_end);
    }
}

static void exec_reset_shared_user_space(thread_t *owner, uintptr_t brk_base) {
    user_as_teardown_for_exec(owner, brk_base);
    exec_ensure_user_mappings();
}

int elf_load_from_path_info(const char *path, uint64_t load_base_override,
                            elf_load_info_t *out_info, elf_tls_info_t *out_tls) {
    if (out_info) memset(out_info, 0, sizeof(*out_info));
    if (out_tls) {
        out_tls->vaddr = 0;
        out_tls->filesz = 0;
        out_tls->memsz = 0;
        out_tls->align = 0;
    }
    struct fs_file *f = fs_open(path);
    if (!f) {
        //kprintf("execve: open failed: %s\n", path ? path : "(null)");
        return -1;
    }
    size_t fsz = f->size;

    /* Read only the ELF header first (avoid buffering whole file). */
    Elf64_Ehdr eh;
    ssize_t rh = fs_read(f, &eh, sizeof(eh), 0);
    if (rh != (ssize_t)sizeof(eh) || !elf_validate_header(&eh, sizeof(eh))) {
        fs_file_free(f);
        return -1;
    }
    if (eh.e_phoff == 0 || eh.e_phnum == 0 || eh.e_phentsize != sizeof(Elf64_Phdr)) {
        fs_file_free(f);
        return -1;
    }

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    /* Read program headers */
    size_t phsz = (size_t)eh.e_phnum * (size_t)eh.e_phentsize;
    if (phsz == 0 || phsz > 256u * 1024u) { fs_file_free(f); return -1; } /* sanity */
    Elf64_Phdr *phdrs = (Elf64_Phdr*)kmalloc(phsz);
    if (!phdrs) { fs_file_free(f); return -1; }
    ssize_t rp = fs_read(f, phdrs, phsz, (size_t)eh.e_phoff);
    if (rp != (ssize_t)phsz) { kfree(phdrs); fs_file_free(f); return -1; }

    uint64_t load_base = load_base_override ? load_base_override : elf_load_base_for_image(&eh, phdrs, (int)eh.e_phnum);
    int has_interp = 0;
    int has_dynamic = 0;
    char interp_path[192];
    interp_path[0] = '\0';

    for (int i = 0; i < (int)eh.e_phnum; i++) {
        if (phdrs[i].p_type == 3 /* PT_INTERP */) {
            if (phdrs[i].p_filesz == 0 || phdrs[i].p_filesz >= sizeof(interp_path)) {
                kfree(phdrs);
                fs_file_free(f);
                return -2;
            }
            if (fsz && phdrs[i].p_offset + phdrs[i].p_filesz > (uint64_t)fsz) {
                kfree(phdrs);
                fs_file_free(f);
                return -1;
            }
            ssize_t ri = fs_read(f, interp_path, (size_t)phdrs[i].p_filesz, (size_t)phdrs[i].p_offset);
            if (ri != (ssize_t)phdrs[i].p_filesz) {
                kfree(phdrs);
                fs_file_free(f);
                return -1;
            }
            interp_path[phdrs[i].p_filesz] = '\0';
            if (interp_path[phdrs[i].p_filesz - 1] == '\0') {
                /* PT_INTERP includes the trailing NUL on Linux. */
            } else {
                interp_path[sizeof(interp_path) - 1] = '\0';
            }
            has_interp = 1;
        }
        if (phdrs[i].p_type == 2 /* PT_DYNAMIC */) {
            has_dynamic = 1;
        }
    }
    if (has_dynamic && !has_interp && eh.e_type == 2 && load_base_override == 0) {
        qemu_debug_printf("elf: refusing ET_EXEC PT_DYNAMIC without PT_INTERP: %s\n", path ? path : "(null)");
        kfree(phdrs);
        fs_file_free(f);
        return -2;
    }

    if (out_tls) {
        for (int i = 0; i < (int)eh.e_phnum; i++) {
            if (phdrs[i].p_type == 7 /* PT_TLS */) {
                out_tls->vaddr = phdrs[i].p_vaddr + load_base;
                out_tls->filesz = phdrs[i].p_filesz;
                out_tls->memsz = phdrs[i].p_memsz;
                out_tls->align = phdrs[i].p_align;
                break;
            }
        }
    }

    uint64_t brk_end = 0;
    uint64_t loaded_lo = UINT64_MAX;
    uint64_t loaded_hi = 0;
    const uint64_t image_entry = (uint64_t)eh.e_entry + load_base;
    uint64_t aux_phdr = 0;
    uint64_t phsz64 = (uint64_t)eh.e_phnum * (uint64_t)eh.e_phentsize;
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type == 6 /* PT_PHDR */) {
            aux_phdr = ph->p_vaddr + load_base;
            break;
        }
    }
    if (aux_phdr == 0) {
        uint64_t want0 = eh.e_phoff;
        uint64_t want1 = eh.e_phoff + phsz64;
        for (int i = 0; i < (int)eh.e_phnum; i++) {
            Elf64_Phdr *ph = &phdrs[i];
            if (ph->p_type != 1) continue; /* PT_LOAD */
            uint64_t poff = ph->p_offset;
            uint64_t pend = ph->p_offset + ph->p_filesz;
            if (want0 >= poff && want1 <= pend) {
                aux_phdr = ph->p_vaddr + load_base + (want0 - poff);
                break;
            }
        }
    }
    /* Load PT_LOAD segments directly from file into their target VAs */
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != 1) continue; /* PT_LOAD */

        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (vend < vstart) { kfree(phdrs); fs_file_free(f); return -1; }

        /* Keep user images below heap floor (64MiB) to avoid corrupting heap. */
        const uint64_t USER_IMAGE_LIMIT = user_image_limit_bytes();
        if (vend > USER_IMAGE_LIMIT) {
            kprintf("elf: user image too high (segment 0x%llx..0x%llx, limit 0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)USER_IMAGE_LIMIT);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
        if (vstart < kernel_end && vend > kernel_start) {
            kprintf("elf: segment overlaps kernel (vaddr 0x%llx..0x%llx kernel 0x%llx..0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)kernel_start, (unsigned long long)kernel_end);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
        if (vstart + ph->p_filesz > MMIO_IDENTITY_LIMIT) {
            kprintf("elf: segment outside identity-mapped range, unsupported vaddr=0x%llx\n",
                    (unsigned long long)vstart);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }

        /* Sanity: file bounds if size is known */
        if (fsz && (uint64_t)ph->p_offset + (uint64_t)ph->p_filesz > (uint64_t)fsz) {
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }

        void *dst = (void*)(uintptr_t)(ph->p_vaddr + load_base);
        /*
         * Privatize only this segment's pages (4K-aligned), not a 2MiB
         * superpage window. Widening to 2MiB made a later PT_LOAD re-zero
         * already-copied .text when has_private missed (zeros at entry →
         * #PF CR2=0). Linux maps each PT_LOAD to its own VMA span.
         */
        {
            uint64_t map_lo = vstart & ~0xFFFULL;
            uint64_t map_hi = (vend + 0xFFFULL) & ~0xFFFULL;
            thread_t *tc = thread_current();
            if (!tc || tc->ring != 3)
                tc = thread_get_current_user();
            if (tc && elf_needs_private_user_pages(tc)) {
                /* Linux load_elf: map into current->mm only; never walk oldmm PTs. */
                mm_t *share = mm_kernel();
                /* copy_old=0 + has_private skip: never wipe a prior PT_LOAD. */
                if (mm_make_private_range(tc->mm, map_lo, map_hi, 0, share) != 0) {
                    kfree(phdrs);
                    fs_file_free(f);
                    return -1;
                }
                /* Do NOT mark_user_identity here: holes become pa==va and the
                 * following elf_copy_into_mm smashes the vfork parent's image. */
            } else {
                uint64_t lo2 = map_lo & ~((uint64_t)PAGE_SIZE_2M - 1);
                uint64_t hi2 = (map_hi + PAGE_SIZE_2M - 1) & ~((uint64_t)PAGE_SIZE_2M - 1);
                for (uint64_t va = lo2; va < hi2; va += PAGE_SIZE_2M) {
                    if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0) {
                        kfree(phdrs);
                        fs_file_free(f);
                        return -1;
                    }
                }
                (void)mark_user_identity_range_2m(map_lo, map_hi);
            }
        }
        if (ph->p_filesz > 0) {
            thread_t *tc = thread_current();
            if (!tc || tc->ring != 3)
                tc = thread_get_current_user();
            if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
                void *kbuf = kmalloc((size_t)ph->p_filesz);
                if (!kbuf) {
                    kfree(phdrs);
                    fs_file_free(f);
                    return -1;
                }
                ssize_t rr = fs_read(f, kbuf, (size_t)ph->p_filesz, (size_t)ph->p_offset);
                if (rr != (ssize_t)ph->p_filesz ||
                    elf_copy_into_mm(tc->mm, (uint64_t)(uintptr_t)dst, kbuf,
                                    (size_t)ph->p_filesz) != 0) {
                    kfree(kbuf);
                    kfree(phdrs);
                    fs_file_free(f);
                    return -1;
                }
                kfree(kbuf);
            } else {
                ssize_t rr = fs_read(f, dst, (size_t)ph->p_filesz, (size_t)ph->p_offset);
                if (rr != (ssize_t)ph->p_filesz) {
                    kfree(phdrs);
                    fs_file_free(f);
                    return -1;
                }
            }
        }
        if (ph->p_memsz > ph->p_filesz) {
            thread_t *tc = thread_current();
            if (!tc || tc->ring != 3)
                tc = thread_get_current_user();
            size_t zlen = (size_t)(ph->p_memsz - ph->p_filesz);
            uint64_t zva = (uint64_t)(uintptr_t)dst + (uint64_t)ph->p_filesz;
            if (tc && elf_needs_private_user_pages(tc) && tc->mm) {
                if (elf_zero_into_mm(tc->mm, zva, zlen) != 0) {
                    kfree(phdrs);
                    fs_file_free(f);
                    return -1;
                }
            } else {
                memset((char *)dst + ph->p_filesz, 0, zlen);
            }
        }
        if (vstart < loaded_lo) loaded_lo = vstart;
        if (vend > loaded_hi) loaded_hi = vend;
        /* Round vend for brk only — never mark PTEs past p_memsz (unmapped 2MiB tail). */
        {
            uint64_t vend_rounded = (vend + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
            if (vend_rounded > vend && vend_rounded <= USER_IMAGE_LIMIT)
                vend = vend_rounded;
        }
        if (vend > brk_end) brk_end = vend;
    }

    if (eh.e_type == 3 /* ET_DYN */) {
        if (elf_apply_rela_relative(load_base, phdrs, (int)eh.e_phnum) != 0) {
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
    }

    /* Pass 2: mark user-accessible after all segments are copied (avoid RO before memset). */
    if (loaded_lo < loaded_hi) {
        if (mark_user_range_exec(loaded_lo, loaded_hi) != 0) {
            kprintf("elf: mark user range failed %s [0x%llx..0x%llx)\n",
                    path ? path : "(null)",
                    (unsigned long long)loaded_lo, (unsigned long long)loaded_hi);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
    }

    if (brk_end) {
        thread_t *tc = thread_current();
        user_as_set_brk_after_load(tc, (uintptr_t)brk_end,
            loaded_hi != UINT64_MAX ? (uintptr_t)loaded_hi : 0);
    }
    if (out_info) {
        out_info->entry = image_entry;
        out_info->load_base = load_base;
        out_info->brk_end = brk_end;
        out_info->phdr = aux_phdr;
        out_info->phent = (uint64_t)eh.e_phentsize;
        out_info->phnum = (uint64_t)eh.e_phnum;
        out_info->loaded_lo = loaded_lo == UINT64_MAX ? 0 : loaded_lo;
        out_info->loaded_hi = loaded_hi;
        out_info->e_type = eh.e_type;
        out_info->has_interp = has_interp;
        out_info->has_dynamic = has_dynamic;
        if (has_interp) {
            strncpy(out_info->interp_path, interp_path, sizeof(out_info->interp_path) - 1);
            out_info->interp_path[sizeof(out_info->interp_path) - 1] = '\0';
        }
    }
    kfree(phdrs);
    fs_file_free(f);
    return 0;
}

int elf_load_from_path(const char *path, uint64_t *out_entry, uintptr_t *out_brk_end,
                       elf_tls_info_t *out_tls) {
    elf_load_info_t info;
    int rc = elf_load_from_path_info(path, 0, &info, out_tls);
    if (rc != 0) return rc;
    if (out_entry) *out_entry = info.entry;
    if (out_brk_end) *out_brk_end = (uintptr_t)info.brk_end;
    return 0;
}

/* Kernel execve: load ELF and prepare user stack then transfer to user mode.
   Simple implementation: expects identity mapping for all segments and stack
   under USER_STACK_TOP (<4GiB). Returns negative on error; on success does not return. */
static int is_space_char(char c) {
    return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

/* Parse "#!<interp> [arg]\n" from buffer.
   Returns 1 on success, 0 if not a shebang or parse error. */
static int parse_shebang(const uint8_t *buf, size_t n,
                         char *out_interp, size_t out_interp_sz,
                         char *out_arg, size_t out_arg_sz) {
    if (!buf || n < 3) return 0;
    if (buf[0] != '#' || buf[1] != '!') return 0;
    if (!out_interp || out_interp_sz == 0) return 0;
    if (!out_arg || out_arg_sz == 0) return 0;

    size_t i = 2;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    if (i >= n) return 0;

    /* interp path */
    size_t ip = 0;
    while (i < n && !is_space_char((char)buf[i])) {
        if (ip + 1 < out_interp_sz) out_interp[ip++] = (char)buf[i];
        i++;
    }
    out_interp[ip] = '\0';
    if (ip == 0) return 0;

    /* optional arg */
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    size_t ap = 0;
    while (i < n && !is_space_char((char)buf[i])) {
        if (ap + 1 < out_arg_sz) out_arg[ap++] = (char)buf[i];
        i++;
    }
    out_arg[ap] = '\0';
    return 1;
}

static char *kstrdup_local(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char*)kmalloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static void exec_register_loaded_range_vma(uint64_t tid, const elf_load_info_t *info) {
    if (!info || info->loaded_hi <= info->loaded_lo) return;
    uintptr_t lo = (uintptr_t)(info->loaded_lo & ~0xFFFULL);
    uintptr_t hi = (uintptr_t)((info->loaded_hi + 0xFFFULL) & ~0xFFFULL);
    if (hi <= lo || hi >= (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    (void)user_vma_add(tid, lo, (size_t)(hi - lo), 7, USER_VMA_KIND_ELF_LOAD);
}

/* Rebuild userspace stack/TLS layout for a specific target tid.
   Used as a recovery path when the final created thread tid differs from the
   initially planned slot (rare concurrent thread creation race). */
static int exec_prepare_layout_for_tid(uint64_t target_tid,
                                       const char *const argv[],
                                       const char *const envp[],
                                       uint64_t aux_phdr,
                                       uint64_t aux_phent,
                                       uint64_t aux_phnum,
                                       uint64_t aux_entry,
                                       uint64_t aux_base,
                                       const elf_tls_info_t *main_tls,
                                       uintptr_t *out_final_stack,
                                       uintptr_t *out_stack_top,
                                       uintptr_t *out_fs_base) {
    if (!out_final_stack || !out_stack_top || !out_fs_base) return -1;

    int argc = 0;
    while (argv && argv[argc]) argc++;
    size_t strings_size = 0;
    for (int i = 0; i < argc; i++) strings_size += strlen(argv[i]) + 1;

    int envc = 0;
    while (envp && envp[envc]) envc++;
    size_t env_strings_size = 0;
    for (int i = 0; i < envc; i++) env_strings_size += strlen(envp[i]) + 1;

    enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9,
           AT_CLKTCK = 17, AT_RANDOM = 25 };
    const size_t aux_pairs = 9;
    const size_t aux_qwords = aux_pairs * 2;
    size_t ptrs = (size_t)(argc + 1 + envc + 1) + aux_qwords;
    size_t ptrs_bytes = ptrs * sizeof(uint64_t);

    const size_t random_bytes = 16;
    size_t total = ptrs_bytes + strings_size + env_strings_size + random_bytes + 32;
    if (total > USER_STACK_SIZE - 128) return -1;

    uintptr_t stack_top = user_stack_top_for_tid(target_tid);
    stack_top &= ~((uintptr_t)0xFULL);
    /* Linux process entry starts with RSP ≡ 0 (mod 16). The dynamic loader is an
       entry point, not a normally-called function; giving it function-entry
       alignment makes early SSE stores (movaps/movdqa) fault on unaligned locals. */
    uintptr_t final_stack = (stack_top - total) & ~((uintptr_t)0xFULL);
    uintptr_t ptrs_addr = final_stack + 8u;
    uintptr_t base = ptrs_addr;
    uintptr_t strings_addr = base + ptrs_bytes;
    uintptr_t random_addr = strings_addr + strings_size + env_strings_size;
    if (strings_addr + strings_size + env_strings_size > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;

    {
        thread_t *tc = thread_current();
        if (elf_needs_private_user_pages(tc)) {
            uintptr_t tip_lo = final_stack > 0x8000u ? (final_stack - 0x8000u) : final_stack;
            if (exec_map_stack_tip(tc, tip_lo, stack_top) != 0)
                return -1;
        }
    }

    /* Same as main exec path: build in kernel, publish via leaf PAs. */
    {
        thread_t *tc = thread_current();
        if (!tc || tc->ring != 3)
            tc = thread_get_current_user();
        mm_t *tip_mm = (tc && elf_needs_private_user_pages(tc)) ? tc->mm : NULL;
        size_t tip_bytes = (size_t)(stack_top - final_stack);
        void *tip_kimg = kmalloc(tip_bytes ? tip_bytes : 8u);
        if (!tip_kimg)
            return -1;
        memset(tip_kimg, 0, tip_bytes);
        {
            uint8_t *base = (uint8_t *)tip_kimg;
            uint64_t *sp64 = (uint64_t *)(base + (ptrs_addr - final_stack));
            char *str_base = (char *)(base + (strings_addr - final_stack));
            char *str_dst = str_base;
            for (int i = 0; i < argc; i++) {
                size_t l = strlen(argv[i]) + 1;
                memcpy(str_dst, argv[i], l);
                sp64[i] = (uint64_t)strings_addr + (uint64_t)(str_dst - str_base);
                str_dst += l;
            }
            sp64[argc] = 0;
            for (int i = 0; i < envc; i++) {
                size_t l = strlen(envp[i]) + 1;
                memcpy(str_dst, envp[i], l);
                sp64[argc + 1 + i] = (uint64_t)strings_addr + (uint64_t)(str_dst - str_base);
                str_dst += l;
            }
            sp64[argc + 1 + envc] = 0;
            {
                uint8_t *rp = base + (random_addr - final_stack);
                for (size_t i = 0; i < 16; i++)
                    rp[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u));
            }
            size_t ax = (size_t)argc + 2 + (size_t)envc;
            sp64[ax + 0] = (uint64_t)AT_PHDR;   sp64[ax + 1] = aux_phdr;
            sp64[ax + 2] = (uint64_t)AT_PHENT;  sp64[ax + 3] = aux_phent ? aux_phent : (uint64_t)sizeof(Elf64_Phdr);
            sp64[ax + 4] = (uint64_t)AT_PHNUM;  sp64[ax + 5] = aux_phnum;
            sp64[ax + 6] = (uint64_t)AT_BASE;   sp64[ax + 7] = aux_base;
            sp64[ax + 8] = (uint64_t)AT_ENTRY;  sp64[ax + 9] = aux_entry;
            sp64[ax +10] = (uint64_t)AT_PAGESZ; sp64[ax +11] = 4096ULL;
            sp64[ax +12] = (uint64_t)AT_RANDOM; sp64[ax +13] = (uint64_t)random_addr;
            sp64[ax +14] = (uint64_t)AT_CLKTCK; sp64[ax +15] = 100ULL;
            sp64[ax +16] = (uint64_t)AT_NULL;   sp64[ax +17] = 0;
            *(uint64_t *)base = (uint64_t)argc;
        }
        if (tip_mm) {
            if (elf_copy_into_mm(tip_mm, (uint64_t)final_stack, tip_kimg, tip_bytes) != 0) {
                kfree(tip_kimg);
                return -1;
            }
        } else if (tc && tc->ring == 3) {
            kfree(tip_kimg);
            return -1;
        } else {
            memcpy((void *)(uintptr_t)final_stack, tip_kimg, tip_bytes);
            uintptr_t stack_base = (stack_top - USER_STACK_SIZE) & ~0xFFFULL;
            uintptr_t tls_base = user_tls_base_for_stack_top(stack_top);
            if (tls_base < stack_base)
                stack_base = tls_base & ~0xFFFULL;
            uintptr_t mark_end = stack_top + (uintptr_t)PAGE_SIZE_2M;
            if (mark_end > (uintptr_t)MMIO_IDENTITY_LIMIT)
                mark_end = (uintptr_t)MMIO_IDENTITY_LIMIT;
            if (mark_user_identity_range_2m((uint64_t)stack_base, (uint64_t)mark_end) != 0) {
                kfree(tip_kimg);
                return -1;
            }
        }
        kfree(tip_kimg);
    }

    enum { MSR_FS_BASE_LOCAL = 0xC0000100u };
    uintptr_t fs_base = 0;
    if (aux_base == 0) {
        if (exec_seed_static_tls(stack_top, random_addr, main_tls, &fs_base) != 0)
            return -1;
        msr_write_u64_local(MSR_FS_BASE_LOCAL, (uint64_t)fs_base);
    } else {
        /* Dynamic ELF starts in ld.so. Linux enters it with FS unset; ld.so will
           allocate TLS and set FS with arch_prctl(ARCH_SET_FS). A fake static
           glibc TCB here makes ld.so follow bogus pthread/locale pointers. */
        msr_write_u64_local(MSR_FS_BASE_LOCAL, 0);
    }

    *out_final_stack = final_stack;
    *out_stack_top = stack_top;
    *out_fs_base = fs_base;
    return 0;
}

/* If `path` is a script with shebang, exec its interpreter. */
static int try_exec_shebang(const char *resolved_path,
                            const char *orig_path,
                            const char *const argv[],
                            const char *const envp[]) {
    if (!resolved_path || !orig_path) return -1;
    struct fs_file *f = fs_open(resolved_path);
    if (!f) return -1;

    uint8_t hdr[256];
    memset(hdr, 0, sizeof(hdr));
    ssize_t rr = fs_read(f, hdr, sizeof(hdr) - 1, 0);
    fs_file_free(f);
    if (rr <= 0) return -1;

    char interp[192];
    char arg[64];
    if (!parse_shebang(hdr, (size_t)rr, interp, sizeof(interp), arg, sizeof(arg))) return -1;

    /* Build new argv: [interp, (arg?), orig_path, argv[1..]] */
    int argc = 0;
    while (argv && argv[argc]) argc++;
    const int has_arg = (arg[0] != '\0');
    const int tail = (argc > 1) ? (argc - 1) : 0;
    const int new_argc = 1 + (has_arg ? 1 : 0) + 1 + tail;

    char *k_interp = kstrdup_local(interp);
    char *k_arg = has_arg ? kstrdup_local(arg) : NULL;
    const char **nargv = (const char**)kmalloc((size_t)(new_argc + 1) * sizeof(char*));
    if (!k_interp || (has_arg && !k_arg) || !nargv) {
        if (nargv) kfree((void*)nargv);
        if (k_interp) kfree(k_interp);
        if (k_arg) kfree(k_arg);
        return -1;
    }

    int p = 0;
    nargv[p++] = k_interp;
    if (has_arg) nargv[p++] = k_arg;
    nargv[p++] = orig_path;
    for (int i = 1; i < argc; i++) nargv[p++] = argv[i];
    nargv[p] = NULL;

    qemu_debug_printf("execve: shebang '%s' -> interp='%s'%s%s%s\n",
                      resolved_path, interp,
                      has_arg ? " arg='" : "",
                      has_arg ? arg : "",
                      has_arg ? "'" : "");
    /* shebang: run interpreter with script path as argv0 */

    int rc = kernel_execve_into_mm(k_interp, nargv, envp);
    kfree((void*)nargv);
    kfree(k_interp);
    if (k_arg) kfree(k_arg);
    return rc;
}

int kernel_execve_from_path(const char *path, const char *const argv[],
                            const char *const envp[]) {
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3)
        cur = thread_get_current_user();
    if (!cur)
        return kernel_execve_into_mm(path, argv, envp);

    /* Drop Soft_COW fork marker before touching a new mm (vfork child). */
    cur->fork_child_user_rip = 0;

    mm_t *old_mm = cur->mm;
    mm_t *old_template = cur->mm_ptemplate;

    /*
     * Linux (torvalds fs/exec.c) order of interest:
     *   copy_strings into bprm->mm pages   // tip exists before wake
     *   exec_mmap: complete_vfork_done + activate_mm
     *   load_elf / setup_arg_pages on new mm
     *
     * AxonOS adaptation (identity map): activate BEFORE tip/ELF so stores
     * never run under oldmm CR3, but keep the vfork parent frozen until tip
     * publish finishes — waking early raced with tip L1 installs and left
     * ash RA==0x801738 ("ls"). Wake + mmput(old) at end of into_mm.
     */
    int exec_dbg = cur->name[0] &&
                   (strstr(cur->name, "linuxrc") || (path && strstr(path, "mount")));
    if (exec_dbg)
        devel_printf("exec-mm: tid=%llu path=%s mm_alloc\n",
            (unsigned long long)(cur->tid ? cur->tid : 1),
            path ? path : "?");

    mm_t *new_mm = mm_alloc();
    if (!new_mm) {
        if (exec_dbg)
            kprintf("exec-mm: tid=%llu mm_alloc FAILED\n",
                (unsigned long long)(cur->tid ? cur->tid : 1));
        return -3;
    }

    if (old_template) {
        mm_release(old_template);
        old_template = NULL;
    }
    cur->exec_discard_template = NULL;
    /* Keep oldmm until tip/ELF done (share baseline + freeze-check + late wake). */
    cur->exec_discard_mm = (old_mm && old_mm != mm_kernel() && old_mm != new_mm)
                               ? old_mm : NULL;
    if (old_mm && old_mm != new_mm && old_mm->pml4)
        cur->mm_ptemplate = mm_retain(old_mm);
    else
        cur->mm_ptemplate = NULL;

    /*
     * Keep process->mm pointing at old_mm until commit.  current->mm is the
     * private bprm construction context used by the loader, but no other
     * thread/process lookup may observe a half-built image.
     */
    cur->mm = new_mm;

    /* activate_mm(new) — parent still vfork_waiting until into_mm finishes. */
    mm_switch(new_mm);
    if (exec_dbg)
        devel_printf("exec-mm: tid=%llu activated cr3=0x%llx (tip under new mm, parent frozen)\n",
            (unsigned long long)(cur->tid ? cur->tid : 1),
            (unsigned long long)(new_mm->cr3 ? new_mm->cr3 : 0));

    int rc = kernel_execve_into_mm(path, argv, envp);
    if (rc != 0) {
        if (cur->mm_ptemplate) {
            mm_release(cur->mm_ptemplate);
            cur->mm_ptemplate = NULL;
        }
        if (cur->exec_discard_mm) {
            mm_t *dead = new_mm;
            cur->mm = cur->exec_discard_mm;
            cur->exec_discard_mm = NULL;
            mm_switch(cur->mm);
            mm_release(dead);
        } else {
            mm_release(new_mm);
        }
        return rc;
    }

    /* Unreachable on success (enter_user_mode). */
    process_sync_from_thread(cur->process, cur);
    return 0;
}

int kernel_execve_init_from_path(const char *path, const char *const argv[],
                                 const char *const envp[]) {
    if (thread_get_current_user() != NULL)
        return -1;
    thread_t *caller = thread_current();
    if (!caller)
        return -1;

    /*
     * Prepare PID1 exactly like a bprm mm.  Loading into swapper and cloning
     * afterwards leaves identity user leaves outside frame ownership; a later
     * kmalloc can then reuse the live init stack physical page.
     */
    mm_t *old_mm = caller->mm;
    mm_t *new_mm = mm_alloc();
    if (!new_mm)
        return -3;
    caller->mm = new_mm;
    mm_switch(new_mm);

    int rc = kernel_execve_into_mm(path, argv, envp);

    caller->mm = old_mm;
    mm_switch(old_mm ? old_mm : mm_kernel());
    mm_release(new_mm);
    return rc;
}

static int kernel_execve_into_mm(const char *path, const char *const argv[],
                                 const char *const envp[]) {
    if (!path) return -1;
    /* IMPORTANT:
       Symlinks are resolved by VFS (`fs_open()` does it via `fs_resolve_symlinks()`).
       Do NOT attempt to "readlink" via fs_open() here, because that would read the
       *target file* (already resolved) rather than the symlink contents. */
    const char *curpath = path;
    elf_load_info_t main_info;
    elf_load_info_t interp_info;
    elf_tls_info_t main_tls;
    memset(&main_info, 0, sizeof(main_info));
    memset(&interp_info, 0, sizeof(interp_info));
    memset(&main_tls, 0, sizeof(main_tls));
    exec_reset_shared_user_space(thread_get_current_user(), 8u * 1024u * 1024u);
    {
        thread_t *tr = thread_get_current_user();
        if (tr && tr->name[0] &&
            (strstr(tr->name, "linuxrc") || (path && strstr(path, "mount"))))
            devel_printf("exec-load: tid=%llu path=%s\n",
                (unsigned long long)(tr->tid ? tr->tid : 1),
                curpath ? curpath : "?");
    }
    int r = elf_load_from_path_info(curpath, 0, &main_info, &main_tls);
    if (r == -2) {
        /* unsupported ELF format */
        return -2;
    }
    if (r != 0) {
        /* Not an ELF. Try shebang scripts (e.g. /linuxrc). */
        return try_exec_shebang(curpath, path, argv, envp);
    }
    {
        thread_t *tr = thread_get_current_user();
        if (tr && tr->name[0] &&
            (strstr(tr->name, "linuxrc") || (path && strstr(path, "mount"))))
            devel_printf("exec-load: tid=%llu ok entry=0x%llx hi=0x%llx\n",
                (unsigned long long)(tr->tid ? tr->tid : 1),
                (unsigned long long)main_info.entry,
                (unsigned long long)main_info.loaded_hi);
    }
    if (strstr(curpath, "openrc"))
        debug_serial_marker("AXON_BOOT_OPENRC_EXEC");
    /* NOTE:
       We currently execute user programs in the *same* address space (same CR3),
       relying on identity mapping and marking PT_LOAD pages as user-accessible in elf_load_from_memory().
       The previous attempt to build a per-process PML4 was buggy and leaked page tables heavily.
       Once we have a real physical-page allocator, we can reintroduce isolated address spaces. */

    uint64_t entry = main_info.entry;
    uintptr_t loaded_brk_end = (uintptr_t)main_info.brk_end;
    uint64_t loaded_image_hi = main_info.loaded_hi;
    uint64_t aux_entry = main_info.entry;
    uint64_t aux_phdr = main_info.phdr;
    uint64_t aux_phent = main_info.phent;
    uint64_t aux_phnum = main_info.phnum;
    uint64_t aux_base = 0;

    if (main_info.has_interp) {
        uint64_t interp_base = elf_interp_base();
        uint64_t min_interp_base = main_info.loaded_hi + (uint64_t)PAGE_SIZE_2M - 1;
        min_interp_base &= ~((uint64_t)PAGE_SIZE_2M - 1);
        if (interp_base < min_interp_base)
            interp_base = min_interp_base;
        r = elf_load_from_path_info(main_info.interp_path, interp_base, &interp_info, NULL);
        if (r != 0) {
            qemu_debug_printf("execve: failed to load interpreter '%s' for '%s': %d\n",
                              main_info.interp_path, path, r);
            return r;
        }
        entry = interp_info.entry;
        aux_base = interp_info.load_base;
        if (interp_info.brk_end > loaded_brk_end)
            loaded_brk_end = (uintptr_t)interp_info.brk_end;
        if (interp_info.loaded_hi > loaded_image_hi)
            loaded_image_hi = interp_info.loaded_hi;
        qemu_debug_printf("execve: dynamic '%s' interp='%s' entry=0x%llx AT_BASE=0x%llx main_entry=0x%llx\n",
                          path, main_info.interp_path,
                          (unsigned long long)entry,
                          (unsigned long long)aux_base,
                          (unsigned long long)aux_entry);
    }

    /* Drop leftover bytes from the previous ET_EXEC (busybox @ 0x400000)
     * beyond the MAIN image only — do not use interp loaded_hi (ld.so lives
     * near 0x2000000 and would skip the scrub). */
    exec_scrub_stale_image_tail(main_info.loaded_hi);

    /* Sanity: after replacing busybox with openrc PIE, PLT @+0x30d0 must be
     * ff25 — not busybox AVX (c57e) or zeros (0000 → add [rax],al → #PF CR2=0). */
    if (path && strstr(path, "openrc") &&
        main_info.load_base == 0x400000ULL && main_info.loaded_hi > 0x4030d0ULL) {
        const uint8_t *p = (const uint8_t *)(uintptr_t)0x4030d0ULL;
        uint64_t got = *(const uint64_t *)(uintptr_t)0x40c050ULL;
        devel_printf("exec-image: @0x4030d0 %02x %02x %02x %02x got@0x40c050=0x%llx (want ff25)\n",
                (unsigned)p[0], (unsigned)p[1], (unsigned)p[2], (unsigned)p[3],
                (unsigned long long)got);
        if (p[0] != 0xffu || p[1] != 0x25u) {
            kprintf("exec-image: BAD image at PLT (not openrc) — abort exec\n");
            return -1;
        }
    }
    /* PG_US for the loaded image comes from make_private / mark_user_range_exec.
     * Remapping 0x400000..0x800000 as identity would alias the vfork parent. */
    {
        thread_t *tc = thread_current();
        if (!tc || tc->ring != 3)
            tc = thread_get_current_user();
        if (!tc || !elf_needs_private_user_pages(tc))
            (void)mark_user_identity_range_2m(0x400000ULL, 0x800000ULL);
    }

    /* Determine which tid we are preparing the stack/TLS for.
       If called from ring0 (osh/kernel), we must base the per-thread stack/TLS layout
       on the tid of the NEW user thread we are about to run, not on the caller's tid0.
       Using tid0 here causes all user programs spawned from osh to share the same stack
       slot, which breaks vfork/exec and leads to user-mode #GP after child exit. */
    thread_t *cur_user = thread_get_current_user();
    uint64_t planned_tid = 0;
    if (cur_user) {
        planned_tid = (uint64_t)cur_user->tid;
    } else {
        /* Kernel-launched exec: use next tid hint for per-thread stack slot calculation.
           The actual blocked thread is created later, after all fallible setup is done,
           to avoid leaking half-initialized threads on early execve failures. */
        planned_tid = (uint64_t)thread_get_count();
    }

    if (cur_user) {
        uint64_t exec_tid = (uint64_t)(cur_user->tid ? cur_user->tid : 1);
        user_vma_remove_all_for_tid(exec_tid);
        exec_register_loaded_range_vma(exec_tid, &main_info);
        if (aux_base != 0)
            exec_register_loaded_range_vma(exec_tid, &interp_info);
    } else {
        /* The actual user thread is created later. Do not pin ELF VMAs to the
           predicted tid; thread slots can be reused and thread_count is only a hint. */
        user_vma_remove_all_for_tid(planned_tid);
    }

    /* Build argv strings and pointers in kernel, then copy into user stack area.
       We must ensure the final RSP passed to user mode is 16-byte aligned to avoid
       misaligned iret frame / ABI issues. Compute aligned base accordingly. */
    int argc = 0;
    while (argv && argv[argc]) argc++;

    /* compute total strings size */
    size_t strings_size = 0;
    for (int i = 0; i < argc; i++) strings_size += strlen(argv[i]) + 1;
    int envc = 0;
    while (envp && envp[envc]) envc++;
    size_t env_strings_size = 0;
    for (int i = 0; i < envc; i++) env_strings_size += strlen(envp[i]) + 1;

    /* Stack layout (SysV x86_64):
       RSP -> argc
              argv[0..argc-1], NULL
              envp[0..], NULL
              auxv pairs (a_type,a_val) ending with AT_NULL
       Many libc start routines expect auxv to exist; without AT_NULL they may parse garbage. */
    enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9,
           AT_CLKTCK = 17, AT_RANDOM = 25 };
    const size_t aux_pairs = 9; /* PHDR,PHENT,PHNUM,BASE,ENTRY,PAGESZ,RANDOM,CLKTCK,NULL */
    const size_t aux_qwords = aux_pairs * 2;
    /* pointer area: argv pointers + NULL + env pointers + NULL + auxv */
    size_t ptrs = (size_t)(argc + 1 + envc + 1) + aux_qwords;
    size_t ptrs_bytes = ptrs * sizeof(uint64_t);

    /* total needed on stack: pointers + strings + env strings + AT_RANDOM bytes + small padding */
    const size_t random_bytes = 16;
    size_t total = ptrs_bytes + strings_size + env_strings_size + random_bytes + 32;
    if (total > USER_STACK_SIZE - 128) {
        kprintf("required stack size too large %u\n", (unsigned)total);
        return -1;
    }

    /* Align stack_top downward to 16 bytes */
    uintptr_t stack_top = user_stack_top_for_tid(planned_tid);
    stack_top &= ~((uintptr_t)0xFULL);

    /* Linux process entry starts with RSP ≡ 0 (mod 16). The dynamic loader is an
       entry point, not a normally-called function; giving it function-entry
       alignment makes early SSE stores (movaps/movdqa) fault on unaligned locals. */
    uintptr_t final_stack = (stack_top - total) & ~((uintptr_t)0xFULL);
    uintptr_t ptrs_addr = final_stack + 8u;
    uintptr_t base = ptrs_addr;

    /* layout: pointers at [ptrs_addr .. ptrs_addr+ptrs_bytes), strings follow,
       then 16 bytes for AT_RANDOM. */
    uintptr_t strings_addr = base + ptrs_bytes;
    uintptr_t random_addr = strings_addr + strings_size + env_strings_size;

    /* Ensure addresses are within identity-mapped range */
    if (strings_addr + strings_size + env_strings_size > (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: stack region outside identity map\n");
        return -1;
    }
    {
        thread_t *tc = thread_current();
        if (elf_needs_private_user_pages(tc)) {
            uintptr_t tip_lo = final_stack > 0x8000u ? (final_stack - 0x8000u) : final_stack;
            if (exec_map_stack_tip(tc, tip_lo, stack_top) != 0) return -1;
        }
    }

    /* Build argv/env/auxv in a kernel buffer; publish once via leaf PAs. */
    thread_t *tip_tc = thread_current();
    if (!tip_tc || tip_tc->ring != 3)
        tip_tc = thread_get_current_user();
    mm_t *tip_mm = (tip_tc && elf_needs_private_user_pages(tip_tc)) ? tip_tc->mm : NULL;
    size_t tip_bytes = (size_t)(stack_top - final_stack);
    void *tip_kimg = kmalloc(tip_bytes ? tip_bytes : 8u);
    if (!tip_kimg) {
        kprintf("execve: OOM stack image\n");
        return -1;
    }
    memset(tip_kimg, 0, tip_bytes);
    {
        uint8_t *base = (uint8_t *)tip_kimg;
        uint64_t *sp64 = (uint64_t *)(base + (ptrs_addr - final_stack));
        char *str_base = (char *)(base + (strings_addr - final_stack));
        char *str_dst = str_base;
        for (int i = 0; i < argc; i++) {
            size_t l = strlen(argv[i]) + 1;
            memcpy(str_dst, argv[i], l);
            sp64[i] = (uint64_t)strings_addr + (uint64_t)(str_dst - str_base);
            str_dst += l;
        }
        sp64[argc] = 0;
        for (int i = 0; i < envc; i++) {
            size_t l = strlen(envp[i]) + 1;
            memcpy(str_dst, envp[i], l);
            sp64[argc + 1 + i] = (uint64_t)strings_addr + (uint64_t)(str_dst - str_base);
            str_dst += l;
        }
        sp64[argc + 1 + envc] = 0;
        {
            uint8_t *rp = base + (random_addr - final_stack);
            for (size_t i = 0; i < 16; i++)
                rp[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u));
        }
        size_t ax = (size_t)argc + 2 + (size_t)envc;
        sp64[ax + 0] = (uint64_t)AT_PHDR;   sp64[ax + 1] = aux_phdr;
        sp64[ax + 2] = (uint64_t)AT_PHENT;  sp64[ax + 3] = aux_phent ? aux_phent : (uint64_t)sizeof(Elf64_Phdr);
        sp64[ax + 4] = (uint64_t)AT_PHNUM;  sp64[ax + 5] = aux_phnum;
        sp64[ax + 6] = (uint64_t)AT_BASE;   sp64[ax + 7] = aux_base;
        sp64[ax + 8] = (uint64_t)AT_ENTRY;  sp64[ax + 9] = aux_entry;
        sp64[ax +10] = (uint64_t)AT_PAGESZ; sp64[ax +11] = 4096ULL;
        sp64[ax +12] = (uint64_t)AT_RANDOM; sp64[ax +13] = (uint64_t)random_addr;
        sp64[ax +14] = (uint64_t)AT_CLKTCK; sp64[ax +15] = 100ULL;
        sp64[ax +16] = (uint64_t)AT_NULL;   sp64[ax +17] = 0;
        *(uint64_t *)base = (uint64_t)argc;
    }
    if (tip_mm) {
        if (elf_copy_into_mm(tip_mm, (uint64_t)final_stack, tip_kimg, tip_bytes) != 0) {
            kfree(tip_kimg);
            kprintf("execve: stack tip publish failed\n");
            return -1;
        }
    } else if (tip_tc && tip_tc->ring == 3) {
        /* Never VA-store tip under a live user/oldmm CR3 (vfork parent smash). */
        kfree(tip_kimg);
        kprintf("execve: refuse identity tip publish (ring3 without private mm)\n");
        return -1;
    } else {
        /* Kernel-launched path only (no user mm). */
        memcpy((void *)(uintptr_t)final_stack, tip_kimg, tip_bytes);
    }
    kfree(tip_kimg);

    /*
     * Legacy shared-CR3 only. Private mm (including vfork-exec load under oldmm):
     * tip/TLS already PG_US from bulk_zero — mark_user_identity would mutate
     * the frozen parent's live CR3.
     */
    {
        thread_t *tc = tip_tc;
        if (tc && !elf_needs_private_user_pages(tc)) {
            uintptr_t stack_base = (stack_top - USER_STACK_SIZE) & ~0xFFFULL;
            uintptr_t tls_base = user_tls_base_for_stack_top(stack_top);
            uintptr_t mark_end = stack_top + (uintptr_t)PAGE_SIZE_2M;
            if (tls_base < stack_base)
                stack_base = tls_base & ~0xFFFULL;
            if (mark_end > (uintptr_t)MMIO_IDENTITY_LIMIT)
                mark_end = (uintptr_t)MMIO_IDENTITY_LIMIT;
            if (mark_user_identity_range_2m((uint64_t)stack_base, (uint64_t)mark_end) != 0)
                kprintf("execve: warn mark stack/TLS 0x%llx..0x%llx (continuing)\n",
                    (unsigned long long)stack_base, (unsigned long long)mark_end);
        }
    }

    /* Seed a minimal Linux-compatible static TLS/TCB layout before entering userspace. */
    enum { MSR_FS_BASE_LOCAL = 0xC0000100u };
    uintptr_t fs_base = 0;
    if (aux_base == 0) {
        if (exec_seed_static_tls(stack_top, random_addr, &main_tls, &fs_base) != 0) {
            kprintf("axonOS: failed to seed static TLS\n");
            return -1;
        }
        msr_write_u64_local(MSR_FS_BASE_LOCAL, (uint64_t)fs_base);
    } else {
        /* Dynamic ELF enters the interpreter first. Let ld.so install the real
           TLS/TCB with arch_prctl instead of exposing the static-glibc fake TCB. */
        msr_write_u64_local(MSR_FS_BASE_LOCAL, 0);
    }


    /* IMPORTANT: userspace must run from a scheduled kernel thread.
       Otherwise syscalls run on the TSS RSP0 stack but the scheduler saves/restores
       `thread_current()->context` for a different stack, and vfork/fork will corrupt
       kernel context (seen as user-mode #GP with non-canonical pointers after vfork).

       Strategy:
       - If we are already in a user thread (thread_get_current_user()!=NULL), perform an
         in-place exec: update current user thread metadata and jump to user entry.
       - If called from ring0 (osh/kernel), spawn a new kernel thread that will enter
         user mode via user_thread_entry, block the caller until it exits, and schedule. */
    if (cur_user) {
        /* in-place exec for current user thread */
        cur_user->user_rip = entry;
        cur_user->user_stack = final_stack;
        cur_user->user_stack_base = (stack_top - USER_STACK_SIZE) & ~0xFFFULL;
        cur_user->user_stack_limit = stack_top;
        cur_user->user_fs_base = (uint64_t)fs_base;
        thread_proc_env_set(cur_user, envp);
        /* update display name */
        strncpy(cur_user->name, path, sizeof(cur_user->name) - 1);
        cur_user->name[sizeof(cur_user->name) - 1] = '\0';
        /* Fresh program image: drop fork-child tracing so libc set_robust_list
         * in the new binary is not treated as glibc _Fork epilogue. */
        cur_user->fork_child_user_rip = 0;
        cur_user->fork_child_trap_rip = 0;
        cur_user->fork_locked_syscall_rip = 0;
        /* Keep inherited sid/pgid across exec so getty is not already a
         * process group leader before its setsid() (pgid == pid → EPERM). */
        if (cur_user->process) {
            if (cur_user->sid <= 0)
                cur_user->sid = cur_user->process->sid;
            if (cur_user->pgid <= 0)
                cur_user->pgid = cur_user->process->pgid;
            process_sync_from_thread(cur_user->process, cur_user);
        }
        /*
         * After setsid(), BusyBox init with empty console id leaves /dev/null
         * on stdio. Re-bind console before entering ash or the shell exits on
         * EOF and ::respawn spins.
         */
        exec_boot_ensure_stdio(cur_user);
        /* Set foreground so Ctrl+C terminates this process when waiting */
        if (cur_user->attached_tty >= 0) {
            devfs_set_tty_fg_pgrp(cur_user->attached_tty, cur_user->pgid);
        }
        if (cur_user->kernel_stack) {
            tss_set_rsp0(cur_user->kernel_stack);
            syscall_bind_kstack_for_thread(cur_user);
        }
        if (loaded_brk_end != 0) {
            user_as_set_brk_after_load(cur_user, loaded_brk_end,
                loaded_image_hi > 0 ? (uintptr_t)loaded_image_hi : 0);
        }
    } else {
        /* Spawn a scheduled user thread and block caller until it exits.
           Create it only now (late), so earlier execve failures do not consume thread slots. */
        thread_t *caller = thread_current();
        extern void user_thread_entry(void);
        thread_t *ut = thread_create_blocked(user_thread_entry, path ? path : "user");
        if (!ut) return -1;
        /*
         * kernel_execve_init_from_path prepared the image in a nascent mm.
         * Share that mm object with the new task; do not clone page tables
         * after loading, because that loses leaf ownership accounting.
         */
        {
            mm_t *kmm = mm_kernel();
            mm_t *user_mm = (caller && caller->mm && caller->mm != kmm)
                                ? mm_retain(caller->mm)
                                : NULL;
            if (!user_mm) {
                int failed_tid = (int)(ut->tid ? ut->tid : 1);
                ut->state = THREAD_TERMINATED;
                (void)thread_reap(failed_tid);
                return -3;
            }
            if (ut->mm)
                mm_release(ut->mm);
            ut->mm = user_mm;
        }
        user_as_reset_on_exec(ut, loaded_brk_end ? loaded_brk_end : (8u * 1024u * 1024u));
        {
            uint64_t actual_tid = (uint64_t)(ut->tid ? ut->tid : 1);
            user_vma_remove_all_for_tid(planned_tid);
            if (actual_tid != planned_tid)
                user_vma_remove_all_for_tid(actual_tid);
            exec_register_loaded_range_vma(actual_tid, &main_info);
            if (aux_base != 0)
                exec_register_loaded_range_vma(actual_tid, &interp_info);
        }
        if ((uint64_t)ut->tid != planned_tid) {
            qemu_debug_printf("execve: warning: planned tid=%llu, actual tid=%llu\n",
                              (unsigned long long)planned_tid,
                              (unsigned long long)ut->tid);
            /* Rebuild layout for actual tid to avoid per-thread region overlap. */
            if (exec_prepare_layout_for_tid((uint64_t)ut->tid,
                                            argv, envp,
                                            aux_phdr, aux_phent, aux_phnum, aux_entry, aux_base,
                                            &main_tls,
                                            &final_stack, &stack_top, &fs_base) != 0) {
                int failed_tid = (int)(ut->tid ? ut->tid : 1);
                ut->state = THREAD_TERMINATED;
                (void)thread_reap(failed_tid);
                return -3; /* transient exec setup race; caller may retry */
            }
        }
        ut->ring = 3;
        ut->user_rip = entry;
        ut->user_stack = final_stack;
        ut->user_stack_base = (stack_top - USER_STACK_SIZE) & ~0xFFFULL;
        ut->user_stack_limit = stack_top;
        ut->user_fs_base = (uint64_t)fs_base;
        if (loaded_brk_end != 0) {
            user_as_set_brk_after_load(ut, loaded_brk_end,
                loaded_image_hi > 0 ? (uintptr_t)loaded_image_hi : 0);
        }
        /* Mark PID 1 only for kernel-launched init candidates */
        if (strcmp(path, "/linuxrc") == 0 || strcmp(path, "/init") == 0 ||
            strcmp(path, "/sbin/init") == 0 ||
            strcmp(path, "/sbin/openrc-init") == 0) {
            thread_mark_init_user(ut);
        }
        /* inherit basic POSIX-ish attributes and stdio from caller (usually tid0 osh) */
        if (caller) {
            ut->uid = caller->uid;
            ut->euid = caller->euid;
            ut->suid = caller->suid;
            ut->gid = caller->gid;
            ut->egid = caller->egid;
            ut->sgid = caller->sgid;
            ut->umask = caller->umask;
            ut->attached_tty = caller->attached_tty;
            strncpy(ut->cwd, caller->cwd[0] ? caller->cwd : "/", sizeof(ut->cwd));
            ut->cwd[sizeof(ut->cwd) - 1] = '\0';
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                ut->fds[i] = caller->fds[i];
                if (ut->fds[i]) {
                    if (ut->fds[i]->refcount <= 0) ut->fds[i]->refcount = 1;
                    else ut->fds[i]->refcount++;
                }
            }
            /* block caller until user program exits */
            ut->waiter_tid = (int)caller->tid;
            caller->state = THREAD_BLOCKED;
        }
        thread_proc_env_set(ut, envp);
        /* A kernel-launched program is a session and process-group leader. */
        ut->sid = (int)(ut->tid ? ut->tid : 1);
        ut->pgid = (int)(ut->tid ? ut->tid : 1);
        if (ut->attached_tty >= 0) {
            devfs_set_tty_fg_pgrp(ut->attached_tty, ut->pgid);
        }
        syscall_bind_kstack_for_thread(ut);
        /* Now make the new user thread runnable. */
        thread_unblock((int)ut->tid);
        /* schedule immediately; when caller resumes, the program has terminated */
        thread_schedule();
        return 0;
    }

    /* Debug: print argv/env passed to execve for user debugging (qemu debug) */
    if (argv) {
        int i = 0;
        qemu_debug_printf("execve: launching %s argv:", path);
        while (argv[i]) {
            qemu_debug_printf(" \"%s\"", argv[i]);
            i++;
            if (i > 16) break;
        }
        qemu_debug_printf("\n");
    }
    if (envp) {
        int i = 0;
        qemu_debug_printf("execve: envp first entries:");
        while (envp[i]) {
            qemu_debug_printf(" %s", envp[i]);
            i++;
            if (i > 8) break;
        }
        qemu_debug_printf("\n");
    }


    if ((uintptr_t)entry >= (uintptr_t)MMIO_IDENTITY_LIMIT || (uintptr_t)final_stack >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: entry or stack outside identity-mapped region, abort\n");
        return -1;
    }

    /* try to read first byte of entry */
    volatile uint8_t *entry_b = (volatile uint8_t*)(uintptr_t)entry;
    uint8_t first = 0;
    /* wrap read in a benign check */
    first = entry_b[0];

    {
        thread_t *tc = thread_current();
        if (tc) {
            process_sync_from_thread(tc->process, tc);
            process_exec_reset(tc->process, tc);
        }
    }

    /* Diagnostic: dump a few bytes at the entry and physical mapping to help debug PFs */
    if ((uintptr_t)entry < (uintptr_t)MMIO_IDENTITY_LIMIT) {
        uint64_t phys = virt_to_phys(entry);
        qemu_debug_printf("execve: DEBUG entry=0x%llx virt_phys=0x%llx final_stack=0x%llx\n",
                          (unsigned long long)entry, (unsigned long long)phys, (unsigned long long)final_stack);
        unsigned char dbuf[32];
        for (int i = 0; i < (int)sizeof(dbuf); i++) {
            dbuf[i] = *((unsigned char*)(uintptr_t)(entry + i));
        }
        qemu_debug_printf("execve: entry_bytes:");
        for (int i = 0; i < (int)sizeof(dbuf); i++) qemu_debug_printf("%02x", (unsigned int)dbuf[i]);
        qemu_debug_printf("\n");
    } else {
        qemu_debug_printf("execve: DEBUG entry outside identity map: 0x%llx\n", (unsigned long long)entry);
    }

    /* Transfer to user mode (does not return on success). */
    {
        thread_t *tc = thread_current();
        if (!tc)
            tc = thread_get_current_user();
        if (tc) {
            if (tc->exec_discard_template) {
                mm_release(tc->exec_discard_template);
                tc->exec_discard_template = NULL;
            }
            if (tc->mm_ptemplate) {
                mm_release(tc->mm_ptemplate);
                tc->mm_ptemplate = NULL;
            }
            /*
             * Finish exec_mmap: tip/ELF are installed on the active new mm.
             * Now complete_vfork_done + mmput(old). Parent was kept frozen
             * through tip publish (unlike waking at activate time).
             */
            if (tc->mm)
                mm_switch(tc->mm);
            if (tc->exec_discard_mm) {
                mm_t *dead = tc->exec_discard_mm;
                tc->exec_discard_mm = NULL;
                mm_dbg_ash_watch("exec-mmap-before-mmput-old", dead);
                mm_release(dead);
            }
            process_release_vfork_parent(tc->process, PROCESS_VFORK_EXEC_COMMIT);
            if (tc->user_fs_base)
                set_user_fs_base(tc->user_fs_base);
        }
    }
    enter_user_mode(entry, final_stack);
    return 0; /* not reached */
}


