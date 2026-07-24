#include <idt.h>
#include <axonos.h>
#include <vga.h>
#include <pic.h>
#include <thread.h>
#include <rtc.h>
//#include <pit.h>
#include <stdint.h>
//#include <thread.h>
#include <stdint.h>
#include <stddef.h>
#include <apic_timer.h>
#include <apic.h>
#include <debug.h>
#include <mmio.h>
#include <klog.h>
#include <syscall.h>
#include <paging.h>
#include <mm.h>
#include <frame.h>
#include <user_map.h>
#include <exec.h>
#include <vsyscall.h>
#include <keyboard.h>
#include <serial.h>
#include <string.h>
// Avoid including <cstdint> because cross-toolchain headers may not provide it; use uint64_t instead

// Forward declare C-linkage helpers from other compilation units
uint64_t dbg_saved_rbx_in;
uint64_t dbg_saved_rbx_out;
extern int syscall_pipe_watch_active;

// локальные таблицы обработчиков (неиспользуемые предупреждения устраним использованием ниже)
static void (*irq_handlers[16])() = {NULL};
static void (*isr_handlers[256])(cpu_registers_t*) = {NULL};

static struct idt_entry_t idt[256];
static struct idt_ptr_t idt_ptr;
// сообщения об исключениях — определение для внешней декларации из idt.h
const char* exception_messages[] = {
        "Division By Zero","Debug","Non Maskable Interrupt","Breakpoint","Into Detected Overflow",
        "Out of Bounds","Invalid Opcode","No Coprocessor","Double fault","Coprocessor Segment Overrun",
        "Bad TSS","Segment not present","Stack fault","General protection fault","Page fault",
        "Unknown Interrupt","Coprocessor Fault","Alignment Fault","Machine Check",
        "Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved",
        "Reserved","Reserved","Reserved","Reserved","Reserved"
};

static inline void read_crs(uint64_t* cr0, uint64_t* cr2, uint64_t* cr3, uint64_t* cr4){
        uint64_t t0=0,t2=0,t3=0,t4=0; (void)t0; (void)t2; (void)t3; (void)t4;
        asm volatile("mov %%cr0, %0" : "=r"(t0));
        asm volatile("mov %%cr2, %0" : "=r"(t2));
        asm volatile("mov %%cr3, %0" : "=r"(t3));
        asm volatile("mov %%cr4, %0" : "=r"(t4));
        if (cr0) *cr0 = t0; if (cr2) *cr2 = t2; if (cr3) *cr3 = t3; if (cr4) *cr4 = t4;
}

static void dump(const char* what, const char* who, cpu_registers_t* regs, uint64_t cr2, uint64_t err, bool user_mode){
        klogprintf("Oops! %s in %s at RIP=0x%llx err=0x%llx\n", what, who, (unsigned long long)regs->rip, (unsigned long long)regs->error_code);
        klogprintf("RIP: 0x%llx\n", (unsigned long long)regs->rip);
        klogprintf("RSP: 0x%llx\n", (unsigned long long)regs->rsp);
        klogprintf("RBP: 0x%llx\n", (unsigned long long)regs->rbp);
        klogprintf("RDI: 0x%llx\n", (unsigned long long)regs->rdi);
        klogprintf("RSI: 0x%llx\n", (unsigned long long)regs->rsi);
        klogprintf("RDX: 0x%llx\n", (unsigned long long)regs->rdx);
        klogprintf("RCX: 0x%llx\n", (unsigned long long)regs->rcx);

        /* Mirror the most important fault info to serial (qemu -serial stdio),
           otherwise user-mode faults printed to VGA are not visible in terminal logs. */
        qemu_debug_printf("Oops! %s in %s RIP=0x%llx err=0x%llx user=%d cr2=0x%llx\n",
                          what, who,
                          (unsigned long long)regs->rip,
                          (unsigned long long)regs->error_code,
                          user_mode ? 1 : 0,
                          (unsigned long long)cr2);
        qemu_debug_printf(" regs: RSP=0x%llx RBP=0x%llx RDI=0x%llx RSI=0x%llx RDX=0x%llx RCX=0x%llx RAX=0x%llx\n",
                          (unsigned long long)regs->rsp,
                          (unsigned long long)regs->rbp,
                          (unsigned long long)regs->rdi,
                          (unsigned long long)regs->rsi,
                          (unsigned long long)regs->rdx,
                          (unsigned long long)regs->rcx,
                          (unsigned long long)regs->rax);
}

static inline uint64_t rdmsr_u64(uint32_t msr) {
        uint32_t lo=0, hi=0;
        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
        return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr_u64(uint32_t msr, uint64_t v) {
        uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
        uint32_t hi = (uint32_t)(v >> 32);
        asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static void ud_fault_handler(cpu_registers_t* regs) {
        /* Invalid Opcode (#UD).
           В ring3 перехватываем FSGSBASE инструкции (RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE),
           которые libc может использовать при наличии CPUID.FSGSBASE. Мы держим CR4.FSGSBASE
           выключенным ради совместимости (см. cpu/gdt.c), поэтому эти опкоды попадают сюда. */
        if ((regs->cs & 3) == 3) {
                const uint8_t *ip = (const uint8_t*)(uintptr_t)regs->rip;
                /* Encoding: F3 0F AE /r with reg field:
                   /0 RDFSBASE, /1 RDGSBASE, /2 WRFSBASE, /3 WRGSBASE */
                /* Match F3 0F AE /r sequence possibly preceded by optional REX prefix(es).
                   Some libc implementations emit a REX prefix before the F3 byte (e.g. 0x48 F3 0F AE ...).
                   Scan a few bytes for the canonical F3 0F AE pattern and emulate when found. */
                int found_off = -1;
                for (int off = 0; off <= 3; off++) {
                        if ((uintptr_t)ip + off + 3 < (uintptr_t)MMIO_IDENTITY_LIMIT &&
                            ip[off] == 0xF3 && ip[off + 1] == 0x0F && ip[off + 2] == 0xAE) {
                                found_off = off;
                                break;
                        }
                }
                if (found_off >= 0) {
                        uint8_t modrm = ip[found_off + 3];
                        uint8_t mod = (modrm >> 6) & 3;
                        uint8_t reg = (modrm >> 3) & 7;
                        uint8_t rm  = (modrm >> 0) & 7;
                        if (mod == 3 && reg <= 3) {
                                /* helpers to access GPR by index (rm) */
                                uint64_t *gpr = NULL;
                                switch (rm) {
                                        case 0: gpr = &regs->rax; break;
                                        case 1: gpr = &regs->rcx; break;
                                        case 2: gpr = &regs->rdx; break;
                                        case 3: gpr = &regs->rbx; break;
                                        case 4: gpr = &regs->rsp; break;
                                        case 5: gpr = &regs->rbp; break;
                                        case 6: gpr = &regs->rsi; break;
                                        case 7: gpr = &regs->rdi; break;
                                }

                                enum { MSR_FS_BASE = 0xC0000100u, MSR_GS_BASE = 0xC0000101u };

                                if (reg == 0 /* RDFSBASE */) {
                                        if (gpr) *gpr = rdmsr_u64(MSR_FS_BASE);
                                        regs->rip += (uint64_t)(found_off + 4);
                                        return;
                                } else if (reg == 1 /* RDGSBASE */) {
                                        if (gpr) *gpr = rdmsr_u64(MSR_GS_BASE);
                                        regs->rip += (uint64_t)(found_off + 4);
                                        return;
                                } else if (reg == 2 /* WRFSBASE */) {
                                        uint64_t new_fs = gpr ? *gpr : 0;
                                        /* keep stack canary stable across FS changes: copy old fs:0x28 into new fs:0x28 */
                                        uint64_t old_fs = rdmsr_u64(MSR_FS_BASE);
                                        uint64_t old_guard = 0;
                                        if (old_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) old_guard = *(volatile uint64_t*)(uintptr_t)(old_fs + 0x28);
                                        else if (0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) old_guard = *(volatile uint64_t*)(uintptr_t)0x28;
                                        wrmsr_u64(MSR_FS_BASE, new_fs);
                                        if (new_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) *(volatile uint64_t*)(uintptr_t)(new_fs + 0x28) = old_guard;
                                        regs->rip += (uint64_t)(found_off + 4);
                                        return;
                                } else if (reg == 3 /* WRGSBASE */) {
                                        uint64_t new_gs = gpr ? *gpr : 0;
                                        wrmsr_u64(MSR_GS_BASE, new_gs);
                                        regs->rip += (uint64_t)(found_off + 4);
                                        return;
                                }
                        }
                }

                dump("invalid opcode", "user", regs, 0, 0, true);
                /* Dump nearby code bytes to help diagnose user UD */
                {
                    uintptr_t rip = (uintptr_t)regs->rip;
                    const int BYTES = 32;
                    uintptr_t start = rip > BYTES ? rip - BYTES : rip;
                    if (start + BYTES*2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        klogprintf("user code dump around RIP=0x%llx:\n", (unsigned long long)rip);
                        const unsigned char *p = (const unsigned char*)(uintptr_t)start;
                        for (int i = 0; i < BYTES*2; i++) {
                            kprintf("%02x ", (unsigned int)p[i]);
                            if ((i & 0xF) == 0xF) kprintf("\n");
                        }
                        klogprintf("\n");
                    } else {
                        klogprintf("user code dump skipped (out of identity range)\n");
                    }
                }
                /* SIGILL — do not hang the CPU (was sti;hlt forever). */
                syscall_user_fatal_exit(4);
                return;
        }
        // Иначе — ядро: печатаем и стоп
        dump("invalid opcode", "kernel", regs, 0, 0, false);
        /* Dump nearby kernel code bytes and kernel syscall stack top to diagnose why UD happened */
        {
            uintptr_t rip = (uintptr_t)regs->rip;
            const int BYTES = 32;
            uintptr_t start = rip > BYTES ? rip - BYTES : rip;
            if (start + BYTES*2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                qemu_debug_printf("kernel code dump around RIP=0x%llx:\n", (unsigned long long)rip);
                const unsigned char *p = (const unsigned char*)(uintptr_t)start;
                for (int i = 0; i < BYTES*2; i++) {
                        qemu_debug_printf("%02x ", (unsigned int)p[i]);
                    if ((i & 0xF) == 0xF) klogprintf("\n");
                }
                qemu_debug_printf("\n");
            } else {
                qemu_debug_printf("kernel code dump skipped (out of identity range)\n");
            }
        }
        {
            extern uint64_t syscall_kernel_rsp0;
            if ((uintptr_t)syscall_kernel_rsp0 != 0 && (uintptr_t)syscall_kernel_rsp0 + 8*16 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                qemu_debug_printf("syscall_kernel_rsp0=0x%llx\n", (unsigned long long)syscall_kernel_rsp0);
                uint64_t *stk = (uint64_t*)(uintptr_t)syscall_kernel_rsp0;
                qemu_debug_printf("kernel syscall stack top qwords:\n");
                for (int i = 0; i < 16; i++) {
                        qemu_debug_printf("[%2d] 0x%016llx\n", i, (unsigned long long)stk[i]);
                }
                qemu_debug_printf("saved RIP slot (offset +104) = 0x%016llx\n", (unsigned long long)stk[13]);
            } else {
                qemu_debug_printf("syscall_kernel_rsp0 not set or out of range\n");
            }
        }
        char choice;
        for (;;) {
            kprint("Reboot? [Y/N]: ");
            choice = kgetc();
            if (choice == 'Y' | choice == 'y') reboot_system(); 
            if (choice == 'N' | choice == 'n') break;
        }        
        kprint("Halt.");
        for(;;){ asm volatile("sti; hlt":::"memory"); }
}

static void debug_fault_handler(cpu_registers_t *regs) {
        /* Temporary single-step probe for the glibc _Fork child return path. */
        regs->rflags &= ~0x100ULL;
        if ((regs->cs & 3) == 3 && syscall_pipe_watch_active) {
                static int steps_left = 12;
                if (steps_left > 0) {
                        steps_left--;
                        devel_printf("user-step: rip=0x%llx rsp=0x%llx rax=0x%llx "
                                "rdx=0x%llx rflags=0x%llx\n",
                                (unsigned long long)regs->rip,
                                (unsigned long long)regs->rsp,
                                (unsigned long long)regs->rax,
                                (unsigned long long)regs->rdx,
                                (unsigned long long)regs->rflags);
                        if (steps_left > 0)
                                regs->rflags |= 0x100ULL;
                }
        }
}

// Handle Divide-by-zero (INT 0). For user faults: kill process and return to idle;
// for kernel faults: print diagnostics and halt.
static void div_zero_handler(cpu_registers_t* regs) {
        qemu_debug_printf("[div0] divide by zero at RIP=0x%llx err=0x%llx\n", (unsigned long long)regs->rip, (unsigned long long)regs->error_code);
        // If fault originated from user mode, terminate the user process safely
        if ((regs->cs & 3) == 3) {
                dump("divide by zero", "user", regs, 0, regs->error_code, true);
                // leave CPU in idle loop to avoid returning into faulty user code
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
        // Kernel fault: print and halt
        dump("divide by zero", "kernel", regs, 0, regs->error_code, false);
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static int fault_try_user_stack_page(uint64_t cr2, uint64_t err) {
        thread_t *t = thread_current();
        if (!t || t->ring != 3) {
                t = thread_get_current_user();
                if (!t) return 0;
        }
        uintptr_t a = (uintptr_t)cr2;
        if (a < 0x200000u || a >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                return 0;
        if (t->user_stack_base == 0 || t->user_stack_limit <= t->user_stack_base)
                return 0;
        /* Include TLS slot immediately below the stack. */
        uintptr_t lo = (uintptr_t)t->user_stack_base;
        if (lo > (uintptr_t)USER_TLS_SIZE)
                lo -= (uintptr_t)USER_TLS_SIZE;
        /* Allow a wide overrun past stack_limit for AVX/SIMD copies. */
        uintptr_t hi = (uintptr_t)t->user_stack_limit + (64ULL * (uintptr_t)PAGE_SIZE_2M);
        if (hi > (uintptr_t)MMIO_IDENTITY_LIMIT)
                hi = (uintptr_t)MMIO_IDENTITY_LIMIT;
        if (a < lo || a >= hi)
                return 0;
        /* Present write-protect: fork Soft_COW — not stack growth. */
        if ((err & 1u) && (err & 2u))
                return 0;
        if (!t->mm)
                return 0;
        /*
         * Linux MAP_GROWSDOWN / demand-zero: install a private zero page.
         * Never identity-map into the kernel heap arena.
         */
        uint64_t page = (uint64_t)a & ~0xFFFULL;
        mm_t *share = t->mm_ptemplate ? t->mm_ptemplate : mm_kernel();
        if (mm_make_private_range_noyield(t->mm, page, page + 0x1000ULL, 0, share) != 0)
                return 0;
        return 1;
}

/* Identity-map pages often start supervisor-only. User touch of present U=0
 * in the low identity window is fixed by setting PG_US.
 * Ceiling is well past USER_STACK_TOP: AVX copies have hit TOP, TOP+2MiB
 * (0x40200000), and will keep walking upward. */
static int fault_try_user_identity_us(uint64_t cr2, uint64_t err) {
        if ((err & 1u) == 0)
                return 0; /* not present — different path */
        if (err & 0x10u)
                return 0; /* instruction fetch — do not widen NX/identity blindly */
        uintptr_t a = (uintptr_t)cr2;
        /* Soft-fix U=0 for any user data access in the low identity window.
         * Previous fixed ceilings (TOP, TOP+2MiB, TOP+128MiB) were exactly hit
         * by AVX overruns (CR2=0x40000000/0x40200000/0x48000000). */
        if (a < 0x200000u || a >= 0x80000000ULL)
                return 0;
        if (a >= (uintptr_t)MMIO_IDENTITY_LIMIT)
                return 0;
        /* Present + user-mode access (err bit2). Ignore pure write-protect COW. */
        if ((err & 4u) == 0)
                return 0;
        if (err & 2u)
                return 0; /* write to present: may be COW */
        /*
         * Private mm: stamping PG_US on a live identity leaf keeps sharing phys
         * with the vfork parent. Copy-privatize the fault page first (preserve
         * content — never blank; that is do_brk_flags only).
         */
        {
                thread_t *t = thread_current();
                if (!t || t->ring != 3)
                        t = thread_get_current_user();
                mm_t *k = mm_kernel();
                if (t && t->mm && k && t->mm->pml4 && k->pml4 &&
                    t->mm->pml4 != k->pml4) {
                        uint64_t lo = (uint64_t)a & ~0xFFFULL;
                        if (mm_privatize_identity_range(t->mm, lo, lo + 0x1000ULL) != 0)
                                return 0;
                        return 1;
                }
        }
        uintptr_t page = a & ~((uintptr_t)PAGE_SIZE_2M - 1);
        if (user_map_mark_identity_2m((uint64_t)page, (uint64_t)(page + PAGE_SIZE_2M)) != 0)
                return 0;
        return 1;
}

static int fault_try_fix_ldso_kernel_phdr(cpu_registers_t *regs, uint64_t cr2) {
        if (!regs) return 0;
        if (regs->rip < 0x02007000ULL || regs->rip >= 0x02007800ULL)
                return 0;
        uint64_t lm_addr = regs->r13;
        if (lm_addr < 0x200000ULL || lm_addr + 0x340ULL >= (uint64_t)MMIO_IDENTITY_LIMIT)
                return 0;
        uint64_t *lm = (uint64_t *)(uintptr_t)lm_addr;
        uint64_t l_addr = lm[0];
        uint64_t *phdr_slot = (uint64_t *)(uintptr_t)(lm_addr + 0x2c0ULL);
        uint16_t *phnum_slot = (uint16_t *)(uintptr_t)(lm_addr + 0x2d0ULL);
        uint64_t old_phdr = *phdr_slot;
        uint16_t phnum = *phnum_slot;
        if (l_addr < 0x200000ULL || l_addr + 0x1000ULL >= (uint64_t)MMIO_IDENTITY_LIMIT)
                return 0;
        if (old_phdr >= (uint64_t)MMIO_IDENTITY_LIMIT)
                return 0;

        uint64_t fixed_phdr = l_addr + 0x40ULL; /* ELF64 e_phoff is normally 0x40 for glibc DSOs. */
        uint16_t e_phnum = phnum;
        const unsigned char *eh = (const unsigned char *)(uintptr_t)l_addr;
        if (eh[0] == 0x7f && eh[1] == 'E' && eh[2] == 'L' && eh[3] == 'F') {
                uint64_t e_phoff = *(const uint64_t *)(uintptr_t)(l_addr + 0x20ULL);
                uint16_t e_phentsize = *(const uint16_t *)(uintptr_t)(l_addr + 0x36ULL);
                uint16_t hdr_phnum = *(const uint16_t *)(uintptr_t)(l_addr + 0x38ULL);
                if (e_phoff != 0 && e_phoff <= 0x10000ULL && e_phentsize == 56 && hdr_phnum != 0) {
                        fixed_phdr = l_addr + e_phoff;
                        e_phnum = hdr_phnum;
                }
        }
        if (e_phnum == 0 || e_phnum > 64)
                e_phnum = 16;
        if (phnum == 0 || phnum > e_phnum)
                phnum = e_phnum;
        if (fixed_phdr + (uint64_t)phnum * 56ULL >= (uint64_t)MMIO_IDENTITY_LIMIT)
                return 0;
        *phdr_slot = fixed_phdr;
        *phnum_slot = phnum;
        if (regs->rbx >= old_phdr && regs->rbx <= old_phdr + (uint64_t)e_phnum * 56ULL)
                regs->rbx = fixed_phdr + (regs->rbx - old_phdr);
        klogprintf("ldso-phdr-fix: lm=0x%llx l_addr=0x%llx old=0x%llx new=0x%llx phnum=%u cr2=0x%llx\n",
                (unsigned long long)lm_addr,
                (unsigned long long)l_addr,
                (unsigned long long)old_phdr,
                (unsigned long long)fixed_phdr,
                (unsigned)phnum,
                (unsigned long long)cr2);
        return 1;
}

static void page_fault_handler(cpu_registers_t* regs) {
        uint64_t cr2;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        int user = (regs->cs & 3) == 3;
        if (user && syscall_pipe_watch_active) {
                static int pf_all_left = 24;
                if (pf_all_left-- > 0)
                        devel_printf("user-pf-any: tid=%d va=0x%llx rip=0x%llx err=0x%llx cr3=0x%llx\n",
                                thread_current() ? (int)(thread_current()->tid
                                    ? thread_current()->tid : 1) : -1,
                                (unsigned long long)cr2,
                                (unsigned long long)regs->rip,
                                (unsigned long long)regs->error_code,
                                (unsigned long long)paging_read_cr3());
        }
        if (user && (regs->error_code & 0x10u) && vsyscall_try_emulate(regs))
                return;
        if (user && (regs->error_code & 1u) && fault_try_fix_ldso_kernel_phdr(regs, cr2))
                return;
        if (user && fault_try_user_stack_page(cr2, regs->error_code))
                return;
        if (user && fault_try_user_identity_us(cr2, regs->error_code))
                return;
        /* fork COW / do_wp_page: present write-protect before any demand-fill. */
        if (user && (regs->error_code & 0x7u) == 0x7u) {
                extern thread_t *thread_current(void);
                extern thread_t *thread_get_current_user(void);
                thread_t *ut = thread_current();
                if (!ut || ut->ring != 3) ut = thread_get_current_user();
                if (ut && ut->mm && ut->mm != mm_kernel()) {
                        mm_t *share = ut->mm_ptemplate ? ut->mm_ptemplate : mm_kernel();
                        if (syscall_pipe_watch_active) {
                                static int cow_enter_left = 16;
                                if (cow_enter_left-- > 0)
                                        devel_printf("cow-enter: tid=%llu va=0x%llx rip=0x%llx cr3=0x%llx tmpl=%d\n",
                                                (unsigned long long)(ut->tid ? ut->tid : 1),
                                                (unsigned long long)cr2,
                                                (unsigned long long)regs->rip,
                                                (unsigned long long)paging_read_cr3(),
                                                ut->mm_ptemplate ? 1 : 0);
                        }
                        int cow_rc = mm_cow_fault_page(ut->mm, cr2, share);
                        /* Detect silent infinite COW: same CR2 succeeding forever
                         * (bad PTE/CR3) freezes openrc after set_robust_list with
                         * no further syscall logs once the print budget is gone. */
                        {
                                static uint64_t storm_cr2;
                                static int storm_count;
                                static int storm_tid;
                                int tid = (int)(ut->tid ? ut->tid : 1);
                                if (cow_rc == 0 && (uint64_t)cr2 == storm_cr2 && tid == storm_tid)
                                        storm_count++;
                                else {
                                        storm_cr2 = (uint64_t)cr2;
                                        storm_tid = tid;
                                        storm_count = (cow_rc == 0) ? 1 : 0;
                                }
                                if (storm_count >= 8) {
                                        devel_printf("cow-storm: tid=%d name=%s va=0x%llx rip=0x%llx rc=%d n=%d — force private\n",
                                                tid,
                                                ut->name[0] ? ut->name : "?",
                                                (unsigned long long)cr2,
                                                (unsigned long long)regs->rip, cow_rc, storm_count);
                                        (void)mm_make_private_range_noyield(ut->mm, cr2 & ~0xFFFULL,
                                                (cr2 & ~0xFFFULL) + 0x1000ULL, 1, share);
                                        storm_count = 0;
                                        return;
                                }
                        }
                        {
                                static int boot_cow_left = 24;
                                if (boot_cow_left-- > 0)
                                        devel_printf("cow-fault: tid=%llu name=%s va=0x%llx rip=0x%llx rc=%d\n",
                                                (unsigned long long)(ut->tid ? ut->tid : 1),
                                                ut->name[0] ? ut->name : "?",
                                                (unsigned long long)cr2,
                                                (unsigned long long)regs->rip,
                                                cow_rc);
                        }
                        if (cow_rc == 0)
                                return;
                }
        }
        /* Demand-fill only for !present (after do_wp_page above). */
        if (user && (regs->error_code & 1u) == 0u && fault_try_mmap_lazy_anon(cr2))
                return;
        if (user && fault_try_user_vma_nonpresent(cr2, regs->error_code))
                return;
        if (user && fault_try_grow_user_heap(cr2)) return;
        if (user && cr2 >= 0x10000ULL && cr2 < 0x200000ULL) {
                if (map_page_2m(0, 0, PG_PRESENT | PG_RW | PG_US) == 0)
                        return;
        }
        /* Any other user fault: always visible (budget-limited). */
        if (user) {
                extern thread_t *thread_current(void);
                extern thread_t *thread_get_current_user(void);
                thread_t *ut = thread_current();
                if (!ut || ut->ring != 3) ut = thread_get_current_user();
                if (ut) {
                        static int boot_pf_left = 48;
                        if (boot_pf_left-- > 0)
                                devel_printf("user-pf: tid=%llu name=%s va=0x%llx rip=0x%llx err=0x%llx fs=0x%llx\n",
                                        (unsigned long long)(ut->tid ? ut->tid : 1),
                                        ut->name[0] ? ut->name : "?",
                                        (unsigned long long)cr2,
                                        (unsigned long long)regs->rip,
                                        (unsigned long long)regs->error_code,
                                        (unsigned long long)ut->user_fs_base);
                }
        }
        if (!user) {
            /*
             * Kernel uaccess store onto a fork-COW user page (e.g. rt_sigaction
             * writing oldact on the child's still-shared stack). Break COW and
             * retry the faulting instruction; aborting uaccess alone left openrc
             * wedged mid-sigaction after fork-eager-cow reported pages=0.
             */
            {
                extern thread_t *thread_current(void);
                extern thread_t *thread_get_current_user(void);
                thread_t *ut = thread_current();
                if (!ut || ut->ring != 3)
                    ut = thread_get_current_user();
                if (ut && ut->uaccess_active && ut->mm && ut->mm != mm_kernel() &&
                    (uintptr_t)cr2 >= ut->uaccess_begin &&
                    (uintptr_t)cr2 < ut->uaccess_end) {
                    static int kcow_retries;
                    mm_t *share = ut->mm_ptemplate ? ut->mm_ptemplate : mm_kernel();
                    if (mm_cow_fault_page(ut->mm, cr2, share) == 0) {
                        if (++kcow_retries < 16)
                            return;
                        kcow_retries = 0;
                        devel_printf("kcow-storm: tid=%llu va=0x%llx — abort uaccess\n",
                                (unsigned long long)(ut->tid ? ut->tid : 1),
                                (unsigned long long)cr2);
                    } else {
                        kcow_retries = 0;
                    }
                }
            }
            uint64_t resume_rip = 0;
            if (syscall_try_handle_uaccess_fault(cr2, &resume_rip)) {
                regs->rip = resume_rip;
                return;
            }
        }
        dump("page fault", user ? "user" : "kernel", regs, cr2, regs->error_code, user);
        /* If the fault happened inside libc memset/memmove, print caller return RIPs.
           We repeatedly see crashes at RIP=0x158c94 (payload memset byte-store). */
        if (!user) {
            uint64_t rip = regs->rip;
            /* Skip CR2-driven dumps when CR2 itself is non-identity — walking
             * frames after a bad pointer often nests another #PF (e.g. 0x100000000). */
            int want_bt = 0;
            if (rip >= 0x158c40ULL && rip < 0x159000ULL) want_bt = 1; /* libc/string area */
            if (want_bt) {
                uint64_t rbp = regs->rbp;
                klogprintf("pf: in libc/string area, rbp=0x%llx\n", (unsigned long long)rbp);
                qemu_debug_printf("pf: in libc/string area, rbp=0x%llx\n", (unsigned long long)rbp);

                for (int depth = 0; depth < 6; depth++) {
                    if (rbp == 0) break;
                    if (rbp < 0x1000ULL || rbp + 16 > (uint64_t)MMIO_IDENTITY_LIMIT) break;
                    uint64_t next_rbp = *(uint64_t*)(uintptr_t)(rbp + 0);
                    uint64_t ret_rip  = *(uint64_t*)(uintptr_t)(rbp + 8);
                    klogprintf("pf: bt[%d] rbp=0x%llx ret=0x%llx next_rbp=0x%llx\n",
                               depth,
                               (unsigned long long)rbp,
                               (unsigned long long)ret_rip,
                               (unsigned long long)next_rbp);
                    qemu_debug_printf("pf: bt[%d] rbp=0x%llx ret=0x%llx next_rbp=0x%llx\n",
                                      depth,
                                      (unsigned long long)rbp,
                                      (unsigned long long)ret_rip,
                                      (unsigned long long)next_rbp);
                    if (next_rbp <= rbp) break;
                    rbp = next_rbp;
                }
            }
        }
        // Read MSR_FS_BASE to help diagnose faults caused by missing TLS base
        uint64_t fsbase_lo = 0, fsbase_hi = 0;
        asm volatile("rdmsr" : "=a"(fsbase_lo), "=d"(fsbase_hi) : "c"(0xC0000100u));
        uint64_t fsbase = ((uint64_t)fsbase_hi << 32) | fsbase_lo;
        
        klogprintf("page fault MSR_FS_BASE=0x%016llx\n", (unsigned long long)fsbase);
        klogprintf("page fault details: CR2=0x%llx err=0x%llx user=%d\n", (unsigned long long)cr2, (unsigned long long)regs->error_code, user);

        qemu_debug_printf("page fault: MSR_FS_BASE=0x%016llx CR2=0x%llx err=0x%llx user=%d\n",
                          (unsigned long long)fsbase,
                          (unsigned long long)cr2,
                          (unsigned long long)regs->error_code,
                          user ? 1 : 0);
        /* Additional diagnostics to help pinpoint cause in user mode */
        if (user) {
            /* dump instruction bytes at RIP */
            if ((uintptr_t)regs->rip < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                const unsigned char *code = (const unsigned char*)(uintptr_t)regs->rip;
                klogprintf("code @ RIP: ");
                for (int i = 0; i < 32; i++) kprintf("%02x ", (unsigned)code[i]);
                kprintf("\n");
                qemu_debug_printf("code @ RIP:");
                for (int i = 0; i < 16; i++) qemu_debug_printf(" %02x", (unsigned)code[i]);
                qemu_debug_printf("\n");
            } else {
                klogprintf("code @ RIP: (outside identity map)\n");
                qemu_debug_printf("code @ RIP: (outside identity map)\n");
            }
            /* dump stack words */
            if ((uintptr_t)regs->rsp < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                const uint64_t *stk = (const uint64_t*)(uintptr_t)regs->rsp;
                klogprintf("stack @ RSP: ");
                for (int i = 0; i < 8; i++) kprintf("0x%016llx ", (unsigned long long)stk[i]);
                kprintf("\n");
            } else {
                klogprintf("stack @ RSP: (outside identity map)\n");
            }
            if (regs->rip >= 0x02007000ULL && regs->rip < 0x02007800ULL) {
                klogprintf("ldso-phdr-walk: rbx=0x%llx r13=0x%llx rax=0x%llx rdx=0x%llx\n",
                    (unsigned long long)regs->rbx,
                    (unsigned long long)regs->r13,
                    (unsigned long long)regs->rax,
                    (unsigned long long)regs->rdx);
                if (regs->r13 >= 0x200000ULL && regs->r13 + 0x2d8ULL < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    const uint64_t *lm = (const uint64_t *)(uintptr_t)regs->r13;
                    klogprintf("ldso-linkmap: l_addr=0x%llx l_name=0x%llx l_ld=0x%llx l_next=0x%llx l_prev=0x%llx\n",
                        (unsigned long long)lm[0],
                        (unsigned long long)lm[1],
                        (unsigned long long)lm[2],
                        (unsigned long long)lm[3],
                        (unsigned long long)lm[4]);
                    klogprintf("ldso-linkmap: phdr@+0x2c0=0x%llx phnum@+0x2d0=0x%llx flags@+0x338=0x%llx\n",
                        (unsigned long long)*(const uint64_t *)(uintptr_t)(regs->r13 + 0x2c0ULL),
                        (unsigned long long)*(const uint64_t *)(uintptr_t)(regs->r13 + 0x2d0ULL),
                        (unsigned long long)*(const uint64_t *)(uintptr_t)(regs->r13 + 0x338ULL));
                } else {
                    klogprintf("ldso-linkmap: r13 outside readable identity range\n");
                }
            }
            /* dump memory near CR2 if available; skip when page is non-present
               (err bit 0 = 0) to avoid a second page fault when reading CR2 */
            if ((regs->error_code & 1) != 0 && (uintptr_t)cr2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                klogprintf("bytes @ CR2: ");
                const unsigned char *p = (const unsigned char*)(uintptr_t)cr2;
                for (int i = 0; i < 32; i++) kprintf("%02x ", (unsigned)p[i]);
                kprintf("\n");
            } else if ((regs->error_code & 1) == 0) {
                klogprintf("bytes @ CR2: (page not present, skipping read)\n");
            } else {
                klogprintf("bytes @ CR2: (outside identity map)\n");
            }
            if (user && regs->rip >= 0x2200000ULL && regs->rip < 0x2300000ULL &&
                (uintptr_t)regs->rip < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                const unsigned char *code = (const unsigned char *)(uintptr_t)regs->rip;
                const unsigned char *base = (const unsigned char *)(uintptr_t)0x2220000ULL;
                klogprintf("libc-pf: rip=0x%llx rip_bytes=", (unsigned long long)regs->rip);
                for (int i = 0; i < 16; i++) kprintf("%02x ", (unsigned)code[i]);
                kprintf(" base@0x2220000=");
                for (int i = 0; i < 16; i++) kprintf("%02x ", (unsigned)base[i]);
                kprintf("\n");
            }
            /* dump page table entries for CR2 */
            {
                uint64_t v = (uint64_t)cr2;
                uint64_t cr3 = paging_read_cr3();
                klogprintf("ptes for CR2 (v=0x%llx): CR3=0x%llx\n", (unsigned long long)v, (unsigned long long)cr3);
                uint64_t *l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
                if (!l4) {
                    klogprintf("ptes for CR2: no active l4\n");
                    goto pte_dump_done;
                }
                int l4i = (v >> 39) & 0x1FF;
                int l3i = (v >> 30) & 0x1FF;
                int l2i = (v >> 21) & 0x1FF;
                int l1i = (v >> 12) & 0x1FF;
                klogprintf("ptes: l4[%d]=0x%016llx\n", l4i, (unsigned long long)l4[l4i]);
                if (l4[l4i] & PG_PRESENT) {
                    uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
                    klogprintf("ptes: l3[%d]=0x%016llx\n", l3i, (unsigned long long)l3[l3i]);
                    if (l3[l3i] & PG_PRESENT) {
                        uint64_t l3e = l3[l3i];
                        if (l3e & PG_PS_2M) {
                            klogprintf("ptes: 1GiB/2MiB large at L3\n");
                        } else {
                            uint64_t l2_phys = l3e & ~0xFFFULL;
                            uint64_t *l2 = (uint64_t*)(uintptr_t)l2_phys;
                            uint64_t l2e = l2[l2i];
                            klogprintf("ptes: l2_phys=0x%llx l2[%d]=0x%016llx P=%d U=%d\n",
                                (unsigned long long)l2_phys, l2i, (unsigned long long)l2e,
                                (int)(!!(l2e & 1)), (int)(!!(l2e & 4)));
                            if (l2e & PG_PRESENT) {
                                if (l2e & PG_PS_2M) {
                                    klogprintf("ptes: 2MiB large at L2\n");
                                } else {
                                    uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
                                    klogprintf("ptes: l1[%d]=0x%016llx\n", l1i, (unsigned long long)l1[l1i]);
                                }
                            }
                        }
                    }
                }
            }
pte_dump_done:
            /* show syscall_kernel_rsp0 if set */
            {
                extern uint64_t syscall_kernel_rsp0;
                if ((uintptr_t)syscall_kernel_rsp0 != 0 && (uintptr_t)syscall_kernel_rsp0 + 8*16 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    klogprintf("syscall_kernel_rsp0=0x%llx\n", (unsigned long long)syscall_kernel_rsp0);
                } else {
                    klogprintf("syscall_kernel_rsp0 not set or out of range\n");
                }
            }
            /* User faults must not freeze the whole CPU — that masked the
             * post-getpid hang as a silent lockup with a blinking cursor. */
            kprintf("user-pf-fatal: killing after unhandled #PF rip=0x%llx cr2=0x%llx err=0x%llx\n",
                    (unsigned long long)regs->rip,
                    (unsigned long long)cr2,
                    (unsigned long long)regs->error_code);
            if (regs->rip == 0 && regs->rsp >= 0x200000ULL &&
                regs->rsp + 16ULL < (uint64_t)MMIO_IDENTITY_LIMIT) {
                uint64_t *sp = (uint64_t *)(uintptr_t)regs->rsp;
                kprintf("user-pf-null-rip: rsp=0x%llx [0]=0x%llx [1]=0x%llx rbp=0x%llx rdi=0x%llx\n",
                        (unsigned long long)regs->rsp,
                        (unsigned long long)sp[0],
                        (unsigned long long)sp[1],
                        (unsigned long long)regs->rbp,
                        (unsigned long long)regs->rdi);
            }
            syscall_user_fatal_exit(11);
            return;
        }
        for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

static void gp_fault_handler(cpu_registers_t* regs){
    if ((regs->cs & 3) == 3) {
        // ash GPF @ 0x801738 ("ls"): dump leaf state for the watch VA.
        if (regs->rip >= MM_ASH_WATCH_LO && regs->rip < MM_ASH_WATCH_HI) {
            thread_t *gt = thread_current();
            if (!gt || gt->ring != 3)
                gt = thread_get_current_user();
            mm_dbg_ash_watch_thread("GPF-ash-rip", gt);
        }
        syscall_user_fatal_exit(11); /* SIGSEGV */
    }
    (void)regs;
    for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static void apic_ipi_resched_handler(cpu_registers_t *regs) {
        (void)regs;
        /* Wake target CPU from hlt; scheduler runs in thread context, not here. */
        apic_eoi();
}

static void df_fault_handler(cpu_registers_t* regs){
        // Double Fault (#DF) — используем отдельный IST стек, чтобы избежать triple fault
        klogprintf("DOUBLE FAULT\n");
        dump("double fault", "kernel", regs, 0, regs->error_code, false);
        // Застываем в безопасной петле с включёнными прерываниями
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

void isr_dispatch(cpu_registers_t* regs) {
        uint8_t vec = (uint8_t)regs->interrupt_number;

        // Если пришёл IRQ1 (клавиатура) — гарантируем EOI даже при отсутствии обработчика
        if (vec == 33) {
                if (isr_handlers[vec]) {
                        isr_handlers[vec](regs);
                }
                pic_send_eoi(1);
        } else if (vec >= 32 && vec <= 47) {
                // IRQ 32..47: EOI required
                if (isr_handlers[vec]) {
                        isr_handlers[vec](regs);
                } else {
                        qemu_debug_printf("Unhandled IRQ %d\n", vec - 32);
                }
                pic_send_eoi(vec - 32);
        } else if (isr_handlers[vec]) {
                // Any other vector: call registered handler if present (e.g., int 0x80, APIC)
                isr_handlers[vec](regs);
        } else if (vec < 32) {
                // Exceptions 0..31 without specific handler: print and halt
                for (;;);
        } else {
                // Unknown vector
                qemu_debug_printf("Unknown interrupt %d (0x%x)\n", vec, vec);
                qemu_debug_printf("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
                for (;;);
        }

        /* Deliver pending signals on return to ring3 from IRQ/IPI/int0x80.
         * Skip CPU exceptions (0..31): #PF fatal paths can still fall through
         * with a dead user frame (rip=0) and must not try to build a sigframe. */
        if (regs && (regs->cs & 3) == 3 && vec >= 32)
                (void)maybe_deliver_pending_signal_iretq(regs);
}

void idt_set_gate(uint8_t num, uint64_t handler, uint16_t selector, uint8_t flags) {
        idt[num].offset_low = handler & 0xFFFF;
        idt[num].offset_mid = (handler >> 16) & 0xFFFF;
        idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
        idt[num].selector = selector;
        idt[num].ist = 0;
        idt[num].flags = flags;
        idt[num].reserved = 0;
}

void idt_set_handler(uint8_t num, void (*handler)(cpu_registers_t*)) {
        isr_handlers[num] = handler;
}

void idt_init() {
        idt_ptr.limit = sizeof(idt) - 1;
        idt_ptr.base = (uint64_t)&idt;
        
        for (int i = 0; i < 256; i++) {
                idt_set_gate(i, isr_stub_table[i], 0x08, 0x8E);
        }
        
        // Register detailed page fault handler
        idt_set_handler(14, page_fault_handler);
        // Register divide-by-zero handler (#0)
        idt_set_handler(0, div_zero_handler);
        idt_set_handler(1, debug_fault_handler);
        // Register UD handler (#6)
        idt_set_handler(6, ud_fault_handler);
        // Register GP fault handler (#13)
        idt_set_handler(13, gp_fault_handler);
        // Register DF handler (#8) and put it on IST1
        idt_set_handler(8, df_fault_handler);
        // Пометим IST=1 у вектора 8
        idt[8].ist = 1;
        
        // Register RTC handler (IRQ 8 = vector 40)
        idt_set_handler(40, rtc_handler);

        idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);
        idt_set_handler(APIC_IPI_RESCHED_VECTOR, apic_ipi_resched_handler);

        asm volatile("lidt %0" : : "m"(idt_ptr));
}