/*
 * core/entry/kernel.c
 * Kernel entry point implementation
 * Author: fcexx
*/

#include <axonos.h>
#include <keyboard.h>
#include <mouse.h>
#include <stdint.h>
#include <stdio.h>
#include <gdt.h>
#include <string.h>
#include <vga.h>
#include <idt.h>
#include <pic.h>
#include <pit.h>
#include <rtc.h>
#include <heap.h>
#include <paging.h>
#include <sysinfo.h>
#include <thread.h>
#include <smp.h>
#include <apic.h>
#include <apic_timer.h>
#include <stat.h>
#include <syscall.h>
#include <iothread.h>
#include <fs.h>
#include <ext2.h>
#include <ramfs.h>
#include <sysfs.h>
#include <fbdev.h>
#include <procfs.h>
#include <initfs.h>
#include <bootparam.h>
#include <mb2_linux_shim.h>
#include <ramfs.h>
#include <fat32.h>
#include <intel_chipset.h>
#include <disk.h>
#include <mmio.h>
#include <pci.h>
#include <devfs.h>
#include <user.h>
#include <serial.h>
#include <usb.h>
#include <exec.h>
#include <klog.h>
#include <boot_logo.h>
#include <debug.h>
#include <font.h>
#include <vbe.h>
#include <cirrus.h>
#include <vmwgfx.h>
#include <vboxsvga.h>
#include <cirrusfb.h>
#include <acpi_powerbtn.h>
#include <nvme.h>
#include <e1000.h>
void ata_dma_init(void);
void scsi_init(void);
int pvscsi_init(void);

static char g_cwd[256] = "/";

extern uint8_t _end[]; /* kernel end symbol from linker */
extern const char nss_dns_so_blob_start[];
extern const char nss_dns_so_blob_end[];

/*
 * Debian glibc ≥2.36 ships hollow libnss_{files,dns}.so.2 (NEEDED libc.so.6,
 * no _nss_* exports). Static busybox __libc_dlopen of ANY such DSO then loads
 * shared libc.so.6 into a static process → fatal
 * ": error while loading shared libraries:".
 *
 * Policy for static early userspace (busybox mount/init):
 *   - remove multiarch NSS stubs entirely (ENOENT → static builtins)
 *   - do NOT install the dns shim under multiarch (it also NEEDs libc.so.6)
 *   - keep a nostdlib libnss_files stub + dns only under /lib/ for later
 */
extern const char nss_files_so_blob_start[];
extern const char nss_files_so_blob_end[];

static int ramfs_write_blob(const char *path, const void *blob, size_t len)
{
    if (!path || !blob || len == 0U)
        return -1;
    (void)fs_unlink(path);
    struct fs_file *lf = fs_create_file(path);
    if (!lf)
        lf = fs_open(path);
    if (!lf)
        return -1;
    fs_write(lf, blob, len, 0);
    fs_file_free(lf);
    return 0;
}

static void ramfs_install_libnss_dns(void)
{
    size_t dns_len = (size_t)(nss_dns_so_blob_end - nss_dns_so_blob_start);
    size_t files_len = (size_t)(nss_files_so_blob_end - nss_files_so_blob_start);
    int u_files, u_dns_ma;

    (void)ramfs_mkdir("/lib");
    (void)ramfs_mkdir("/lib/x86_64-linux-gnu");

    u_files = fs_unlink("/lib/x86_64-linux-gnu/libnss_files.so.2");
    u_dns_ma = fs_unlink("/lib/x86_64-linux-gnu/libnss_dns.so.2");
    (void)fs_unlink("/lib/libnss_files.so.2");
    (void)fs_unlink("/lib/libnss_dns.so.2");

    /*
     * Multiarch is what glibc searches first. Install ONLY the nostdlib
     * files stub there (no NEEDED). Never put the libc-linked dns shim there.
     */
    if (files_len)
        (void)ramfs_write_blob("/lib/x86_64-linux-gnu/libnss_files.so.2",
                               nss_files_so_blob_start, files_len);
    if (dns_len)
        (void)ramfs_write_blob("/lib/libnss_dns.so.2",
                               nss_dns_so_blob_start, dns_len);

    kprintf("nss-fix: unlink files=%d dns_ma=%d files_stub=%zu dns_lib=%zu\n",
            u_files, u_dns_ma, files_len, dns_len);
}

static inline uintptr_t align_up_uintptr(uintptr_t v, uintptr_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

ssize_t sysfs_show_const(char *buf, size_t size, void *priv) {
    if (!buf || size == 0) return 0;

    const char *text = (const char*)priv;
    if (!text) text = "";
    size_t len = strlen(text);
    if (len > size) len = size;
    memcpy(buf, text, len);
    if (len < size) buf[len++] = '\n';

    return (ssize_t)len;
}

ssize_t sysfs_show_cpu_name_attr(char *buf, size_t size, void *priv) {
    (void)priv;

    if (!buf || size == 0) return 0;
    const char *name = sysinfo_cpu_name();
    size_t len = strlen(name);
    if (len > size) len = size;
    memcpy(buf, name, len);
    if (len < size) buf[len++] = '\n';

    return (ssize_t)len;
}

static size_t sysfs_write_int(char *buf, size_t size, int value) {
    if (!buf || size == 0) return 0;

    char tmp[32];
    size_t n = 0;
    unsigned int v;
    int neg = 0;
    if (value < 0) { neg = 1; v = (unsigned int)(-value); }
    else v = (unsigned int)value;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    if (neg && n < sizeof(tmp)) tmp[n++] = '-';
    size_t written = 0;
    while (n && written < size) {
        buf[written++] = tmp[--n];
    }
    return written;
}

ssize_t sysfs_show_ram_mb_attr(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;

    int mb = sysinfo_ram_mb();
    if (mb < 0) {
        return sysfs_show_const(buf, size, (void*)"unknown");
    }
    
    size_t written = sysfs_write_int(buf, size, mb);
    if (written < size) buf[written++] = '\n';

    return (ssize_t)written;
}

/* Linux /sys/devices/system/cpu/{online,possible,present} — musl/glibc sysconf(_SC_NPROCESSORS_*)
 * and some tools read these before /proc/stat; a missing or wrong file yields nproc==1 despite /proc/cpuinfo. */
static ssize_t sysfs_show_cpu_range_list(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    int n = smp_cpu_count();
    if (n < 1)
        n = 1;
    if (n > SMP_MAX_CPUS)
        n = SMP_MAX_CPUS;
    int w = (n <= 1) ? snprintf(buf, size, "0\n") : snprintf(buf, size, "0-%d\n", n - 1);
    if (w < 0)
        return 0;
    if ((size_t)w > size)
        return (ssize_t)size;
    return (ssize_t)w;
}

/* Populate default sysfs tree when userspace mounts sysfs via SYS_mount. */
void kernel_sysfs_populate_default(void) {
    sysfs_mkdir("/sys/kernel");
    sysfs_mkdir("/sys/class");
    sysfs_mkdir("/sys/bus");
    sysfs_mkdir("/sys/devices/system/cpu");
    static const struct sysfs_attr attr_cpu = { sysfs_show_cpu_name_attr, NULL, NULL };
    static const struct sysfs_attr attr_ram = { sysfs_show_ram_mb_attr, NULL, NULL };
    static const struct sysfs_attr attr_cpu_range = { sysfs_show_cpu_range_list, NULL, NULL };
    sysfs_create_file("/sys/kernel/cpu_name", &attr_cpu);
    sysfs_create_file("/sys/kernel/ram_mb", &attr_ram);
    sysfs_create_file("/sys/devices/system/cpu/online", &attr_cpu_range);
    sysfs_create_file("/sys/devices/system/cpu/possible", &attr_cpu_range);
    sysfs_create_file("/sys/devices/system/cpu/present", &attr_cpu_range);
    {
        int nc = smp_cpu_count();
        if (nc < 1)
            nc = 1;
        if (nc > SMP_MAX_CPUS)
            nc = SMP_MAX_CPUS;
        for (int i = 0; i < nc; i++) {
            char path[80];
            snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d", i);
            sysfs_mkdir(path);
        }
    }
    usb_sysfs_populate_default();
    pci_sysfs_init();  /* /sys/bus/pci/devices для lspci */
    /* Video registers /dev/fb0 before /sys exists — publish graphics sysfs now. */
    fbdev_sysfs_publish_late();
    keyboard_publish_sysfs();
    mouse_publish_sysfs();
}

static int boot_try_run_init(void) {
    /* OpenRC-first when shipped; otherwise standard Linux init paths from initfs. */
    static const char *candidates[] = {
        "/sbin/init",
        "/linuxrc",
        "/bin/sh",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        const char *p = candidates[i];
        struct stat st;
        if (vfs_stat(p, &st) != 0) {
            klogprintf("boot: skip init %s (not found)\n", p);
            continue;
        }
        /* Accept regular files and symlinks (symlinks already resolved by exec). */
        if (!((st.st_mode & S_IFREG) == S_IFREG || (st.st_mode & S_IFLNK) == S_IFLNK)) continue;
        const char *argv0[3] = { p, NULL, NULL };
        if (strcmp(p, "/bin/sh") == 0) {
            argv0[1] = "-i";
        }
        static const char *init_env[] = {
            "HOME=/root",
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "SHELL=/bin/sh",
            "TERM=linux",
            "LC_ALL=C",
            "LANG=C",
            "USER=root",
            "PS1=\\[\\033[1;31m\\]\\u\\033[0m@\\h \\033[0;37m\\w\\033[0m\\$ ",
            NULL
        };
        if (strcmp(p, "/bin/sh") == 0) {
            thread_t *t = thread_current();
            if (t) {
                int tty = devfs_get_active();
                if (!t->fds[0] || !devfs_is_tty_file(t->fds[0])) {
                    struct fs_file *console = devfs_open_direct("/dev/console");
                    if (console) {
                        if (t->fds[0]) fs_file_free(t->fds[0]);
                        t->fds[0] = console;
                    }
                }
                if (!t->fds[1] && t->fds[0]) { t->fds[1] = t->fds[0]; t->fds[1]->refcount++; }
                if (!t->fds[2] && t->fds[0]) { t->fds[2] = t->fds[0]; t->fds[2]->refcount++; }
                t->attached_tty = tty;
                t->sid = (int)(t->tid ? t->tid : 1);
                t->pgid = (int)(t->tid ? t->tid : 1);
                devfs_set_tty_fg_pgrp(tty, t->pgid);
                if (t->fds[0] && devfs_is_tty_file(t->fds[0])) {
                    (void)devfs_set_tty_controlling_sid(t->fds[0], t->sid);
                    (void)devfs_tty_attach_thread(t->fds[0], t);
                }
                klogprintf("boot: fallback shell tty=%d sid=%d pgid=%d\n",
                    tty, t->sid, t->pgid);
            }
        }
        klogprintf("boot: trying init %s\n", p);
        {
            thread_t *bt = thread_current();
            if (bt)
                exec_boot_ensure_stdio(bt);
        }
        int rc = kernel_execve_init_from_path(p, argv0, init_env);
        if (rc == -3) {
            /* Transient exec layout race: one bounded retry for early boot init path. */
            rc = kernel_execve_init_from_path(p, argv0, init_env);
        }
        if (rc == 0) {
            klogprintf("boot: init %s exited, trying fallback\n", p);
            if (strcmp(p, "/bin/sh") == 0) {
                i--;
                klogprintf("boot: emergency shell exited; respawning /bin/sh -i\n");
                thread_sleep(500);
            }
            continue;
        }
        klogprintf("boot: init %s returned rc=%d\n", p, rc);

    }
    return -1;
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info) {
    qemu_debug_printf("Kernel started\n");
    enable_cursor();
    sysinfo_init(multiboot_magic, multiboot_info);

    /* Linux boot_params (zeropage): filled by real linux+initrd loaders, or synthesized
     * from Multiboot2 module2 by mb2_linux_shim (GRUB does not pass boot_params with multiboot2). */
    static __attribute__((aligned(4096))) uint8_t axon_synth_bootparams[LINUX_BOOTPARAM_MIN_SIZE];
    uint64_t axon_boot_params_phys = 0;
    if (multiboot_magic == 0x36d76289u && multiboot_info != 0) {
        if (mb2_linux_shim_fill_bootparams(multiboot_magic, multiboot_info, axon_synth_bootparams,
                                           sizeof axon_synth_bootparams, "initfs") == 0)
            axon_boot_params_phys = (uint64_t)(uintptr_t)axon_synth_bootparams;
    }

    /*
     * GRUB allocates very large Multiboot modules top-down. A ~550 MiB initfs
     * can then straddle PCI/VRAM apertures once firmware BAR decoding is
     * enabled (VMware failure observed at PA 0x917de830). Relocate it before
     * PCI/video initialization into ordinary low RAM. The ramfs intentionally
     * borrows regular-file data from this region, so it must remain reserved
     * for the lifetime of the system.
     *
     * Prefer PA above USER_STACK_TOP so the identity heap can sit after the
     * initrd. Never land on the Multiboot/GRUB linear framebuffer — gfxterm
     * kprintf would then paint glyphs into the cpio (classic "bad magic" a few
     * hundred bytes in). Linux keeps initrd in memblock-reserved RAM for the
     * same reason.
     */
    if (axon_boot_params_phys) {
        uintptr_t rd_start = 0;
        size_t rd_size = 0;
        if (linux_bootparams_ramdisk((const void *)(uintptr_t)axon_boot_params_phys,
                                     &rd_start, &rd_size) == 0) {
            uint64_t fb_lo = 0, fb_hi = 0;
            if (multiboot_magic == 0x36d76289u && multiboot_info != 0) {
                uint8_t *p = (uint8_t *)(uintptr_t)multiboot_info;
                uint32_t total_size = *(uint32_t *)p;
                if (total_size >= 16u && total_size <= (64u * 1024u * 1024u)) {
                    uint32_t off = 8;
                    while (off + 8u <= total_size) {
                        uint32_t tag_type = *(uint32_t *)(p + off);
                        uint32_t tag_size = *(uint32_t *)(p + off + 4);
                        if (tag_size < 8u) break;
                        if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
                        if (tag_type == 0u) break;
                        if (tag_type == 8u && tag_size >= 32u) {
                            uint64_t fb_addr = *(uint64_t *)(p + off + 8);
                            uint32_t pitch = *(uint32_t *)(p + off + 16);
                            uint32_t height = *(uint32_t *)(p + off + 24);
                            if (fb_addr && fb_addr != 0xB8000ULL && fb_addr != 0xB0000ULL &&
                                pitch && height) {
                                uint64_t fb_sz = (uint64_t)pitch * (uint64_t)height;
                                if (fb_sz > 0 && fb_addr + fb_sz > fb_addr) {
                                    fb_lo = fb_addr;
                                    fb_hi = fb_addr + fb_sz;
                                }
                            }
                            break;
                        }
                        off += (tag_size + 7u) & ~7u;
                    }
                }
            }

            uint64_t ram_bytes = (uint64_t)sysinfo_ram_mb() * 1024ULL * 1024ULL;
            const uintptr_t candidates[] = {
                (uintptr_t)0x42000000u,
                (uintptr_t)USER_STACK_TOP + (32u * 1024u * 1024u),
                (uintptr_t)0x48000000u,
                (uintptr_t)0x50000000u,
            };
            uintptr_t safe_start = 0;
            for (unsigned ci = 0; ci < sizeof(candidates) / sizeof(candidates[0]); ci++) {
                uintptr_t cand = candidates[ci];
                uintptr_t cand_end = 0;
                if (__builtin_add_overflow(cand, rd_size, &cand_end))
                    continue;
                if ((uint64_t)cand_end + (32ull * 1024ull * 1024ull) > ram_bytes)
                    continue;
                if (fb_hi > fb_lo) {
                    uint64_t a0 = (uint64_t)cand, a1 = (uint64_t)cand_end;
                    if (a0 < fb_hi && fb_lo < a1) {
                        /* Candidate overlaps GRUB FB — try just after the FB. */
                        uint64_t after = (fb_hi + 0x1fffffull) & ~0x1fffffull;
                        if (after < (uint64_t)USER_STACK_TOP + (16ull * 1024ull * 1024ull))
                            after = (uint64_t)USER_STACK_TOP + (32ull * 1024ull * 1024ull);
                        if (after > (uint64_t)(uintptr_t)-1)
                            continue;
                        cand = (uintptr_t)after;
                        if (__builtin_add_overflow(cand, rd_size, &cand_end))
                            continue;
                        if ((uint64_t)cand_end + (32ull * 1024ull * 1024ull) > ram_bytes)
                            continue;
                        a0 = (uint64_t)cand;
                        a1 = (uint64_t)cand_end;
                        if (a0 < fb_hi && fb_lo < a1)
                            continue;
                    }
                }
                if ((uintptr_t)rd_start == cand)
                    break; /* already safe */
                safe_start = cand;
                break;
            }
            if (safe_start && (uintptr_t)rd_start != safe_start) {
                memmove((void *)safe_start, (const void *)rd_start, rd_size);
                uint8_t *bp = (uint8_t *)(uintptr_t)axon_boot_params_phys;
                *(uint32_t *)(bp + LINUX_BOOTPARAM_OFF_RAMDISK_IMG) =
                    (uint32_t)(uint64_t)safe_start;
                *(uint32_t *)(bp + LINUX_BOOTPARAM_OFF_EXT_RD_IMG) =
                    (uint32_t)((uint64_t)safe_start >> 32);
                kprintf("initfs: relocated %llu bytes 0x%llx -> 0x%llx before PCI\n",
                        (unsigned long long)rd_size,
                        (unsigned long long)rd_start,
                        (unsigned long long)safe_start);
                if (fb_hi > fb_lo)
                    kprintf("initfs: avoided GRUB fb [0x%llx..0x%llx)\n",
                            (unsigned long long)fb_lo, (unsigned long long)fb_hi);
            } else if (fb_hi > fb_lo) {
                uint64_t a0 = (uint64_t)rd_start, a1 = (uint64_t)rd_start + (uint64_t)rd_size;
                if (a0 < fb_hi && fb_lo < a1)
                    kprintf("initfs: WARNING ramdisk overlaps GRUB fb — cpio may be corrupted by console\n");
            }
        }
    }

    /* Initialize heap EARLY and place it above kernel + initrd (Linux boot_params). */
    {
        uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
        uintptr_t mods_end = initfs_linux_ramdisk_exclusive_end(axon_boot_params_phys);
        uintptr_t mods_end_aligned = 0;
        if (mods_end) {
            mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
            if (mods_end_aligned > heap_start) heap_start = mods_end_aligned;
        }
        /*
         * Avoid placing the heap below 64 MiB only when that does not re-enter the
         * multiboot module/initrd range. Forcing heap_start=64M while a ~160 MiB
         * module lives at 0x080b9000..0x1234xxxx overlaps the arena with the CPIO:
         * kmalloc returns addresses inside the module, unpack corrupts heap headers,
         * krealloc then fails with magic=0.
         */
        const uintptr_t HEAP_MIN_START = (uintptr_t)(64u * 1024u * 1024u);
        if (heap_start < HEAP_MIN_START) {
            uintptr_t want = HEAP_MIN_START;
            if (mods_end_aligned != 0 && want < mods_end_aligned)
                want = mods_end_aligned;
            if (heap_start < want)
                heap_start = want;
        }
        /* kzip_stub may have filled [AXON_MB2_MODULE_RELOC_BASE, AXON_MB2_MODULE_RELOC_CEIL) even when
         * synthesized boot_params do not describe a ramdisk (mods_end unknown). Keep heap above that
         * arena so a late in-place initfs unpack is not clobbered by kmalloc (net/pci/… before initfs). */
        if (multiboot_magic == 0x36d76289u && mods_end_aligned == 0u) {
            uintptr_t reloc_ceiling = (uintptr_t)AXON_MB2_MODULE_RELOC_CEIL;
            if (heap_start < reloc_ceiling)
                heap_start = reloc_ceiling;
        }
        /* Heap size must not exceed installed RAM. The heap implementation is a
           simple identity-mapped arena; if we size it past RAM we will scribble
           into non-existent memory and get "random" initfs extraction failures. */
        size_t heap_size = 0;
        size_t initrd_sz = 0;
        if (axon_boot_params_phys) {
            uintptr_t rd_st = 0;
            if (linux_bootparams_ramdisk((const void *)(uintptr_t)axon_boot_params_phys, &rd_st, &initrd_sz) != 0)
                initrd_sz = 0;
        }
        int ram_mb = sysinfo_ram_mb();
        if (ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            const uint64_t guard = 4ULL * 1024ULL * 1024ULL; /* 4 MiB (was 8) — more heap for VMware/low-RAM */
            if (ram_bytes > start + guard + (16ULL * 1024ULL * 1024ULL)) {
                uint64_t max = ram_bytes - start - guard;
                heap_size = (size_t)max;
            }
        }
        if (heap_size == 0 && ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            if (ram_bytes > start + (4ULL * 1024ULL * 1024ULL))
                heap_size = (size_t)(ram_bytes - start - (4ULL * 1024ULL * 1024ULL));
        }
        if (heap_size == 0)
            heap_size = 64ULL * 1024ULL * 1024ULL; /* safe default when RAM unknown */
        if (initrd_sz > 0 && (uint64_t)heap_size < (uint64_t)initrd_sz + (32ULL * 1024ULL * 1024ULL))
            kprintf("warning: heap %llu MiB may be too small for initfs %llu MiB — increase VM RAM\n",
                    (unsigned long long)(heap_size / (1024ULL * 1024ULL)),
                    (unsigned long long)(initrd_sz / (1024ULL * 1024ULL)));
        /*
         * Keep the identity-mapped kernel heap OUT of the low user layout
         * [USER_MMAP_BASE .. USER_STACK_TOP). Go (docker) reserves large anon
         * arenas there; if kmalloc lives in the same VA window, mmap hits
         * "overlap kernel heap (heap above user VA cap)" and the runtime dies
         * before mallocinit completes.
         *
         * Prefer heap_start >= USER_STACK_TOP + 16MiB when RAM allows; still
         * honor mods_end/initrd so we never cover the ramdisk. On tiny VMs
         * keep the old low placement (docker needs ≥~1.5GiB RAM).
         */
        {
            const uintptr_t HEAP_ABOVE_USER =
                (uintptr_t)USER_STACK_TOP + (16u * 1024u * 1024u);
            int raise_ok = 1;
            if (ram_mb > 0) {
                uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
                if (ram_bytes < (uint64_t)HEAP_ABOVE_USER + (64ULL * 1024ULL * 1024ULL))
                    raise_ok = 0;
            }
            if (raise_ok) {
                if (heap_start < HEAP_ABOVE_USER)
                    heap_start = HEAP_ABOVE_USER;
                if (mods_end_aligned != 0 && heap_start < mods_end_aligned)
                    heap_start = mods_end_aligned;
            }
        }
        /* Recompute heap_size against the (possibly raised) heap_start. */
        if (ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            const uint64_t guard = 4ULL * 1024ULL * 1024ULL;
            if (ram_bytes > start + guard + (16ULL * 1024ULL * 1024ULL))
                heap_size = (size_t)(ram_bytes - start - guard);
            else if (ram_bytes > start + guard)
                heap_size = (size_t)(ram_bytes - start - guard);
            else
                heap_size = 0;
        }
        if (heap_size == 0)
            heap_size = 64ULL * 1024ULL * 1024ULL;
        /* Cap: never cross MMIO_IDENTITY_LIMIT; if still below STACK_TOP (tiny
         * RAM / huge initrd), also stay below TLS as before. */
        {
            uint64_t hs = (uint64_t)heap_start;
            uint64_t max_heap_end = (uint64_t)MMIO_IDENTITY_LIMIT;
            /* The simple heap is a contiguous identity arena and does not yet
             * split around E820/MMIO holes. Keep it below 2 GiB so VMware PCI
             * BARs cannot become allocator memory after the large initfs is
             * relocated out of the high GRUB module range. */
            if (max_heap_end > 0x80000000ULL)
                max_heap_end = 0x80000000ULL;
            if (max_heap_end > 4ULL * 1024ULL * 1024ULL)
                max_heap_end -= 4ULL * 1024ULL * 1024ULL;
            if (hs < (uint64_t)USER_STACK_TOP) {
                uint64_t tls = (uint64_t)USER_TLS_BASE;
                const uint64_t tls_guard = 1ULL << 20;
                uint64_t tls_cap = tls > tls_guard ? tls - tls_guard : tls;
                if (tls_cap < max_heap_end)
                    max_heap_end = tls_cap;
            }
            if (max_heap_end > hs && hs + (uint64_t)heap_size > max_heap_end)
                heap_size = (size_t)(max_heap_end - hs);
        }
        if (heap_size < (16ULL * 1024ULL * 1024ULL))
            kprintf("warning: kernel heap only %llu MiB after user-VA split — increase VM RAM\n",
                    (unsigned long long)(heap_size / (1024ULL * 1024ULL)));
        heap_init(heap_start, heap_size);
        kprintf("Kernel starting... heap_start: %p heap_size=%llu heap_total=%llu heap_base=%p ram_mb=%d kernel_end: %p mods_end: %p\n",
                (void*)heap_start,
                (unsigned long long)heap_size,
                (unsigned long long)heap_total_bytes(),
                (void*)heap_base_addr(),
                sysinfo_ram_mb(),
                (void*)(uintptr_t)_end, (void*)mods_end);
        /* Default 8x16 until VFS/console.pf2 (or explicit pf2 load). */
        font_init_default();
    }

    gdt_init();
    smp_init(multiboot_magic, multiboot_info);

    /* Per-CPU IST1 stacks for Double Fault (avoids triple-fault when SMP is enabled). */
    {
        const size_t DF_STACK_SIZE = 16 * 1024;
        int ndf = smp_have_acpi_cpu_topology() ? smp_cpu_count() : SMP_MAX_CPUS;
        if (ndf < 1)
            ndf = 1;
        if (ndf > SMP_MAX_CPUS)
            ndf = SMP_MAX_CPUS;
        for (int i = 0; i < ndf; i++) {
            void *df_stack = kmalloc(DF_STACK_SIZE + 16);
            if (df_stack) {
                uintptr_t top = (uintptr_t)df_stack + DF_STACK_SIZE + 16;
                uintptr_t df_top = align_up_uintptr(top, 16);
                tss_set_ist_for_cpu(i, 1, (uint64_t)df_top);
                devel_printf("Set kernel DF IST1 for cpu %d at %p.\n", i,
                             (void *)(uintptr_t)df_top);
            } else {
                kprintf("Failed to allocate DF IST stack for cpu %d (warning)\n", i);
            }
        }
    }
    int vbe_init = 0;
    /* Initialize VBE framebuffer console after heap is available */
    if (multiboot_info != 0) {
        if (vbe_init_from_multiboot(multiboot_magic, multiboot_info)) {
            if (vbe_is_available()) {
                uint32_t w = vbe_get_width();
                uint32_t h = vbe_get_height();
                uint32_t p = vbe_get_pitch();
                uint32_t b = vbe_get_bpp();
                if (vbefb_init(w, h, p, b) == 0) {
                    kprintf("vbe: framebuffer initialized %ux%u@%u\n", (unsigned)w, (unsigned)h, (unsigned)b);
                    vbe_init = 1;
                } else {
                    kprintf("vbe: framebuffer init failed\n");
                    vbe_init = 0;
                }
            }
        } else {
            kprintf("vbe: init_from_multiboot returned error\n");
            vbe_init = 0;
        }
    }

    idt_init();
    pic_init();
    pit_init();

    mmio_init();
    ramfs_register();
    /* Create /dev in ramfs before initfs so it is always visible in ls / and before getty runs */
    ext2_register();

    /* sysfs, procfs, devfs mount — only via SYS_mount from userspace (e.g. init) */

    klog_init(); // for logging into /var/log/kernel file
    klogprintf(OS_NAME " v" OS_VERSION ".\n");
    sysinfo_print_platform();
    sysinfo_print_dmi();
    sysinfo_print_e820(multiboot_magic, multiboot_info);
    if (vbe_is_available() == 1) klogprintf("screen: Set mode: %ux%u@%u.\n", vbe_get_width(), vbe_get_height(), vbe_get_bpp());
    else klogprintf("screen: Set VGA+ 80x25 16 colors\n");

    /* ACPI fixed-feature power button (SCI). Best-effort: do not fail boot on errors. */
    (void)acpi_powerbtn_init(multiboot_magic, multiboot_info);
    
    apic_init();
    apic_timer_init();
    idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);

    syscall_init();/* syscall (int 0x80) initialization */
    
    paging_init();

    // Enabling interrupts
    asm volatile("sti");
    /* Recalibrate after STI when PIT ticks are guaranteed to progress. */
    apic_timer_calibrate();
    /* TSC vs PIT while IRQ0 still drives timer_ticks (before APIC-only timekeeping). */
    klog_calibrate_tsc();

    /* Enable APIC timer if it behaves sanely; otherwise keep PIT.
       Real hardware can hang or run at wildly wrong rate with bad APIC calibration. */
    apic_timer_start(100);
    {
        uint64_t apic_start = apic_timer_ticks;
        uint64_t pit_start = pit_get_ticks();
        while ((pit_get_ticks() - pit_start) < 200) {
            asm volatile("pause");
        }
        uint64_t apic_delta = apic_timer_ticks - apic_start;
        /* At 100 Hz over ~200 ms we expect around 20 ticks; allow wide tolerance. */
        int apic_ok = (apic_delta >= 5 && apic_delta <= 80);
        if (apic_ok) {
            apic_timer_stop();
            pit_disable();
            pic_mask_irq(0);
            /*
             * Linux commonly uses HZ=250.  A 1 kHz periodic LAPIC interrupt
             * can remain continuously pending under VMware when the handler
             * and context switch exceed 1 ms, starving ring-3 completely.
             */
            apic_timer_start(250);
            /* Confirm APIC is actually ticking at the new rate; otherwise revert to PIT. */
            uint64_t t0 = apic_timer_ticks;
            if (klog_tsc_per_us) {
                uint64_t wait_start = time_monotonic_us();
                while (apic_timer_ticks == t0 &&
                       time_monotonic_us() - wait_start < 50000u)
                    asm volatile("pause" ::: "memory");
            } else {
                for (volatile uint64_t i = 0;
                     i < 10000000u && apic_timer_ticks == t0; i++)
                    asm volatile("pause" ::: "memory");
            }
            if (apic_timer_ticks == t0) {
                kprintf("APIC: no ticks after 250Hz start, falling back to PIT\n");
                apic_timer_stop();
                pic_unmask_irq(0);
                pit_init();
            }
        } else {
            kprintf("APIC: unstable (%llu ticks/200ms), using PIT\n", (unsigned long long)apic_delta);
            apic_timer_stop();
        }
    }

    smp_finalize_topology(multiboot_magic, multiboot_info);

    pci_init();
    pci_dump_devices();
    intel_chipset_init();
    usb_init();

    /* Keep NIC driver non-intrusive until full net stack is wired.
       This avoids affecting boot stability on machines where NIC init timing is sensitive. */
    thread_init();
    smp_boot_aps();
 
    iothread_init();

    // POSIX user subsystem
    user_init();

    // Registering all disk file systems
    fat32_register();

    if (e1000_init() != 0) {
        klogprintf("net: e1000 not found\n");
    } else {
        if (syscall_net_preinit() != 0)
            klogprintf("net: failed to register eth0\n");
    }

    
    /* If an initfs module was provided by the bootloader, unpack it into ramfs */
    int r = initfs_process_linux_bootparams(axon_boot_params_phys);
    if (r == 0) {
        klogprintf("initfs: unpacked successfully\n");
        initfs_debug_list_vfs();
        struct stat st;
        if (vfs_stat("/linuxrc", &st) == 0)
            klogprintf("initfs: /linuxrc present\n");
        else if (vfs_stat("/init", &st) == 0)
            klogprintf("initfs: /init present\n");
        else if (vfs_stat("/sbin/init", &st) == 0)
            klogprintf("initfs: /sbin/init present\n");
        else if (vfs_stat("/bin/init", &st) == 0)
            klogprintf("initfs: /bin/init present\n");
        else
            kprintf("initfs: warning: no init (/linuxrc,/init,/sbin/init,/bin/init) found\n");
    } else {
        klogprintf("initfs: error: failed, code: %d\n", r);
        for (;;);
    }

    /* Optional runtime .pf2 from initfs (/etc/fonts/console.pf2, …). */
    font_try_load_console_pf2();

    klogprintf("boot: post-initfs setup (devfs, disks, /etc)...\n");

    /* register devfs and mount at /dev so /dev/tty0, /dev/console etc. exist before init/getty */
    if (devfs_register() == 0) {
        klogprintf("devfs: registering devfs\n");
        if (devfs_mount("/dev") == 0) {
            klogprintf("devfs: mounted at /dev\n");
            scsi_init();
            ata_dma_init();
            (void)pvscsi_init();
            (void)nvme_init();
            {
                int n = devfs_block_count();
                klogprintf("List of block devices: %d\n", n);
                for (int i = 0; i < n; i++) {
                    char name[64];
                    int did = -1;
                    uint32_t secs = 0;
                    if (devfs_block_get(i, name, sizeof(name), &did, &secs) == 0)
                        klogprintf("  /dev/%s disk_id=%d sectors=%u\n", name, did, (unsigned)secs);
                }
            }
            (void)usb_publish_devfs_nodes();
        }
        /* initialize stdio fds for current thread (main) */
        struct fs_file *console = devfs_open_direct("/dev/console");
        if (console) {
            /* allocate fd slots for main thread using helper to manage refcounts */
            int fd0 = thread_fd_alloc(console);
            if (fd0 >= 0) {
                /* ensure we have fd 0..2 set; if not, duplicate */
                thread_t* t = thread_current();
                if (t) {
                    if (fd0 != 0) { /* move to 0 */
                        if (t->fds[0]) fs_file_free(t->fds[0]);
                        t->fds[0] = t->fds[fd0];
                        t->fds[fd0] = NULL;
                    }
                    if (!t->fds[1]) { t->fds[1] = t->fds[0]; if (t->fds[1]) t->fds[1]->refcount++; }
                    if (!t->fds[2]) { t->fds[2] = t->fds[0]; if (t->fds[2]) t->fds[2]->refcount++; }
                }
            } else {
                fs_file_free(console);
            }
        }
    } else {
        klogprintf("devfs: failed to register\n");
    }

    /* Fbcon before long PCI/disk logs: otherwise klog uses VGA 80x25 and lines wrap ~66 chars with timestamps. */
    if (vmwgfx_kernel_init() == 0) {
        devfs_tty_realloc_for_console();
        boot_logo_show();
        klogprintf("video: vmwgfx fbcon enabled early (wide console)\n");
    } else if (cirrus_kernel_init() == 0) {
        devfs_tty_realloc_for_console();
        boot_logo_show();
        klogprintf("video: cirrus fbcon enabled early\n");
    }

    /* /etc/passwd and /etc/group so whoami/id/groups/adduser work.
       Use static buffers to avoid heap overflow. Seed a normal user so
       `adduser miha root` (BusyBox: add existing user to group) is meaningful. */
    (void)ramfs_mkdir("/etc");
    (void)ramfs_mkdir("/root");
    (void)ramfs_mkdir("/home");
    (void)ramfs_mkdir("/home/miha");
    static const char root_passwd_line[] =
        "root:x:0:0:root:/root:/bin/sh\n"
        "miha:x:1000:1000:miha:/home/miha:/bin/sh\n";
    const size_t root_passwd_len = sizeof(root_passwd_line) - 1;
    struct fs_file *pf = fs_create_file("/etc/passwd");
    if (!pf) pf = fs_open("/etc/passwd");
    if (pf) {
        (void)vfs_ftruncate(pf, 0);
        fs_write(pf, root_passwd_line, root_passwd_len, 0);
        fs_file_free(pf);
    }
    /* Member lists required: BusyBox id(1) getgrouplist fails on "root:x:0:". */
    static const char root_group_line[] =
        "root:x:0:root,miha\n"
        "users:x:100:miha\n"
        "miha:x:1000:miha\n";
    const size_t root_group_len = sizeof(root_group_line) - 1;
    struct fs_file *gf = fs_create_file("/etc/group");
    if (!gf) gf = fs_open("/etc/group");
    if (gf) {
        (void)vfs_ftruncate(gf, 0);
        fs_write(gf, root_group_line, root_group_len, 0);
        fs_file_free(gf);
    }
    /* adduser expects /etc/shadow to exist and appends entries with O_APPEND. */
    {
        /* empty password field = login with Enter */
        static const char root_shadow[] =
            "root::0:0:99999:7:::\n"
            "miha::0:0:99999:7:::\n";
        struct fs_file *sf = fs_create_file("/etc/shadow");
        if (!sf) sf = fs_open("/etc/shadow");
        if (sf) {
            (void)vfs_ftruncate(sf, 0);
            fs_write(sf, root_shadow, sizeof(root_shadow) - 1, 0);
            fs_file_free(sf);
        }
    }
    /* adduser/addgroup may readlink /etc/gshadow; create minimal file. */
    {
        static const char root_gshadow[] =
            "root::root,miha\n"
            "users::miha\n"
            "miha::miha\n";
        struct fs_file *gsf = fs_create_file("/etc/gshadow");
        if (!gsf) gsf = fs_open("/etc/gshadow");
        if (gsf) {
            (void)vfs_ftruncate(gsf, 0);
            fs_write(gsf, root_gshadow, sizeof(root_gshadow) - 1, 0);
            fs_file_free(gsf);
        }
    }
    (void)ramfs_mkdir("/var");
    (void)ramfs_mkdir("/var/run");
    (void)ramfs_mkdir("/var/log");  /* ensure exists for wtmp (klog also creates it) */
    (void)ramfs_mkdir("/var/log/nginx");
    (void)ramfs_mkdir("/var/run");
    (void)ramfs_mkdir("/srv");
    (void)ramfs_mkdir("/srv/www");
    {
        static const char index_html[] = "ok\n";
        struct fs_file *idx = fs_create_file("/srv/www/index.html");
        if (!idx) idx = fs_open("/srv/www/index.html");
        if (idx) {
            (void)vfs_ftruncate(idx, 0);
            fs_write(idx, index_html, sizeof(index_html) - 1, 0);
            fs_file_free(idx);
        }
    }
    /* Linux-default nginx.conf: epoll, sendfile, dual-stack, master/daemon on. */
    {
        struct stat st;
        if (vfs_stat("/etc/nginx/nginx.conf", &st) == 0) {
            static const char nginx_conf[] =
                "user root;\n"
                "worker_processes  1;\n"
                "error_log  /var/log/nginx/error.log warn;\n"
                "pid        /var/run/nginx.pid;\n"
                "\n"
                "events {\n"
                "    # packaged nginx has no epoll module; kernel epoll ABI is ready\n"
                "    use poll;\n"
                "    worker_connections  256;\n"
                "}\n"
                "\n"
                "http {\n"
                "    include       mime.types;\n"
                "    default_type  application/octet-stream;\n"
                "    access_log    /var/log/nginx/access.log;\n"
                "\n"
                "    sendfile        on;\n"
                "    keepalive_timeout  65;\n"
                "\n"
                "    server {\n"
                "        listen       80 default_server;\n"
                "        listen       [::]:80 default_server;\n"
                "        server_name  localhost;\n"
                "\n"
                "        root   /srv/www;\n"
                "        index  index.html index.htm;\n"
                "\n"
                "        location / {\n"
                "            try_files $uri $uri/ =404;\n"
                "        }\n"
                "    }\n"
                "}\n";
            struct fs_file *nf = fs_open("/etc/nginx/nginx.conf");
            if (!nf) nf = fs_create_file("/etc/nginx/nginx.conf");
            if (nf) {
                (void)vfs_ftruncate(nf, 0);
                fs_write(nf, nginx_conf, sizeof(nginx_conf) - 1, 0);
                fs_file_free(nf);
            }
        }
    }
    (void)ramfs_mkdir("/run");
    (void)ramfs_mkdir("/run/lock");
    (void)ramfs_mkdir("/run/openrc");
    (void)ramfs_mkdir("/run/openrc/daemons");
    (void)ramfs_mkdir("/run/openrc/started");
    (void)ramfs_mkdir("/run/openrc/stopped");
    (void)ramfs_mkdir("/run/openrc/starting");
    (void)ramfs_mkdir("/run/openrc/stopping");
    (void)ramfs_mkdir("/run/openrc/inactive");
    (void)ramfs_mkdir("/run/openrc/wasinactive");
    (void)ramfs_mkdir("/run/openrc/failed");
    (void)ramfs_mkdir("/run/openrc/crashed");
    (void)ramfs_mkdir("/run/openrc/hotplugged");
    (void)ramfs_mkdir("/run/openrc/scheduled");
    (void)ramfs_mkdir("/run/openrc/exclusive");
    (void)ramfs_mkdir("/run/openrc/options");
    if (ramfs_symlink("/var/run/openrc", "/run/openrc") != 0)
        (void)ramfs_mkdir("/var/run/openrc");
    if (ramfs_symlink("/var/lock", "/run/lock") != 0)
        (void)ramfs_mkdir("/var/lock");
    {
        struct fs_file *sf = fs_open("/run/openrc/softlevel");
        if (!sf) sf = fs_create_file("/run/openrc/softlevel");
        if (sf) {
            static const char softlevel[] = "sysinit\n";
            if (sf->size == 0)
                fs_write(sf, softlevel, sizeof(softlevel) - 1, 0);
            fs_file_free(sf);
        }
    }
    (void)ramfs_mkdir("/tmp");  /* passwd uses mkstemp in /tmp for shadow update */
    (void)ramfs_mkdir("/var/tmp");
    /* tmux and many POSIX tools expect sticky tmp dirs (01777). */
    (void)fs_chmod("/tmp", S_IFDIR | 01777);
    (void)fs_chmod("/var/tmp", S_IFDIR | 01777);
    /* /var/log/wtmp: login history for last(1). Empty at boot; login appends utmp records. */
    {
        struct fs_file *wf = fs_create_file("/var/log/wtmp");
        if (!wf) wf = fs_open("/var/log/wtmp");
        if (wf) fs_file_free(wf);
    }
    /* BusyBox init / login expect /var/run/utmp (ENOENT after openrc death). */
    {
        struct fs_file *uf = fs_create_file("/var/run/utmp");
        if (!uf) uf = fs_open("/var/run/utmp");
        if (uf) fs_file_free(uf);
    }
#ifdef CONFIGURE_NET_START
    {
        /* No "dns" here: libnss_dns.so NEEDs libc.so.6 and kills static busybox. */
        static const char nsswitch[] =
            "passwd: files\n"
            "group: files\n"
            "shadow: files\n"
            "gshadow: files\n"
            "hosts: files\n"
            "networks: files\n"
            "protocols: files\n"
            "services: files\n"
            "ethers: files\n"
            "rpc: files\n"
            "netgroup: files\n";
        (void)fs_unlink("/etc/nsswitch.conf");
        struct fs_file *nf = fs_create_file("/etc/nsswitch.conf");
        if (!nf) nf = fs_open("/etc/nsswitch.conf");
        if (nf) {
            fs_write(nf, nsswitch, sizeof(nsswitch) - 1, 0);
            fs_file_free(nf);
        }
    }
#endif
    {
        static const char hosts_min[] = "127.0.0.1\tlocalhost\n";
        (void)fs_unlink("/etc/hosts");
        struct fs_file *hf = fs_create_file("/etc/hosts");
        if (!hf) hf = fs_open("/etc/hosts");
        if (hf) {
            fs_write(hf, hosts_min, sizeof(hosts_min) - 1, 0);
            fs_file_free(hf);
        }
    }
    /* glibc resolver trad: order hosts then DNS; avoids surprise open(2) ENOENT on some setups. */
    {
        static const char host_conf[] = "order hosts,bind\nmulti on\n";
        (void)fs_unlink("/etc/host.conf");
        struct fs_file *cf = fs_create_file("/etc/host.conf");
        if (!cf) cf = fs_open("/etc/host.conf");
        if (cf) {
            fs_write(cf, host_conf, sizeof(host_conf) - 1, 0);
            fs_file_free(cf);
        }
    }
    syscall_net_ensure_resolv();
    ramfs_install_libnss_dns();
    /* Programs (mount, sh) open /etc/localtime; create so open doesn't fail. */
    {
        struct fs_file *lt = fs_create_file("/etc/localtime");
        if (lt) fs_file_free(lt);
    }
    /* /etc/profile: sourced by login shells (getty->login->sh -l). Sets PS1 and TERM for vim. */
    {
        static const char profile[] =
            "export TERM=builtin_ansi\n"
            "export USER=root\n"
            "export LOGNAME=root\n"
            "export HOME=/root\n"
            "export PS1='\\[\\033[1;31m\\]\\u\\033[0m@\\h \\033[1;37m\\w\\033[0m \\$ '\n"
            "export OPENSSL_CONF=/etc/ssl/openssl.cnf\n"
            "export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n"
            "export SSL_CERT_DIR=/etc/ssl/certs\n";
        struct fs_file *pf = fs_create_file("/etc/profile");
        if (!pf) pf = fs_open("/etc/profile");
        if (pf) {
            (void)vfs_ftruncate(pf, 0);
            fs_write(pf, profile, sizeof(profile) - 1, 0);
            fs_file_free(pf);
        }
    }
    /*
     * Interactive non-login bash (typing `bash`) reads this. Musl-static bash
     * caches getpwuid at startup; if that fails the prompt stays
     * "I have no name!" unless PS1 is overridden without \\u.
     */
    {
        static const char bashrc[] =
            "export USER=${USER:-root}\n"
            "export LOGNAME=${LOGNAME:-root}\n"
            "export HOME=${HOME:-/root}\n"
            "if [ \"${UID:-0}\" = 0 ] || [ \"$(id -u 2>/dev/null)\" = 0 ]; then\n"
            "  PS1='\\[\\033[1;31m\\]root\\[\\033[0m\\]@\\h \\[\\033[0;37m\\]\\w\\[\\033[0m\\]\\$ '\n"
            "fi\n";
        struct fs_file *bf = fs_create_file("/etc/bash.bashrc");
        if (!bf) bf = fs_open("/etc/bash.bashrc");
        if (bf) {
            (void)vfs_ftruncate(bf, 0);
            fs_write(bf, bashrc, sizeof(bashrc) - 1, 0);
            fs_file_free(bf);
        }
        struct fs_file *rbf = fs_create_file("/root/.bashrc");
        if (!rbf) rbf = fs_open("/root/.bashrc");
        if (rbf) {
            static const char rbashrc[] = "[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc\n";
            (void)vfs_ftruncate(rbf, 0);
            fs_write(rbf, rbashrc, sizeof(rbashrc) - 1, 0);
            fs_file_free(rbf);
        }
    }
    /* /etc/issue: getty prints this before login prompt. \l = tty name (tty1, tty2, ...) */
    {
        static const char issue[] = OS_NAME" "OS_VERSION"-"OS_PREFIX" (\\l)\n\n";
        struct fs_file *ifile = fs_create_file("/etc/issue");
        if (!ifile) ifile = fs_open("/etc/issue");
        if (ifile) {
            fs_write(ifile, issue, sizeof(issue) - 1, 0);
            fs_file_free(ifile);
        }
    }
    /* Linux os-release: tools use ID_LIKE=linux; uname sysname is separately "Linux". */
    {
        static const char osrel[] =
            "NAME=\"" OS_NAME "\"\n"
            "PRETTY_NAME=\"" OS_NAME " " OS_VERSION "\"\n"
            "ID=axonos\n"
            "ID_LIKE=linux\n"
            "VERSION=\"" OS_VERSION "\"\n"
            "VERSION_ID=\"" OS_VERSION "\"\n"
            "HOME_URL=\"https://axont.ru\"\n";
        struct fs_file *of = fs_create_file("/etc/os-release");
        if (!of) of = fs_open("/etc/os-release");
        if (of) {
            (void)vfs_ftruncate(of, 0);
            fs_write(of, osrel, sizeof(osrel) - 1, 0);
            fs_file_free(of);
        }
    }
    /* /etc/securetty: TTY devices from which root can log in */
    {
        static const char securetty[] = "console\ntty1\ntty2\ntty3\ntty4\ntty5\ntty6\nttyS0\nttyS1\n";
        struct fs_file *sf = fs_create_file("/etc/securetty");
        if (!sf) sf = fs_open("/etc/securetty");
        if (sf) {
            fs_write(sf, securetty, sizeof(securetty) - 1, 0);
            fs_file_free(sf);
        }
    }
    /* /etc/motd: message of the day, shown after successful login */
    {
        static const char motd[] = "\nWelcome to " OS_NAME " " OS_VERSION "\n"
                                   "  * Website: https://axont.ru\n"
                                   "  * GitHub: https://github.com/axonteam-dev/axonos.git\n"
                                   "  * AxonHub: https://xhub.axont.ru/ \n"
                                   "Feedback on axont@axont.ru\n\n";
        struct fs_file *mf = fs_create_file("/etc/motd");
        if (!mf) mf = fs_open("/etc/motd");
        if (mf) {
            fs_write(mf, motd, sizeof(motd) - 1, 0);
            fs_file_free(mf);
        }
    }
    /* BusyBox udhcpc default script (Linux semantics: userspace DHCP). */
    {
        (void)ramfs_mkdir("/usr");
        (void)ramfs_mkdir("/usr/share");
        (void)ramfs_mkdir("/usr/share/udhcpc");
        static const char udhcpc_script[] =
            "#!/bin/sh\n"
            "[ -z \"$1\" ] && exit 1\n"
            "RESOLV_CONF=\"/etc/resolv.conf\"\n"
            "[ -n \"$broadcast\" ] && BROADCAST=\"broadcast $broadcast\"\n"
            "[ -n \"$subnet\" ] && NETMASK=\"netmask $subnet\"\n"
            "case \"$1\" in\n"
            "deconfig)\n"
            "\tifconfig \"$interface\" 0.0.0.0\n"
            "\t;;\n"
            "renew|bound)\n"
            "\tifconfig \"$interface\" \"$ip\" $BROADCAST $NETMASK\n"
            "\tif [ -n \"$router\" ]; then\n"
            "\t\twhile route del default gw 0.0.0.0 dev \"$interface\" 2>/dev/null; do :; done\n"
            "\t\tfor i in $router; do\n"
            "\t\t\troute add default gw \"$i\" dev \"$interface\"\n"
            "\t\tdone\n"
            "\tfi\n"
            "\techo -n > \"$RESOLV_CONF\"\n"
            "\t[ -n \"$domain\" ] && echo \"search $domain\" >> \"$RESOLV_CONF\"\n"
            "\tfor i in $dns; do\n"
            "\t\techo \"nameserver $i\" >> \"$RESOLV_CONF\"\n"
            "\tdone\n"
            "\t;;\n"
            "esac\n"
            "exit 0\n";
        (void)fs_unlink("/usr/share/udhcpc/default.script");
        struct fs_file *us = fs_create_file("/usr/share/udhcpc/default.script");
        if (!us) us = fs_open("/usr/share/udhcpc/default.script");
        if (us) {
            fs_write(us, udhcpc_script, sizeof(udhcpc_script) - 1, 0);
            fs_file_free(us);
        }
        (void)fs_chmod("/usr/share/udhcpc/default.script", S_IFREG | 0755);
    }
    /* /etc/termcap: vt102/linux with arrow keys (ku/kd/kr/kl) so vim moves cursor correctly */
    {
        static const char termcap[] =
            "vt102|vt100|linux|linux-term:"
            /* 1280x800 / 8x16 fbcon ≈ 160×50; ioctl winsize overrides for other vmwgfx modes */
            "co#160:li#50:cl=\\E[2J\\E[H:cm=\\E[%i%d;%dH:nd=\\E[C:up=\\E[A:"
            "ce=\\E[K:cd=\\E[J:so=\\E[7m:se=\\E[0m:us=\\E[4m:ue=\\E[0m:"
            "ku=\\E[A:kd=\\E[B:kr=\\E[C:kl=\\E[D:"
            "ti=\\E[?1049h:te=\\E[?1049l:\n";
        struct fs_file *tc = fs_create_file("/etc/termcap");
        if (!tc) tc = fs_open("/etc/termcap");
        if (tc) {
            fs_write(tc, termcap, sizeof(termcap) - 1, 0);
            fs_file_free(tc);
        }
    }

    /* OpenRC init scripts use #!/sbin/openrc-run; some initfs builds only ship
     * /usr/sbin/openrc-run. */
    {
        struct stat st;
        if (vfs_stat("/sbin/openrc-run", &st) != 0 && vfs_stat("/usr/sbin/openrc-run", &st) == 0) {
            (void)ramfs_mkdir("/sbin");
            if (ramfs_symlink("/sbin/openrc-run", "/usr/sbin/openrc-run") != 0) {
                klogprintf("boot: warning: failed to link /sbin/openrc-run\n");
            }
        }
    }

    /* Compatibility: many distros' adduser scripts call /sbin/addgroup explicitly,
     * while initfs may only provide /usr/sbin/addgroup. Create a tiny wrapper if needed. */
    {
        struct stat st;
        if (vfs_stat("/sbin/addgroup", &st) != 0 && vfs_stat("/usr/sbin/addgroup", &st) == 0) {
            (void)ramfs_mkdir("/sbin");
            /* Shebang runs with argv [interp, script_path, orig_argv[1], ...]; shift drops script path so $@ = real args for addgroup */
            static const char addgroup_wrapper[] = "#!/bin/sh\nshift\nexec /usr/sbin/addgroup \"$@\"\n";
            const size_t L = sizeof(addgroup_wrapper) - 1;
            struct fs_file *af = fs_create_file("/sbin/addgroup");
            if (!af) af = fs_open("/sbin/addgroup");
            if (af) {
                fs_write(af, addgroup_wrapper, L, 0);
                fs_file_free(af);
            }
        }
    }
    ps2_keyboard_init();
    ps2_mouse_init();
    boot_logo_dismiss();

    /* OpenRC rc_sys() reads /proc before init.sh mounts it; provide proc early.
     * Same for sysfs: openrc's sysfs service greps /proc/filesystems and mounts
     * /sys — pre-mount so mountinfo sees it and remount is a no-op. */
    {
        (void)procfs_register();
        (void)ramfs_mkdir("/proc");
        if (procfs_mount("/proc") != 0)
            klogprintf("boot: warning: failed to mount /proc\n");
    }
    {
        (void)sysfs_register();
        (void)ramfs_mkdir("/sys");
        if (sysfs_mount("/sys") == 0)
            kernel_sysfs_populate_default();
        else
            klogprintf("boot: warning: failed to mount /sys\n");
    }

    // Prefer linuxrc/init if present; fallback to kernel shell.
    if (boot_try_run_init() != 0) {
        klogprintf("fatal: There is nothing to run. Download the correct initfs from https://apm.axont.ru/Packages/initfs.cpio and place it in the root of the boot device.");
    }
    
    for(;;) {
        asm volatile("sti; hlt" ::: "memory");
    }
}