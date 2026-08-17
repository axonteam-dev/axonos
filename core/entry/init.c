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
#include <pmm.h>
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
#include <tmpfs.h>
#include <sysfs.h>
#include <fbdev.h>
#include <procfs.h>
#include <initfs.h>
#include <squashfs.h>
#include <overlayfs.h>
#include <bootparam.h>
#include <mb2_linux_shim.h>
#include <ramfs.h>
#include <fat32.h>
#include <minix.h>
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
#include <keyring.h>
void ata_dma_init(void);
void scsi_init(void);
int pvscsi_init(void);
int mptspi_init(void);

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
extern const char axonos_system_ca_pem_start[];
extern const char axonos_system_ca_pem_end[];

static int ramfs_mkdir_p(const char *path)
{
        char tmp[512];
        size_t len;
        char *p;
        int rc;

        if (!path || path[0] != '/')
                return -1;
        len = strlen(path);
        if (len == 0 || len >= sizeof(tmp))
                return -1;
        memcpy(tmp, path, len + 1);
        /* Strip trailing slash so the final component is created too. */
        while (len > 1 && tmp[len - 1] == '/') {
                tmp[len - 1] = '\0';
                len--;
        }
        for (p = tmp + 1; *p; p++) {
                if (*p != '/')
                        continue;
                *p = '\0';
                if (tmp[1] != '\0') {
                        rc = ramfs_mkdir(tmp);
                        if (rc != 0 && rc != -4) /* -4 = EEXIST */
                                return -1;
                }
                *p = '/';
        }
        /* Final component (loop only creates parents on '/'). */
        if (tmp[1] != '\0') {
                rc = ramfs_mkdir(tmp);
                if (rc != 0 && rc != -4)
                        return -1;
        }
        return 0;
}

/*
 * Install into overlay upper (ramfs). Upper wins over squashfs lower — same as
 * Linux overlay. Borrowed file points at immutable boot blob (no ftruncate
 * promote, which kept failing and left stock relative gendepends.sh).
 */
static int ramfs_write_blob(const char *path, const void *blob, size_t len)
{
        char parent[512];
        char *slash;
        size_t plen;
        int rc;

        if (!path || !blob || len == 0U || path[0] != '/')
                return -1;

        plen = strlen(path);
        if (plen >= sizeof(parent))
                return -1;
        memcpy(parent, path, plen + 1);
        slash = strrchr(parent, '/');
        if (!slash)
                return -1;
        if (slash != parent) {
                *slash = '\0';
                if (ramfs_mkdir_p(parent) != 0) {
                        kprintf("blob: mkdir -p failed %s\n", parent);
                        return -1;
                }
        }

        (void)ramfs_remove(path);
        rc = ramfs_create_borrowed_file(path, blob, len);
        if (rc != 0) {
                (void)ramfs_remove(path);
                rc = ramfs_create_borrowed_file(path, blob, len);
        }
        if (rc != 0) {
                kprintf("blob: upper create failed %s rc=%d\n", path, rc);
                return -1;
        }

        {
                struct fs_file *vf = fs_open(path);
                struct stat st;
                if (!vf) {
                        kprintf("blob: vfs re-open failed %s\n", path);
                        return -1;
                }
                /* Borrowed upper is the blob itself — do not memcpy the whole
                 * DSO back through overlay (that stalled boot after NSS). */
                if (vfs_fstat(vf, &st) != 0 || (size_t)st.st_size != len) {
                        kprintf("blob: verify size mismatch %s size=%lld want=%zu\n",
                                path, (long long)st.st_size, len);
                        fs_file_free(vf);
                        return -1;
                }
                if (strstr(path, "gendepends")) {
                        char *got = (char *)kmalloc(len + 1);
                        ssize_t n;
                        if (!got) {
                                fs_file_free(vf);
                                return -1;
                        }
                        n = fs_read(vf, got, len, 0);
                        if (n != (ssize_t)len || !strstr(got, "\n/etc/init.d")) {
                                kprintf("blob: missing /etc/init.d marker %s\n", path);
                                kfree(got);
                                fs_file_free(vf);
                                return -1;
                        }
                        kfree(got);
                }
                fs_file_free(vf);
        }
        (void)ramfs_chmod(path, S_IFREG | 0755);
        return 0;
}

static int boot_write_bytes(const char *path, const void *data, size_t len)
{
        char parent[512];
        char *slash;
        size_t plen;
        struct fs_file *f;

        if (!path || path[0] != '/')
                return -1;
        plen = strlen(path);
        if (plen >= sizeof(parent))
                return -1;
        memcpy(parent, path, plen + 1);
        slash = strrchr(parent, '/');
        if (slash && slash != parent) {
                *slash = '\0';
                if (ramfs_mkdir_p(parent) != 0)
                        return -1;
        }
        f = fs_create_file(path);
        if (!f)
                f = fs_open(path);
        if (!f)
                return -1;
        (void)vfs_ftruncate(f, 0);
        if (data && len)
                (void)fs_write(f, data, len, 0);
        fs_file_free(f);
        return 0;
}

/*
 * Linux kernel_init: late_initcall(load_system_certificate_list) then
 * integrity_load_keys(), still before run_init_process. Export the same
 * trust anchor as /etc/ssl so OpenSSL follows the usual distro layout.
 */
static void boot_load_system_certs(void)
{
        const char *pem = axonos_system_ca_pem_start;
        size_t pem_len = (size_t)(axonos_system_ca_pem_end - axonos_system_ca_pem_start);
        static const char openssl_cnf[] =
                "# System-wide OpenSSL configuration (kernel-generated)\n"
                "HOME = /root\n"
                "RANDFILE = /dev/urandom\n"
                "\n"
                "[ req ]\n"
                "default_bits = 2048\n"
                "default_md = sha256\n"
                "string_mask = utf8only\n"
                "distinguished_name = req_distinguished_name\n"
                "\n"
                "[ req_distinguished_name ]\n";

        /* Linux: late_initcall(load_system_certificate_list) copies
         * CONFIG_SYSTEM_TRUSTED_KEYS into .builtin_trusted_keys. It does
         * not run ECDSA keygen on the boot CPU. */
        kprintf("certs: installing built-in system CA (Linux load_system_certificate_list)\n");
        if (keyring_load_system_certs() != 0)
                kprintf("certs: keyring init failed\n");
        if (keyring_install_system_ca(pem, pem_len) != 0)
                kprintf("certs: warning: cannot cache CA on .builtin_trusted_keys\n");
        (void)ramfs_mkdir_p("/etc/ssl/certs");
        (void)ramfs_mkdir_p("/etc/ssl/private");
        if (boot_write_bytes("/etc/ssl/openssl.cnf", openssl_cnf,
                             sizeof(openssl_cnf) - 1) != 0)
                kprintf("certs: warning: cannot write /etc/ssl/openssl.cnf\n");
        if (pem_len == 0) {
                kprintf("certs: built-in CA PEM empty (host openssl missing at build)\n");
                return;
        }
        if (boot_write_bytes("/etc/ssl/certs/ca-certificates.crt", pem, pem_len) != 0)
                kprintf("certs: warning: cannot write ca-certificates.crt\n");
        if (boot_write_bytes("/etc/ssl/certs/axonos-system-ca.pem", pem, pem_len) != 0)
                kprintf("certs: warning: cannot write axonos-system-ca.pem\n");
        (void)fs_unlink("/etc/ssl/cert.pem");
        if (overlayfs_symlink("/etc/ssl/cert.pem",
                              "/etc/ssl/certs/ca-certificates.crt") != 0)
                (void)boot_write_bytes("/etc/ssl/cert.pem", pem, pem_len);
        kprintf("certs: system CA ready (%zu bytes PEM) in .builtin_trusted_keys\n",
                pem_len);
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
        /* OpenRC PID1 is openrc-init (/sbin/init → openrc-init in initfs).
         * Prefer it over BusyBox linuxrc. /sbin/openrc is the runlevel helper, not PID1. */
        static const char *candidates[] = {
                "/linuxrc",
                "/sbin/openrc-init",
                "/usr/sbin/openrc-init",
                "/sbin/init",
                "/bin/sh",
                NULL
        };
        int have_openrc = 0;
        {
                struct stat st;
                if (vfs_stat("/sbin/openrc-init", &st) == 0 ||
                        vfs_stat("/usr/sbin/openrc-init", &st) == 0 ||
                        vfs_stat("/sbin/openrc", &st) == 0 ||
                        vfs_stat("/usr/sbin/openrc", &st) == 0)
                        have_openrc = 1;
        }
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
         * GRUB allocates very large Multiboot modules top-down. Relocate before
         * PCI/video so the image cannot sit in a BAR/aperture or in the mid-RAM
         * window where the identity heap prefers to live (USER_STACK_TOP+32MiB =
         * 0x62000000 used to collide with that policy and show up later as
         * "cpio magic not found" with a .text-looking head).
         *
         * Park the initrd under the top of RAM; keep the heap strictly below it.
         * Never land on the Multiboot/GRUB linear framebuffer.
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

                        {
                                const uint8_t *h = (const uint8_t *)rd_start;
                                int magic_ok = 0;
                                if (rd_size >= 4 && h[0] == 'h' && h[1] == 's' && h[2] == 'q' && h[3] == 's')
                                        magic_ok = 1;
                                else if (rd_size >= 6 && h[0] == '0' && h[1] == '7' && h[2] == '0' &&
                                                 h[3] == '7' && h[4] == '0' && (h[5] == '1' || h[5] == '2'))
                                        magic_ok = 1;
                                kprintf("initfs: GRUB module phys 0x%llx size %llu head %02x %02x %02x %02x %s\n",
                                                (unsigned long long)rd_start, (unsigned long long)rd_size,
                                                rd_size > 0 ? h[0] : 0, rd_size > 1 ? h[1] : 0,
                                                rd_size > 2 ? h[2] : 0, rd_size > 3 ? h[3] : 0,
                                                magic_ok ? "(ok)" : "(BAD magic — image may be corrupted)");
                        }

                        uint64_t identity_end = sysinfo_identity_usable_end(multiboot_info);
                        if (identity_end == 0) {
                                int reported_mb = sysinfo_ram_mb();
                                uint64_t reported = reported_mb > 0
                                        ? (uint64_t)reported_mb * 1024ULL * 1024ULL : 0x80000000ULL;
                                identity_end = reported < 0x80000000ULL ? reported : 0x80000000ULL;
                        }
                        uintptr_t safe_start = 0;
                        if (identity_end > (uint64_t)rd_size + (64ull * 1024ull * 1024ull)) {
                                /* Top of identity-mapped usable RAM, with a 16 MiB guard. */
                                uint64_t top = identity_end - (16ull * 1024ull * 1024ull);
                                uint64_t cand64 = (top - (uint64_t)rd_size) & ~((uint64_t)(2u * 1024u * 1024u) - 1ull);
                                /* Stay above user mmap window + 64MiB so heap has room below. */
                                uint64_t floor = (uint64_t)USER_STACK_TOP + (64ull * 1024ull * 1024ull);
                                if (cand64 >= floor && cand64 + (uint64_t)rd_size <= top) {
                                        int fb_hit = 0;
                                        if (fb_hi > fb_lo) {
                                                uint64_t a0 = cand64, a1 = cand64 + (uint64_t)rd_size;
                                                if (a0 < fb_hi && fb_lo < a1)
                                                        fb_hit = 1;
                                        }
                                        if (!fb_hit)
                                                safe_start = (uintptr_t)cand64;
                                }
                        }
                        /* Fallback: fixed high candidates (never the old STACK_TOP+32MiB slot). */
                        if (!safe_start) {
                                const uintptr_t candidates[] = {
                                        (uintptr_t)0x78000000u,
                                        (uintptr_t)0x70000000u,
                                        (uintptr_t)USER_STACK_TOP + (128u * 1024u * 1024u),
                                };
                                for (unsigned ci = 0; ci < sizeof(candidates) / sizeof(candidates[0]); ci++) {
                                        uintptr_t cand = candidates[ci];
                                        uintptr_t cand_end = 0;
                                        if (__builtin_add_overflow(cand, rd_size, &cand_end))
                                                continue;
                                        if ((uint64_t)cand_end + (16ull * 1024ull * 1024ull) > identity_end)
                                                continue;
                                        if (cand < (uintptr_t)USER_STACK_TOP + (64u * 1024u * 1024u))
                                                continue;
                                        if (fb_hi > fb_lo) {
                                                uint64_t a0 = (uint64_t)cand, a1 = (uint64_t)cand_end;
                                                if (a0 < fb_hi && fb_lo < a1)
                                                        continue;
                                        }
                                        safe_start = cand;
                                        break;
                                }
                        }
                        if (safe_start && (uintptr_t)rd_start != safe_start) {
                                memmove((void *)safe_start, (const void *)rd_start, rd_size);
                                uint8_t *bp = (uint8_t *)(uintptr_t)axon_boot_params_phys;
                                *(uint32_t *)(bp + LINUX_BOOTPARAM_OFF_RAMDISK_IMG) =
                                        (uint32_t)(uint64_t)safe_start;
                                *(uint32_t *)(bp + LINUX_BOOTPARAM_OFF_EXT_RD_IMG) =
                                        (uint32_t)((uint64_t)safe_start >> 32);
                                {
                                        const uint8_t *h = (const uint8_t *)safe_start;
                                        kprintf("initfs: relocated %llu bytes 0x%llx -> 0x%llx head %02x %02x %02x %02x\n",
                                                        (unsigned long long)rd_size,
                                                        (unsigned long long)rd_start,
                                                        (unsigned long long)safe_start,
                                                        h[0], h[1], h[2], h[3]);
                                }
                                if (fb_hi > fb_lo)
                                        kprintf("initfs: avoided GRUB fb [0x%llx..0x%llx)\n",
                                                        (unsigned long long)fb_lo, (unsigned long long)fb_hi);
                        } else if (fb_hi > fb_lo) {
                                uint64_t a0 = (uint64_t)rd_start, a1 = (uint64_t)rd_start + (uint64_t)rd_size;
                                if (a0 < fb_hi && fb_lo < a1)
                                        kprintf("initfs: WARNING ramdisk overlaps GRUB fb — image may be corrupted by console\n");
                        }
                }
        }

        /* Initialize heap EARLY. Initrd is parked near the top of RAM; the heap
         * fills [HEAP_ABOVE_USER .. initrd_start). Legacy low initrd still pushes
         * the heap to mods_end. */
        {
                uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
                uintptr_t rd_st = 0;
                size_t initrd_sz = 0;
                uintptr_t mods_end = 0;
                uintptr_t mods_end_aligned = 0;
                int initrd_high = 0;
                if (axon_boot_params_phys &&
                        linux_bootparams_ramdisk((const void *)(uintptr_t)axon_boot_params_phys,
                                                                         &rd_st, &initrd_sz) == 0 &&
                        initrd_sz > 0 && rd_st != 0) {
                        mods_end = rd_st + initrd_sz;
                        if (mods_end > rd_st)
                                mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
                        /* High parking: above user window + 64MiB. */
                        if (rd_st >= (uintptr_t)USER_STACK_TOP + (64u * 1024u * 1024u))
                                initrd_high = 1;
                }
                const uintptr_t HEAP_MIN_START = (uintptr_t)(64u * 1024u * 1024u);
                const uintptr_t HEAP_ABOVE_USER =
                        (uintptr_t)USER_STACK_TOP + (16u * 1024u * 1024u);
                int ram_mb = sysinfo_ram_mb();
                uint64_t identity_end = sysinfo_identity_usable_end(multiboot_info);
                if (identity_end == 0) {
                        uint64_t reported = ram_mb > 0
                                ? (uint64_t)ram_mb * 1024ULL * 1024ULL : 0x80000000ULL;
                        identity_end = reported < 0x80000000ULL ? reported : 0x80000000ULL;
                }

                if (!initrd_high) {
                        /* Legacy: heap starts after a low/mid initrd. */
                        if (mods_end_aligned != 0 && mods_end_aligned > heap_start)
                                heap_start = mods_end_aligned;
                        if (heap_start < HEAP_MIN_START) {
                                uintptr_t want = HEAP_MIN_START;
                                if (mods_end_aligned != 0 && want < mods_end_aligned)
                                        want = mods_end_aligned;
                                if (heap_start < want)
                                        heap_start = want;
                        }
                        if (multiboot_magic == 0x36d76289u && mods_end_aligned == 0u) {
                                uintptr_t reloc_ceiling = (uintptr_t)AXON_MB2_MODULE_RELOC_CEIL;
                                if (heap_start < reloc_ceiling)
                                        heap_start = reloc_ceiling;
                        }
                } else {
                        /* High initrd: heap lives below it, above the user mmap window. */
                        heap_start = HEAP_ABOVE_USER;
                        if (heap_start < HEAP_MIN_START)
                                heap_start = HEAP_MIN_START;
                }

                size_t heap_size = 0;
                {
                        int raise_ok = 1;
                        if (identity_end > 0) {
                                if (identity_end < (uint64_t)HEAP_ABOVE_USER + (256ULL * 1024ULL * 1024ULL))
                                        raise_ok = 0;
                        }
                        if (raise_ok && !initrd_high) {
                                if (heap_start < HEAP_ABOVE_USER)
                                        heap_start = HEAP_ABOVE_USER;
                                if (mods_end_aligned != 0 && heap_start < mods_end_aligned)
                                        heap_start = mods_end_aligned;
                        } else if (raise_ok && initrd_high) {
                                if (heap_start < HEAP_ABOVE_USER)
                                        heap_start = HEAP_ABOVE_USER;
                        }
                }

                /* Size the arena: never enter the initrd or past RAM/MMIO. */
                {
                        uint64_t hs = (uint64_t)heap_start;
                        const uint64_t guard = 4ULL * 1024ULL * 1024ULL;
                        uint64_t max_heap_end = identity_end;
                        if (max_heap_end > (uint64_t)MMIO_IDENTITY_LIMIT)
                                max_heap_end = (uint64_t)MMIO_IDENTITY_LIMIT;
                        if (max_heap_end > guard)
                                max_heap_end -= guard;
                        if (initrd_high && rd_st > 0 && (uint64_t)rd_st < max_heap_end)
                                max_heap_end = (uint64_t)rd_st;
                        if (hs < (uint64_t)USER_STACK_TOP) {
                                if (max_heap_end > 0x80000000ULL)
                                        max_heap_end = 0x80000000ULL;
                        }
                        if (hs < (uint64_t)USER_STACK_TOP) {
                                uint64_t tls = (uint64_t)USER_TLS_BASE;
                                const uint64_t tls_guard = 1ULL << 20;
                                uint64_t tls_cap = tls > tls_guard ? tls - tls_guard : tls;
                                if (tls_cap < max_heap_end)
                                        max_heap_end = tls_cap;
                        }
                        if (max_heap_end > hs + (16ULL * 1024ULL * 1024ULL))
                                heap_size = (size_t)(max_heap_end - hs);
                        else if (max_heap_end > hs)
                                heap_size = (size_t)(max_heap_end - hs);
                        else
                                heap_size = 0;
                }
                if (heap_size == 0)
                        heap_size = 64ULL * 1024ULL * 1024ULL;
                if (initrd_sz > 0 && (uint64_t)heap_size < (128ULL * 1024ULL * 1024ULL))
                        kprintf("warning: heap %llu MiB may be tight with initfs %llu MiB — increase VM RAM\n",
                                        (unsigned long long)(heap_size / (1024ULL * 1024ULL)),
                                        (unsigned long long)(initrd_sz / (1024ULL * 1024ULL)));
                if (heap_size < (128ULL * 1024ULL * 1024ULL))
                        kprintf("warning: kernel heap only %llu MiB after user-VA split — increase VM RAM (docker needs ≥2GiB)\n",
                                        (unsigned long long)(heap_size / (1024ULL * 1024ULL)));
                /*
                 * Linux: buddy owns pages; kmalloc is a small-object layer.
                 * Carve Soft_OWNED frames out of the high end of this arena so
                 * fork/exec cannot exhaust the object heap (was ~392MiB OOM).
                 */
                {
                        uintptr_t arena_hi = heap_start + heap_size;
                        /*
                         * ramfs/tmpfs file payloads currently use kmalloc, so
                         * the object arena is also the writable-root backing
                         * store. Keep a substantial PMM reserve for user pages,
                         * but do not arbitrarily cap the overlay at 128 MiB.
                         */
                        const size_t OBJECT_HEAP_MAX = 1024ULL * 1024ULL * 1024ULL;
                        /*
                         * Dynamic toolchains map many DSOs concurrently.
                         * Reserving only 64 MiB let opkg unpack GCC but left ld
                         * unable to map libstdc++. Keep Linux-like separation
                         * between filesystem cache/object memory and user pages.
                         */
                        const size_t PMM_MIN = (heap_size > (1024ULL * 1024ULL * 1024ULL))
                                ? (384ULL * 1024ULL * 1024ULL)
                                : (192ULL * 1024ULL * 1024ULL);
                        if (heap_size > PMM_MIN + (128ULL * 1024ULL * 1024ULL)) {
                                size_t object_heap = heap_size - PMM_MIN;
                                if (object_heap > OBJECT_HEAP_MAX)
                                        object_heap = OBJECT_HEAP_MAX;
                                heap_size = object_heap;
                                heap_init(heap_start, heap_size);
                                pmm_init(heap_start + heap_size, arena_hi);
                        } else {
                                heap_init(heap_start, heap_size);
                        }
                }
                kprintf("Kernel starting... heap_start: %p heap_size=%llu heap_total=%llu heap_base=%p ram_mb=%d kernel_end: %p initrd: %p..%p\n",
                                (void*)heap_start,
                                (unsigned long long)heap_size,
                                (unsigned long long)heap_total_bytes(),
                                (void*)heap_base_addr(),
                                sysinfo_ram_mb(),
                                (void*)(uintptr_t)_end,
                                (void*)(uintptr_t)rd_st,
                                (void*)(uintptr_t)mods_end);
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
#ifdef EXT2_SUPPORT
        ext2_register();
#endif
        squashfs_register();
        overlayfs_register();

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
        /*
         * Bring up LAPIC timekeeping against the still-running PIT, refine the
         * period so wall time is accurate, then switch off IRQ0. Linux commonly
         * uses HZ=250; higher rates only amplify our still-heavy IRQ handler.
         */
        const uint32_t apic_hz = 250u;
        apic_timer_start(apic_hz);
        if (!sysinfo_is_hypervisor() && !apic_timer_uses_tsc_deadline()) {
                kprintf("APIC: no usable TSC-deadline on bare metal; keeping PIT at 250 Hz\n");
                apic_timer_stop();
        } else {
                uint32_t measured = apic_timer_refine(apic_hz, 200u);
                int apic_ok = (measured >= apic_hz / 4u && measured <= apic_hz * 4u);
                if (apic_ok) {
                        /* Converge count while PIT is still the wall reference. */
                        for (int pass = 0; pass < 3; pass++) {
                                measured = apic_timer_refine(apic_hz, 120u);
                                uint32_t err = (measured > apic_hz) ? (measured - apic_hz)
                                                                                                        : (apic_hz - measured);
                                if (err * 100u <= apic_hz) /* within 1% */
                                        break;
                        }
                        pit_disable();
                        pic_mask_irq(0);
                        /* Confirm IRQs still arrive; otherwise fall back to PIT. */
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
                                kprintf("APIC: no ticks after switch, falling back to PIT\n");
                                apic_timer_stop();
                                pic_unmask_irq(0);
                                pit_init();
                        } else {
                                /*
                                 * Linux keeps clockevent programming separate
                                 * from the clocksource. The count was already
                                 * converged against PIT; never rescale it again
                                 * from TSC after IRQ0 has been disabled.
                                 */
                                apic_timer_state.frequency = apic_hz;
                                timer_frequency = apic_hz;
                                klog_reanchor_tsc();
                                kprintf("APIC: clockevent live at %u Hz; TSC clocksource active\n",
                                        apic_hz);
                        }
                } else {
                        kprintf("APIC: unstable (measured %u Hz), using PIT\n", measured);
                        apic_timer_stop();
                }
        }

        kprintf("boot: post-timer (smp/pci/threads/initfs)...\n");
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
#ifdef FAT32_SUPPORT
        fat32_register();
#endif
#ifdef MINIX_SUPPORT
        minix_register();
#endif

        if (e1000_init() != 0) {
                klogprintf("net: e1000 not found\n");
        } else {
                if (syscall_net_preinit() != 0)
                        klogprintf("net: failed to register eth0\n");
        }

        kprintf("boot: mounting initfs...\n");
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
        /* register devfs and mount at /dev so /dev/tty0, /dev/console etc. exist before init/getty */
        if (devfs_register() == 0) {
                klogprintf("devfs: registering devfs\n");
                if (devfs_mount("/dev") == 0) {
                        klogprintf("devfs: mounted at /dev\n");
                        scsi_init();
                        ata_dma_init();
                        (void)pvscsi_init();
                        (void)mptspi_init();
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
                        klog_sync_varlog();
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
        } 
#ifdef DRIVER_CIRRUS
        if (cirrus_kernel_init() == 0) {
                devfs_tty_realloc_for_console();
                boot_logo_show();
                klogprintf("video: cirrus fbcon enabled early\n");
        }
#endif
        /* Linux device_initcall: i8042/input before userspace /etc synthesis. */
        ps2_keyboard_init();
        ps2_mouse_init();
        /* /etc/passwd and /etc/group so whoami/id/groups/adduser work.
           Use static buffers to avoid heap overflow. Seed a normal user so
           `adduser miha root` (BusyBox: add existing user to group) is meaningful. */
        (void)ramfs_mkdir("/etc");
        (void)ramfs_mkdir("/root");
        (void)ramfs_mkdir("/home");
        static const char root_passwd_line[] =
                "root:x:0:0:root:/root:/bin/sh\n";
        const size_t root_passwd_len = sizeof(root_passwd_line) - 1;
        struct fs_file *pf = fs_create_file("/etc/passwd");
        if (!pf) pf = fs_open("/etc/passwd");
        if (pf) {
                (void)vfs_ftruncate(pf, 0);
                fs_write(pf, root_passwd_line, root_passwd_len, 0);
                fs_file_free(pf);
        }
        /* Member lists required: BusyBox id(1) getgrouplist fails on "root:x:0:".
         * Include Linux base groups OpenRC checkpath expects (uucp for /run/lock). */
        static const char root_group_line[] =
                "root:x:0:root\n"
                "daemon:x:1:\n"
                "bin:x:2:\n"
                "sys:x:3:\n"
                "adm:x:4:\n"
                "tty:x:5:\n"
                "disk:x:6:\n"
                "lp:x:7:\n"
                "mail:x:8:\n"
                "news:x:9:\n"
                "uucp:x:10:\n"
                "man:x:12:\n"
                "proxy:x:13:\n"
                "kmem:x:15:\n"
                "dialout:x:20:\n"
                "fax:x:21:\n"
                "voice:x:22:\n"
                "cdrom:x:24:\n"
                "floppy:x:25:\n"
                "tape:x:26:\n"
                "sudo:x:27:\n"
                "audio:x:29:\n"
                "dip:x:30:\n"
                "www-data:x:33:\n"
                "backup:x:34:\n"
                "operator:x:37:\n"
                "list:x:38:\n"
                "irc:x:39:\n"
                "src:x:40:\n"
                "shadow:x:42:\n"
                "utmp:x:43:\n"
                "video:x:44:\n"
                "sasl:x:45:\n"
                "plugdev:x:46:\n"
                "messagebus:x:101:\n"
                "nogroup:x:65534:\n";
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
                        "root::0:0:99999:7:::\n";
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
        /* Do NOT mkdir /var/run — squashfs has /var/run -> /run. mkdir on overlay
         * upper would shadow that symlink and break Linux /var/run semantics. */
        (void)ramfs_mkdir("/var/log");  /* ensure exists for wtmp (klog also creates it) */
        (void)ramfs_mkdir("/var/log/nginx");
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
                                "pid                /var/run/nginx.pid;\n"
                                "\n"
                                "events {\n"
                                "        # packaged nginx has no epoll module; kernel epoll ABI is ready\n"
                                "        use poll;\n"
                                "        worker_connections  256;\n"
                                "}\n"
                                "\n"
                                "http {\n"
                                "        include           mime.types;\n"
                                "        default_type  application/octet-stream;\n"
                                "        access_log        /var/log/nginx/access.log;\n"
                                "\n"
                                "        sendfile                on;\n"
                                "        keepalive_timeout  65;\n"
                                "\n"
                                "        server {\n"
                                "                listen           80 default_server;\n"
                                "                listen           [::]:80 default_server;\n"
                                "                server_name  localhost;\n"
                                "\n"
                                "                root   /srv/www;\n"
                                "                index  index.html index.htm;\n"
                                "\n"
                                "                location / {\n"
                                "                        try_files $uri $uri/ =404;\n"
                                "                }\n"
                                "        }\n"
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
        /* Linux: /run is a tmpfs (often already mounted by initramfs). Pre-mount so
         * OpenRC mountinfo -q /run succeeds and init.sh skips fstabinfo/mount.
         * Never mkdir /var/run — squashfs ships /var/run -> /run.
         * Final verify + remount happens after /proc is up (see below). */
        (void)ramfs_mkdir("/run");
        if (tmpfs_mount("/run") != 0)
                kprintf("boot: warning: failed to mount tmpfs on /run (will retry)\n");
        else
                kprintf("boot: tmpfs mounted on /run\n");
        (void)ramfs_mkdir("/run/lock");
        (void)ramfs_mkdir("/run/openrc");
        /* opkg state must live on a writable upper/tmpfs. Keeping it below
         * squashfs /var made libarchive fail creating control/list files. */
        (void)ramfs_mkdir("/run/opkg");
        (void)ramfs_mkdir("/run/opkg/lists");
        (void)ramfs_mkdir("/run/opkg/info");
        (void)ramfs_mkdir("/run/opkg/cache");
        {
                struct fs_file *status = fs_create_file("/run/opkg/status");
                if (!status)
                        status = fs_open("/run/opkg/status");
                if (status)
                        fs_file_free(status);
        }
        {
                struct stat st;
                if (vfs_lstat("/var/run", &st) != 0)
                        (void)ramfs_symlink("/var/run", "/run");
                if (vfs_lstat("/var/lock", &st) != 0)
                        (void)ramfs_symlink("/var/lock", "/run/lock");
        }

        /* Linux /etc/fstab — OpenRC fstabinfo --mount /proc|/run uses this. */
        {
                static const char fstab[] =
                        "# <file system>\t<mount point>\t<type>\t<options>\t\t<dump>\t<pass>\n"
                        "proc\t\t/proc\t\tproc\tdefaults\t\t0\t0\n"
                        "sysfs\t\t/sys\t\tsysfs\tdefaults\t\t0\t0\n"
                        "devtmpfs\t/dev\t\tdevtmpfs\tmode=0755\t\t0\t0\n"
                        "tmpfs\t\t/run\t\ttmpfs\tmode=0755,nosuid,nodev\t0\t0\n"
                        "tmpfs\t\t/tmp\t\ttmpfs\tmode=1777,nosuid,nodev\t0\t0\n";
                struct fs_file *ff = fs_create_file("/etc/fstab");
                if (!ff) ff = fs_open("/etc/fstab");
                if (ff) {
                        (void)vfs_ftruncate(ff, 0);
                        fs_write(ff, fstab, sizeof(fstab) - 1, 0);
                        fs_file_free(ff);
                }
        }
        /* Do not create /etc/conf.d/rc — OpenRC 0.53 warns and wants rc.conf only. */
        (void)fs_unlink("/etc/conf.d/rc");
        /* Linux fstab: tmpfs on /tmp (mode=1777).  tmux realpath($TMUX_TMPDIR:/tmp/)
         * and mkdir /tmp/tmux-<uid> mode 0700 require a real sticky world-writable
         * tmp — not an overlay merged dir with fake 0755. */
        (void)ramfs_mkdir("/tmp");
        if (tmpfs_mount("/tmp") != 0)
                kprintf("boot: warning: failed to mount tmpfs on /tmp\n");
        else
                kprintf("boot: tmpfs mounted on /tmp\n");
        (void)ramfs_mkdir("/var/tmp");
        /* Materialize /mnt in overlay upper so mkdir /mnt/foo works without -p races. */
        (void)ramfs_mkdir("/mnt");
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
        /*
         * Resolver files must exist before the first opkg/wget invocation.
         * 10.0.2.3 is QEMU user-net's DNS proxy; a later DHCP bound/renew
         * atomically replaces this fallback with lease-provided servers.
         */
        {
                struct stat st;
                if (vfs_stat("/etc/resolv.conf", &st) != 0) {
                        static const char resolv_fallback[] =
                                "options timeout:2 attempts:5 single-request-reopen\n"
                                "nameserver 10.0.2.3\n"
                                "nameserver 1.1.1.1\n";
                        struct fs_file *rf = fs_create_file("/etc/resolv.conf");
                        if (!rf) rf = fs_open("/etc/resolv.conf");
                        if (rf) {
                                (void)vfs_ftruncate(rf, 0);
                                fs_write(rf, resolv_fallback, sizeof(resolv_fallback) - 1, 0);
                                fs_file_free(rf);
                        }
                }
        }
        /*
         * Entware glibc is configured with /opt/etc as sysconfdir, while
         * native AxonOS/BusyBox follows Linux's /etc. Share the authoritative
         * NSS databases so both libcs resolve exactly the same users/groups.
         */
        {
                static const struct {
                        const char *compat;
                        const char *native;
                } nss_compat[] = {
                        { "/opt/etc/passwd",       "/etc/passwd" },
                        { "/opt/etc/group",        "/etc/group" },
                        { "/opt/etc/shadow",       "/etc/shadow" },
                        { "/opt/etc/gshadow",      "/etc/gshadow" },
                        { "/opt/etc/hosts",         "/etc/hosts" },
                        { "/opt/etc/resolv.conf",   "/etc/resolv.conf" },
                };
                for (size_t i = 0; i < sizeof(nss_compat) / sizeof(nss_compat[0]); i++) {
                        (void)fs_unlink(nss_compat[i].compat);
                        if (overlayfs_symlink(nss_compat[i].compat, nss_compat[i].native) != 0)
                                kprintf("boot: warning: cannot create NSS compatibility link %s\n",
                                        nss_compat[i].compat);
                }
        }
        {
                static const char entware_nsswitch[] =
                        "passwd: files\n"
                        "shadow: files\n"
                        "group: files\n"
                        "hosts: files dns\n"
                        "networks: files\n"
                        "protocols: files\n"
                        "services: files\n";
                struct fs_file *nf = fs_create_file("/opt/etc/nsswitch.conf");
                if (!nf) nf = fs_open("/opt/etc/nsswitch.conf");
                if (nf) {
                        (void)vfs_ftruncate(nf, 0);
                        fs_write(nf, entware_nsswitch, sizeof(entware_nsswitch) - 1, 0);
                        fs_file_free(nf);
                }
        }
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
        /* Linux: load_system_certificate_list + integrity_load_keys before PID 1. */
        boot_load_system_certs();

        /* Programs (mount, sh) open /etc/localtime; create so open doesn't fail. */
        {
                struct fs_file *lt = fs_create_file("/etc/localtime");
                if (lt) fs_file_free(lt);
        }
        /* /etc/profile: login shells (getty→login→sh -l). */
        {
                static const char profile[] =
                        "export PATH=/opt/bin:/opt/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                        "export TERM=linux\n"
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
                static const char motd[] = "\nWelcome to " OS_NAME " " OS_VERSION "-" OS_PREFIX "\n"
                                                                   "The programs included with the AxonOS system are free software;\n"
                                                                   "the exact distribution terms for each program are described in the web.\n"
                                                                   "\n"
                                                                   "AxonOS is distributed under the MIT License.\n"
                                                                   "AxonOS comes with ABSOLUTELY NO WARRANTY, to the extent\n"
                                                                   "permitted by applicable law.\n"
                                                                   "\n"
                                                                   "Unauthorized access is prohibited. All activities are logged.\n\n";
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
                        "\techo \"options timeout:2 attempts:5 single-request-reopen\" >> \"$RESOLV_CONF\"\n"
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
        /* No /etc/termcap stub: ncurses uses terminfo from initfs (…/terminfo/l/linux). */

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
                /* Same for openrc / openrc-init when only usr/sbin is populated. */
                if (vfs_stat("/sbin/openrc", &st) != 0 && vfs_stat("/usr/sbin/openrc", &st) == 0) {
                        (void)ramfs_mkdir("/sbin");
                        (void)ramfs_symlink("/sbin/openrc", "/usr/sbin/openrc");
                }
                if (vfs_stat("/sbin/openrc-init", &st) != 0 && vfs_stat("/usr/sbin/openrc-init", &st) == 0) {
                        (void)ramfs_mkdir("/sbin");
                        (void)ramfs_symlink("/sbin/openrc-init", "/usr/sbin/openrc-init");
                }
                if (vfs_stat("/sbin/init", &st) != 0) {
                        if (vfs_stat("/sbin/openrc-init", &st) == 0)
                                (void)ramfs_symlink("/sbin/init", "/sbin/openrc-init");
                        else if (vfs_stat("/usr/sbin/openrc-init", &st) == 0)
                                (void)ramfs_symlink("/sbin/init", "/usr/sbin/openrc-init");
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
        boot_logo_dismiss();

        /* OpenRC rc_sys() reads /proc before init.sh mounts it; provide proc early.
         * Same for sysfs: openrc's sysfs service greps /proc/filesystems and mounts
         * /sys — pre-mount so mountinfo sees it and remount is a no-op.
         * /run tmpfs is pre-mounted earlier (with /etc/fstab) so mountinfo -q /run
         * succeeds — same as a Linux initramfs leaving /run mounted. */
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
        /* Confirm /run is visible the way OpenRC mountinfo reads it. Retry mount
         * here (after /proc) so a transient early failure still leaves tmpfs on
         * /run before openrc-init starts. Dump the VFS mount table to the console. */
        {
                (void)ramfs_mkdir("/run");
                if (tmpfs_mount("/run") != 0)
                        kprintf("boot: RETRY failed: tmpfs on /run\n");
                struct fs_driver *md = fs_get_mount_driver_exact("/run");
                if (!md || !md->ops || !md->ops->name || strcmp(md->ops->name, "tmpfs") != 0)
                        kprintf("boot: /run NOT tmpfs in mount table — OpenRC will try mount\n");
                else
                        kprintf("boot: /run ready for mountinfo (tmpfs)\n");
                {
                        int n = fs_mount_count();
                        kprintf("boot: VFS mounts (%d):\n", n);
                        for (int i = 0; i < n; i++) {
                                char mp[64], dn[32];
                                if (fs_mount_get(i, mp, sizeof(mp), dn, sizeof(dn)) == 0)
                                        kprintf("  [%d] %s on %s\n", i, dn, mp);
                        }
                }
                /* Exact bytes OpenRC mountinfo parses via fopen("/proc/mounts"). */
                {
                        struct fs_file *mf = fs_open("/proc/mounts");
                        if (!mf) {
                                kprintf("boot: FATAL cannot open /proc/mounts\n");
                        } else {
                                char buf[1024];
                                ssize_t nr = fs_read(mf, buf, sizeof(buf) - 1, 0);
                                fs_file_free(mf);
                                if (nr <= 0) {
                                        kprintf("boot: FATAL /proc/mounts empty (read=%zd)\n", nr);
                                } else {
                                        buf[nr] = '\0';
                                        kprintf("boot: /proc/mounts (%zd bytes):\n%s", nr, buf);
                                        if (!strstr(buf, " /run "))
                                                kprintf("boot: FATAL /proc/mounts missing ' /run '\n");
                                }
                        }
                }
        }

        /* Final printk snapshot for /var/log/kernel (ring stays authoritative via /dev/kmsg). */
        klog_sync_varlog();

        // Prefer OpenRC (openrc-init) over BusyBox linuxrc; shell is last resort.
        if (boot_try_run_init() != 0) {
                klogprintf("fatal: There is nothing to run. Download the correct initfs from https://apm.axont.ru/Packages/initfs.cpio and place it in the root of the boot device.");
        }
        
        for(;;) {
                asm volatile("sti; hlt" ::: "memory");
        }
}