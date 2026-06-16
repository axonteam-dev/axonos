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
#include <procfs.h>
#include <initfs.h>
#include <bootparam.h>
#include <mb2_linux_shim.h>
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

extern uint8_t _end[];
extern const char nss_dns_so_blob_start[];
extern const char nss_dns_so_blob_end[];

static uintptr_t align_up_uintptr(uintptr_t v, uintptr_t a)
{
    return (v + (a - 1)) & ~(a - 1);
}

static void ramfs_write_bytes(const char *path, const void *data, size_t len)
{
    struct fs_file *f;

    if (!path || !data || len == 0)
        return;
    f = fs_create_file(path);
    if (!f)
        f = fs_open(path);
    if (!f)
        return;
    fs_write(f, data, len, 0);
    fs_file_free(f);
}

static void ramfs_touch(const char *path)
{
    struct fs_file *f;

    f = fs_create_file(path);
    if (!f)
        f = fs_open(path);
    if (f)
        fs_file_free(f);
}

static void ramfs_install_libnss_dns(void)
{
    size_t len = (size_t)(nss_dns_so_blob_end - nss_dns_so_blob_start);

    if (len == 0)
        return;
    (void)ramfs_mkdir("/lib");
    (void)fs_unlink("/lib/libnss_dns.so.2");
    ramfs_write_bytes("/lib/libnss_dns.so.2", nss_dns_so_blob_start, len);
}

ssize_t sysfs_show_const(char *buf, size_t size, void *priv)
{
    const char *text = (const char *)priv;

    if (!buf || size == 0)
        return 0;
    if (!text)
        text = "";
    size_t len = strlen(text);
    if (len > size)
        len = size;
    memcpy(buf, text, len);
    if (len < size)
        buf[len++] = '\n';
    return (ssize_t)len;
}

ssize_t sysfs_show_cpu_name_attr(char *buf, size_t size, void *priv)
{
    const char *name;

    (void)priv;
    if (!buf || size == 0)
        return 0;
    name = sysinfo_cpu_name();
    size_t len = strlen(name);
    if (len > size)
        len = size;
    memcpy(buf, name, len);
    if (len < size)
        buf[len++] = '\n';
    return (ssize_t)len;
}

static size_t sysfs_write_int(char *buf, size_t size, int value)
{
    char tmp[32];
    size_t n = 0;
    unsigned int v;
    int neg = 0;

    if (!buf || size == 0)
        return 0;
    if (value < 0) {
        neg = 1;
        v = (unsigned int)(-value);
    } else {
        v = (unsigned int)value;
    }
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    if (neg && n < sizeof(tmp))
        tmp[n++] = '-';

    size_t written = 0;
    while (n && written < size)
        buf[written++] = tmp[--n];
    return written;
}

ssize_t sysfs_show_ram_mb_attr(char *buf, size_t size, void *priv)
{
    (void)priv;
    if (!buf || size == 0)
        return 0;

    int mb = sysinfo_ram_mb();
    if (mb < 0)
        return sysfs_show_const(buf, size, (void *)"unknown");

    size_t written = sysfs_write_int(buf, size, mb);
    if (written < size)
        buf[written++] = '\n';
    return (ssize_t)written;
}

/* musl/glibc read these before /proc/stat; missing files yield nproc==1. */
static ssize_t sysfs_show_cpu_range_list(char *buf, size_t size, void *priv)
{
    (void)priv;
    if (!buf || size == 0)
        return 0;

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

void kernel_sysfs_populate_default(void)
{
    int nc;

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

    nc = smp_cpu_count();
    if (nc < 1)
        nc = 1;
    if (nc > SMP_MAX_CPUS)
        nc = SMP_MAX_CPUS;
    for (int i = 0; i < nc; i++) {
        char path[80];
        snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d", i);
        sysfs_mkdir(path);
    }

    usb_sysfs_populate_default();
    pci_sysfs_init();
    keyboard_publish_sysfs();
    mouse_publish_sysfs();
}

static int boot_try_run_init(void)
{
    static const char *candidates[] = {
        "/linuxrc", "/init", "/sbin/init", "/bin/init", NULL
    };

    for (int i = 0; candidates[i]; i++) {
        const char *p = candidates[i];
        struct stat st;

        if (vfs_stat(p, &st) != 0)
            continue;
        if (!((st.st_mode & S_IFREG) == S_IFREG || (st.st_mode & S_IFLNK) == S_IFLNK))
            continue;

        const char *argv0[2] = { p, NULL };
        static const char *init_env[] = {
            "PS1=\\[\\033[1;31m\\]\\u\\033[0m@\\h \e[0;37m\\w\\033[0m\\$ ", NULL
        };
        int rc = kernel_execve_from_path(p, argv0, init_env);

        if (rc == -3)
            rc = kernel_execve_from_path(p, argv0, init_env);
        if (rc == 0)
            return 0;
        klogprintf("boot: init %s returned rc=%d\n", p, rc);
    }
    return -1;
}

static uintptr_t boot_heap_start(uint32_t mb_magic, uint64_t mb_info, uint64_t boot_params_phys)
{
    uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
    uintptr_t mods_end = initfs_linux_ramdisk_exclusive_end(boot_params_phys);
    uintptr_t mods_end_aligned = 0;

    if (mods_end) {
        mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
        if (mods_end_aligned > heap_start)
            heap_start = mods_end_aligned;
    }

    const uintptr_t heap_min = (uintptr_t)(64u * 1024u * 1024u);
    if (heap_start < heap_min) {
        uintptr_t want = heap_min;
        if (mods_end_aligned != 0 && want < mods_end_aligned)
            want = mods_end_aligned;
        if (heap_start < want)
            heap_start = want;
    }

    if (mb_magic == 0x36d76289u && mods_end_aligned == 0) {
        uintptr_t reloc_ceiling = (uintptr_t)AXON_MB2_MODULE_RELOC_CEIL;
        if (heap_start < reloc_ceiling)
            heap_start = reloc_ceiling;
    }
    return heap_start;
}

static size_t boot_heap_size(uintptr_t heap_start, uint64_t boot_params_phys)
{
    size_t heap_size = 0;
    size_t initrd_sz = 0;
    int ram_mb = sysinfo_ram_mb();

    if (boot_params_phys) {
        uintptr_t rd_st = 0;
        if (linux_bootparams_ramdisk((const void *)(uintptr_t)boot_params_phys, &rd_st, &initrd_sz) != 0)
            initrd_sz = 0;
    }

    if (ram_mb > 0) {
        uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
        uint64_t start = (uint64_t)heap_start;
        const uint64_t guard = 4ULL * 1024ULL * 1024ULL;

        if (ram_bytes > start + guard + (16ULL * 1024ULL * 1024ULL))
            heap_size = (size_t)(ram_bytes - start - guard);
        else if (ram_bytes > start + guard)
            heap_size = (size_t)(ram_bytes - start - guard);
    }

    if (heap_size == 0)
        heap_size = 64ULL * 1024ULL * 1024ULL;

    if (initrd_sz > 0 && (uint64_t)heap_size < (uint64_t)initrd_sz + (32ULL * 1024ULL * 1024ULL))
        kprintf("warning: heap %llu MiB may be too small for initfs %llu MiB — increase VM RAM\n",
                (unsigned long long)(heap_size / (1024ULL * 1024ULL)),
                (unsigned long long)(initrd_sz / (1024ULL * 1024ULL)));

    {
        uint64_t tls = (uint64_t)USER_TLS_BASE;
        const uint64_t tls_guard = 1ULL << 20;
        uint64_t max_heap_end = tls > tls_guard ? tls - tls_guard : tls;
        uint64_t hs = (uint64_t)heap_start;

        if (max_heap_end > hs && hs + (uint64_t)heap_size > max_heap_end)
            heap_size = (size_t)(max_heap_end - hs);
    }
    return heap_size;
}

static void boot_init_heap(uint32_t mb_magic, uint64_t mb_info, uint64_t boot_params_phys)
{
    uintptr_t heap_start = boot_heap_start(mb_magic, mb_info, boot_params_phys);
    size_t heap_size = boot_heap_size(heap_start, boot_params_phys);
    uintptr_t mods_end = initfs_linux_ramdisk_exclusive_end(boot_params_phys);

    heap_init(heap_start, heap_size);
    kprintf("Kernel starting... heap_start: %p heap_size=%llu heap_total=%llu heap_base=%p ram_mb=%d kernel_end: %p mods_end: %p\n",
            (void *)heap_start,
            (unsigned long long)heap_size,
            (unsigned long long)heap_total_bytes(),
            (void *)heap_base_addr(),
            sysinfo_ram_mb(),
            (void *)(uintptr_t)_end, (void *)mods_end);
}

static void boot_init_df_stacks(void)
{
    const size_t df_stack_size = 16 * 1024;
    int ndf = smp_have_acpi_cpu_topology() ? smp_cpu_count() : SMP_MAX_CPUS;

    if (ndf < 1)
        ndf = 1;
    if (ndf > SMP_MAX_CPUS)
        ndf = SMP_MAX_CPUS;

    for (int i = 0; i < ndf; i++) {
        void *df_stack = kmalloc(df_stack_size + 16);
        if (!df_stack) {
            kprintf("Failed to allocate DF IST stack for cpu %d (warning)\n", i);
            continue;
        }
        uintptr_t top = (uintptr_t)df_stack + df_stack_size + 16;
        uintptr_t df_top = align_up_uintptr(top, 16);
        tss_set_ist_for_cpu(i, 1, (uint64_t)df_top);
        kprintf("Set kernel DF IST1 for cpu %d at %p.\n", i, (void *)(uintptr_t)df_top);
    }
}

static int boot_init_vbe(uint32_t mb_magic, uint64_t mb_info)
{
    if (mb_info == 0)
        return 0;
    if (!vbe_init_from_multiboot(mb_magic, mb_info)) {
        kprintf("vbe: init_from_multiboot returned error\n");
        return 0;
    }
    if (!vbe_is_available())
        return 0;

    uint32_t w = vbe_get_width();
    uint32_t h = vbe_get_height();
    uint32_t p = vbe_get_pitch();
    uint32_t b = vbe_get_bpp();
    if (vbefb_init(w, h, p, b) != 0) {
        kprintf("vbe: framebuffer init failed\n");
        return 0;
    }
    kprintf("vbe: framebuffer initialized %ux%u@%u\n", (unsigned)w, (unsigned)h, (unsigned)b);
    return 1;
}

static void boot_select_timer(void)
{
    apic_timer_start(100);

    uint64_t apic_start = apic_timer_ticks;
    uint64_t pit_start = pit_get_ticks();
    while ((pit_get_ticks() - pit_start) < 200)
        asm volatile("pause");

    uint64_t apic_delta = apic_timer_ticks - apic_start;
    int apic_ok = (apic_delta >= 5 && apic_delta <= 80);
    if (!apic_ok) {
        kprintf("APIC: unstable (%llu ticks/200ms), using PIT\n", (unsigned long long)apic_delta);
        apic_timer_stop();
        return;
    }

    apic_timer_stop();
    pit_disable();
    pic_mask_irq(0);
    apic_timer_start(1000);

    uint64_t t0 = apic_timer_ticks;
    for (int i = 0; i < 100000; i++) {
        if (apic_timer_ticks != t0)
            break;
        asm volatile("pause");
    }
    if (apic_timer_ticks != t0)
        return;

    kprintf("APIC: no ticks after 1000Hz start, falling back to PIT\n");
    apic_timer_stop();
    pic_unmask_irq(0);
    pit_init();
}

static void boot_init_video_early(void)
{
    if (vmwgfx_kernel_init() == 0) {
        devfs_tty_realloc_for_console();
        boot_logo_show();
        klogprintf("video: vmwgfx fbcon enabled early (wide console)\n");
        return;
    }
    if (cirrus_kernel_init() == 0) {
        devfs_tty_realloc_for_console();
        boot_logo_show();
        klogprintf("video: cirrus fbcon enabled early\n");
    }
}

static void boot_attach_stdio(void)
{
    struct fs_file *console = devfs_open_direct("/dev/console");
    thread_t *t;
    int fd0;

    if (!console)
        return;
    fd0 = thread_fd_alloc(console);
    if (fd0 < 0) {
        fs_file_free(console);
        return;
    }

    t = thread_current();
    if (!t)
        return;
    if (fd0 != 0) {
        if (t->fds[0])
            fs_file_free(t->fds[0]);
        t->fds[0] = t->fds[fd0];
        t->fds[fd0] = NULL;
    }
    if (!t->fds[1]) {
        t->fds[1] = t->fds[0];
        if (t->fds[1])
            t->fds[1]->refcount++;
    }
    if (!t->fds[2]) {
        t->fds[2] = t->fds[0];
        if (t->fds[2])
            t->fds[2]->refcount++;
    }
}

static void boot_init_devfs(void)
{
    int i, n;

    if (devfs_register() != 0) {
        klogprintf("devfs: failed to register\n");
        return;
    }

    klogprintf("devfs: registering devfs\n");
    if (devfs_mount("/dev") != 0)
        return;

    klogprintf("devfs: mounted at /dev\n");
    scsi_init();
    ata_dma_init();
    (void)pvscsi_init();
    (void)nvme_init();

    n = devfs_block_count();
    klogprintf("List of block devices: %d\n", n);
    for (i = 0; i < n; i++) {
        char name[64];
        int did = -1;
        uint32_t secs = 0;
        if (devfs_block_get(i, name, sizeof(name), &did, &secs) == 0)
            klogprintf("  /dev/%s disk_id=%d sectors=%u\n", name, did, (unsigned)secs);
    }
    (void)usb_publish_devfs_nodes();
    boot_attach_stdio();
}

static void boot_populate_etc(void)
{
    static const char root_passwd_line[] = "root:x:0:0:root:/root:/bin/sh\n";
    static const char root_group_line[] = "root:x:0:\nusers:x:100:\n";
    static const char root_shadow[] = "root::0:0:99999:7:::\n";
    static const char root_gshadow[] = "root::\nusers::\n";
    static const char nsswitch[] =
        "passwd: files\n"
        "group: files\n"
        "shadow: files\n"
        "gshadow: files\n"
        "hosts: files dns\n"
        "networks: files\n"
        "protocols: files\n"
        "services: files\n"
        "ethers: files\n"
        "rpc: files\n"
        "netgroup: files\n";
    static const char hosts_min[] = "127.0.0.1\tlocalhost\n";
    static const char host_conf[] = "order hosts,bind\nmulti on\n";
    static const char gai_conf[] =
        "precedence  ::1/128       50\n"
        "precedence  ::/0          40\n"
        "precedence  ::ffff:0:0/96 100\n";
    static const char profile[] =
        "export TERM=builtin_ansi\n"
        "export PS1='\\[\\033[1;31m\\]\\u\\033[0m@\\h \\033[1;37m\\w\\033[0m \\$ '\n"
        "export OPENSSL_CONF=/etc/ssl/openssl.cnf\n"
        "export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n"
        "export SSL_CERT_DIR=/etc/ssl/certs\n";
    static const char issue[] = "AxonOS " OS_VERSION " (\\l)\n\n";
    static const char securetty[] = "console\ntty1\ntty2\ntty3\ntty4\ntty5\ntty6\nttyS0\nttyS1\n";
    static const char motd[] =
        "\nWelcome to " OS_NAME " " OS_VERSION "\n"
        "  * Website: https://axont.ru\n"
        "  * GitHub: https://github.com/fcexx/AxonOS.git\n"
        "  * AxonHub: https://axont.ru/axonhub\n"
        "Feedback on axont@axont.ru\n\n";
    static const char termcap[] =
        "vt102|vt100|linux|linux-term:"
        "co#160:li#50:cl=\\E[2J\\E[H:cm=\\E[%i%d;%dH:nd=\\E[C:up=\\E[A:"
        "ce=\\E[K:cd=\\E[J:so=\\E[7m:se=\\E[0m:us=\\E[4m:ue=\\E[0m:"
        "ku=\\E[A:kd=\\E[B:kr=\\E[C:kl=\\E[D:"
        "ti=\\E[?1049h:te=\\E[?1049l:\n";

    (void)ramfs_mkdir("/etc");
    ramfs_write_bytes("/etc/passwd", root_passwd_line, sizeof(root_passwd_line) - 1);
    ramfs_write_bytes("/etc/group", root_group_line, sizeof(root_group_line) - 1);
    ramfs_write_bytes("/etc/shadow", root_shadow, sizeof(root_shadow) - 1);
    ramfs_write_bytes("/etc/gshadow", root_gshadow, sizeof(root_gshadow) - 1);

    (void)ramfs_mkdir("/var");
    (void)ramfs_mkdir("/var/run");
    (void)ramfs_mkdir("/var/log");
    (void)ramfs_mkdir("/tmp");
    (void)ramfs_mkdir("/var/tmp");
    (void)fs_chmod("/tmp", S_IFDIR | 01777);
    (void)fs_chmod("/var/tmp", S_IFDIR | 01777);
    ramfs_touch("/var/log/wtmp");

    (void)fs_unlink("/etc/nsswitch.conf");
    ramfs_write_bytes("/etc/nsswitch.conf", nsswitch, sizeof(nsswitch) - 1);
    (void)fs_unlink("/etc/hosts");
    ramfs_write_bytes("/etc/hosts", hosts_min, sizeof(hosts_min) - 1);
    (void)fs_unlink("/etc/host.conf");
    ramfs_write_bytes("/etc/host.conf", host_conf, sizeof(host_conf) - 1);
    (void)fs_unlink("/etc/gai.conf");
    ramfs_write_bytes("/etc/gai.conf", gai_conf, sizeof(gai_conf) - 1);

    syscall_net_ensure_resolv();
    ramfs_install_libnss_dns();
    ramfs_touch("/etc/localtime");

    ramfs_write_bytes("/etc/profile", profile, sizeof(profile) - 1);
    ramfs_write_bytes("/etc/issue", issue, sizeof(issue) - 1);
    ramfs_write_bytes("/etc/securetty", securetty, sizeof(securetty) - 1);
    ramfs_write_bytes("/etc/motd", motd, sizeof(motd) - 1);
    ramfs_write_bytes("/etc/termcap", termcap, sizeof(termcap) - 1);
}

static void boot_install_addgroup_wrapper(void)
{
    struct stat st;
    static const char addgroup_wrapper[] = "#!/bin/sh\nshift\nexec /usr/sbin/addgroup \"$@\"\n";

    if (vfs_stat("/sbin/addgroup", &st) == 0 || vfs_stat("/usr/sbin/addgroup", &st) != 0)
        return;
    (void)ramfs_mkdir("/sbin");
    ramfs_write_bytes("/sbin/addgroup", addgroup_wrapper, sizeof(addgroup_wrapper) - 1);
}

static int boot_unpack_initfs(uint64_t boot_params_phys)
{
    struct stat st;
    int r = initfs_process_linux_bootparams(boot_params_phys);

    if (r != 0) {
        klogprintf("initfs: error: failed, code: %d\n", r);
        for (;;)
            ;
    }

    klogprintf("initfs: unpacked successfully\n");
    initfs_debug_list_vfs();
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
    return 0;
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info)
{
    static __attribute__((aligned(4096))) uint8_t axon_synth_bootparams[LINUX_BOOTPARAM_MIN_SIZE];
    uint64_t axon_boot_params_phys = 0;
    int vbe_init = 0;

    qemu_debug_printf("Kernel started\n");
    enable_cursor();
    sysinfo_init(multiboot_magic, multiboot_info);

    if (multiboot_magic == 0x36d76289u && multiboot_info != 0) {
        if (mb2_linux_shim_fill_bootparams(multiboot_magic, multiboot_info, axon_synth_bootparams,
                                           sizeof axon_synth_bootparams, "initfs") == 0)
            axon_boot_params_phys = (uint64_t)(uintptr_t)axon_synth_bootparams;
    }

    boot_init_heap(multiboot_magic, multiboot_info, axon_boot_params_phys);

    gdt_init();
    smp_init(multiboot_magic, multiboot_info);
    boot_init_df_stacks();
    vbe_init = boot_init_vbe(multiboot_magic, multiboot_info);

    idt_init();
    pic_init();
    pit_init();

    mmio_init();
    ramfs_register();
    ext2_register();

    klog_init();
    klogprintf(OS_NAME " v" OS_VERSION ".\n");
    sysinfo_print_platform();
    sysinfo_print_dmi();
    sysinfo_print_e820(multiboot_magic, multiboot_info);
    if (vbe_is_available() == 1)
        klogprintf("screen: Set mode: %ux%u@%u.\n", vbe_get_width(), vbe_get_height(), vbe_get_bpp());
    else
        klogprintf("screen: Set VGA+ 80x25 16 colors\n");

    (void)acpi_powerbtn_init(multiboot_magic, multiboot_info);

    apic_init();
    apic_timer_init();
    idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);
    syscall_init();
    paging_init();

    asm volatile("sti");
    apic_timer_calibrate();
    klog_calibrate_tsc();
    boot_select_timer();

    smp_finalize_topology(multiboot_magic, multiboot_info);
    pci_init();
    boot_init_video_early();
    pci_dump_devices();
    intel_chipset_init();
    usb_init();

    thread_init();
    smp_boot_aps();
    iothread_init();
    user_init();
    fat32_register();

    if (e1000_init() != 0) {
        klogprintf("net: e1000 not found\n");
    } else {
        int nrc = syscall_net_preinit();
        klogprintf("net: preinit %s\n", (nrc == 0) ? "ok" : "failed");
    }

    boot_unpack_initfs(axon_boot_params_phys);
    klogprintf("boot: post-initfs setup (devfs, disks, /etc)...\n");

    boot_init_devfs();
    boot_populate_etc();
    boot_install_addgroup_wrapper();

    ps2_keyboard_init();
    ps2_mouse_init();
    boot_logo_dismiss();

    if (boot_try_run_init() != 0) {
        klogprintf("fatal: There's nothing to run. Download the correct initfs from https://apm.axont.ru/Packages/initfs.cpio and place it in the root of the boot device.");
    }

    for (;;)
        asm volatile("sti; hlt" ::: "memory");
}
