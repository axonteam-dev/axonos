/* initfs.h — initrd via Linux boot_params (ramdisk_image/size).
 * Preferred: SquashFS image mounted RO under overlay (upper=ramfs).
 * Fallback: legacy cpio newc unpack into ramfs. */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Mount (squashfs) or unpack (cpio) initrd from Linux zeropage at boot_params_phys.
 * Returns 0 on success, negative on error, 2/3 on missing/invalid boot_params. */
int initfs_process_linux_bootparams(uint64_t boot_params_phys);

/* First physical byte after the initrd region (4 KiB aligned), or 0 if none / invalid. */
uintptr_t initfs_linux_ramdisk_exclusive_end(uint64_t boot_params_phys);

void initfs_debug_list_vfs(void);
