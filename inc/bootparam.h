/* bootparam.h — subset of Linux x86 boot protocol (zeropage) for initrd */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* setup_header.header ("HdrS") at boot_params + 0x202 */
#define LINUX_BOOTPARAM_HEADER_MAGIC 0x53726448u

/* ramdisk_image / ramdisk_size live in setup_header (boot_params + 0x218 / 0x21c).
 * High halves are in boot_params.ext_ramdisk_* (NOT in setup_header), per Linux uapi. */
#define LINUX_BOOTPARAM_OFF_HDR_MAGIC   0x202u
#define LINUX_BOOTPARAM_OFF_RAMDISK_IMG 0x218u
#define LINUX_BOOTPARAM_OFF_RAMDISK_SZ  0x21cu
#define LINUX_BOOTPARAM_OFF_EXT_RD_IMG  0x0c0u
#define LINUX_BOOTPARAM_OFF_EXT_RD_SZ   0x0c4u

/* Smallest buffer Linux bootloaders use for boot_params; shim uses the same size. */
#define LINUX_BOOTPARAM_MIN_SIZE 4096u

/* Historical kzip low reloc window (kept for heap floor when no initrd).
 * Large SquashFS images are now parked under top-of-RAM by boot/kzip_stub.c
 * before the payload ELF is loaded — do not assume modules live here. */
#define AXON_MB2_MODULE_RELOC_BASE 0x02000000u
#define AXON_MB2_MODULE_RELOC_CEIL 0x05000000u

/* Max initrd size from GRUB module2 / mb2_linux_shim (was 512 MiB — too small for large initfs). */
#define AXON_INITRD_SIZE_MAX ((uint64_t)(2048u * 1024u * 1024u))

/* Returns 0 and fills *start_out/*size_out (physical initrd region) if HdrS present and size != 0. */
int linux_bootparams_ramdisk(const void *boot_params, uintptr_t *start_out, size_t *size_out);
