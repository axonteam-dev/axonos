#pragma once

#include <stddef.h>
#include <stdint.h>

typedef unsigned long ino_t;
typedef unsigned int mode_t;
typedef unsigned int nlink_t;
typedef unsigned long dev_t; /* Linux-compatible device identity for stat/fstat. */
typedef long off_t;
typedef long time_t;

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    unsigned int st_uid;
    unsigned int st_gid;
    dev_t st_rdev; /* Linux: encoded major/minor for char/block nodes */
    off_t st_size;
    time_t st_atime;
    time_t st_mtime;
    time_t st_ctime;
};

/* Linux makedev for small majors (fb=29, tty=4, …) — matches glibc new_encode_dev for maj<0x1000, min<0x100. */
#ifndef MKDEV
#define MKDEV(ma, mi) ((dev_t)((((dev_t)(ma) & 0xfffu) << 8) | ((dev_t)(mi) & 0xffu)))
#endif
#ifndef FB_MAJOR
#define FB_MAJOR 29
#endif

/* File type macros */
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif

/* Device special files (needed for /dev block/char nodes) */
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif


