#pragma once

#include <stddef.h>
#include <stdint.h>
#include <spinlock.h>
#include <axonos.h>

#define SYSV_SHM_MAX_SEGMENTS 64
#define SYSV_SHM_MAX_ATTACH   256
#define SYSV_SHM_BASE         ((uintptr_t)0x0E000000ULL)

typedef struct {
    int used;
    int shmid;
    int key;
    size_t size;
    uintptr_t base;
    uint32_t mode;
    uid_t cuid;
    gid_t cgid;
    uid_t uid;
    gid_t gid;
    uint32_t cpid;
    uint32_t lpid;
    uint64_t atime;
    uint64_t dtime;
    uint64_t ctime;
    uint32_t nattch;
    int removed;
} sysv_shm_seg_t;

typedef struct {
    int used;
    int shmid;
    uint64_t tid;
    uintptr_t addr;
    int readonly;
} sysv_shm_attach_t;

struct sysv_ipc_perm_compat {
    uint32_t key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint16_t mode;
    uint16_t __pad1;
    uint16_t seq;
    uint16_t __pad2;
    uint64_t __unused1;
    uint64_t __unused2;
};

struct sysv_shmid_ds_compat {
    struct sysv_ipc_perm_compat shm_perm;
    uint64_t shm_segsz;
    int64_t shm_atime;
    int64_t shm_dtime;
    int64_t shm_ctime;
    int32_t shm_cpid;
    int32_t shm_lpid;
    uint64_t shm_nattch;
    uint64_t __unused4;
    uint64_t __unused5;
};

extern sysv_shm_seg_t g_sysv_shm[SYSV_SHM_MAX_SEGMENTS];
extern sysv_shm_attach_t g_sysv_shm_attach[SYSV_SHM_MAX_ATTACH];
extern int g_sysv_shm_next_id;
extern uintptr_t g_sysv_shm_next_addr;
extern spinlock_t g_sysv_shm_lock;

uint64_t sysv_shm_now_secs(void);
sysv_shm_seg_t *sysv_shm_find_by_id_nolock(int shmid);
sysv_shm_seg_t *sysv_shm_find_by_key_nolock(int key);
uintptr_t sysv_shm_alloc_va_nolock(size_t size);
int sysv_shm_register_attach_nolock(int shmid, uint64_t tid, uintptr_t addr, int readonly);
int sysv_shm_detach_one_by_tid_addr_nolock(uint64_t tid, uintptr_t addr, int *out_shmid);
void sysv_shm_cleanup_removed_nolock(sysv_shm_seg_t *seg);
void sysv_shm_detach_all_for_tid(uint64_t tid);
