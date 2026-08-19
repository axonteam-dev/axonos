#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <stat.h>
#include <heap.h>
#include <vga.h>
#include <ext2.h>
/* driver-specific stat helpers */
#include <sysfs.h>
#include <ramfs.h>
#include <procfs.h>
#include <devfs.h>
#include <fat32.h>
#include <minix.h>
#include <isofs.h>
#include <squashfs.h>
#include <overlayfs.h>
#include <ns.h>
#include <cgroup.h>

#ifndef EIO
#define EIO 5
#endif

#define MAX_FS_DRIVERS 16

static struct fs_driver *g_drivers[MAX_FS_DRIVERS];
static int g_drivers_count = 0;

int fs_mount_count(void) {
        int *cnt = NULL;
        (void)ns_mnt_vec(&cnt);
        return cnt ? *cnt : 0;
}

int fs_mount_get(int index, char *out_path, size_t out_path_len, char *out_fs_name, size_t out_fs_name_len) {
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        struct ns_mount *m;
        if (!cnt || index < 0 || index >= *cnt || !vec) return -1;
        if (!out_path || out_path_len == 0 || !out_fs_name || out_fs_name_len == 0) return -1;

        m = &vec[index];
        if (!m->driver || !m->driver->ops || !m->driver->ops->name) return -1;

        size_t plen = strlen(m->path);
        if (plen >= out_path_len) plen = out_path_len - 1;
        memcpy(out_path, m->path, plen);
        out_path[plen] = '\0';

        const char *fsn = m->driver->ops->name;
        size_t flen = strlen(fsn);
        if (flen >= out_fs_name_len) flen = out_fs_name_len - 1;
        memcpy(out_fs_name, fsn, flen);
        out_fs_name[flen] = '\0';
        return 0;
}

int fs_get_mount_children(const char *dir_path, char names[][64], int max_count) {
        if (!dir_path || !names || max_count <= 0) return 0;

        /* normalize dir_path into a small fixed buffer */
        char dir[64];
        size_t dlen = strlen(dir_path);
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        if (dlen == 0) return 0;
        if (dlen >= sizeof(dir)) dlen = sizeof(dir) - 1;
        memcpy(dir, dir_path, dlen);
        dir[dlen] = '\0';
        /* strip trailing slashes (except root) */
        while (dlen > 1 && dir[dlen - 1] == '/') {
                dir[dlen - 1] = '\0';
                dlen--;
        }
        if (dlen == 0) { dir[0] = '/'; dir[1] = '\0'; dlen = 1; }

        int out = 0;
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count && out < max_count; i++) {
                if (!vec[i].driver) continue;
                if (vec[i].path[0] != '/') continue;

                /* normalize mount path (strip trailing slashes) */
                char mp[64];
                size_t mlen = vec[i].path_len;
                if (mlen == 0) continue;
                if (mlen >= sizeof(mp)) mlen = sizeof(mp) - 1;
                memcpy(mp, vec[i].path, mlen);
                mp[mlen] = '\0';
                while (mlen > 1 && mp[mlen - 1] == '/') {
                        mp[mlen - 1] = '\0';
                        mlen--;
                }
                if (strcmp(mp, "/") == 0) continue;

                const char *slash = strrchr(mp, '/');
                if (!slash) continue;

                char parent[64];
                const char *child = slash + 1;
                if (!child[0]) continue;
                if (strchr(child, '/')) continue; /* must be direct child */

                if (slash == mp) {
                        parent[0] = '/';
                        parent[1] = '\0';
                } else {
                        size_t plen = (size_t)(slash - mp);
                        if (plen >= sizeof(parent)) plen = sizeof(parent) - 1;
                        memcpy(parent, mp, plen);
                        parent[plen] = '\0';
                }

                if (strcmp(parent, dir) != 0) continue;

                /* de-dup */
                int dup = 0;
                for (int j = 0; j < out; j++) {
                        if (strncmp(names[j], child, 64) == 0) { dup = 1; break; }
                }
                if (dup) continue;

                strncpy(names[out], child, 63);
                names[out][63] = '\0';
                out++;
        }
        return out;
}

static void fs_ensure_ramfs_mountpoint_dir(const char *path) {
        if (!path || path[0] != '/') return;
        char tmp[64];
        size_t len = strlen(path);
        if (len == 0) return;
        if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;

        memcpy(tmp, path, len);
        tmp[len] = '\0';

        // drop trailing slashes (except for "/")
        while (len > 1 && tmp[len - 1] == '/') {
                tmp[len - 1] = '\0';
                len--;
        }

        // create intermediate prefixes: /a, /a/b, ... 
        for (size_t i = 1; i < len; i++) {
                if (tmp[i] == '/') {
                        tmp[i] = '\0';
                        (void)ramfs_mkdir(tmp);
                        tmp[i] = '/';
                }
        }

        (void)ramfs_mkdir(tmp);
}

/* Linux: mount "/" covers every absolute path. The old check required
 * path[mp_len] to be '\0' or '/', so path[1] on "/var/..." is 'v' and
 * overlay on "/" never matched. Then fs_create_file fell through to
 * ramfs_create, which cannot see squashfs-only parents and returns -2
 * (ENOENT) — apt's mkstemp(/var/cache/apt/srcpkgcache.bin.XXXXXX). */
static int fs_mount_covers_path(const char *path, size_t path_len,
                                const char *mp, size_t mp_len)
{
        if (!path || !mp || path_len < mp_len)
                return 0;
        if (strncmp(path, mp, mp_len) != 0)
                return 0;
        if (mp_len == 1 && mp[0] == '/')
                return path[0] == '/';
        return path[mp_len] == '\0' || path[mp_len] == '/';
}

static struct fs_driver *fs_match_mount(const char *path) {
        if (!path) return NULL;
        size_t path_len = strlen(path);
        struct fs_driver *best = NULL;
        size_t best_len = 0;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                struct ns_mount *m = &vec[i];
                if (!m->driver) continue;
                if (!fs_mount_covers_path(path, path_len, m->path, m->path_len))
                        continue;
                if (m->path_len > best_len) {
                        best = m->driver;
                        best_len = m->path_len;
                }
        }
        return best;
}

/* Public wrapper to get mounted driver for a given path */
struct fs_driver *fs_get_mount_driver(const char *path) {
        return fs_match_mount(path);
}

struct fs_driver *fs_get_mount_driver_exact(const char *path) {
        if (!path) return NULL;
        size_t len = strlen(path);
        while (len > 1 && path[len - 1] == '/')
                len--;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                struct ns_mount *m = &vec[i];
                if (!m->driver) continue;
                if (m->path_len != len) continue;
                if (strncmp(m->path, path, len) == 0)
                        return m->driver;
        }
        return NULL;
}

int fs_get_mount_index(const char *path) {
        if (!path) return -1;
        size_t path_len = strlen(path);
        size_t best_len = 0;
        int best = -1;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                struct ns_mount *m = &vec[i];
                if (!m->driver) continue;
                if (!fs_mount_covers_path(path, path_len, m->path, m->path_len))
                        continue;
                if (m->path_len > best_len) {
                        best_len = m->path_len;
                        best = i;
                }
        }
        return best;
}

/* helper: returns true if file is associated with driver 'drv'.
   file->fs_private may point to drv->driver_data or to drv itself.
   Never treat NULL==NULL as a match: pipe ends and unset mounts must not
   be claimed by drivers with driver_data==NULL (ext2). */
static int fs_file_matches_driver(const struct fs_driver *drv, const struct fs_file *file) {
        if (!drv || !file || !file->fs_private) return 0;
        if (file->type == FS_TYPE_PIPE || file->type == FS_TYPE_SOCKET)
                return 0;
        if (file->fs_private == drv->driver_data) return 1;
        if (file->fs_private == (void*)drv) return 1;
        return 0;
}

int fs_get_mount_path(const struct fs_driver *drv, char *out, size_t outlen) {
        if (!drv || !out || outlen == 0) return -1;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                if (vec[i].driver == drv) {
                        size_t len = vec[i].path_len;
                        if (len >= outlen) return -1;
                        memcpy(out, vec[i].path, len);
                        out[len] = '\0';
                        return 0;
                }
        }
        return -1;
}

/* Return the mount prefix that best matches the provided path (longest match).
   Writes prefix into out (null-terminated). Returns 0 on success, -1 if none. */
int fs_get_matching_mount_prefix(const char *path, char *out, size_t outlen) {
        if (!path || !out || outlen == 0) return -1;
        size_t path_len = strlen(path);
        size_t best_len = 0;
        const char *best = NULL;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                struct ns_mount *m = &vec[i];
                if (!m->driver) continue;
                if (!fs_mount_covers_path(path, path_len, m->path, m->path_len))
                        continue;
                if (m->path_len > best_len) {
                        best_len = m->path_len;
                        best = m->path;
                }
        }
        if (!best) return -1;
        if (best_len >= outlen) return -1;
        memcpy(out, best, best_len);
        out[best_len] = '\0';
        return 0;
}

int fs_register_driver(struct fs_driver *drv) {
        if (!drv || !drv->ops) return -1;
        for (int i = 0; i < g_drivers_count; i++) {
                if (g_drivers[i] == drv)
                        return 0; /* already registered */
        }
        if (g_drivers_count >= MAX_FS_DRIVERS) return -1;
        g_drivers[g_drivers_count++] = drv;
        return 0;
}

int fs_unregister_driver(struct fs_driver *drv) {
        for (int i = 0; i < g_drivers_count; i++) {
                if (g_drivers[i] == drv) {
                        for (int j = i; j + 1 < g_drivers_count; j++) g_drivers[j] = g_drivers[j+1];
                        g_drivers[--g_drivers_count] = NULL;
                        return 0;
                }
        }
        return -1;
}

int fs_mount(const char *path, struct fs_driver *drv) {
        if (!path || !drv) return -1;
        size_t len = strlen(path);
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count;
        if (len == 0 || len >= sizeof(vec[0].path)) return -1;
        mount_count = cnt ? *cnt : 0;
        /* Linux: remounting the same fstype on the same path is a no-op success for
         * our virtual mounts; a different driver on a busy mountpoint is EBUSY. */
        for (int i = 0; i < mount_count; i++) {
                if (vec[i].path_len == len && strcmp(vec[i].path, path) == 0) {
                        if (vec[i].driver == drv)
                                return 0;
                        return -1; /* busy: something else already mounted here */
                }
        }
        if (mount_count >= NS_MNT_MAX) return -1;

        // Make mountpoint visible in ramfs directory listings
        fs_ensure_ramfs_mountpoint_dir(path);
        strcpy(vec[mount_count].path, path);
        vec[mount_count].path_len = len;
        vec[mount_count].driver = drv;
        if (cnt)
                (*cnt)++;
        return 0;
}

int fs_mkdir(const char *path) {
        if (!path) return -1;
        struct fs_driver *mount_drv = fs_match_mount(path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->mkdir) {
                int r = mount_drv->ops->mkdir(path);
                if (r == 0) return 0;
                if (r < 0) return r;
        }

        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->mkdir) continue;
                int r = drv->ops->mkdir(path);
                if (r == 0) return 0;
                if (r < 0 && r != -1) return r;
        }
        return -1;
}

int fs_unmount(const char *path) {
        if (!path) return -1;
        int *cnt = NULL;
        struct ns_mount *vec = ns_mnt_vec(&cnt);
        int mount_count = cnt ? *cnt : 0;
        for (int i = 0; i < mount_count; i++) {
                if (strcmp(vec[i].path, path) == 0) {
                        for (int j = i; j + 1 < mount_count; j++) vec[j] = vec[j+1];
                        vec[--mount_count].driver = NULL;
                        vec[mount_count].path[0] = '\0';
                        vec[mount_count].path_len = 0;
                        if (cnt)
                                *cnt = mount_count;
                        return 0;
                }
        }
        return -1;
}

static void fs_file_mark_opened(struct fs_file *file) {
        if (!file) return;
        if (file->refcount < 1) file->refcount = 1;
}

struct fs_file *fs_open_nofollow(const char *path) {
        if (!path) return NULL;
        struct fs_driver *mount_drv = fs_match_mount(path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->open) {
                struct fs_file *file = NULL;
                int rr = mount_drv->ops->open(path, &file);

                if (rr == 0 && file) {
                        if (!file->fs_private) file->fs_private = (void*)mount_drv;
                        fs_file_mark_opened(file);
                        return file;
                }

                return NULL;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->open) continue;

                struct fs_file *file = NULL;
                int r = drv->ops->open(path, &file);

                if (r == 0 && file) {
                        struct fs_driver *m = fs_match_mount(path);

                        if (m && m->ops && m->ops->open) {
                                struct fs_file *mount_file = NULL;
                                if (m->ops->open(path, &mount_file) == 0 && mount_file) {
                                        if (!mount_file->fs_private) mount_file->fs_private = (void*)m;

                                        fs_file_mark_opened(file);
                                        fs_file_free(file);
                                        fs_file_mark_opened(mount_file);
                                        return mount_file;
                                }
                        }
                        if (!file->fs_private) file->fs_private = (void*)drv;
                        fs_file_mark_opened(file);
                        return file;
                }
                if (r < 0 && r != -1) return NULL; // real error
        }
        return NULL;
}

static int fs_readlink_no_resolve(const char *path, char *out, size_t out_cap, size_t *out_len) {
        if (!path || !out || out_cap == 0) return -1;
        struct fs_file *lf = fs_open_nofollow(path);
        if (!lf) return -1;
        struct stat st;
        int sr = vfs_fstat(lf, &st);
        if (sr != 0 || ((st.st_mode & S_IFLNK) != S_IFLNK)) {
                fs_file_free(lf);
                return -1;
        }
        size_t sz = (size_t)lf->size;
        if (sz == 0) { fs_file_free(lf); return -1; }
        if (sz >= out_cap) sz = out_cap - 1;
        ssize_t rr = fs_read(lf, out, sz, 0);
        fs_file_free(lf);
        if (rr <= 0) return -1;
        out[(size_t)rr] = '\0';
        if (out_len) *out_len = (size_t)rr;
        return 0;
}

/* Normalize an absolute path:
   - collapse repeated '/'
   - remove '.' components
   - resolve '..' components (without going above '/')
   Returns newly allocated string (caller must kfree), or NULL on OOM. */
static char *fs_normalize_abs_path(const char *in) {
        if (!in) return NULL;
        if (in[0] != '/') {
                /* only absolute supported here */
                char *cp = (char*)kmalloc(strlen(in) + 1);
                if (cp) strcpy(cp, in);
                return cp;
        }
        const char *parts[96];
        size_t plen[96];
        int pc = 0;
        const char *p = in;
        while (*p) {
                while (*p == '/') p++;
                if (!*p) break;
                const char *seg = p;
                while (*p && *p != '/') p++;
                size_t len = (size_t)(p - seg);
                if (len == 0) continue;
                if (len == 1 && seg[0] == '.') {
                        /* skip */
                } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
                        if (pc > 0) pc--;
                } else {
                        if (pc < (int)(sizeof(parts)/sizeof(parts[0]))) {
                                parts[pc] = seg;
                                plen[pc] = len;
                                pc++;
                        }
                }
        }
        /* compute size */
        size_t out_len = 1; /* leading '/' */
        for (int i = 0; i < pc; i++) out_len += plen[i] + 1;
        if (out_len < 2) out_len = 2;
        char *out = (char*)kmalloc(out_len);
        if (!out) return NULL;
        size_t w = 0;
        out[w++] = '/';
        for (int i = 0; i < pc; i++) {
                if (w > 1 && out[w - 1] != '/') out[w++] = '/';
                memcpy(out + w, parts[i], plen[i]);
                w += plen[i];
                out[w] = '\0';
                if (i + 1 < pc) out[w++] = '/';
        }
        if (w == 0) { out[0] = '/'; w = 1; }
        out[w] = '\0';
        return out;
}

/* Resolve symlinks anywhere in the path (like a simplified realpath).
   - follows up to 16 symlinks
   - follows symlinks in intermediate components always
   - follows final symlink too (for open/exec)
   Returns newly allocated absolute path on success; caller must kfree(). */
static char *fs_resolve_symlinks(const char *path) {
        if (!path) return NULL;
        char *cur = (char*)kmalloc(strlen(path) + 1);
        if (!cur) return NULL;
        strcpy(cur, path);

        for (int depth = 0; depth < 16; depth++) {
                /* Walk prefixes: /a, /a/b, /a/b/c ... and detect first symlink. */
                if (cur[0] != '/') return cur;
                size_t len = strlen(cur);
                size_t i = 1;
                int restarted = 0;
                while (i < len) {
                        while (i < len && cur[i] == '/') i++;
                        if (i >= len) break;
                        size_t comp_end = i;
                        while (comp_end < len && cur[comp_end] != '/') comp_end++;

                        /* prefix = cur[0:comp_end] */
                        size_t prefix_len = comp_end;
                        char *prefix = (char*)kmalloc(prefix_len + 1);
                        if (!prefix) { kfree(cur); return NULL; }
                        memcpy(prefix, cur, prefix_len);
                        prefix[prefix_len] = '\0';

                        struct fs_file *pf = fs_open_nofollow(prefix);
                        if (!pf) {
                                /* prefix does not exist -> stop resolving and return current path */
                                kfree(prefix);
                                return cur;
                        }
                        struct stat st;
                        int sr = vfs_fstat(pf, &st);
                        fs_file_free(pf);
                        if (sr != 0) { kfree(prefix); return cur; }

                        if ((st.st_mode & S_IFLNK) == S_IFLNK) {
                                /* read link target */
                                char target[512];
                                size_t tlen = 0;
                                if (fs_readlink_no_resolve(prefix, target, sizeof(target), &tlen) != 0) {
                                        kfree(prefix);
                                        return cur;
                                }

                                /* remaining path after this component (including leading slash if any) */
                                const char *rest = (comp_end < len) ? (cur + comp_end) : "";

                                /* build base path from target (absolute or relative-to-parent) */
                                char base[768];
                                if (target[0] == '/') {
                                        strncpy(base, target, sizeof(base) - 1);
                                        base[sizeof(base) - 1] = '\0';
                                } else {
                                        /* parent directory of prefix */
                                        const char *slash = strrchr(prefix, '/');
                                        size_t plen = slash ? (size_t)(slash - prefix) : 0;
                                        if (plen == 0) plen = 1;
                                        if (plen >= sizeof(base) - 2) plen = sizeof(base) - 2;
                                        memcpy(base, prefix, plen);
                                        base[plen] = '\0';
                                        if (plen == 1) { base[0] = '/'; base[1] = '\0'; }
                                        size_t bl = strlen(base);
                                        if (bl > 1 && base[bl - 1] == '/') base[bl - 1] = '\0';
                                        bl = strlen(base);
                                        if (bl + 1 < sizeof(base)) { base[bl] = '/'; base[bl + 1] = '\0'; }
                                        strncat(base, target, sizeof(base) - strlen(base) - 1);
                                }

                                /* join base + rest */
                                size_t newcap = strlen(base) + strlen(rest) + 2;
                                char *newp = (char*)kmalloc(newcap);
                                if (!newp) { kfree(prefix); kfree(cur); return NULL; }
                                strcpy(newp, base);
                                if (rest[0]) {
                                        size_t bl = strlen(newp);
                                        if (bl > 0 && newp[bl - 1] == '/' && rest[0] == '/') {
                                                strncat(newp, rest + 1, newcap - strlen(newp) - 1);
                                        } else {
                                                strncat(newp, rest, newcap - strlen(newp) - 1);
                                        }
                                }

                                kfree(prefix);
                                kfree(cur);
                                /* normalize (handle ../ in symlink target) */
                                {
                                        char *norm = fs_normalize_abs_path(newp);
                                        kfree(newp);
                                        if (!norm) return NULL;
                                        cur = norm;
                                }
                                restarted = 1;
                                break; /* restart outer depth loop */
                        }

                        kfree(prefix);
                        i = comp_end;
                }
                if (!restarted) return cur;
        }
        return cur;
}

/* Try drivers in registration order. Drivers should return -1 if they do not handle the path. */
struct fs_file *fs_create_file(const char *path) {
        if (!path) return NULL;
        struct fs_driver *mount_drv = fs_match_mount(path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->create) {
                struct fs_file *file = NULL;
                if (mount_drv->ops->create(path, &file) == 0) {
                        if (file) file->refcount = 1;
                        return file;
                }
                /* This mount owns the path. Do not fall through to ramfs_create:
                 * a squashfs-only parent makes ramfs return -2 and used to abort
                 * before overlay_create could copy-up the directory chain. */
                return NULL;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->create) continue;
                struct fs_file *file = NULL;
                int r = drv->ops->create(path, &file);
                if (r == 0 && file) {
                        /* driver should set file->fs_private to drv->driver_data if needed */
                        file->refcount = 1;
                        return file;
                }
                if (r < 0 && r != -1) {
                        /* real error, stop */
                        return NULL;
                }
                /* r == -1 -> not handled, try next */
        }
        return NULL;
}

struct fs_file *fs_open(const char *path) {
        if (!path) return NULL;
        int dbg = 0;
        int direct_miss = 0;

        /* Fast path: most paths have no symlinks. Try direct open first. */
        struct fs_file *f = fs_open_nofollow(path);
        if (f) {
                /* Git's .git/ paths should never need symlink resolution; avoid heavy resolve path. */
                if (strstr(path, "/.git/") != NULL) {
                        return f;
                }
                struct stat st;
                int sr = vfs_fstat(f, &st);
                if (sr == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
                        return f;  /* regular file or dir, no resolution needed */
                }
                /* Linux nsfs: open(/proc/pid/ns/X) does not follow the magic link. */
                if (sr == 0 && ns_path_is_proc_ns(path))
                        return f;
                /* Symlink, or stat failed (driver didn't fill st_mode): resolve before returning.
                   ld.so open()+read() on an unresolved symlink reads the link text, not the ELF. */
                fs_file_free(f);
        } else {
                direct_miss = 1;
        }

        /* Git's .git/ paths should never need symlink resolution; if not found directly,
           treat as missing instead of walking prefixes (can hang under concurrent ops). */
        if (strstr(path, "/.git/") != NULL) {
                return NULL;
        }

        char *resolved_path = fs_resolve_symlinks(path);
        if (!resolved_path) return NULL;
        /*
         * The exact path was already looked up above. If resolving prefixes
         * found no symlink and did not rewrite it, a second full overlay and
         * SquashFS lookup can only return the same ENOENT.
         */
        if (direct_miss && strcmp(resolved_path, path) == 0) {
                kfree(resolved_path);
                return NULL;
        }

        struct fs_file *result = NULL;
        struct fs_driver *mount_drv = fs_match_mount(resolved_path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->open) {
                struct fs_file *file = NULL;
                int rr = mount_drv->ops->open(resolved_path, &file);
                if (rr == 0 && file) {
                        if (!file->fs_private) file->fs_private = (void*)mount_drv;
                        result = file;
                } else {
                        /* Path is under a mount; do not fall through so /dev returns devfs, not empty ramfs */
                        kfree(resolved_path);
                        return NULL;
                }
        }

        if (!result) {
                for (int i = 0; i < g_drivers_count; i++) {
                        struct fs_driver *drv = g_drivers[i];
                        if (!drv || !drv->ops || !drv->ops->open) continue;
                        struct fs_file *file = NULL;
                        int r = drv->ops->open(resolved_path, &file);
                        if (r == 0 && file) {
                                if (!file->fs_private) file->fs_private = (void*)drv;
                                result = file;
                                break;
                        }
                        if (r < 0 && r != -1) break;
                }
        }

        kfree(resolved_path);
        fs_file_mark_opened(result);
        return result;
}

ssize_t fs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
        if (!file || !file->path) return -EIO;
        /* debug logging removed */
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops) continue;
                /* debug logging removed */
                if (!fs_file_matches_driver(drv, file)) continue;
                /* debug logging removed */
                if (!drv->ops->read) return -EIO;
                ssize_t rr = drv->ops->read(file, buf, size, offset);
                if (rr < 0 && rr == -1) return -EIO;
                return rr;
        }
        return -EIO;
}

ssize_t fs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
        if (!file || !file->path) return -1;
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !fs_file_matches_driver(drv, file)) continue;
                if (!drv->ops->write) return -1;
                return drv->ops->write(file, buf, size, offset);
        }
        return -1;
}

void fs_file_get(struct fs_file *file) {
        if (!file) return;
        if (file->refcount < 1) file->refcount = 1;
        else file->refcount++;
}

void fs_file_free(struct fs_file *file) {
        if (!file) return;
        /* reference-counted: decrement and only free when zero */
        if (file->refcount > 1) { file->refcount--; return; }
        if (file->refcount < 1) {
#if !AXON_PRODUCTION
                static int warn_left = 8;
                if (warn_left-- > 0)
                        kprintf("fs_file_free: refcount=%d path=%s (skip)\n",
                                file->refcount, file->path ? file->path : "(null)");
#endif
                return;
        }
        file->refcount = 0;
        if (file->type == FS_TYPE_PIPE) {
                pipe_release_end(file);
                if (file->path)
                        kfree((void *)file->path);
                file->path = NULL;
                kfree(file);
                return;
        }
        if (file->type == FS_TYPE_SOCKET) {
                net_fs_file_destroy(file);
                return;
        }
        if (file->type == FS_TYPE_EPOLL) {
                epoll_fs_file_destroy(file);
                return;
        }
        if (file->type == FS_TYPE_EVENTFD) {
                eventfd_fs_file_destroy(file);
                return;
        }
        if (file->type == FS_TYPE_SIGNALFD) {
                signalfd_fs_file_destroy(file);
                return;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops) continue;
                if (fs_file_matches_driver(drv, file)) {
                        if (drv->ops->release) drv->ops->release(file);
                        return;
                }
        }

        kfree((void*)file->path);
        kfree(file);
}

int fs_file_set_user_path(struct fs_file *file, const char *user_path) {
        if (!file || !user_path || !user_path[0])
                return -1;
        size_t plen = strlen(user_path) + 1;
        char *pp = (char *)kmalloc(plen);
        if (!pp)
                return -1;
        memcpy(pp, user_path, plen);
        if (file->path)
                kfree((void *)file->path);
        file->path = pp;
        return 0;
}

int fs_chmod(const char *path, mode_t mode) {
        if (!path) return -1;
        struct fs_driver *mount_drv = fs_match_mount(path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->chmod) {
                int r = mount_drv->ops->chmod(path, mode);
                if (r == 0) return 0;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->chmod) continue;
                int r = drv->ops->chmod(path, mode);
                if (r == 0) return 0;
                if (r < 0 && r != -1) return -1;
        }
        return -1;
}

int fs_link(const char *oldpath, const char *newpath) {
        if (!oldpath || !newpath) return -1;
        struct fs_driver *mount_drv = fs_match_mount(oldpath);
        if (mount_drv && mount_drv->ops && mount_drv->ops->link) {
                int r = mount_drv->ops->link(oldpath, newpath);
                if (r == 0) return 0;
                if (r < 0) return r;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->link) continue;
                int r = drv->ops->link(oldpath, newpath);
                if (r == 0) return 0;
                if (r < 0 && r != -1) return r;
        }
        return -1;
}

int fs_rename(const char *oldpath, const char *newpath) {
        if (!oldpath || !newpath) return -1;
        if (strcmp(oldpath, newpath) == 0) return 0;
        struct fs_driver *mount_drv = fs_match_mount(oldpath);
        if (mount_drv && mount_drv->ops && mount_drv->ops->rename) {
                int r = mount_drv->ops->rename(oldpath, newpath);
                if (r == 0) return 0;
                if (r < 0) return r;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->rename) continue;
                int r = drv->ops->rename(oldpath, newpath);
                if (r == 0) return 0;
                if (r < 0 && r != -1) return r;
        }
        return -1;
}

int fs_unlink(const char *path) {
        if (!path) return -1;
        struct fs_driver *mount_drv = fs_match_mount(path);
        if (mount_drv && mount_drv->ops && mount_drv->ops->unlink) {
                int r = mount_drv->ops->unlink(path);
                if (r == 0) return 0;
                if (r < 0) return r;
        }
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv || !drv->ops || !drv->ops->unlink) continue;
                int r = drv->ops->unlink(path);
                if (r == 0) return 0;
                if (r < 0 && r != -1) return r;
        }
        return -1;
}

ssize_t fs_readdir_next(struct fs_file *file, void *buf, size_t size) {
        if (!file) return -1;
        ssize_t r = fs_read(file, buf, size, file->pos);
        if (r <= 0) return r;

        /* Directory reads must advance by whole dirent records, otherwise the next
           call can start in the middle of an entry and userspace `getdents*` parsing
           will fail (this is what makes mountpoints like /dev appear "missing"). */
        size_t rr = (size_t)r;
        size_t off = 0;
        while (off + sizeof(struct ext2_dir_entry) <= rr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)((uint8_t*)buf + off);
                if (de->rec_len < (uint16_t)sizeof(struct ext2_dir_entry)) break;
                size_t rec = (size_t)de->rec_len;
                if (rec == 0) break;
                if (off + rec > rr) break; /* partial record at end */
                off += rec;
        }
        if (off == 0) {
                /* Fallback: avoid stalling on unexpected formats. */
                file->pos += (off_t)rr;
                return r;
        }
        file->pos += (off_t)off;
        return (ssize_t)off;
}

int vfs_fstat(struct fs_file *file, struct stat *st) {
        if (!file || !st) return -1;
        memset(st, 0, sizeof(*st));
        /* try driver-specific if possible */
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv) continue;
                if (!fs_file_matches_driver(drv, file)) continue;
                const char *name = drv->ops ? drv->ops->name : NULL;
                if (name && strcmp(name, "sysfs") == 0) {
                        if (sysfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && (strcmp(name, "ramfs") == 0 || strcmp(name, "tmpfs") == 0)) {
                        if (ramfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "procfs") == 0) {
                        if (procfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "cgroup2") == 0) {
                        if (cgroupfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "devfs") == 0) {
                        if (devfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "squashfs") == 0) {
                        if (squashfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && (strcmp(name, "overlay") == 0 || strcmp(name, "overlayfs") == 0)) {
                        if (overlayfs_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "fat32") == 0) {
                        if (fat32_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && strcmp(name, "minix") == 0) {
                        if (minix_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && (strcmp(name, "ext2") == 0 || strcmp(name, "ext3") == 0)) {
                        if (ext2_fill_stat(file, st) == 0) goto fix_mode;
                } else if (name && (strcmp(name, "iso9660") == 0 || strcmp(name, "isofs") == 0)) {
                        if (isofs_fill_stat(file, st) == 0) goto fix_mode;
                }
                break;
        }
        /* fallback: fill from fs_file fields */
        if (file->type == FS_TYPE_DIR)
                st->st_mode = S_IFDIR | 0755;
        else if (file->type == FS_TYPE_PIPE)
                st->st_mode = S_IFIFO | 0600;
        else if (file->type == FS_TYPE_SOCKET)
                st->st_mode = S_IFSOCK | 0666;
        else
                st->st_mode = S_IFREG | 0644;

        goto done;
fix_mode:
        /* Add type bits only when driver left them zero. Do not overwrite existing type
           so boot init path is not changed (avoids rc=-1 when exec fails for script/interp). */
        {
                unsigned int have_type = (st->st_mode & 0170000u);
                if (have_type == 0) {
                        unsigned int want_type = S_IFREG;
                        if (file->type == FS_TYPE_DIR) want_type = S_IFDIR;
                        else if (file->type == FS_TYPE_PIPE) want_type = S_IFIFO;
                        else if (file->type == FS_TYPE_SOCKET) want_type = S_IFSOCK;
                        st->st_mode = (st->st_mode & 07777u) | want_type;
                }
        }
        /* Linux: each mount is a distinct st_dev so tools can detect mountpoints
         * (stat(path).st_dev != stat(path/..).st_dev). */
        {
                int mi = file->path ? fs_get_mount_index(file->path) : -1;
                st->st_dev = (dev_t)(mi >= 0 ? (mi + 2) : 1);
        }
        return 0;
done:
        st->st_size = (off_t)file->size;
        st->st_nlink = 1;
        {
                int mi = file->path ? fs_get_mount_index(file->path) : -1;
                st->st_dev = (dev_t)(mi >= 0 ? (mi + 2) : 1);
        }
        return 0;
}

int vfs_ftruncate(struct fs_file *file, off_t length) {
        if (!file) return -9; /* EBADF */
        for (int i = 0; i < g_drivers_count; i++) {
                struct fs_driver *drv = g_drivers[i];
                if (!drv) continue;
                if (!fs_file_matches_driver(drv, file)) continue;
                const char *name = drv->ops ? drv->ops->name : NULL;
                if (name && (strcmp(name, "ramfs") == 0 || strcmp(name, "tmpfs") == 0))
                        return ramfs_ftruncate(file, length);
                if (name && strcmp(name, "fat32") == 0)
                        return fat32_ftruncate(file, length);
                if (name && (strcmp(name, "overlay") == 0 || strcmp(name, "overlayfs") == 0))
                        return overlayfs_ftruncate(file, length);
                /* Matched a driver without truncate — try others (e.g. wrap vs inner). */
                continue;
        }
        return -95; /* EOPNOTSUPP */
}

int vfs_stat(const char *path, struct stat *st) {
        if (!path || !st) return -1;
        struct fs_file *f = fs_open(path);
        if (!f) return -1;
        int r = vfs_fstat(f, st);
        fs_file_free(f);
        return r;
}

/* Like lstat(): do not follow the final symlink. */
int vfs_lstat(const char *path, struct stat *st) {
        if (!path || !st) return -1;
        struct fs_file *f = fs_open_nofollow(path);
        if (!f) return -1;
        int r = vfs_fstat(f, st);
        fs_file_free(f);
        return r;
}

/* Read symlink target into buf. Returns bytes copied (no NUL) or -1 on error. */
ssize_t vfs_readlink(const char *path, char *buf, size_t bufsiz) {
        if (!path || !buf || bufsiz == 0) return -1;
        struct fs_file *f = fs_open_nofollow(path);
        if (!f) return -1;
        struct stat st;
        if (vfs_fstat(f, &st) != 0 || ((st.st_mode & S_IFLNK) != S_IFLNK)) {
                fs_file_free(f);
                return -1;
        }
        size_t sz = (size_t)f->size;
        if (sz > bufsiz) sz = bufsiz;
        ssize_t rr = fs_read(f, buf, sz, 0);
        fs_file_free(f);
        return rr;
}
