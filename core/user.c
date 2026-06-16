#include <user.h>
#include <heap.h>
#include <string.h>
#include <thread.h>
#include <vga.h>
#include <fs.h>

#define MAX_USERS 64

static struct user g_users[MAX_USERS];
static int g_user_count;
static uid_t g_current_uid = ROOT_UID;

static unsigned long simple_hash(const char *s)
{
    unsigned long h = 5381;

    while (*s)
        h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}

static char *strdup_k(const char *s)
{
    size_t n;
    char *p;

    if (!s)
        return NULL;
    n = strlen(s);
    p = (char *)kmalloc(n + 1);
    if (!p) {
        kprintf("user OOM: strdup_k(%llu) failed (user_add/user_groups)\n",
                (unsigned long long)(n + 1));
        return NULL;
    }
    memcpy(p, s, n + 1);
    return p;
}

int user_add(const char *name, uid_t uid, gid_t gid, const char *groups)
{
    struct user *u;

    if (!name)
        return -1;
    if (g_user_count >= MAX_USERS)
        return -1;
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].name, name) == 0)
            return -2;
    }

    u = &g_users[g_user_count++];
    strncpy(u->name, name, sizeof(u->name) - 1);
    u->name[sizeof(u->name) - 1] = '\0';
    u->uid = uid;
    u->gid = gid;
    u->passwd_hash = NULL;
    if (groups && groups[0])
        u->groups = strdup_k(groups);
    else
        u->groups = strdup_k(name);
    return 0;
}

static int parse_passwd_line(const char *line, char *out_name, size_t name_sz,
                             uid_t *out_uid, gid_t *out_gid)
{
    const char *p;
    const char *name_start;
    size_t nlen;
    unsigned int uid = 0;
    unsigned int gid = 0;

    if (!line || !out_name || name_sz == 0 || !out_uid || !out_gid)
        return -1;
    p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (!*p)
        return -1;

    name_start = p;
    while (*p && *p != ':')
        p++;
    nlen = (size_t)(p - name_start);
    if (nlen >= name_sz || nlen == 0)
        return -1;
    memcpy(out_name, name_start, nlen);
    out_name[nlen] = '\0';
    if (*p != ':')
        return -1;
    p++;
    while (*p && *p != ':')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p >= '0' && *p <= '9') {
        uid = uid * 10u + (unsigned int)(*p - '0');
        p++;
    }
    if (*p != ':')
        return -1;
    p++;
    while (*p >= '0' && *p <= '9') {
        gid = gid * 10u + (unsigned int)(*p - '0');
        p++;
    }
    *out_uid = (uid_t)uid;
    *out_gid = (gid_t)gid;
    return 0;
}

struct user *user_find(const char *name)
{
    if (!name)
        return NULL;
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_users[i].name, name) == 0)
            return &g_users[i];
    }

    struct fs_file *f = fs_open("/etc/passwd");
    if (!f || f->size == 0 || f->size >= (64u * 1024u)) {
        if (f)
            fs_file_free(f);
        return NULL;
    }

    char *buf = (char *)kmalloc((size_t)f->size + 1);
    if (!buf) {
        fs_file_free(f);
        return NULL;
    }

    ssize_t r = fs_read(f, buf, (size_t)f->size, 0);
    if (r > 0) {
        char *p = buf;

        buf[(size_t)r] = '\0';
        while (*p) {
            char *line = p;
            char *nl = strchr(p, '\n');
            char pname[32];
            uid_t puid;
            gid_t pgid;

            if (nl) {
                *nl = '\0';
                p = nl + 1;
            } else {
                p += strlen(p);
            }
            if (line[0] == '\0' || line[0] == '#')
                continue;
            if (parse_passwd_line(line, pname, sizeof(pname), &puid, &pgid) != 0)
                continue;

            int found = 0;
            for (int i = 0; i < g_user_count; i++) {
                if (strcmp(g_users[i].name, pname) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found && g_user_count < MAX_USERS) {
                if (user_add(pname, puid, pgid, pname) == 0 && strcmp(pname, name) == 0) {
                    kfree(buf);
                    fs_file_free(f);
                    return &g_users[g_user_count - 1];
                }
            } else if (strcmp(pname, name) == 0) {
                kfree(buf);
                fs_file_free(f);
                return user_find(name);
            }
        }
    }

    kfree(buf);
    fs_file_free(f);
    return NULL;
}

int user_set_password(const char *name, const char *password)
{
    struct user *u = user_find(name);
    unsigned long h;
    char buf[32];
    int n;

    if (!u)
        return -1;
    if (u->passwd_hash)
        kfree(u->passwd_hash);
    h = simple_hash(password ? password : "");
    n = snprintf(buf, sizeof(buf), "%lu", h);
    u->passwd_hash = (char *)kmalloc((size_t)n + 1);
    if (!u->passwd_hash) {
        kprintf("user OOM: user_set_password kmalloc(%llu) failed for %s\n",
                (unsigned long long)((size_t)n + 1), name);
        return -1;
    }
    memcpy(u->passwd_hash, buf, (size_t)n + 1);
    return 0;
}

int user_check_password(const char *name, const char *password)
{
    struct user *u = user_find(name);
    unsigned long h;
    char buf[32];
    int n;

    if (!u || !u->passwd_hash)
        return 0;
    h = simple_hash(password ? password : "");
    n = snprintf(buf, sizeof(buf), "%lu", h);
    return (strcmp(u->passwd_hash, buf) == 0) ? 1 : 0;
}

int user_set_current(const char *name)
{
    struct user *u = user_find(name);

    if (!u)
        return -1;
    g_current_uid = u->uid;
    return 0;
}

int user_init(void)
{
    g_user_count = 0;
    user_add(ROOT_USER_NAME, ROOT_UID, ROOT_GID, "root");
    user_set_current(ROOT_USER_NAME);
    return 0;
}

int user_export_passwd(char **out, size_t *out_len)
{
    size_t cap;
    char *buf;
    size_t pos = 0;

    if (!out || !out_len)
        return -1;
    cap = (size_t)g_user_count * 64 + 16;
    buf = (char *)kmalloc(cap);
    if (!buf) {
        kprintf("user OOM: user_export_passwd kmalloc(%llu) failed\n",
                (unsigned long long)cap);
        return -1;
    }

    for (int i = 0; i < g_user_count; i++) {
        struct user *u = &g_users[i];
        const char *gecos = u->name;
        char *htmp = NULL;
        const char *home;
        int n;

        if (u->uid == 0) {
            home = "/root";
        } else {
            size_t hlen = strlen(u->name) + 7;
            htmp = (char *)kmalloc(hlen);
            if (!htmp) {
                kprintf("user OOM: user_export_passwd /home/<name> kmalloc(%llu) failed\n",
                        (unsigned long long)hlen);
                home = "/home";
            } else {
                snprintf(htmp, hlen, "/home/%s", u->name);
                home = htmp;
            }
        }
        n = snprintf(buf + pos, (pos < cap) ? cap - pos : 0,
                       "%s:x:%u:%u:%s:%s:/bin/sh\n",
                       u->name, u->uid, u->gid, gecos, home);
        if (htmp)
            kfree(htmp);
        if (n <= 0)
            break;
        pos += (size_t)n;
        if (pos + 128 > cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)krealloc(buf, ncap);
            if (!nb)
                break;
            buf = nb;
            cap = ncap;
        }
    }

    *out = buf;
    *out_len = pos;
    return 0;
}

uid_t user_get_next_uid(void)
{
    uid_t max = 1000;

    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].uid >= max)
            max = g_users[i].uid;
    }
    return max + 1;
}

const char *user_get_current_name(void)
{
    thread_t *t = thread_current();
    uid_t uid = t ? t->euid : g_current_uid;

    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].uid == uid)
            return g_users[i].name;
    }
    return ROOT_USER_NAME;
}

uid_t user_get_current_uid(void)
{
    thread_t *t = thread_current();
    return t ? t->euid : g_current_uid;
}

static int copy_out(char *out, size_t outsz, const char *s)
{
    size_t n;

    if (!out || outsz == 0)
        return -1;
    if (!s)
        s = "";
    n = strlen(s);
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, s, n);
    out[n] = '\0';
    return 0;
}

int user_lookup_name_by_uid(uid_t uid, char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return -1;
    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].uid == uid)
            return copy_out(out, outsz, g_users[i].name);
    }
    if (uid == ROOT_UID)
        return copy_out(out, outsz, ROOT_USER_NAME);
    return -1;
}

static int parse_uint_field(const char *s, unsigned int *out)
{
    unsigned int v = 0;
    int any = 0;

    if (!s || !out)
        return -1;
    while (*s == ' ' || *s == '\t')
        s++;
    while (*s >= '0' && *s <= '9') {
        any = 1;
        v = v * 10u + (unsigned int)(*s - '0');
        s++;
    }
    if (!any)
        return -1;
    *out = v;
    return 0;
}

int user_lookup_group_by_gid(gid_t gid, char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return -1;
    if (gid == ROOT_GID)
        return copy_out(out, outsz, "root");

    struct fs_file *f = fs_open("/etc/group");
    if (f) {
        size_t sz = f->size;
        if (sz > 0 && sz < (64u * 1024u)) {
            char *buf = (char *)kmalloc(sz + 1);
            if (buf) {
                ssize_t r = fs_read(f, buf, sz, 0);
                if (r > 0) {
                    char *p = buf;

                    buf[(size_t)r] = '\0';
                    while (*p) {
                        char *line = p;
                        char *nl = strchr(p, '\n');

                        if (nl) {
                            *nl = '\0';
                            p = nl + 1;
                        } else {
                            p += strlen(p);
                        }
                        if (line[0] == '\0' || line[0] == '#')
                            continue;

                        char *c1 = strchr(line, ':');
                        if (!c1)
                            continue;
                        *c1 = '\0';
                        char *rest = c1 + 1;
                        char *c2 = strchr(rest, ':');
                        if (!c2)
                            continue;
                        rest = c2 + 1;
                        char *c3 = strchr(rest, ':');
                        if (c3)
                            *c3 = '\0';
                        unsigned int gval = 0;
                        if (parse_uint_field(rest, &gval) == 0 && (gid_t)gval == gid) {
                            int rc = copy_out(out, outsz, line);
                            kfree(buf);
                            fs_file_free(f);
                            return rc;
                        }
                    }
                }
                kfree(buf);
            }
        }
        fs_file_free(f);
    }

    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].gid == gid)
            return copy_out(out, outsz, g_users[i].name);
    }
    return -1;
}
