/*
 * Minimal Linux-like keyring / keyctl subsystem.
 *
 * Key types:
 *  - "keyring": container that lists serial numbers of linked keys.
 *  - "asymmetric": a lazily-generated, cached self-signed ECDSA P-256 x.509
 *    certificate. The certificate (DER) is produced on the first read and
 *    cached in the key; the private key is kept only long enough to sign,
 *    then discarded (asymmetric keys expose only the certificate).
 *  - "user": opaque bytes (stored as-is).
 *
 * All keys live in a single global table; special ring IDs map to a session
 * keyring created at init. This is single-user, so the mapping is coarse.
 */

#include <keyring.h>
#include <spinlock.h>
#include <string.h>
#include <crypto_rand.h>
#include <sha256.h>
#include <ecc.h>
#include <x509.h>
#include <rtc.h>
#include <heap.h>
#include <vga.h>

#define KEYRING_MAX 64
#define KEY_DESC_MAX 64
#define KEY_SUBJ_MAX (X509_CN_MAX + 1)

typedef struct kr_slot {
    int      used;
    uint32_t serial;
    int      type;
    uint32_t uid, gid;
    uint32_t perms;
    char     description[KEY_DESC_MAX];
    char     subject[KEY_SUBJ_MAX];
    uint8_t *payload;        /* keyring: linked serials; user: raw bytes */
    size_t   payload_len;
    uint8_t *cert;           /* asymmetric: cached DER cert */
    size_t   cert_len;
    int      generated;
} kr_slot_t;

static spinlock_t g_kr_lock;
static kr_slot_t g_keys[KEYRING_MAX];
static uint32_t g_next_serial = 1;
static uint32_t g_session_serial;
static int g_kr_inited = 0;

static kr_slot_t *slot_by_serial(uint32_t serial) {
    for (int i = 0; i < KEYRING_MAX; i++)
        if (g_keys[i].used && g_keys[i].serial == serial)
            return &g_keys[i];
    return NULL;
}

static kr_slot_t *slot_alloc(void) {
    for (int i = 0; i < KEYRING_MAX; i++)
        if (!g_keys[i].used) {
            memset(&g_keys[i], 0, sizeof g_keys[i]);
            g_keys[i].used = 1;
            g_keys[i].serial = g_next_serial++;
            return &g_keys[i];
        }
    return NULL;
}

static int ring_resolve(int ring_id) {
    if (ring_id >= 0)
        return slot_by_serial((uint32_t)ring_id) ? ring_id : -1;
    /* negative special ids: map to the session keyring for now */
    return (int)g_session_serial;
}

/* Format "YYMMDDHHMMSSZ" from RTC fields; clamp to [1950, 2049] for UTCTime. */
static void fmt_utctime(uint8_t out[13], const rtc_datetime_t *dt) {
    int year = dt->year;
    if (year < 1950) year = 1950;
    if (year > 2049) year = 2049;
    out[0] = (uint8_t)('0' + (year % 100) / 10);
    out[1] = (uint8_t)('0' + (year % 100) % 10);
    out[2] = (uint8_t)('0' + dt->month / 10);
    out[3] = (uint8_t)('0' + dt->month % 10);
    out[4] = (uint8_t)('0' + dt->day / 10);
    out[5] = (uint8_t)('0' + dt->day % 10);
    out[6] = (uint8_t)('0' + dt->hour / 10);
    out[7] = (uint8_t)('0' + dt->hour % 10);
    out[8] = (uint8_t)('0' + dt->minute / 10);
    out[9] = (uint8_t)('0' + dt->minute % 10);
    out[10] = (uint8_t)('0' + dt->second / 10);
    out[11] = (uint8_t)('0' + dt->second % 10);
    out[12] = 'Z';
}

static int slot_gen_cert(kr_slot_t *s) {
    if (s->generated)
        return 0;
    x509_req_t req;
    memset(&req, 0, sizeof req);
    strncpy(req.subject, s->subject, X509_CN_MAX);
    req.subject[X509_CN_MAX] = 0;
    if (req.subject[0] == 0)
        strcpy(req.subject, "AxonOS");
    crypto_rand_bytes(req.serial, 20);
    req.serial[0] &= 0x7f; /* keep positive */
    if (req.serial[0] == 0) req.serial[0] = 0x01;
    req.serial_len = 20;
    rtc_datetime_t dt;
    rtc_read_datetime(&dt);
    fmt_utctime(req.not_before, &dt);
    uint16_t save = dt.year;
    dt.year = (save < 2049) ? (uint16_t)(save + 10) : (uint16_t)2049;
    fmt_utctime(req.not_after, &dt);
    if (ecc_keygen(&req.key) != 0)
        return -1;
    uint8_t *der = kmalloc(2048);
    if (!der)
        return -1;
    size_t len = 0;
    if (x509_generate(&req, der, 2048, &len) != 0) {
        kfree(der);
        return -1;
    }
    s->cert = der;
    s->cert_len = len;
    s->generated = 1;
    return 0;
}

int keyring_init(void) {
    if (g_kr_inited)
        return 0;
    acquire(&g_kr_lock);
    if (!g_kr_inited) {
        kr_slot_t *s = slot_alloc();
        if (s) {
            s->type = KEY_TYPE_KEYRING;
            strcpy(s->description, "session");
            strcpy(s->subject, "session");
            g_session_serial = s->serial;
        }
        g_kr_inited = 1;
    }
    release(&g_kr_lock);
    return g_session_serial ? 0 : -1;
}

long keyring_add_key(int type, const char *description, const void *payload,
                     size_t plen, int ring_id) {
    if (type != KEY_TYPE_KEYRING && type != KEY_TYPE_ASYMMETRIC &&
        type != KEY_TYPE_USER)
        return -5; /* EINVAL */
    if (!description || description[0] == 0)
        return -5;

    acquire(&g_kr_lock);
    int ring = ring_resolve(ring_id);
    if (ring < 0) { release(&g_kr_lock); return -126; } /* ENOKEY */

    kr_slot_t *s = slot_alloc();
    if (!s) { release(&g_kr_lock); return -28; } /* ENOSPC */
    s->type = type;
    strncpy(s->description, description, KEY_DESC_MAX - 1);
    s->description[KEY_DESC_MAX - 1] = 0;
    strncpy(s->subject, description, KEY_SUBJ_MAX - 1);
    s->subject[KEY_SUBJ_MAX - 1] = 0;
    s->uid = 0; s->gid = 0;
    s->perms = 0x3f3f0000;

    if (type == KEY_TYPE_ASYMMETRIC) {
        /* payload (if any) replaces the subject/CN */
        if (payload && plen > 0) {
            size_t n = plen < KEY_SUBJ_MAX - 1 ? plen : KEY_SUBJ_MAX - 1;
            memcpy(s->subject, payload, n);
            s->subject[n] = 0;
            if (strlen(s->description) == 0) {
                strncpy(s->description, s->subject, KEY_DESC_MAX - 1);
                s->description[KEY_DESC_MAX - 1] = 0;
            }
        }
        s->cert = NULL; s->cert_len = 0; s->generated = 0;
    } else if (type == KEY_TYPE_USER) {
        if (plen > 0 && payload) {
            uint8_t *p = kmalloc(plen);
            if (p) {
                memcpy(p, payload, plen);
                s->payload = p;
                s->payload_len = plen;
            }
        }
    } else { /* keyring */
        /* link into parent ring? The payload/ring semantics are minimal:
         * a keyring key just exists; keys are linked via KEYCTL_LINK. */
    }

    /* link into destination ring (append serial) */
    kr_slot_t *ring_slot = slot_by_serial((uint32_t)ring);
    if (ring_slot && ring_slot->type == KEY_TYPE_KEYRING) {
        uint32_t *pl = (uint32_t *)ring_slot->payload;
        size_t cnt = ring_slot->payload_len / 4;
        if (cnt < 64) {
            uint32_t *np = kmalloc((cnt + 1) * 4);
            if (np) {
                if (cnt) memcpy(np, pl, cnt * 4);
                np[cnt] = s->serial;
                kfree(pl);
                ring_slot->payload = (uint8_t *)np;
                ring_slot->payload_len = (cnt + 1) * 4;
            }
        }
    }
    uint32_t serial = s->serial;
    release(&g_kr_lock);
    return (long)serial;
}

long keyring_request_key(int type, const char *description,
                         const char *callout, int ring_id) {
    (void)callout;
    acquire(&g_kr_lock);
    kr_slot_t *found = NULL;
    int ring = ring_resolve(ring_id);
    kr_slot_t *ring_slot = (ring >= 0) ? slot_by_serial((uint32_t)ring) : NULL;
    for (int i = 0; i < KEYRING_MAX; i++) {
        if (!g_keys[i].used || g_keys[i].type != type)
            continue;
        if (ring_slot && ring_slot->type == KEY_TYPE_KEYRING) {
            /* must be linked into the ring */
            uint32_t *pl = (uint32_t *)ring_slot->payload;
            size_t cnt = ring_slot->payload_len / 4;
            int linked = 0;
            for (size_t j = 0; j < cnt; j++)
                if (pl[j] == g_keys[i].serial) { linked = 1; break; }
            if (!linked)
                continue;
        }
        if (strncmp(g_keys[i].description, description, KEY_DESC_MAX - 1) == 0) {
            found = &g_keys[i];
            break;
        }
    }
    if (found) {
        uint32_t serial = found->serial;
        release(&g_kr_lock);
        return (long)serial;
    }
    release(&g_kr_lock);
    return keyring_add_key(type, description, NULL, 0, ring_id);
}

/* Linux keyctl() subset. a2..a5 already kernel pointers / scalars. */
long keyctl_do(int cmd, long a2, long a3, long a4, long a5) {
    (void)a4; (void)a5;
    switch (cmd) {
    case KEYCTL_GET_KEYRING_ID: {
        int ringid = (int)a2;
        int create = (int)a3;
        int ring = ring_resolve(ringid);
        if (ring < 0 && create)
            return keyring_add_key(KEY_TYPE_KEYRING, "keyring", NULL, 0, 0);
        return ring;
    }
    case KEYCTL_JOIN_SESSION_KEYRING: {
        /* clear + create a fresh session keyring */
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(g_session_serial);
        if (s) {
            kfree(s->payload);
            s->payload = NULL;
            s->payload_len = 0;
        }
        kr_slot_t *ns = slot_alloc();
        uint32_t serial = ns ? ns->serial : g_session_serial;
        if (ns) {
            ns->type = KEY_TYPE_KEYRING;
            strcpy(ns->description, "session");
            strcpy(ns->subject, "session");
            g_session_serial = ns->serial;
        }
        release(&g_kr_lock);
        return (long)serial;
    }
    case KEYCTL_UPDATE: {
        uint32_t serial = (uint32_t)a2;
        const uint8_t *payload = (const uint8_t *)a3;
        size_t plen = (size_t)a4;
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(serial);
        if (!s) { release(&g_kr_lock); return -126; }
        if (s->type == KEY_TYPE_ASYMMETRIC) {
            /* update = regenerate certificate */
            kfree(s->cert);
            s->cert = NULL; s->cert_len = 0; s->generated = 0;
            if (payload && plen > 0) {
                size_t n = plen < KEY_SUBJ_MAX - 1 ? plen : KEY_SUBJ_MAX - 1;
                memcpy(s->subject, payload, n);
                s->subject[n] = 0;
            }
            int r = slot_gen_cert(s);
            release(&g_kr_lock);
            return r;
        }
        if (s->type == KEY_TYPE_USER) {
            kfree(s->payload);
            s->payload = NULL; s->payload_len = 0;
            if (plen > 0 && payload) {
                uint8_t *p = kmalloc(plen);
                if (p) { memcpy(p, payload, plen); s->payload = p; s->payload_len = plen; }
            }
        }
        release(&g_kr_lock);
        return 0;
    }
    case KEYCTL_REVOKE: {
        uint32_t serial = (uint32_t)a2;
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(serial);
        if (!s) { release(&g_kr_lock); return -126; }
        kfree(s->payload); s->payload = NULL; s->payload_len = 0;
        kfree(s->cert); s->cert = NULL; s->cert_len = 0; s->generated = 0;
        memset(s, 0, sizeof *s);
        release(&g_kr_lock);
        return 0;
    }
    case KEYCTL_DESCRIBE: {
        uint32_t serial = (uint32_t)a2;
        char *buf = (char *)a3;
        size_t buflen = (size_t)a4;
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(serial);
        if (!s) { release(&g_kr_lock); return -126; }
        const char *tn = (s->type == KEY_TYPE_KEYRING) ? "keyring" :
                         (s->type == KEY_TYPE_ASYMMETRIC) ? "asymmetric" : "user";
        int need = (int)snprintf(NULL, 0, "%s;%u;%u;%08x;%s", tn,
                                 s->uid, s->gid, s->perms, s->description);
        if (buf && buflen > 0) {
            int n = need < (int)buflen ? need : (int)buflen - 1;
            snprintf(buf, (size_t)n + 1, "%s;%u;%u;%08x;%s", tn,
                     s->uid, s->gid, s->perms, s->description);
        }
        release(&g_kr_lock);
        return need;
    }
    case KEYCTL_CLEAR: {
        uint32_t serial = (uint32_t)a2;
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(serial);
        if (!s) { release(&g_kr_lock); return -126; }
        kfree(s->payload); s->payload = NULL; s->payload_len = 0;
        release(&g_kr_lock);
        return 0;
    }
    case KEYCTL_LINK: {
        uint32_t keyid = (uint32_t)a2;
        uint32_t ringid = (uint32_t)a3;
        acquire(&g_kr_lock);
        kr_slot_t *k = slot_by_serial(keyid);
        kr_slot_t *r = slot_by_serial(ringid);
        if (!k || !r || r->type != KEY_TYPE_KEYRING) { release(&g_kr_lock); return -22; }
        uint32_t *pl = (uint32_t *)r->payload;
        size_t cnt = r->payload_len / 4;
        for (size_t j = 0; j < cnt; j++)
            if (pl[j] == keyid) { release(&g_kr_lock); return 0; } /* already linked */
        if (cnt < 64) {
            uint32_t *np = kmalloc((cnt + 1) * 4);
            if (np) {
                if (cnt) memcpy(np, pl, cnt * 4);
                np[cnt] = keyid;
                kfree(pl);
                r->payload = (uint8_t *)np;
                r->payload_len = (cnt + 1) * 4;
            }
        }
        release(&g_kr_lock);
        return 0;
    }
    case KEYCTL_UNLINK: {
        uint32_t keyid = (uint32_t)a2;
        uint32_t ringid = (uint32_t)a3;
        acquire(&g_kr_lock);
        kr_slot_t *r = slot_by_serial(ringid);
        if (!r || r->type != KEY_TYPE_KEYRING) { release(&g_kr_lock); return -22; }
        uint32_t *pl = (uint32_t *)r->payload;
        size_t cnt = r->payload_len / 4;
        size_t w = 0;
        for (size_t j = 0; j < cnt; j++)
            if (pl[j] != keyid) pl[w++] = pl[j];
        r->payload_len = w * 4;
        release(&g_kr_lock);
        return 0;
    }
    case KEYCTL_SEARCH: {
        uint32_t ringid = (uint32_t)a2;
        const char *type = (const char *)a3;
        const char *desc = (const char *)a4;
        uint32_t dest = (uint32_t)a5;
        int t = 0;
        if (strcmp(type, "keyring") == 0) t = KEY_TYPE_KEYRING;
        else if (strcmp(type, "asymmetric") == 0) t = KEY_TYPE_ASYMMETRIC;
        else if (strcmp(type, "user") == 0) t = KEY_TYPE_USER;
        if (!t || !desc) return -22;
        (void)dest;
        long serial = keyring_request_key(t, desc, NULL, (int)ringid);
        return serial;
    }
    case KEYCTL_READ: {
        uint32_t serial = (uint32_t)a2;
        uint8_t *buf = (uint8_t *)a3;
        size_t buflen = (size_t)a4;
        acquire(&g_kr_lock);
        kr_slot_t *s = slot_by_serial(serial);
        if (!s) { release(&g_kr_lock); return -126; }
        size_t total;
        const uint8_t *src;
        if (s->type == KEY_TYPE_ASYMMETRIC) {
            if (slot_gen_cert(s) != 0) { release(&g_kr_lock); return -5; }
            src = s->cert;
            total = s->cert_len;
        } else if (s->type == KEY_TYPE_USER) {
            src = s->payload;
            total = s->payload_len;
        } else { /* keyring: dump linked serials (LE) */
            src = s->payload;
            total = s->payload_len;
        }
        size_t n = buflen < total ? buflen : total;
        if (buf && n > 0 && src)
            memcpy(buf, src, n);
        release(&g_kr_lock);
        return (long)total;
    }
    case KEYCTL_INSTANTIATE:
    default:
        return -38; /* ENOSYS */
    }
}

int keyring_count(void) {
    int c = 0;
    for (int i = 0; i < KEYRING_MAX; i++)
        if (g_keys[i].used) c++;
    return c;
}

void keyring_walk(keyring_walk_fn cb) {
    for (int i = 0; i < KEYRING_MAX; i++) {
        if (!g_keys[i].used) continue;
        cb(g_keys[i].serial, g_keys[i].type, g_keys[i].uid, g_keys[i].gid,
           g_keys[i].perms, g_keys[i].description,
           strlen(g_keys[i].description));
    }
}
