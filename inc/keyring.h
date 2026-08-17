#ifndef KEYRING_H
#define KEYRING_H

#include <stdint.h>
#include <stddef.h>

/* Minimal Linux-like keyring / keyctl subsystem for AxonOS.
 * Supports "keyring" and "asymmetric" (self-signed ECDSA P-256 x.509) types.
 * Asymmetric keys lazily generate their certificate on first read and cache it.
 */

/* Special keyring IDs (negative). */
#define KEY_SPEC_THREAD_KEYRING      (-1)
#define KEY_SPEC_PROCESS_KEYRING     (-2)
#define KEY_SPEC_SESSION_KEYRING     (-3)
#define KEY_SPEC_USER_KEYRING        (-4)
#define KEY_SPEC_USER_SESSION_KEYRING (-5)
#define KEY_SPEC_GROUP_KEYRING       (-6)
#define KEY_SPEC_REQKEY_AUTH_KEY     (-7)
#define KEY_SPEC_REQKEY_AUTH_THREAD  (-8)

/* Key types. */
#define KEY_TYPE_KEYRING    1
#define KEY_TYPE_ASYMMETRIC 2
#define KEY_TYPE_USER       3

/* keyctl() commands (subset of Linux <linux/keyctl.h>). */
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_CHOWN 4
#define KEYCTL_SETPERM 5
#define KEYCTL_DESCRIBE 6
#define KEYCTL_CLEAR 7
#define KEYCTL_LINK 8
#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12

int keyring_init(void);

/*
 * Linux load_system_certificate_list() + integrity_load_keys():
 * create session / .builtin_trusted_keys / .secondary_trusted_keys.
 * The compiled-in CA PEM is installed via keyring_install_system_ca().
 */
int keyring_load_system_certs(void);

/* Cache built-in CA PEM on .builtin_trusted_keys (no runtime ECC). */
int keyring_install_system_ca(const void *pem, size_t len);

/* Cached system CA (PEM bytes). Pointer valid until keyring teardown. */
int keyring_system_cert_der(const uint8_t **der, size_t *len);

/* add_key(type, description, payload, plen, ring_id).
 * type is one of KEY_TYPE_*; description is a kernel-space NUL-terminated string.
 * Returns the new key serial, or a negative errno value. */
long keyring_add_key(int type, const char *description, const void *payload,
                     size_t plen, int ring_id);

/* request_key(type, description, callout, ring_id). Returns serial or -errno. */
long keyring_request_key(int type, const char *description,
                         const char *callout, int ring_id);

/* keyctl(cmd, a2, a3, a4, a5). a2..a5 are kernel-space pointers/values. */
long keyctl_do(int cmd, long a2, long a3, long a4, long a5);

/* Number of keys currently present (for /proc/keys). */
int keyring_count(void);

/* Walk keys for /proc/keys: calls cb(serial, type, uid, gid, perms, desc, len).
 * Returns 0 on success. cb receives kernel pointers valid during the call. */
typedef void (*keyring_walk_fn)(uint32_t serial, int type, uint32_t uid,
                                uint32_t gid, uint32_t perms,
                                const char *desc, size_t desc_len);
void keyring_walk(keyring_walk_fn cb);

#endif /* KEYRING_H */
