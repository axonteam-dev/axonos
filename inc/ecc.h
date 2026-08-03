#ifndef ECC_H
#define ECC_H

#include <stdint.h>

/* ECDSA P-256 / secp256r1 (RFC 5758) */

typedef struct {
    uint8_t x[32]; /* big-endian */
    uint8_t y[32]; /* big-endian */
} ecc_point_t;

typedef struct {
    uint8_t d[32];     /* private scalar, big-endian */
    ecc_point_t pub;   /* public point Q = d*G */
} ecc_key_t;

/* Generate a fresh P-256 keypair (d in [1, n-2]). Returns 0 on success. */
int ecc_keygen(ecc_key_t *out);

/* ECDSA sign of a 32-byte hash using RFC 6979 deterministic k.
 * Returns 0 on success; r, s big-endian. */
int ecdsa_sign(const uint8_t d[32], const uint8_t hash[32],
               uint8_t r[32], uint8_t s[32]);

/* ECDSA verify. Returns 0 if valid, -1 otherwise. */
int ecdsa_verify(const ecc_point_t *pub, const uint8_t hash[32],
                 const uint8_t r[32], const uint8_t s[32]);

/* Point on curve check (for tests / key sanity). Returns 1 if on curve. */
int ecc_point_on_curve(const uint8_t x[32], const uint8_t y[32]);

/* Scalar multiplication Q = k*G, affine output (for tests / tools). */
int ecc_scalar_mult_base(const uint8_t k[32], uint8_t xout[32], uint8_t yout[32]);

#endif /* ECC_H */
