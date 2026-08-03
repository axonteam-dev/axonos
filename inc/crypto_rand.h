#ifndef CRYPTO_RAND_H
#define CRYPTO_RAND_H

#include <stddef.h>

/* Fill buf with len bytes of pseudo-random data.
 * Seeded once from kernel entropy sources (TSC, PIT, RTC, addresses).
 * SHA-256 based counter-mode generator (not an audited CSPRNG, but far
 * better than xorshift and sufficient for key generation in a hobby OS). */
void crypto_rand_bytes(void *buf, size_t len);

#endif /* CRYPTO_RAND_H */
