/* Thin zlib inflate wrapper (miniz) for SquashFS gzip blocks. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decompress a zlib-wrapped deflate stream (SquashFS "gzip").
 * Returns 0 on success and sets *out_len to produced bytes.
 * out_cap must be large enough for the uncompressed result. */
int zlib_inflate(void *out, size_t out_cap, size_t *out_len,
                 const void *in, size_t in_len);

#ifdef __cplusplus
}
#endif
