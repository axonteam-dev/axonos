/*
 * Kernel zlib inflate via miniz tinfl.
 * SquashFS "gzip" compressor stores zlib streams (RFC 1950), not gzip wrappers.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <heap.h>
#include <zlib_inflate.h>

#include <miniz.h>
#include <miniz_tinfl.h>
#include "miniz_tinfl_impl.inc"

int zlib_inflate(void *out, size_t out_cap, size_t *out_len,
                 const void *in, size_t in_len)
{
    size_t got;

    if (!out || !in || !out_len || out_cap == 0 || in_len == 0)
        return -1;

    got = tinfl_decompress_mem_to_mem(out, out_cap, in, in_len,
                                      TINFL_FLAG_PARSE_ZLIB_HEADER |
                                          TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (got == (size_t)TINFL_DECOMPRESS_MEM_TO_MEM_FAILED)
        return -1;
    *out_len = got;
    return 0;
}
