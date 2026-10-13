/*
 * Kernel zlib inflate via miniz tinfl.
 * SquashFS "gzip" compressor stores zlib streams (RFC 1950), not gzip wrappers.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <heap.h>
#include <zlib_inflate.h>
#include <klog.h>

#include <miniz.h>
#include <miniz_tinfl.h>
#include "miniz_tinfl_impl.inc"

int zlib_inflate(void *out, size_t out_cap, size_t *out_len,
                 const void *in, size_t in_len)
{
    tinfl_decompressor decomp;
    tinfl_status status;
    size_t consumed = in_len, got = out_cap;

    if (!out || !in || !out_len || out_cap == 0 || in_len == 0)
        return -1;

    tinfl_init(&decomp);
    status = tinfl_decompress(&decomp, in, &consumed, out, out, &got,
                              TINFL_FLAG_PARSE_ZLIB_HEADER |
                              TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (status != TINFL_STATUS_DONE) {
        klogprintf("zlib-inflate: status=%d state=%u in=%zu/%zu out=%zu/%zu adler=%08x expected=%08x\n",
            (int)status, (unsigned)decomp.m_state, consumed, in_len, got, out_cap,
            (unsigned)decomp.m_check_adler32, (unsigned)decomp.m_z_adler32);
        klogprintf("zlib-state: bits=%u dist=%u count=%u tables=%u/%u/%u input=%p output=%p\n",
            (unsigned)decomp.m_num_bits, (unsigned)decomp.m_dist,
            (unsigned)decomp.m_counter, (unsigned)decomp.m_table_sizes[0],
            (unsigned)decomp.m_table_sizes[1], (unsigned)decomp.m_table_sizes[2], in, out);
        return -1;
    }
    *out_len = got;
    return 0;
}
