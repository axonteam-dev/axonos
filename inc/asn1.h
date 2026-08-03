#ifndef ASN1_H
#define ASN1_H

#include <stdint.h>
#include <stddef.h>

/* Minimal DER writer (X.690) for x.509 certificate generation. */

#define DER_TAG_BOOLEAN      0x01
#define DER_TAG_INTEGER      0x02
#define DER_TAG_BIT_STRING   0x03
#define DER_TAG_OCTET_STRING 0x04
#define DER_TAG_NULL         0x05
#define DER_TAG_OID          0x06
#define DER_TAG_UTF8STRING   0x0c
#define DER_TAG_UTCTIME      0x17
#define DER_TAG_SEQUENCE     0x30
#define DER_TAG_SET          0x31
#define DER_TAG_PRINTABLE    0x13
#define DER_TAG_CONTEXT0     0xa0

typedef struct {
    uint8_t *buf;    /* caller-provided output buffer */
    size_t   len;    /* bytes written so far */
    size_t   cap;
    int      err;    /* set to 1 on overflow / bad args */
} der_writer_t;

void der_w_init(der_writer_t *w, uint8_t *buf, size_t cap);

/* Raw byte appends (they report overflow via w->err). */
void der_w_u8(der_writer_t *w, uint8_t b);
void der_w_bytes(der_writer_t *w, const uint8_t *data, size_t n);

/* Append a complete TLV: tag, length, content. */
void der_w_tlv(der_writer_t *w, uint8_t tag, const uint8_t *content, size_t n);

/* Canonical length-of-length handling: minimal bytes, short form when < 128. */
void der_w_len(der_writer_t *w, size_t len);

/* Framed constructed types with length back-patching. */
typedef struct { size_t lenpos; } der_frame_t;
void der_w_begin(der_writer_t *w, uint8_t tag, der_frame_t *f);
void der_w_end(der_writer_t *w, der_frame_t *f);

/* Typed values. */
void der_w_null(der_writer_t *w);
void der_w_oid(der_writer_t *w, const uint8_t *oid, size_t oid_len);
void der_w_int_bytes(der_writer_t *w, const uint8_t *v, size_t n); /* sign-corrected */
void der_w_int_u32(der_writer_t *w, uint32_t v);
void der_w_bitstring(der_writer_t *w, const uint8_t *data, size_t n);
void der_w_printable(der_writer_t *w, const char *s);
void der_w_utf8(der_writer_t *w, const char *s);
void der_w_utctime(der_writer_t *w, const uint8_t yymmddhhmmssz[13]);

/* Total size of what was written (== w->len unless err). */
static inline size_t der_w_size(const der_writer_t *w) { return w->len; }

#endif /* ASN1_H */
