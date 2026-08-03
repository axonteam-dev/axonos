/*
 * Minimal DER (X.690) writer for AxonOS x.509 generation.
 */

#include <asn1.h>
#include <string.h>

void der_w_init(der_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->len = 0;
    w->cap = cap;
    w->err = 0;
}

void der_w_u8(der_writer_t *w, uint8_t b) {
    if (w->err) return;
    if (w->len >= w->cap) { w->err = 1; return; }
    w->buf[w->len++] = b;
}

void der_w_bytes(der_writer_t *w, const uint8_t *data, size_t n) {
    if (w->err) return;
    if (n > w->cap - w->len) { w->err = 1; return; }
    memcpy(w->buf + w->len, data, n);
    w->len += n;
}

void der_w_len(der_writer_t *w, size_t len) {
    if (len < 128) {
        der_w_u8(w, (uint8_t)len);
    } else if (len <= 0xff) {
        der_w_u8(w, 0x81); der_w_u8(w, (uint8_t)len);
    } else if (len <= 0xffff) {
        der_w_u8(w, 0x82);
        der_w_u8(w, (uint8_t)(len >> 8)); der_w_u8(w, (uint8_t)len);
    } else if (len <= 0xffffff) {
        der_w_u8(w, 0x83);
        der_w_u8(w, (uint8_t)(len >> 16));
        der_w_u8(w, (uint8_t)(len >> 8));
        der_w_u8(w, (uint8_t)len);
    } else {
        der_w_u8(w, 0x84);
        der_w_u8(w, (uint8_t)(len >> 24));
        der_w_u8(w, (uint8_t)(len >> 16));
        der_w_u8(w, (uint8_t)(len >> 8));
        der_w_u8(w, (uint8_t)len);
    }
}

void der_w_tlv(der_writer_t *w, uint8_t tag, const uint8_t *content, size_t n) {
    der_w_u8(w, tag);
    der_w_len(w, n);
    der_w_bytes(w, content, n);
}

void der_w_begin(der_writer_t *w, uint8_t tag, der_frame_t *f) {
    der_w_u8(w, tag);
    f->lenpos = w->len;
    der_w_u8(w, 0x00); /* one-byte length placeholder */
}

/* Back-patch the length; extends the length field if content grows past 127.
 * The writer buffer must have slack for the inserted bytes (x509 uses a
 * generously sized buffer, certs are < 1 KiB). */
void der_w_end(der_writer_t *w, der_frame_t *f) {
    if (w->err) return;
    size_t content = w->len - f->lenpos - 1;
    if (content < 128) {
        w->buf[f->lenpos] = (uint8_t)content;
        return;
    }
    int extra = 0;
    if (content <= 0xff) extra = 1;
    else if (content <= 0xffff) extra = 2;
    else extra = 3;
    if (content > 0xffffff) extra = 4;
    /* shift content right to make room for the extra length octets */
    memmove(w->buf + f->lenpos + 1 + extra,
            w->buf + f->lenpos + 1, content);
    w->buf[f->lenpos] = (uint8_t)(0x80 | extra);
    for (int i = 0; i < extra; i++)
        w->buf[f->lenpos + 1 + i] =
            (uint8_t)(content >> (8 * (extra - 1 - i)));
    w->len += (size_t)extra;
}

void der_w_null(der_writer_t *w) {
    der_w_tlv(w, DER_TAG_NULL, NULL, 0);
}

void der_w_oid(der_writer_t *w, const uint8_t *oid, size_t oid_len) {
    der_w_tlv(w, DER_TAG_OID, oid, oid_len);
}

/* INTEGER with minimal encoding: strip leading zeros, add 0x00 if sign bit set. */
void der_w_int_bytes(der_writer_t *w, const uint8_t *v, size_t n) {
    if (w->err) return;
    while (n > 0 && v[0] == 0) { v++; n--; }
    if (n == 0) { der_w_tlv(w, DER_TAG_INTEGER, (const uint8_t[]){0}, 1); return; }
    if (v[0] & 0x80) {
        der_w_u8(w, DER_TAG_INTEGER);
        der_w_len(w, n + 1);
        der_w_u8(w, 0x00);
        der_w_bytes(w, v, n);
    } else {
        der_w_tlv(w, DER_TAG_INTEGER, v, n);
    }
}

void der_w_int_u32(der_writer_t *w, uint32_t v) {
    uint8_t b[4];
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)v;
    der_w_int_bytes(w, b, 4);
}

/* BIT STRING; unused-bits octet is 0. */
void der_w_bitstring(der_writer_t *w, const uint8_t *data, size_t n) {
    if (w->err) return;
    der_w_u8(w, DER_TAG_BIT_STRING);
    der_w_len(w, n + 1);
    der_w_u8(w, 0x00);
    der_w_bytes(w, data, n);
}

void der_w_printable(der_writer_t *w, const char *s) {
    der_w_tlv(w, DER_TAG_PRINTABLE, (const uint8_t *)s, strlen(s));
}

void der_w_utf8(der_writer_t *w, const char *s) {
    der_w_tlv(w, DER_TAG_UTF8STRING, (const uint8_t *)s, strlen(s));
}

/* UTCTime "YYMMDDHHMMSSZ" (13 bytes, explicit Z). */
void der_w_utctime(der_writer_t *w, const uint8_t yymmddhhmmssz[13]) {
    der_w_tlv(w, DER_TAG_UTCTIME, yymmddhhmmssz, 13);
}
