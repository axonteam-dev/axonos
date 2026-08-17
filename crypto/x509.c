/*
 * Self-signed x.509 v3 certificate generation (ECDSA P-256, SHA-256).
 * RFC 5280 structure; DER-encoded via the asn1 writer.
 */

#include <x509.h>
#include <asn1.h>
#include <sha256.h>
#include <ecc.h>
#include <string.h>

static const uint8_t OID_ECPUBKEY[]      = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01}; /* 1.2.840.10045.2.1   */
static const uint8_t OID_P256[]          = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07}; /* 1.2.840.10045.3.1.7 */
static const uint8_t OID_ECDSA_SHA256[]  = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02}; /* 1.2.840.10045.4.3.2 */
static const uint8_t OID_CN[]            = {0x55,0x04,0x03}; /* 2.5.4.3 */
static const uint8_t OID_C[]             = {0x55,0x04,0x06}; /* 2.5.4.6 */

/* SubjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING EC point. */
static void write_spki(der_writer_t *w, const ecc_key_t *key) {
    der_frame_t spki, alg;
    der_w_begin(w, DER_TAG_SEQUENCE, &spki);
    der_w_begin(w, DER_TAG_SEQUENCE, &alg);
    der_w_oid(w, OID_ECPUBKEY, sizeof OID_ECPUBKEY);
    der_w_oid(w, OID_P256, sizeof OID_P256);
    der_w_end(w, &alg);
    uint8_t raw[65];
    raw[0] = 0x04; /* uncompressed point */
    memcpy(raw + 1, key->pub.x, 32);
    memcpy(raw + 33, key->pub.y, 32);
    der_w_bitstring(w, raw, 65);
    der_w_end(w, &spki);
}

/* RDNSequence: SET of (C=RU, CN=<subject>). */
static void write_name(der_writer_t *w, const char *cn) {
    der_frame_t fname, fset1, fat1, fset2, fat2;
    der_w_begin(w, DER_TAG_SEQUENCE, &fname);
    der_w_begin(w, DER_TAG_SET, &fset1);
    der_w_begin(w, DER_TAG_SEQUENCE, &fat1);
    der_w_oid(w, OID_C, sizeof OID_C);
    der_w_printable(w, "RU");
    der_w_end(w, &fat1);
    der_w_end(w, &fset1);
    der_w_begin(w, DER_TAG_SET, &fset2);
    der_w_begin(w, DER_TAG_SEQUENCE, &fat2);
    der_w_oid(w, OID_CN, sizeof OID_CN);
    der_w_utf8(w, cn);
    der_w_end(w, &fat2);
    der_w_end(w, &fset2);
    der_w_end(w, &fname);
}

int x509_generate(const x509_req_t *req, uint8_t *out, size_t cap,
                  size_t *out_len) {
    if (req->serial_len == 0 || req->serial_len > X509_SERIAL_MAX)
        return -1;

    der_frame_t ftbs, fver, fsig, fval;
    uint8_t tbsbuf[1024];
    der_writer_t tbs;
    der_w_init(&tbs, tbsbuf, sizeof tbsbuf);

    /* TBSCertificate */
    der_w_begin(&tbs, DER_TAG_SEQUENCE, &ftbs);
    der_w_begin(&tbs, DER_TAG_CONTEXT0, &fver);  /* [0] EXPLICIT Version */
    der_w_int_u32(&tbs, 2);                      /* v3 */
    der_w_end(&tbs, &fver);
    der_w_int_bytes(&tbs, req->serial, req->serial_len);
    der_w_begin(&tbs, DER_TAG_SEQUENCE, &fsig);  /* signature */
    der_w_oid(&tbs, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256);
    der_w_null(&tbs);
    der_w_end(&tbs, &fsig);
    write_name(&tbs, req->subject);           /* issuer */
    der_w_begin(&tbs, DER_TAG_SEQUENCE, &fval);  /* validity */
    der_w_utctime(&tbs, req->not_before);
    der_w_utctime(&tbs, req->not_after);
    der_w_end(&tbs, &fval);
    write_name(&tbs, req->subject);           /* subject == issuer */
    write_spki(&tbs, &req->key);
    der_w_end(&tbs, &ftbs);
    if (tbs.err) return -1;
    size_t tbs_len = der_w_size(&tbs);

    /* signature over TBS */
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256(tbsbuf, tbs_len, hash);
    uint8_t r[32], s[32];
    if (ecdsa_sign(req->key.d, hash, r, s) != 0) return -1;

    /* ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } */
    uint8_t sigbuf[80];
    der_writer_t sig;
    der_w_init(&sig, sigbuf, sizeof sigbuf);
    der_frame_t fsigval;
    der_w_begin(&sig, DER_TAG_SEQUENCE, &fsigval);
    der_w_int_bytes(&sig, r, 32);
    der_w_int_bytes(&sig, s, 32);
    der_w_end(&sig, &fsigval);
    if (sig.err) return -1;

    /* Certificate ::= SEQUENCE { tbs, sigAlg, signatureValue } */
    der_writer_t cert;
    der_w_init(&cert, out, cap);
    der_frame_t fcert, fcertsig;
    der_w_begin(&cert, DER_TAG_SEQUENCE, &fcert);
    der_w_bytes(&cert, tbsbuf, tbs_len);
    der_w_begin(&cert, DER_TAG_SEQUENCE, &fcertsig);
    der_w_oid(&cert, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256);
    der_w_null(&cert);
    der_w_end(&cert, &fcertsig);
    der_w_bitstring(&cert, sigbuf, der_w_size(&sig));
    der_w_end(&cert, &fcert);
    if (cert.err) return -1;
    if (out_len) *out_len = der_w_size(&cert);
    return 0;
}

int x509_der_to_pem(const uint8_t *der, size_t der_len, char *out, size_t cap,
                    size_t *out_len)
{
    static const char hdr[] = "-----BEGIN CERTIFICATE-----\n";
    static const char ftr[] = "-----END CERTIFICATE-----\n";
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, n = 0, col = 0;
    size_t b64_len, lines, need;

    if (!der || !out || der_len == 0)
        return -1;
    b64_len = ((der_len + 2) / 3) * 4;
    lines = (b64_len + 63) / 64;
    need = (sizeof(hdr) - 1) + b64_len + lines + (sizeof(ftr) - 1);
    if (cap < need + 1)
        return -1;

    memcpy(out + n, hdr, sizeof(hdr) - 1);
    n += sizeof(hdr) - 1;
    for (i = 0; i < der_len; i += 3) {
        unsigned nleft = (unsigned)(der_len - i);
        uint32_t v = ((uint32_t)der[i]) << 16;
        if (nleft > 1)
            v |= ((uint32_t)der[i + 1]) << 8;
        if (nleft > 2)
            v |= (uint32_t)der[i + 2];
        out[n++] = b64[(v >> 18) & 63];
        out[n++] = b64[(v >> 12) & 63];
        out[n++] = (nleft > 1) ? b64[(v >> 6) & 63] : '=';
        out[n++] = (nleft > 2) ? b64[v & 63] : '=';
        col += 4;
        if (col >= 64) {
            out[n++] = '\n';
            col = 0;
        }
    }
    if (col)
        out[n++] = '\n';
    memcpy(out + n, ftr, sizeof(ftr) - 1);
    n += sizeof(ftr) - 1;
    out[n] = '\0';
    if (out_len)
        *out_len = n;
    return 0;
}
