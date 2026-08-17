#ifndef X509_H
#define X509_H

#include <stdint.h>
#include <stddef.h>
#include <ecc.h>

/* Self-signed ECDSA P-256 / SHA-256 x.509 v3 certificate generation. */

#define X509_CN_MAX 64
#define X509_SERIAL_MAX 20

typedef struct {
    char     subject[X509_CN_MAX + 1]; /* CN (also used as issuer) */
    uint8_t  serial[X509_SERIAL_MAX];  /* big-endian serial number */
    size_t   serial_len;
    uint8_t  not_before[13];           /* "YYMMDDHHMMSSZ" */
    uint8_t  not_after[13];
    ecc_key_t key;                     /* keypair embedded in the cert */
} x509_req_t;

/* Build a DER-encoded self-signed certificate.
 * Returns 0 on success, -1 on error. Writes *out_len bytes into out. */
int x509_generate(const x509_req_t *req, uint8_t *out, size_t cap,
                  size_t *out_len);

/* PEM-encode a DER certificate (BEGIN/END CERTIFICATE, 64-col). */
int x509_der_to_pem(const uint8_t *der, size_t der_len, char *out, size_t cap,
                    size_t *out_len);

#endif /* X509_H */
