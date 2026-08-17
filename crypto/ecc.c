/*
 * P-256 (secp256r1) field arithmetic and ECDSA for AxonOS.
 *
 * Field elements: 4x64-bit little-endian limbs. Internal field arithmetic uses
 * Montgomery form (R = 2^256) with CIOS Montgomery reduction. Scalar arithmetic
 * mod n (curve order) uses the same machinery with a different modulus.
 * 128-bit intermediates via GCC __uint128_t.
 */

#include <ecc.h>
#include <crypto_rand.h>
#include <sha256.h>
#include <string.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
#define P0 0xffffffffffffffffULL
#define P1 0x00000000ffffffffULL
#define P2 0x0000000000000000ULL
#define P3 0xffffffff00000001ULL

/* n (curve order) */
#define N0 0xf3b9cac2fc632551ULL
#define N1 0xbce6faada7179e84ULL
#define N2 0xffffffffffffffffULL
#define N3 0xffffffff00000000ULL

/* b of y^2 = x^3 - 3x + b */
#define B0 0x3bce3c3e27d2604bULL
#define B1 0x651d06b0cc53b0f6ULL
#define B2 0xb3ebbd55769886bcULL
#define B3 0x5ac635d8aa3a93e7ULL

/* Base point G */
#define GX0 0xf4a13945d898c296ULL
#define GX1 0x77037d812deb33a0ULL
#define GX2 0xf8bce6e563a440f2ULL
#define GX3 0x6b17d1f2e12c4247ULL
#define GY0 0xcbb6406837bf51f5ULL
#define GY1 0x2bce33576b315eceULL
#define GY2 0x8ee7eb4a7c0f9e16ULL
#define GY3 0x4fe342e2fe1a7f9bULL

static const u64 P[4] = { P0, P1, P2, P3 };
static const u64 N[4] = { N0, N1, N2, N3 };
static const u64 B[4] = { B0, B1, B2, B3 };

/* -p[0]^-1 mod 2^64 (p[0] = -1) */
#define P0INV 1ULL
/* -n[0]^-1 mod 2^64 (computed at build time) */
#define N0INV 0xccd1c8aaee00bc4fULL

/* 2^512 mod p / mod n (LE limbs). Computed offline — boot must not loop 512×add. */
static const u64 R2P[4] = {
    0x0000000000000003ULL, 0xfffffffbffffffffULL,
    0xfffffffffffffffeULL, 0x00000004fffffffdULL
};
static const u64 R2N[4] = {
    0x83244c95be79eea2ULL, 0x4699799c49bd6fa6ULL,
    0x2845b2392b6bec59ULL, 0x66e12d94f3d95620ULL
};
static u64 GXm[4], GYm[4]; /* G in Montgomery form */
static u64 ONEM[4]; /* 1 in Montgomery form (Z=1 for affine points) */
static u64 PM2[4]; /* p-2 (Fermat inversion exponent) */
static u64 NM2[4]; /* n-2 (scalar inverse exponent) */
static int g_curve_ready = 0;

static const u64 ONE[4] = { 1, 0, 0, 0 };

/* ---------------- generic big-int helpers ---------------- */

static int fe_ge(const u64 a[4], const u64 b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1;
}

static int fe_equal(const u64 a[4], const u64 b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static int fe_is_zero(const u64 a[4]) {
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

static void fe_set_zero(u64 r[4]) { r[0] = r[1] = r[2] = r[3] = 0; }
static void fe_copy(u64 r[4], const u64 a[4]) {
    r[0] = a[0]; r[1] = a[1]; r[2] = a[2]; r[3] = a[3];
}

static void fe_add_m(u64 r[4], const u64 a[4], const u64 b[4], const u64 mod[4]) {
    u64 s[5];
    u64 carry = 0;
    for (int i = 0; i < 4; i++) {
        u128 cur = (u128)a[i] + b[i] + carry;
        s[i] = (u64)cur;
        carry = (u64)(cur >> 64);
    }
    s[4] = carry;

    /* inputs < mod < 2^256, sum < 2*mod < 2^257: at most two subtractions. */
    for (int k = 0; k < 2; k++) {
        if (s[4] == 0 && !fe_ge(s, mod)) break;
        u64 borrow = 0;
        for (int i = 0; i < 5; i++) {
            u128 cur = (u128)s[i] - (i < 4 ? mod[i] : 0) - borrow;
            s[i] = (u64)cur;
            borrow = (u64)((cur >> 64) & 1);
        }
    }
    fe_copy(r, s);
}

static void fe_sub_m(u64 r[4], const u64 a[4], const u64 b[4], const u64 mod[4]) {
    u64 s[4];
    u64 borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 cur = (u128)a[i] - b[i] - borrow;
        s[i] = (u64)cur;
        borrow = (u64)((cur >> 64) & 1);
    }
    if (borrow) {
        u64 carry = 0;
        for (int i = 0; i < 4; i++) {
            u128 cur = (u128)s[i] + mod[i] + carry;
            s[i] = (u64)cur;
            carry = (u64)(cur >> 64);
        }
    }
    fe_copy(r, s);
}

/* Montgomery multiplication: r = a*b*2^-256 mod m. mod0inv = -m[0]^-1 mod 2^64. */
static void mont_mul_m(u64 r[4], const u64 a[4], const u64 b[4],
                       const u64 mod[4], u64 mod0inv) {
    u64 t[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    for (int i = 0; i < 4; i++) {
        u64 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 cur = (u128)t[j] + (u128)a[i] * b[j] + carry;
            t[j] = (u64)cur;
            carry = (u64)(cur >> 64);
        }
        for (int j = 4; j < 8 && carry; j++) {
            u128 cur = (u128)t[j] + carry;
            t[j] = (u64)cur;
            carry = (u64)(cur >> 64);
        }

        u64 m = t[0] * mod0inv;

        u64 carry2 = 0;
        for (int j = 0; j < 4; j++) {
            u128 cur = (u128)t[j] + (u128)m * mod[j] + carry2;
            t[j] = (u64)cur;
            carry2 = (u64)(cur >> 64);
        }
        for (int j = 4; j < 8 && carry2; j++) {
            u128 cur = (u128)t[j] + carry2;
            t[j] = (u64)cur;
            carry2 = (u64)(cur >> 64);
        }

        for (int j = 0; j < 7; j++) t[j] = t[j + 1];
        t[7] = 0;
    }

    /* Final reduction: result in t[0..3] is < 2*mod < 2^257. t[4..7] may hold
     * the top bit. Compare the 5-limb value against mod, subtract once if >=. */
    if (t[4] || t[5] || t[6] || t[7]) {
        u64 borrow = 0;
        for (int i = 0; i < 8; i++) {
            u128 cur = (u128)t[i] - (i < 4 ? mod[i] : 0) - borrow;
            t[i] = (u64)cur;
            borrow = (u64)((cur >> 64) & 1);
        }
    } else if (fe_ge(t, mod)) {
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            u128 cur = (u128)t[i] - mod[i] - borrow;
            t[i] = (u64)cur;
            borrow = (u64)((cur >> 64) & 1);
        }
    }
    fe_copy(r, t);
}

static void fe_mul_p(u64 r[4], const u64 a[4], const u64 b[4]) {
    mont_mul_m(r, a, b, P, P0INV);
}
static void fe_sqr_p(u64 r[4], const u64 a[4]) { mont_mul_m(r, a, a, P, P0INV); }
static void fe_add_p(u64 r[4], const u64 a[4], const u64 b[4]) { fe_add_m(r, a, b, P); }
static void fe_sub_p(u64 r[4], const u64 a[4], const u64 b[4]) { fe_sub_m(r, a, b, P); }

static void to_mont_p(u64 r[4], const u64 a[4]) { mont_mul_m(r, a, R2P, P, P0INV); }
static void from_mont_p(u64 r[4], const u64 a[4]) { mont_mul_m(r, a, ONE, P, P0INV); }

/* r = a*b mod n (normal form in, normal form out) */
static void mod_mul_n(u64 r[4], const u64 a[4], const u64 b[4]) {
    u64 am[4], bm[4], tmp[4];
    mont_mul_m(am, a, R2N, N, N0INV);
    mont_mul_m(bm, b, R2N, N, N0INV);
    mont_mul_m(tmp, am, bm, N, N0INV);
    mont_mul_m(r, tmp, ONE, N, N0INV);
}
static void mod_add_n(u64 r[4], const u64 a[4], const u64 b[4]) { fe_add_m(r, a, b, N); }
static void mod_sub_n(u64 r[4], const u64 a[4], const u64 b[4]) { fe_sub_m(r, a, b, N); }

/* reduce arbitrary 256-bit value mod n (value < 2^256, n > 2^255: one subtraction) */
static void mod_reduce_n(u64 r[4], const u64 a[4]) {
    fe_copy(r, a);
    if (fe_ge(r, N)) {
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            u128 cur = (u128)r[i] - N[i] - borrow;
            r[i] = (u64)cur;
            borrow = (u64)((cur >> 64) & 1);
        }
    }
}

/* r = base^exp mod m (right-to-left binary exponentiation, Montgomery domain).
 * exp is 256-bit LE. */
static void mod_exp(u64 r[4], const u64 base[4], const u64 exp[4],
                    const u64 mod[4], u64 mod0inv, const u64 r2[4]) {
    u64 bm[4], acc[4];
    mont_mul_m(bm, base, r2, mod, mod0inv);     /* base -> Montgomery */
    mont_mul_m(acc, ONE, r2, mod, mod0inv);      /* 1 in Montgomery form (= R mod m) */
    for (int bit = 0; bit < 256; bit++) {
        if ((exp[bit >> 6] >> (bit & 63)) & 1)
            mont_mul_m(acc, acc, bm, mod, mod0inv);
        mont_mul_m(bm, bm, bm, mod, mod0inv);
    }
    mont_mul_m(r, acc, ONE, mod, mod0inv);       /* back to normal form */
}

static void curve_init(void) {
    if (g_curve_ready) return;
    to_mont_p(ONEM, ONE);
    fe_copy(PM2, P); PM2[0] -= 2;
    fe_copy(NM2, N); NM2[0] -= 2;
    {
        const u64 gx[4] = { GX0, GX1, GX2, GX3 };
        const u64 gy[4] = { GY0, GY1, GY2, GY3 };
        to_mont_p(GXm, gx);
        to_mont_p(GYm, gy);
    }
    g_curve_ready = 1;
}

/* ---------------- Jacobian point ops (field values in Montgomery form) ---------------- */

static void point_set_infinity(u64 X[4], u64 Y[4], u64 Z[4]) {
    fe_set_zero(X); fe_copy(Y, ONEM); fe_set_zero(Z);
}

static void point_copy(u64 X3[4], u64 Y3[4], u64 Z3[4],
                       const u64 X1[4], const u64 Y1[4], const u64 Z1[4]) {
    fe_copy(X3, X1); fe_copy(Y3, Y1); fe_copy(Z3, Z1);
}

/* R = 2*P (Jacobian, a = -3). Alias-safe: copies inputs to locals first. */
static void point_double(u64 X3[4], u64 Y3[4], u64 Z3[4],
                         const u64 X1[4], const u64 Y1[4], const u64 Z1[4]) {
    u64 x1[4], y1[4], z1[4];
    fe_copy(x1, X1); fe_copy(y1, Y1); fe_copy(z1, Z1);
    if (fe_is_zero(z1) || fe_is_zero(y1)) {
        point_set_infinity(X3, Y3, Z3);
        return;
    }
    u64 A[4], Bc[4], C[4], S[4], E[4], F[4], t[4], t2[4];
    fe_sqr_p(A, x1);            /* X1^2 */
    fe_sqr_p(Bc, y1);           /* Y1^2 */
    fe_sqr_p(C, Bc);            /* Y1^4 */
    fe_add_p(t, x1, Bc);
    fe_sqr_p(S, t);             /* (X1+B)^2 */
    fe_sub_p(S, S, A);
    fe_sub_p(S, S, C);
    fe_add_p(S, S, S);          /* S = 2*((X1+B)^2 - A - C) */
    fe_sqr_p(t, z1);            /* Z1^2 */
    fe_sqr_p(t2, t);            /* Z1^4 */
    fe_sub_p(E, A, t2);         /* X1^2 - Z1^4 */
    fe_add_p(t, E, E);
    fe_add_p(E, E, t);          /* E = 3*(X1^2 - Z1^4) */
    fe_sqr_p(F, E);             /* E^2 */
    fe_sub_p(X3, F, S);
    fe_sub_p(X3, X3, S);        /* X3 = E^2 - 2*S */
    fe_sub_p(t, S, X3);
    fe_mul_p(Y3, E, t);         /* E*(S - X3) */
    fe_add_p(t, C, C);
    fe_add_p(t, t, t);
    fe_add_p(t, t, t);          /* 8*C */
    fe_sub_p(Y3, Y3, t);        /* Y3 = E*(S-X3) - 8*C */
    fe_mul_p(Z3, y1, z1);
    fe_add_p(Z3, Z3, Z3);       /* Z3 = 2*Y1*Z1 */
}

/* R = P + Q, Q affine (Z=1). Alias-safe. */
static void point_add_mixed(u64 X3[4], u64 Y3[4], u64 Z3[4],
                            const u64 X1[4], const u64 Y1[4], const u64 Z1[4],
                            const u64 X2[4], const u64 Y2[4]) {
    u64 x1[4], y1[4], z1[4], x2[4], y2[4];
    fe_copy(x1, X1); fe_copy(y1, Y1); fe_copy(z1, Z1);
    fe_copy(x2, X2); fe_copy(y2, Y2);
    if (fe_is_zero(z1)) {
        fe_copy(X3, x2); fe_copy(Y3, y2); fe_copy(Z3, ONEM);
        return;
    }
    u64 Z1Z1[4], U2[4], S2[4], H[4], r[4], HH[4], I[4], J[4], V[4], t[4], t2[4];
    fe_sqr_p(Z1Z1, z1);
    fe_mul_p(U2, x2, Z1Z1);
    fe_mul_p(t, y2, z1);
    fe_mul_p(S2, t, Z1Z1);
    fe_sub_p(H, U2, x1);
    fe_sub_p(r, S2, y1);
    fe_add_p(r, r, r);          /* r = 2*(S2 - Y1) */
    if (fe_is_zero(H)) {
        if (fe_is_zero(r)) { point_double(X3, Y3, Z3, x1, y1, z1); return; }
        point_set_infinity(X3, Y3, Z3);
        return;
    }
    fe_sqr_p(HH, H);
    fe_add_p(I, HH, HH);
    fe_add_p(I, I, I);          /* I = 4*HH */
    fe_mul_p(J, H, I);
    fe_mul_p(V, x1, I);
    fe_sqr_p(t, r);
    fe_sub_p(X3, t, J);
    fe_sub_p(X3, X3, V);
    fe_sub_p(X3, X3, V);        /* X3 = r^2 - J - 2*V */
    fe_sub_p(t, V, X3);
    fe_mul_p(Y3, r, t);
    fe_mul_p(t, y1, J);
    fe_add_p(t, t, t);
    fe_sub_p(Y3, Y3, t);        /* Y3 = r*(V-X3) - 2*Y1*J */
    fe_add_p(t, z1, H);
    fe_sqr_p(t2, t);
    fe_sub_p(t2, t2, Z1Z1);
    fe_sub_p(t2, t2, HH);
    fe_copy(Z3, t2);
}

/* General Jacobian + Jacobian addition. Textbook formula (a = -3). */
static void point_add_jacobian(u64 X3[4], u64 Y3[4], u64 Z3[4],
                               const u64 X1[4], const u64 Y1[4], const u64 Z1[4],
                               const u64 X2[4], const u64 Y2[4], const u64 Z2[4]) {
    if (fe_is_zero(Z1)) { point_copy(X3, Y3, Z3, X2, Y2, Z2); return; }
    if (fe_is_zero(Z2)) { point_copy(X3, Y3, Z3, X1, Y1, Z1); return; }
    u64 Z1Z1[4], Z2Z2[4], U1[4], U2[4], S1[4], S2[4], H[4], r[4];
    u64 HH[4], HHH[4], t[4], t2[4];
    fe_sqr_p(Z1Z1, Z1);
    fe_sqr_p(Z2Z2, Z2);
    fe_mul_p(U1, X1, Z2Z2);
    fe_mul_p(U2, X2, Z1Z1);
    fe_mul_p(t, Y1, Z2);
    fe_mul_p(S1, t, Z2Z2);
    fe_mul_p(t, Y2, Z1);
    fe_mul_p(S2, t, Z1Z1);
    fe_sub_p(H, U2, U1);
    fe_sub_p(r, S2, S1);
    if (fe_is_zero(H)) {
        if (fe_is_zero(r)) { point_double(X3, Y3, Z3, X1, Y1, Z1); return; }
        point_set_infinity(X3, Y3, Z3);
        return;
    }
    fe_sqr_p(HH, H);          /* H^2 */
    fe_mul_p(HHH, HH, H);     /* H^3 */
    fe_sqr_p(t, r);           /* r^2 */
    fe_sub_p(t, t, HHH);      /* r^2 - H^3 */
    fe_mul_p(t2, U1, HH);     /* U1*H^2 */
    fe_add_p(t2, t2, t2);
    fe_sub_p(X3, t, t2);      /* X3 = r^2 - H^3 - 2*U1*H^2 */
    fe_sub_p(t, U1, X3);
    fe_mul_p(t, t, HH);
    fe_mul_p(Y3, r, t);       /* r*(U1 - X3)*H^2 */
    fe_mul_p(t, S1, HHH);
    fe_sub_p(Y3, Y3, t);      /* Y3 = r*(U1-X3)*H^2 - S1*H^3 */
    fe_mul_p(Z3, Z1, Z2);
    fe_mul_p(Z3, Z3, H);      /* Z3 = Z1*Z2*H */
}

/* Q = k*P, P affine given in Montgomery form. */
static void scalar_mult(const u64 k[4], const u64 BXm[4], const u64 BYm[4],
                        u64 QX[4], u64 QY[4], u64 QZ[4]) {
    point_set_infinity(QX, QY, QZ);
    for (int bit = 255; bit >= 0; bit--) {
        point_double(QX, QY, QZ, QX, QY, QZ);
        if ((k[bit >> 6] >> (bit & 63)) & 1)
            point_add_mixed(QX, QY, QZ, QX, QY, QZ, BXm, BYm);
    }
}

/* Q = k*G. k in normal form LE limbs. */
static void scalar_mult_base(const u64 k[4], u64 QX[4], u64 QY[4], u64 QZ[4]) {
    scalar_mult(k, GXm, GYm, QX, QY, QZ);
}

/* Jacobian -> affine (normal-form output). Returns -1 for infinity. */
static int jacobian_to_affine(const u64 X[4], const u64 Y[4], const u64 Z[4],
                              u64 xout[4], u64 yout[4]) {
    u64 zinv[4], z2[4], z3[4], Xn[4], Yn[4], znormal[4];
    if (fe_is_zero(Z)) return -1;
    from_mont_p(znormal, Z);                      /* Z in normal form */
    mod_exp(zinv, znormal, PM2, P, P0INV, R2P);   /* Z^-1 normal form */
    to_mont_p(zinv, zinv);                        /* back to Montgomery domain */
    fe_mul_p(z2, zinv, zinv);
    fe_mul_p(z3, z2, zinv);
    fe_mul_p(Xn, X, z2);
    fe_mul_p(Yn, Y, z3);
    from_mont_p(xout, Xn);
    from_mont_p(yout, Yn);
    return 0;
}

/* ---------------- byte conversion ---------------- */

static void be_to_limbs(u64 out[4], const uint8_t in[32]) {
    for (int i = 0; i < 4; i++) {
        u64 v = 0;
        for (int j = 0; j < 8; j++)
            v = (v << 8) | in[i * 8 + j];
        out[3 - i] = v;
    }
}

static void limbs_to_be(uint8_t out[32], const u64 in[4]) {
    for (int i = 0; i < 4; i++) {
        u64 v = in[3 - i];
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(v >> (56 - j * 8));
    }
}

/* ---------------- public API ---------------- */

int ecc_point_on_curve(const uint8_t xb[32], const uint8_t yb[32]) {
    u64 x[4], y[4], X[4], Y[4], lhs[4], rhs[4], t[4], Bc[4], x3[4];
    curve_init();
    be_to_limbs(x, xb);
    be_to_limbs(y, yb);
    to_mont_p(X, x);
    to_mont_p(Y, y);
    fe_sqr_p(lhs, Y);             /* y^2 */
    fe_sqr_p(rhs, X);             /* x^2 */
    fe_mul_p(x3, rhs, X);         /* x^3 */
    to_mont_p(Bc, B);
    fe_add_p(rhs, x3, Bc);        /* x^3 + b */
    fe_add_p(t, X, X);
    fe_add_p(t, t, X);            /* 3x */
    fe_sub_p(rhs, rhs, t);        /* x^3 - 3x + b */
    return fe_equal(lhs, rhs) ? 1 : 0;
}

int ecc_scalar_mult_base(const uint8_t kb[32], uint8_t xout[32], uint8_t yout[32]) {
    u64 k[4], QX[4], QY[4], QZ[4], ax[4], ay[4];
    curve_init();
    be_to_limbs(k, kb);
    scalar_mult_base(k, QX, QY, QZ);
    if (jacobian_to_affine(QX, QY, QZ, ax, ay) != 0) return -1;
    limbs_to_be(xout, ax);
    limbs_to_be(yout, ay);
    return 0;
}

int ecc_keygen(ecc_key_t *out) {
    curve_init();
    if (!out) return -1;
    for (int attempt = 0; attempt < 16; attempt++) {
        uint8_t buf[32];
        crypto_rand_bytes(buf, sizeof(buf));
        u64 d[4];
        be_to_limbs(d, buf);
        mod_reduce_n(d, d);
        if (fe_is_zero(d)) continue;
        u64 QX[4], QY[4], QZ[4], ax[4], ay[4];
        scalar_mult_base(d, QX, QY, QZ);
        if (jacobian_to_affine(QX, QY, QZ, ax, ay) != 0) continue;
        limbs_to_be(out->d, d);
        limbs_to_be(out->pub.x, ax);
        limbs_to_be(out->pub.y, ay);
        return 0;
    }
    return -1;
}

/* ---------------- RFC 6979 deterministic nonce ---------------- */

static int ecdsa_generate_k(const uint8_t d[32], const uint8_t h1[32], u64 kout[4]) {
    uint8_t V[32], K[32];
    uint8_t b2o[32];
    u64 t[4];

    memset(V, 0x01, 32);
    memset(K, 0x00, 32);

    /* bits2octets(H1): reduce mod n */
    be_to_limbs(t, h1);
    mod_reduce_n(t, t);
    limbs_to_be(b2o, t);

    /* K = HMAC_K(V || 0x00 || x || h1') */
    {
        uint8_t buf[97];
        memcpy(buf, V, 32);
        buf[32] = 0x00;
        memcpy(buf + 33, d, 32);
        memcpy(buf + 65, b2o, 32);
        hmac_sha256(K, 32, buf, 97, K);
    }
    hmac_sha256(K, 32, V, 32, V);
    {
        uint8_t buf[97];
        memcpy(buf, V, 32);
        buf[32] = 0x01;
        memcpy(buf + 33, d, 32);
        memcpy(buf + 65, b2o, 32);
        hmac_sha256(K, 32, buf, 97, K);
    }
    hmac_sha256(K, 32, V, 32, V);

    for (int i = 0; i < 128; i++) {
        hmac_sha256(K, 32, V, 32, V);
        u64 kk[4];
        be_to_limbs(kk, V);
        if (!fe_is_zero(kk) && !fe_ge(kk, N)) {
            fe_copy(kout, kk);
            return 0;
        }
        uint8_t buf[33];
        memcpy(buf, V, 32);
        buf[32] = 0x00;
        hmac_sha256(K, 32, buf, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }
    return -1;
}

static void inv_mod_n(u64 r[4], const u64 a[4]) {
    mod_exp(r, a, NM2, N, N0INV, R2N);   /* a^(n-2) mod n */
}

int ecdsa_sign(const uint8_t d[32], const uint8_t hash[32],
               uint8_t rb[32], uint8_t sb[32]) {
    curve_init();
    u64 k[4];
    if (ecdsa_generate_k(d, hash, k) != 0)
        return -1;

    u64 QX[4], QY[4], QZ[4], ax[4], ay[4], r[4];
    scalar_mult_base(k, QX, QY, QZ);
    if (jacobian_to_affine(QX, QY, QZ, ax, ay) != 0)
        return -1;
    mod_reduce_n(r, ax);
    if (fe_is_zero(r))
        return ecdsa_sign(d, hash, rb, sb);

    u64 dlimbs[4], el[4], kinv[4], rd[4], t[4], s[4];
    be_to_limbs(dlimbs, d);
    be_to_limbs(el, hash);
    mod_reduce_n(el, el);

    mod_mul_n(rd, r, dlimbs);          /* r*d mod n */
    mod_add_n(t, el, rd);              /* e + r*d mod n */
    inv_mod_n(kinv, k);                /* k^-1 mod n */
    mod_mul_n(s, kinv, t);             /* s = k^-1*(e + r*d) mod n */
    if (fe_is_zero(s))
        return ecdsa_sign(d, hash, rb, sb);

    limbs_to_be(rb, r);
    limbs_to_be(sb, s);
    return 0;
}

int ecdsa_verify(const ecc_point_t *pub, const uint8_t hash[32],
                 const uint8_t rb[32], const uint8_t sb[32]) {
    curve_init();
    u64 r[4], s[4], e[4];
    be_to_limbs(r, rb);
    be_to_limbs(s, sb);
    be_to_limbs(e, hash);
    if (fe_is_zero(r) || fe_is_zero(s)) return -1;
    if (fe_ge(r, N) || fe_ge(s, N)) return -1;
    mod_reduce_n(e, e);
    if (!ecc_point_on_curve(pub->x, pub->y)) return -1;

    u64 w[4], u1[4], u2[4], x1[4], y1[4], z1[4];
    inv_mod_n(w, s);                   /* w = s^-1 mod n */
    mod_mul_n(u1, e, w);               /* u1 = e*w mod n */
    mod_mul_n(u2, r, w);               /* u2 = r*w mod n */

    u64 G1X[4], G1Y[4], G1Z[4], QX[4], QY[4], QZ[4], RX[4], RY[4], RZ[4];
    u64 qx[4], qy[4];
    scalar_mult_base(u1, G1X, G1Y, G1Z);
    be_to_limbs(qx, pub->x);
    be_to_limbs(qy, pub->y);
    to_mont_p(qx, qx);
    to_mont_p(qy, qy);
    scalar_mult(u2, qx, qy, QX, QY, QZ);
    if (fe_is_zero(QZ)) {
        point_copy(RX, RY, RZ, G1X, G1Y, G1Z);
    } else if (fe_is_zero(G1Z)) {
        point_copy(RX, RY, RZ, QX, QY, QZ);
    } else {
        point_add_jacobian(RX, RY, RZ, G1X, G1Y, G1Z, QX, QY, QZ);
    }
    if (jacobian_to_affine(RX, RY, RZ, x1, y1) != 0) return -1;
    mod_reduce_n(x1, x1);
    (void)z1;
    return fe_equal(x1, r) ? 0 : -1;
}
