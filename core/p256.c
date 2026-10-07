/* p256.c — ECDH на secp256r1 для зонда подтверждения (d2k_p256.h).
 *
 * УСТРОЙСТВО. Поле — восемь 32-битных слов, младшее первым; умножение —
 * Монтгомери (CIOS) с 64-битным накоплением: одна и та же арифметика на
 * ARM, MIPS32 и x86, без __int128. Точки — якобиевы координаты, a = -3.
 * Скалярное умножение — удвоение и сложение от старшего бита: не постоянного
 * времени (см. заголовок — ключ одноразовый, это зонд).
 *
 * Проверка — test_p256.c: генератор и векторы OpenSSL в обе стороны. */
#include <stdint.h>
#include <string.h>

#include "d2k_p256.h"
#include "d2k_tls13core.h"

typedef uint32_t fe[8];

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const fe P = { 0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
                      0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu };
/* n — порядок генератора. */
static const fe N = { 0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
                      0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu };
static const fe B = { 0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u, 0x651d06b0u,
                      0x769886bcu, 0xb3ebbd55u, 0xaa3a93e7u, 0x5ac635d8u };
static const fe GX = { 0xd898c296u, 0xf4a13945u, 0x2deb33a0u, 0x77037d81u,
                       0x63a440f2u, 0xf8bce6e5u, 0xe12c4247u, 0x6b17d1f2u };
static const fe GY = { 0x37bf51f5u, 0xcbb64068u, 0x6b315eceu, 0x2bce3357u,
                       0x7c0f9e16u, 0x8ee7eb4au, 0xfe1a7f9bu, 0x4fe342e2u };

static void fe_copy(fe r, const fe a) { memcpy(r, a, sizeof(fe)); }

/* a >= b без учёта знака. */
static int ge(const fe a, const fe b) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] != b[i]) { return a[i] > b[i]; }
    }
    return 1;
}

static int is_zero(const fe a) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) { acc |= a[i]; }
    return acc == 0;
}

/* r = a - b, вернуть заём. */
static uint32_t sub_raw(fe r, const fe a, const fe b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)d;
        borrow = (d >> 63) & 1;
    }
    return (uint32_t)borrow;
}

/* r = a + b, вернуть перенос. */
static uint32_t add_raw(fe r, const fe a, const fe b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (uint32_t)carry;
}

static void fe_add(fe r, const fe a, const fe b) {
    fe t;
    uint32_t c = add_raw(t, a, b);
    if (c || ge(t, P)) { sub_raw(t, t, P); }
    fe_copy(r, t);
}

static void fe_sub(fe r, const fe a, const fe b) {
    fe t;
    if (sub_raw(t, a, b)) { add_raw(t, t, P); }
    fe_copy(r, t);
}

/* Монтгомери: r = a·b·2^-256 mod p. -p^-1 mod 2^32 = 1, потому что младшее
 * слово p — 0xffffffff (p ≡ -1 mod 2^32). */
static void fe_mul(fe r, const fe a, const fe b) {
    uint32_t t[10] = {0};
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + c;
            t[j] = (uint32_t)s;
            c = s >> 32;
        }
        uint64_t s = (uint64_t)t[8] + c;
        t[8] = (uint32_t)s;
        t[9] = (uint32_t)(s >> 32);
        uint32_t m = t[0]; /* t[0] * (-p^-1) mod 2^32, множитель 1 */
        c = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t u = (uint64_t)t[j] + (uint64_t)m * P[j] + c;
            if (j > 0) { t[j - 1] = (uint32_t)u; }
            c = u >> 32;
        }
        s = (uint64_t)t[8] + c;
        t[7] = (uint32_t)s;
        s = (uint64_t)t[9] + (s >> 32);
        t[8] = (uint32_t)s;
        t[9] = 0;
    }
    fe res;
    memcpy(res, t, sizeof res);
    if (t[8] || ge(res, P)) { sub_raw(res, res, P); }
    fe_copy(r, res);
}

static void fe_sqr(fe r, const fe a) { fe_mul(r, a, a); }

/* R^2 mod p и R mod p (R = 2^256) — константы, а не ленивый расчёт:
 * зонды идут из нескольких рабочих потоков d2kc сразу. */
static const fe R2 = { 0x00000003u, 0x00000000u, 0xffffffffu, 0xfffffffbu,
                       0xfffffffeu, 0xffffffffu, 0xfffffffdu, 0x00000004u };
static const fe ONE_M = { 0x00000001u, 0x00000000u, 0x00000000u, 0xffffffffu,
                          0xffffffffu, 0xffffffffu, 0xfffffffeu, 0x00000000u };

static void to_mont(fe r, const fe a) { fe_mul(r, a, R2); }
static void from_mont(fe r, const fe a) {
    fe one = { 1, 0, 0, 0, 0, 0, 0, 0 };
    fe_mul(r, a, one);
}

/* r = a^(p-2): обратный по малой теореме Ферма, в домене Монтгомери. */
static void fe_inv(fe r, const fe a) {
    fe e, acc;
    fe two = { 2, 0, 0, 0, 0, 0, 0, 0 };
    sub_raw(e, P, two);
    fe_copy(acc, ONE_M);
    for (int i = 255; i >= 0; i--) {
        fe_sqr(acc, acc);
        if ((e[i / 32] >> (i % 32)) & 1) { fe_mul(acc, acc, a); }
    }
    fe_copy(r, acc);
}

static void fe_from_be(fe r, const uint8_t *b) {
    for (int i = 0; i < 8; i++) {
        const uint8_t *q = b + 28 - 4 * i;
        r[i] = (uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 | (uint32_t)q[2] << 8 | q[3];
    }
}

static void fe_to_be(uint8_t *b, const fe a) {
    for (int i = 0; i < 8; i++) {
        uint8_t *q = b + 28 - 4 * i;
        q[0] = (uint8_t)(a[i] >> 24); q[1] = (uint8_t)(a[i] >> 16);
        q[2] = (uint8_t)(a[i] >> 8);  q[3] = (uint8_t)a[i];
    }
}

/* Точка в якобиевых координатах (Монтгомери); inf — бесконечность. */
typedef struct { fe x, y, z; int inf; } jpt;

static void pt_double(jpt *r, const jpt *p) {
    if (p->inf || is_zero(p->y)) { r->inf = 1; return; }
    fe delta, gamma, beta, alpha, t1, t2, x3, y3, z3;
    fe_sqr(delta, p->z);
    fe_sqr(gamma, p->y);
    fe_mul(beta, p->x, gamma);
    fe_sub(t1, p->x, delta);
    fe_add(t2, p->x, delta);
    fe_mul(alpha, t1, t2);
    fe_add(t1, alpha, alpha);
    fe_add(alpha, t1, alpha);              /* alpha = 3(x-δ)(x+δ) */
    fe_sqr(x3, alpha);
    fe_add(t1, beta, beta);                /* 2β */
    fe_add(t1, t1, t1);                    /* 4β */
    fe_add(t2, t1, t1);                    /* 8β */
    fe_sub(x3, x3, t2);
    fe_add(z3, p->y, p->z);
    fe_sqr(z3, z3);
    fe_sub(z3, z3, gamma);
    fe_sub(z3, z3, delta);
    fe_sub(t1, t1, x3);                    /* 4β - x3 */
    fe_mul(y3, alpha, t1);
    fe_sqr(t2, gamma);                     /* γ² */
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);                    /* 8γ² */
    fe_sub(y3, y3, t2);
    fe_copy(r->x, x3); fe_copy(r->y, y3); fe_copy(r->z, z3);
    r->inf = 0;
}

static void pt_add(jpt *r, const jpt *p, const jpt *q) {
    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }
    fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t, x3, y3, z3;
    fe_sqr(z1z1, p->z);
    fe_sqr(z2z2, q->z);
    fe_mul(u1, p->x, z2z2);
    fe_mul(u2, q->x, z1z1);
    fe_mul(t, q->z, z2z2);
    fe_mul(s1, p->y, t);
    fe_mul(t, p->z, z1z1);
    fe_mul(s2, q->y, t);
    fe_sub(h, u2, u1);
    fe_sub(rr, s2, s1);
    if (is_zero(h)) {
        if (is_zero(rr)) { pt_double(r, p); return; }
        r->inf = 1;
        return;
    }
    fe_add(i, h, h);
    fe_sqr(i, i);                          /* I = (2H)² */
    fe_mul(j, h, i);                       /* J = H·I */
    fe_add(rr, rr, rr);                    /* r = 2(S2-S1) */
    fe_mul(v, u1, i);
    fe_sqr(x3, rr);
    fe_sub(x3, x3, j);
    fe_sub(x3, x3, v);
    fe_sub(x3, x3, v);
    fe_sub(t, v, x3);
    fe_mul(y3, rr, t);
    fe_mul(t, s1, j);
    fe_add(t, t, t);
    fe_sub(y3, y3, t);
    fe_add(z3, p->z, q->z);
    fe_sqr(z3, z3);
    fe_sub(z3, z3, z1z1);
    fe_sub(z3, z3, z2z2);
    fe_mul(z3, z3, h);
    fe_copy(r->x, x3); fe_copy(r->y, y3); fe_copy(r->z, z3);
    r->inf = 0;
}

/* k (big-endian, 32 байта) · точка (аффинная, в домене Монтгомери). */
static void pt_mul(jpt *r, const uint8_t k[32], const fe ax, const fe ay) {
    jpt base, acc;
    fe_copy(base.x, ax); fe_copy(base.y, ay); fe_copy(base.z, ONE_M); base.inf = 0;
    acc.inf = 1;
    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 7; bit >= 0; bit--) {
            pt_double(&acc, &acc);
            if ((k[byte] >> bit) & 1) { pt_add(&acc, &acc, &base); }
        }
    }
    *r = acc;
}

/* Аффинные координаты (обычный домен, не Монтгомери). -1 — бесконечность. */
static int pt_affine(const jpt *p, fe x, fe y) {
    if (p->inf || is_zero(p->z)) { return -1; }
    fe zi, zi2, zi3, t;
    fe_inv(zi, p->z);
    fe_sqr(zi2, zi);
    fe_mul(zi3, zi2, zi);
    fe_mul(t, p->x, zi2);
    from_mont(x, t);
    fe_mul(t, p->y, zi3);
    from_mont(y, t);
    return 0;
}

static int scalar_ok(const uint8_t k[32]) {
    fe s;
    fe_from_be(s, k);
    return !is_zero(s) && !ge(s, N);
}

int d2k_p256_public(const uint8_t priv[32], uint8_t pub[65]) {
    if (!priv || !pub || !scalar_ok(priv)) { return -1; }
    fe gx, gy, x, y;
    to_mont(gx, GX);
    to_mont(gy, GY);
    jpt r;
    pt_mul(&r, priv, gx, gy);
    if (pt_affine(&r, x, y) != 0) { return -1; }
    pub[0] = 0x04;
    fe_to_be(pub + 1, x);
    fe_to_be(pub + 33, y);
    return 0;
}

int d2k_p256_keypair(uint8_t priv[32], uint8_t pub[65]) {
    if (!priv || !pub) { return -1; }
    for (int tries = 0; tries < 16; tries++) {
        if (d2k_t13_random(priv, 32) != 0) { return -1; }
        if (scalar_ok(priv)) { return d2k_p256_public(priv, pub); }
    }
    return -1;
}

int d2k_p256_ecdh(const uint8_t priv[32], const uint8_t peer[65], uint8_t out_x[32]) {
    if (!priv || !peer || !out_x || !scalar_ok(priv) || peer[0] != 0x04) { return -1; }
    fe x, y;
    fe_from_be(x, peer + 1);
    fe_from_be(y, peer + 33);
    if (ge(x, P) || ge(y, P)) { return -1; }
    /* y² = x³ - 3x + b */
    fe xm, ym, bm, lhs, rhs, t;
    to_mont(xm, x);
    to_mont(ym, y);
    to_mont(bm, B);
    fe_sqr(lhs, ym);
    fe_sqr(rhs, xm);
    fe_mul(rhs, rhs, xm);
    fe_add(t, xm, xm);
    fe_add(t, t, xm);
    fe_sub(rhs, rhs, t);
    fe_add(rhs, rhs, bm);
    if (memcmp(lhs, rhs, sizeof(fe)) != 0) { return -1; }
    jpt r;
    pt_mul(&r, priv, xm, ym);
    fe sx, sy;
    if (pt_affine(&r, sx, sy) != 0) { return -1; }
    fe_to_be(out_x, sx);
    return 0;
}
