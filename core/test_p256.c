/* test_p256.c — ECDH P-256 против независимой реализации.
 *
 * Векторы получены OpenSSL 3.6 (07.10.2026): genpkey -algorithm EC
 * ec_paramgen_curve:P-256 для двух ключей, затем pkeyutl -derive в обе
 * стороны — общий секрет совпал. Ошибка в арифметике кривой не падает: она
 * даёт «рукопожатие не сошлось» на живом сервере, и искать её пришлось бы в
 * сети, а не на столе. */
#include <stdio.h>
#include <string.h>
#include "d2k_p256.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", m); fails++; } } while (0)

static void unhex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

int main(void) {
    uint8_t a_priv[32], a_pub[65], b_priv[32], b_pub[65], shared[32];
    unhex("60c7bc1c40275f75883df0d27252a20f8d8b579fd851bc7d8a53bec208dd9f49", a_priv, 32);
    unhex("047329d9a06f3f2172e1bb01e72a4b4b1342390b4c313a155fa8c87b4e277a716b"
          "8aefdab467ffd7e9066d6503e958861aa7bb1dfb37db1ba6deaf0359e82728c0", a_pub, 65);
    unhex("da668fed084f9c98cc8af59971b1e93899af333ba232e67a197f635cd4962e57", b_priv, 32);
    unhex("04d24a399cf4c6aa04d6e0a57e8624b1e85fe1284b3d651b52016e2d2d948fb3d2"
          "2d57fd6fd00c25bbb10b9fd8964ef8103e669644ab487487afabc6adf73022d1", b_pub, 65);
    unhex("95d0bba82edfce37acd0970a227952abd68abade6ceb1331bee2544cd160419f", shared, 32);

    /* 1·G = G: генератор и перевод в поле и обратно. */
    uint8_t one[32] = {0}, g[65], gx[65];
    one[31] = 1;
    unhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
          "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", g, 65);
    CHECK(d2k_p256_public(one, gx) == 0 && !memcmp(gx, g, 65), "1·G не равно генератору");

    uint8_t pub[65], out[32];
    CHECK(d2k_p256_public(a_priv, pub) == 0 && !memcmp(pub, a_pub, 65), "открытая точка ключа A");
    CHECK(d2k_p256_public(b_priv, pub) == 0 && !memcmp(pub, b_pub, 65), "открытая точка ключа B");
    CHECK(d2k_p256_ecdh(a_priv, b_pub, out) == 0 && !memcmp(out, shared, 32), "секрет A·B");
    CHECK(d2k_p256_ecdh(b_priv, a_pub, out) == 0 && !memcmp(out, shared, 32), "секрет B·A");

    /* Отказы: формат точки, точка не на кривой, скаляры вне 1..n-1. */
    uint8_t bad[65];
    memcpy(bad, b_pub, 65); bad[0] = 0x02;
    CHECK(d2k_p256_ecdh(a_priv, bad, out) != 0, "сжатая/чужая форма точки принята");
    memcpy(bad, b_pub, 65); bad[64] ^= 1;
    CHECK(d2k_p256_ecdh(a_priv, bad, out) != 0, "точка не на кривой принята");
    memset(bad, 0xff, 65); bad[0] = 0x04;
    CHECK(d2k_p256_ecdh(a_priv, bad, out) != 0, "координаты вне поля приняты");
    uint8_t zero[32] = {0}, n[32];
    unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", n, 32);
    CHECK(d2k_p256_public(zero, pub) != 0, "нулевой скаляр принят");
    CHECK(d2k_p256_public(n, pub) != 0, "скаляр n принят");

    /* Свежие пары: симметрия секрета. */
    for (int i = 0; i < 4; i++) {
        uint8_t p1[32], q1[65], p2[32], q2[65], s1[32], s2[32];
        CHECK(d2k_p256_keypair(p1, q1) == 0 && d2k_p256_keypair(p2, q2) == 0, "пара не создалась");
        CHECK(memcmp(p1, p2, 32) != 0, "две пары с одним ключом");
        CHECK(d2k_p256_ecdh(p1, q2, s1) == 0 && d2k_p256_ecdh(p2, q1, s2) == 0 &&
              !memcmp(s1, s2, 32), "секрет свежих пар не симметричен");
    }
    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    puts("p256: генератор, векторы OpenSSL в обе стороны, отказы и свежие пары — пройдено");
    return 0;
}
