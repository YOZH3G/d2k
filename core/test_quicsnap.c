/* test_quicsnap.c — пачка Initial-датаграмм клиента (задача 66).
 *
 * Поле 15.10.2026: Chrome с постквантовым key_share шлёт ClientHello двумя
 * Initial, и снимок из одной датаграммы — обрывок. Стенд двух датаграмм общий
 * с задачей 40 (test_quic_pq.h): имя лежит во ВТОРОЙ датаграмме, как у Chrome
 * с его перестановкой расширений.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_quicsnap.h"
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "test_quic_pq.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

int main(void) {
    uint8_t d1[1500], d2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2k_test_pq_initials("rutracker.org", d1, &l1, d2, &l2) == 0, "стенд двух датаграмм");
    const uint8_t *dg[2] = {d1, d2};
    size_t len[2] = {l1, l2};

    /* --- упаковка и разбор --------------------------------------------- */
    uint8_t blob[D2K_SHAPE_MAX];
    size_t bl = d2k_qsnap_pack(dg, len, 2, blob, sizeof blob);
    CHECK(bl == 4 + 2 + l1 + 2 + l2, "длина пачки: магия, число, по длине на датаграмму");
    CHECK(d2k_qsnap_is(blob, bl), "магия пачки не узнана");
    /* Одиночная датаграмма пачкой не притворяется: у длинного заголовка QUIC
       обязателен бит 0x80, и с 'Q' она начаться не может. */
    CHECK(!d2k_qsnap_is(d1, l1), "одиночная датаграмма принята за пачку");

    d2k_qsnap s;
    CHECK(d2k_qsnap_parse(blob, bl, &s) == 0, "разбор пачки");
    CHECK(s.n == 2 && s.len[0] == l1 && s.len[1] == l2, "число и длины датаграмм");
    CHECK(!memcmp(s.dg[0], d1, l1) && !memcmp(s.dg[1], d2, l2), "байты датаграмм не те");

    /* --- приветствие и имя ---------------------------------------------- */
    uint8_t ch[8192];
    size_t chl = 0;
    CHECK(d2k_quic_dgrams_hello(dg, len, 2, ch, sizeof ch, &chl) == 0,
          "ClientHello из двух датаграмм");
    CHECK(chl > 4 && ch[0] == 0x01, "собрано не ClientHello");
    CHECK(chl == 4 + ((size_t)ch[1] << 16 | (size_t)ch[2] << 8 | ch[3]),
          "собрано не до заявленной длины");

    uint8_t ch_s[8192];
    size_t ch_sl = 0;
    CHECK(d2k_qsnap_client_hello(&s, ch_s, sizeof ch_s, &ch_sl) == 0 &&
          ch_sl == chl && !memcmp(ch_s, ch, chl), "пачка даёт тот же ClientHello");

    char name[256];
    CHECK(d2k_qsnap_sni(&s, name, sizeof name) == 0 && !strcmp(name, "rutracker.org"),
          "имя из второй датаграммы");

    /* Первая датаграмма в одиночку — обрывок, а не приветствие. */
    d2k_qsnap one = s;
    one.n = 1;
    CHECK(d2k_qsnap_client_hello(&one, ch_s, sizeof ch_s, &ch_sl) != 0,
          "половина приветствия принята за целое");
    CHECK(d2k_qsnap_sni(&one, name, sizeof name) != 0, "имя выдумано из обрывка");

    /* --- перезапечатка --------------------------------------------------- */
    uint8_t re[D2K_SHAPE_MAX];
    size_t rl = 0;
    CHECK(d2k_qsnap_recid(&s, re, sizeof re, &rl) == 0, "перезапечатка пачки");
    CHECK(rl == bl, "перезапечатка изменила длину пачки");
    d2k_qsnap r;
    CHECK(d2k_qsnap_parse(re, rl, &r) == 0 && r.n == 2 &&
          r.len[0] == l1 && r.len[1] == l2, "перезапечатанное — та же форма");
    /* DCID лежит с 6-го байта длинного заголовка: 1 тип + 4 версия + 1 длина. */
    CHECK(memcmp(r.dg[0] + 6, s.dg[0] + 6, 8) != 0, "DCID не обновлён");
    CHECK(!memcmp(r.dg[0] + 6, r.dg[1] + 6, 8), "у датаграмм пачки разные DCID");
    uint8_t ch_r[8192];
    size_t ch_rl = 0;
    CHECK(d2k_qsnap_client_hello(&r, ch_r, sizeof ch_r, &ch_rl) == 0 &&
          ch_rl == chl && !memcmp(ch_r, ch, chl),
          "перезапечатанная пачка не раскрывается в тот же ClientHello");
    uint8_t re2[D2K_SHAPE_MAX];
    size_t rl2 = 0;
    CHECK(d2k_qsnap_recid(&s, re2, sizeof re2, &rl2) == 0 && rl2 == rl &&
          memcmp(re2, re, rl) != 0, "две перезапечатки дали один DCID");

    /* --- форма ------------------------------------------------------------ */
    d2k_quic_form f;
    CHECK(d2k_qsnap_form(&s, &f) == 0 && f.n == 2 && f.dgram_len == (uint16_t)l1 &&
          f.ch_len == (uint16_t)chl, "форма пачки");

    /* --- отказы ----------------------------------------------------------- */
    /* Датаграммы разных соединений (Retry посреди полёта, чужой поток в
       кольце датапата) не склеиваются в одно приветствие. */
    const uint8_t *mdg[2] = {d1, r.dg[1]};
    uint8_t mixed[D2K_SHAPE_MAX];
    size_t ml = d2k_qsnap_pack(mdg, len, 2, mixed, sizeof mixed);
    d2k_qsnap m;
    CHECK(ml > 0 && d2k_qsnap_parse(mixed, ml, &m) == 0, "упаковка смешанной пачки");
    CHECK(d2k_qsnap_client_hello(&m, ch_s, sizeof ch_s, &ch_sl) != 0,
          "датаграммы разных DCID склеены в одно приветствие");
    CHECK(d2k_qsnap_recid(&m, re, sizeof re, &rl) != 0, "смешанная пачка перезапечатана");

    /* Любое усечение отвергается целиком, а не разбирается наполовину. */
    for (size_t k = 0; k < bl; k++) {
        d2k_qsnap t;
        CHECK(d2k_qsnap_parse(blob, k, &t) != 0, "усечённая пачка принята");
    }
    /* Лишние байты в хвосте — тоже отказ: это не та пачка, что слал клиент. */
    uint8_t longer[D2K_SHAPE_MAX];
    memcpy(longer, blob, bl);
    longer[bl] = 0;
    {
        d2k_qsnap t;
        CHECK(d2k_qsnap_parse(longer, bl + 1, &t) != 0, "пачка с хвостом принята");
    }

    /* Мусор нужной длины — не приветствие и не перезапечатывается. */
    uint8_t junk[64];
    memset(junk, 0x5a, sizeof junk);
    const uint8_t *jdg[1] = {junk};
    size_t jlen[1] = {sizeof junk};
    uint8_t jb[128];
    size_t jbl = d2k_qsnap_pack(jdg, jlen, 1, jb, sizeof jb);
    d2k_qsnap j;
    CHECK(jbl > 0 && d2k_qsnap_parse(jb, jbl, &j) == 0, "упаковка мусора");
    CHECK(d2k_qsnap_client_hello(&j, ch_s, sizeof ch_s, &ch_sl) != 0,
          "мусор принят за приветствие");
    CHECK(d2k_qsnap_recid(&j, re, sizeof re, &rl) != 0, "мусор перезапечатан");

    /* Пределы упаковки. */
    CHECK(d2k_qsnap_pack(dg, len, 0, blob, sizeof blob) == 0, "пустая пачка собрана");
    CHECK(d2k_qsnap_pack(dg, len, D2K_QSNAP_MAX_DGRAMS + 1, blob, sizeof blob) == 0,
          "пачка сверх предела собрана");
    CHECK(d2k_qsnap_pack(dg, len, 2, blob, 16) == 0, "пачка собрана в тесный буфер");

    if (fails) { printf("test_quicsnap: провалов %d\n", fails); return 1; }
    printf("test_quicsnap: все проверки прошли\n");
    return 0;
}
