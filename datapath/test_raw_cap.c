/* test_raw_cap.c — предел длины посылки берётся с ВЫХОДА сырой посылки, а не с
 * туннеля (поле 22.10.2026, issue #5/#7).
 *
 * Только Linux, под root, в своём сетевом пространстве имён — запускать через
 * test_raw_cap.sh (unshare -n). Там два dummy: OUT с MTU 1500 — выход сырой
 * посылки, LOW с MTU 1280 — VPN-туннель, через который ничего нашего не идёт.
 *
 * Без правки d2k_raw_open без --iface брал наименьший MTU среди поднятых —
 * 1280 — и датапат отвергал на активации каждый план с посылкой 1440 байт
 * (3302 отказа за ночь у репортёра). Шаг 1 воспроизводит именно это, шаги 2–7
 * проверяют уточнение по выходу. */
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#include "d2k_raw.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "test_raw_cap OUT LOW (имена интерфейсов)\n");
        return 2;
    }
    const char *out = argv[1], *low = argv[2];
    uint32_t oif = if_nametoindex(out), lowif = if_nametoindex(low);
    uint32_t none = 0x7ffffff0u;   /* такого индекса нет */
    assert(oif && lowif);
    char err[256], names[128];

    /* 1. Угаданный предел — наименьший среди поднятых, то есть туннель. Так
          было в поле: предел 1280 при выходе с MTU 1500. */
    d2k_raw *r = d2k_raw_open(0, NULL, err, sizeof err);
    if (!r) { fprintf(stderr, "d2k_raw_open: %s\n", err); return 1; }
    assert(d2k_raw_maxlen(r) == 1280);

    /* 2. Выход сырой посылки — OUT: предел поднимается до его MTU. */
    assert(d2k_raw_adopt_egress(r, &oif, 1, names, sizeof names) == 1);
    assert(d2k_raw_maxlen(r) == 1500);
    assert(strstr(names, out) != NULL && strstr(names, "1500") != NULL);

    /* 3. Тот же выход снова — ничего не меняется (и опущенный ответом ядра
          предел такой вызов тоже не поднял бы). */
    assert(d2k_raw_adopt_egress(r, &oif, 1, NULL, 0) == 0);
    assert(d2k_raw_maxlen(r) == 1500);

    /* 4. Несколько выходов — наименьший из них: маршрут через туннель
          действительно опускает предел. */
    uint32_t both[2] = {oif, lowif};
    assert(d2k_raw_adopt_egress(r, both, 2, names, sizeof names) == 1);
    assert(d2k_raw_maxlen(r) == 1280);
    assert(strstr(names, low) != NULL && strstr(names, out) != NULL);

    /* 5. Неизвестный индекс — ничего не узнали, предел прежний. */
    assert(d2k_raw_adopt_egress(r, &none, 1, NULL, 0) == -1);
    assert(d2k_raw_maxlen(r) == 1280);

    /* 6. Снова только OUT — предел возвращается к его MTU. */
    assert(d2k_raw_adopt_egress(r, &oif, 1, NULL, 0) == 1);
    assert(d2k_raw_maxlen(r) == 1500);
    d2k_raw_close(r);

    /* 7. Названный оператором предел (--iface LOW) объявлен, а не угадан:
          выход его не перепрыгивает. */
    d2k_raw *d = d2k_raw_open(0, low, err, sizeof err);
    if (!d) { fprintf(stderr, "d2k_raw_open(%s): %s\n", low, err); return 1; }
    assert(d2k_raw_maxlen(d) == 1280);
    assert(d2k_raw_adopt_egress(d, &oif, 1, NULL, 0) == -1);
    assert(d2k_raw_maxlen(d) == 1280);
    d2k_raw_close(d);

    puts("test_raw_cap: ok");
    return 0;
}
