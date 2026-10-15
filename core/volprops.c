/* volprops.c — те же пять вопросов о коробке, но при обрыве ОБЪЁМА.
 *
 * ЗАЧЕМ ОТДЕЛЬНО ОТ compose.c. Вопрос у d2k_props_ask считается пройденным по
 * обмену: план встал, обращение состоялось, пришёл ServerHello. Для блока
 * рукопожатия это и есть ответ. При обрыве объёма рукопожатие проходит САМО,
 * без всякого приёма: коробка режет поток позже, на 23–35 КБ исходящих данных
 * (поле 15.10.2026, семь целей — optimizationguide-pa.googleapis.com,
 * theme-p01-dra.hihonorcdn.com, gew1-spclient.spotify.com и другие). Тем же
 * критерием первый же вопрос «прошёл» бы, не померив ничего, и вектор свойств
 * стал бы выдумкой. Поэтому путь обрыва объёма вопросов не задавал вовсе —
 * 0 зондов, — а план всё равно собирался из ПУСТОГО вектора и был догадкой:
 * d2k_compose на нулевом векторе даёт «всё сразу» (приманка с битой суммой
 * ×2 + два разреза + перекрытие + обратный порядок). В поле он не прошёл ни
 * разу из шестнадцати, а первый же кандидат запасного перебора — seqovl-1,
 * один разрез с перекрытием в один байт, — проходил за 5–10 с.
 *
 * ЧТО ЗДЕСЬ. Те же пять вопросов, тот же сборщик плана
 * (d2k_props_question_plan) и та же запись свойства
 * (d2k_props_question_passed) — иначе две копии развилки разошлись бы молча,
 * как предупреждает d2k_compose_internal.h. Меняется ТОЛЬКО критерий ответа:
 * вопрос прошёл, если под его планом исходящая лестница БОЛЬШЕ НЕ РВЁТСЯ.
 * Это тот самый сигнал, которым блокировка и была измерена, — а не другой,
 * заведомо проходящий.
 *
 * ПОЧЕМУ ЗАНЯТЫЙ ПОРТ. План вопроса ставится на конкретный местный порт
 * (d2k_props_bind_family до установки плана, как в compose.c): иначе вопрос
 * подействовал бы на живые соединения человека к тому же имени. Лестница
 * поэтому идёт на уже занятом сокете — d2k_volume_probe_on.
 *
 * ПОЧЕМУ БЕЗ МЕТКИ. Базовый объёмный замер метит свой зонд, чтобы мерить
 * ЛИНИЮ мимо уже стоящего плана. Здесь спрашивается обратное — сработал ли
 * план ВОПРОСА, — и метка увела бы его пакеты мимо очереди датапата, то есть
 * сломала бы ровно то, что измеряется (тот же разбор, что в шапке
 * d2k_props_ask про mark).
 *
 * Промах не пишет ничего (§2.4): «не прошло» — не то же самое, что «нет». */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_volume.h"
#include "d2k_volprops.h"

/* Потолок тела фальшивки — тот же, что у опроса рукопожатия: двойная длина
   правды плюс записи плана (см. d2k_props_ask_traced). Своё число, а не
   D2K_COMPOSE_HELLO_MAX из compose.c: тот остаётся внутренним потолком
   сборщика, и тянуть его в заголовок ради одного размера буфера значило бы
   закрепить деталь, которую сборщик вправе менять у себя. Сборщик сам
   откажет (вернёт не ноль), если план не влезет. */
#define VP_PLAN_MAX (2 * 1800 + 256)

static void vp_hex(const uint8_t *b, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

d2k_props d2k_props_ask_volume(const d2k_volprops_in *in, d2k_volprops_step *steps) {
    d2k_props pr;
    memset(&pr, 0, sizeof pr);
    if (steps) { memset(steps, 0, sizeof *steps * D2K_PROPS_QUESTIONS); }
    if (!in || in->link_fd < 0 || !in->ip || in->ip[0] == '\0' ||
        !in->trigger.bytes || in->trigger.len == 0) {
        return pr; /* нечем спросить — не измерено, а не «нет» */
    }

    uint8_t family = 4;
    uint8_t addr[16] = {0};
    if (strchr(in->ip, '%')) { return pr; }
    if (inet_pton(AF_INET, in->ip, addr) != 1) {
        if (inet_pton(AF_INET6, in->ip, addr) != 1) { return pr; }
        family = 6;
    }

    size_t sni_off = 0, sni_len = 0;
    char name[256];
    if (d2k_hello_sni(in->trigger.bytes, in->trigger.len, &sni_off, &sni_len) != 0 ||
        sni_len == 0 || sni_len >= sizeof name) {
        return pr; /* датапат матчит план по имени — задать нечем */
    }
    memcpy(name, in->trigger.bytes + sni_off, sni_len);
    name[sni_len] = '\0';

    d2k_shape sh = d2k_hello_shape(in->trigger.bytes, in->trigger.len);
    uint8_t qshape = (sh == D2K_SHAPE_UNKNOWN) ? (uint8_t)D2K_LINK_SHAPE_GRANDFATHER
                                               : (uint8_t)sh;

    for (int q = 0; q < D2K_PROPS_QUESTIONS; q++) {
        static uint8_t planbuf[VP_PLAN_MAX];
        size_t plan_len = 0;
        if (d2k_props_question_plan(q, in->control, in->trigger.len,
                                    planbuf, sizeof planbuf, &plan_len) != 0) {
            if (steps) { steps[q].rc = D2K_VP_NOT_ASKED; }
            continue; /* этот вопрос сегодня не собрать */
        }
        uint8_t qid[D2K_PLAN_ID_LEN];
        if (plan_tlv_stamp_ident(planbuf, plan_len, qid) != 0) {
            if (steps) { steps[q].rc = D2K_VP_NOT_ASKED; }
            continue;
        }
        static char hexbuf[2 * VP_PLAN_MAX + 1];
        vp_hex(planbuf, plan_len, hexbuf);

        /* Порт занимается ДО установки плана — иначе план вопроса достался бы
           чужому обращению к тому же имени (0010, R1). */
        int qfd = -1;
        uint16_t qsport = 0;
        if (d2k_props_bind_family(family, &qfd, &qsport) != 0 || qsport == 0) {
            if (steps) { steps[q].rc = D2K_VP_NO_PORT; }
            continue;
        }
        char err[160];
        if (d2k_link_set_name_family(in->link_fd, name, 6, hexbuf, qshape, qsport,
                                     family, err, sizeof err) != 0) {
            close(qfd);
            if (steps) { steps[q].rc = D2K_VP_REFUSED; }
            continue; /* датапат не взял план — это про нас, не про коробку */
        }

        /* Лестница на занятом сокете и БЕЗ метки: вопрос спрашивает, сработал
           ли его план, а метка увела бы пакеты мимо очереди датапата. Сокет
           закрывает сама проба. */
        d2k_vol_result vr = d2k_volume_probe_on(qfd, in->ip, in->port, name,
                                                in->plain, in->tls12,
                                                in->hello_wire, 0, in->path);
        int passed = vr.verdict != D2K_VOL_CUT && vr.verdict != D2K_VOL_UNREACHABLE;
        if (steps) {
            steps[q].rc = passed ? D2K_VP_PASSED
                        : vr.verdict == D2K_VOL_UNREACHABLE ? D2K_VP_UNREACHABLE
                                                            : D2K_VP_STILL_CUT;
            steps[q].at_kb = vr.at_kb;
            snprintf(steps[q].reason, sizeof steps[q].reason, "%s", vr.reason);
        }
        if (!passed) {
            /* План, про который это же измерение сказало «не помогает», стоять
               не остаётся — тот же порядок, что у опроса рукопожатия. */
            char derr[128];
            (void)d2k_link_del_name_probe_family(in->link_fd, name, 6, qshape,
                                                 qsport, family, derr, sizeof derr);
            continue; /* промах не пишет ничего (§2.4) */
        }
        d2k_props_question_passed(q, &pr);
        /* Прошедший вопрос — уже стратегия: его план остаётся стоять, и второй
           вопрос той же цели не задаётся (как в d2k_props_ask_traced). */
        break;
    }
    return pr;
}
