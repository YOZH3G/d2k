/* One serialized TCP measurement program, executed by detect and datapath. */
#include "d2k_compose.h"
#include "d2k_hello.h"
#include "profiles/rx_fake.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int append_fmt(char *buf, size_t cap, size_t *pos, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *pos) {
        return -1;
    }
    *pos += (size_t)n;
    return 0;
}

static int append_hex(char *buf, size_t cap, size_t *pos,
                       const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (append_fmt(buf, cap, pos, "%02x", b[i]) != 0) { return -1; }
    }
    return 0;
}

/* Полный TLS-record ClientHello с именем name в SNI, из восстановленного
   fake_default_tls (profiles/rx_fake.h). Один источник для RX-лестницы и для
   приманки вопроса «приветствие под меткой времени» (поле 10.10.2026). */
int d2k_white_decoy_hello(const char *name, uint8_t *out, size_t cap, size_t *len) {
    size_t hl = 0;
    if (!out || cap < 5 || !name || !name[0] ||
        d2k_hello_rename(d2k_rx_fake_template + 5, sizeof d2k_rx_fake_template - 5,
                          name, out + 5, cap - 5, &hl) != 0) { return -1; }
    /* hello_rename accepts the handshake, not its record wrapper. */
    memcpy(out, d2k_rx_fake_template, 3);
    out[3] = (uint8_t)(hl >> 8);
    out[4] = (uint8_t)hl;
    *len = hl + 5;
    return 0;
}

static int template_plan(const uint8_t *hello, size_t hello_len, unsigned split,
                         size_t send_cap, char *buf, size_t cap) {
    size_t pos = 0;
    if (!hello || !hello_len || !split) return -1;
    if (send_cap > 0 && (hello_len > send_cap || send_cap - hello_len < 132)) return -1;
    if (append_fmt(buf, cap, &pos,
            "d2k-plan 1 8\nid 00000000000000000000000000000000\n"
            "proto tcp tls\nwire tcp-template-v1\ninput tls-sni\nsegment %u\n",
            (unsigned)D2K_ARM_SEGMENT_MAX) ||
        append_fmt(buf, cap, &pos, "payload 1 ") ||
        append_hex(buf, cap, &pos, hello, hello_len) ||
        append_fmt(buf, cap, &pos,
            "\npoison 1 tcpts\nfake payload=1 poison=1 repeats=8 gap_us=0 place=before tlsmod=rnd,dupsid\n"
            "split payload_start +%u\norder forward\n", split)) return -1;
    return 0;
}

int d2k_rx_volume_plan_named(unsigned variant, d2k_shape shape, size_t send_cap,
                             const char *name, char *buf, size_t cap) {
    static const unsigned split_at[D2K_RX_VOLUME_PLAN_VARIANTS] = {2, 1, 3, 4, 5};
    uint8_t hello[D2K_ARM_DECOY_MAX];
    size_t hello_len = 0;
    if (!buf || !cap || variant >= D2K_RX_VOLUME_PLAN_VARIANTS ||
        shape != D2K_SHAPE_MODERN ||
        d2k_white_decoy_hello(name, hello, sizeof hello, &hello_len)) return -1;
    return template_plan(hello, hello_len, split_at[variant], send_cap, buf, cap);
}

/* Имя приманки по умолчанию, пока белое имя сети не подобрано (поле
 * 10.10.2026 взяло его первым): семя из восстановленной ручной команды. */
int d2k_rx_volume_plan(unsigned variant, d2k_shape shape, size_t send_cap,
                       char *buf, size_t cap) {
    return d2k_rx_volume_plan_named(variant, shape, send_cap, "hcaptcha.com", buf, cap);
}

/* Compact text, exact binary payload: keep the measured prefix and the
 * original sender's 0x0f padding without allocating huge task text buffers. */
static int measured_payload(char *buf, size_t cap, size_t *pos, unsigned id,
                             size_t len, const uint8_t *prefix, size_t prefix_len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (append_fmt(buf, cap, pos, "payload-pad64 %u %zu 15", id, len)) { return -1; }
    if (prefix_len > len) { prefix_len = len; } /* raw sender's memcpy(min(...)) */
    if (prefix_len) {
        if (append_fmt(buf, cap, pos, " ")) { return -1; }
        for (size_t i = 0; i < prefix_len; i += 3) {
            size_t left = prefix_len - i;
            uint32_t v = (uint32_t)prefix[i] << 16;
            if (left > 1) { v |= (uint32_t)prefix[i + 1] << 8; }
            if (left > 2) { v |= prefix[i + 2]; }
            if (append_fmt(buf, cap, pos, "%c%c%c%c", b64[v >> 18], b64[(v >> 12) & 63],
                left > 1 ? b64[(v >> 6) & 63] : '=', left > 2 ? b64[v & 63] : '=')) { return -1; }
        }
    }
    return append_fmt(buf, cap, pos, "\n");
}

int d2k_arm_plan_measured_cap(const d2k_arm *a, const d2k_arm_input *in,
                              size_t send_cap, char *buf, size_t cap) {
    if (!a || !in || !buf || !cap) { return -1; }
    buf[0] = '\0';
    if (in->trigger_len < 2 || in->trigger_len > D2K_ARM_TRIGGER_MAX ||
        in->decoy_len > sizeof in->decoy || in->sni_off > in->trigger_len ||
        in->sni_len > in->trigger_len - in->sni_off || a->repeats > 255 ||
        a->ttl > 255 || a->gap_ms > UINT32_MAX / 1000u) { return -1; }
    /* The composite ECH question is the recovered field program. The raw
       probe executes this very text, so it cannot measure padded 2*n bytes
       and then arm a different template/TLS modifier/header program. */
    if (a->tcpts && a->decoy_hello && a->repeats == 8 && a->split_pos == 2 &&
        !a->badsum && !a->md5 && !a->ttl && !a->seq_out && !a->gap_ms &&
        !a->disorder && !a->disorder_pos && !a->between && !a->seqovl &&
        !a->seqovl_hello && !a->ipidzero && !a->oob) {
        if (!in->sni_off || in->sni_len <= 1) return -1;
        return template_plan(in->decoy, in->decoy_len, 2, send_cap, buf, cap);
    }
    if (a->disorder_pos) {
        if (!a->disorder || a->disorder_pos >= in->trigger_len || a->seqovl ||
            a->seqovl_hello || a->badsum || a->md5 || a->repeats || a->gap_ms || a->between ||
            a->ttl || a->seq_out || a->decoy_hello || a->tcpts || a->ipidzero ||
            a->oob || a->split_pos) { return -1; }
        size_t plan_pos = 0;
        if (append_fmt(buf, cap, &plan_pos,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\n")) { return -1; }
        /* A fixed payload cut does not require a name. Preserve the reusable
         * SNI contract for named inputs, and bind nameless measured inputs. */
        if (in->sni_off > 0 && in->sni_len > 1) {
            if (append_fmt(buf, cap, &plan_pos, "input tls-sni\n")) { return -1; }
        } else if (append_fmt(buf, cap, &plan_pos, "input %zu %zu %zu\n",
                              in->trigger_len, in->sni_off, in->sni_len)) { return -1; }
        return append_fmt(buf, cap, &plan_pos,
            "segment %u\nsplit payload_start +%u\norder reverse\n",
            (unsigned)D2K_ARM_SEGMENT_MAX, a->disorder_pos);
    }
    if (a->oob) {
        if (a->seqovl || a->seqovl_hello || a->badsum || a->md5 || a->repeats || a->gap_ms ||
            a->disorder || a->between || a->ttl || a->seq_out || a->decoy_hello ||
            a->tcpts || a->ipidzero || a->split_pos || in->sni_off == 0 || in->sni_len <= 1 ||
            in->sni_off + in->sni_len > in->trigger_len) { return -1; }
        size_t pos = 0;
        return append_fmt(buf, cap, &pos,
            "d2k-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\ninput tls-sni\nsegment %u\noob sni_middle 0f\norder forward\n",
            (unsigned)D2K_ARM_SEGMENT_MAX);
    }
    size_t n = in->trigger_len, pos = 0;
    size_t ov = a->seqovl_hello ? in->decoy_len : a->seqovl;
    if (ov > D2K_ARM_DECOY_MAX) { return -1; }
    int between = a->between;
    /* Метка времени — тоже подделка (сервер отбросит её по PAWS): вопрос о
       ней задаётся без битой суммы (§0.1, 07.10.2026). */
    int fake = !between && (a->badsum || a->md5 || a->ttl || a->seq_out || a->tcpts);
    int disorder = !between && a->disorder;
    /* raw.c prioritizes fake_between over disorder/seqovl; it uses SNI
     * START, not the old Plan builder's two cuts at 1 and SNI middle. */
    size_t mid = between ? 1 : n / 2;
    if (in->sni_len > 1 && in->sni_off > 0) {
        mid = in->sni_off + (between ? 0 : in->sni_len / 2);
    }
    if (between) { if (mid >= n) { mid = 1; } ov = 0; }
    else { if (mid < 2) { mid = 2; } if (mid >= n) { mid = n - 1; } }
    /* Прямой разрез настоящей нагрузки (семейство C) несовместим с обратным
       порядком и промежуточной фальшивкой: там свой разрез. Вне окна — отказ,
       как у disorder_pos: разрез, которого не мерили, ставить нельзя. */
    if (a->split_pos && (between || disorder || (size_t)a->split_pos >= n)) { return -1; }
    if (!fake && !between && !disorder && !ov && !a->disorder_pos && !a->split_pos) { return -1; }
    /* ПРЕДЕЛ ОТПРАВКИ (задача 37, I2). Посылки плана режутся сегментом
       D2K_ARM_SEGMENT_MAX — тем же потолком, что у сырого отправителя замера
       (raw.c), так что найденное воздействие уходит теми же сегментами, что и
       на замере; при обычном канале (1500) самая длинная посылка — 1440(+12
       с меткой времени), и план проходит. Урезать приставку или фальшивку
       ниже того, что прошло на замере, — уже ДРУГОЕ воздействие (то же
       правило, что у seqovl-hello в d2k_arm_plan), поэтому канал уже этого
       предела плечо не принимает вовсе: датапат отверг бы его как BAD_PLAN,
       опыта бы не было. Считается, как в d2k_plan_max_emit: фальшивки и
       приставка перекрытия, по сегменту. */
    if (send_cap > 0) {
        size_t body = (fake || between) ? (between ? n - mid : 2 * n) : 0;
        if (ov > body) { body = ov; }
        if (body > D2K_ARM_SEGMENT_MAX) { body = D2K_ARM_SEGMENT_MAX; }
        size_t hdr = 40 + (fake && a->md5 ? 20 : fake && a->tcpts ? 12 : 0);
        if (body && hdr + body > send_cap) { return -1; }
    }
    if (a->disorder_pos) {
        if (a->disorder_pos >= n) { return -1; }
        if (append_fmt(buf, cap, &pos,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\ninput tls-sni\nsegment %u\n"
            "split payload_start +%u\norder reverse\n",
            (unsigned)D2K_ARM_SEGMENT_MAX, a->disorder_pos)) { return -1; }
        return 0;
    }
    /* Перестановка режет вход не по измеренному числу, а по середине SNI.
     * Поэтому длина и смещения конкретного ClientHello не являются
     * зависимостью плана: зонд TLS 1.2 может построить своё приветствие с
     * другим расположением имени. Перекрытие при этом остаётся снятой
     * приманкой — именно её байты нужны для распознавания коробкой; якоря
     * входа, а не доказанная приманка, должны быть параметрическими. */
    if (disorder && !fake && in->sni_off > 0 && in->sni_len > 1) {
        if (append_fmt(buf, cap, &pos,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\ninput tls-sni\nsegment %u\n",
            (unsigned)D2K_ARM_SEGMENT_MAX)) { return -1; }
        if (ov) {
            if (measured_payload(buf, cap, &pos, 2, ov, in->decoy, in->decoy_len) ||
                append_fmt(buf, cap, &pos, "seqovl payload=2 poison=0\n")) { return -1; }
        }
        return append_fmt(buf, cap, &pos,
            "split payload_start +1\nsplit sni_middle +0\norder reverse\npace 12000\n");
    }
    /* ВХОД ПРИШПИЛИВАЕТСЯ К ДЛИНЕ ТОЛЬКО ТАМ, ГДЕ ПЛАН ОТ НЕЁ ЗАВИСИТ.
     *
     * От входа зависят приманка (её длина считается от n) и перестановка
     * (разрез уезжает в план ЧИСЛОМ, снятым с этого приветствия). Плечо без
     * них — чистое перекрытие — не содержит ни одного такого числа: длина
     * приставки своя, порядок прямой, разрезов нет.
     *
     * Прежде пришпиливались все плечи кроме чистой перестановки, и цена
     * этого измерена в поле 18.09.2026: приветствие Discord 1534 байта при
     * MSS 1388 приходит ДВУМЯ сегментами, к первому план с пришпиленной
     * длиной не применяется вовсе («план неприменим к этому пакету» на зонде
     * подтверждения), а дождаться второго нельзя — пока первый лежит в
     * очереди без вердикта, ядро остаток не выпускает. Найденный замером
     * приём «seqovl-1» так и не доезжал до провода. */
    int param = !fake && !between && !disorder &&
                in->sni_off > 0 && in->sni_len > 1;
    if (param) {
        if (append_fmt(buf, cap, &pos,
            "d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "wire detect-tcp-v1\ninput tls-sni\nsegment %u\n",
            (unsigned)D2K_ARM_SEGMENT_MAX)) { return -1; }
    } else if (append_fmt(buf, cap, &pos,
        "d2k-plan 1 %u\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\n"
        "input %zu %zu %zu\nsegment %u\n",
        a->md5 ? 12u : 4u, n, in->sni_off, in->sni_len, (unsigned)D2K_ARM_SEGMENT_MAX)) { return -1; }
    size_t flen = between ? n - mid : 2 * n;
    const uint8_t *prefix = in->decoy;
    size_t prefix_len = in->decoy_len;
    if (fake || between) {
        if (measured_payload(buf, cap, &pos, 1, flen,
                             prefix, between ? 0 : prefix_len)) { return -1; }
        if (append_fmt(buf, cap, &pos, "poison 1")) { return -1; }
        if (a->badsum && append_fmt(buf, cap, &pos, " badsum")) { return -1; }
        if (a->ttl && append_fmt(buf, cap, &pos, " ttl=%u", a->ttl)) { return -1; }
        if (!between) {
            if (a->md5 && append_fmt(buf, cap, &pos, " md5")) { return -1; }
            if (a->tcpts && append_fmt(buf, cap, &pos, " tcpts")) { return -1; }
            if (a->ipidzero && append_fmt(buf, cap, &pos, " ipidzero")) { return -1; }
            if (a->seq_out && append_fmt(buf, cap, &pos, " seqshift=-66000")) { return -1; }
        }
        if (append_fmt(buf, cap, &pos, "\n")) { return -1; }
    }
    if (ov) {
        if (fake && ov <= flen) {
            if (append_fmt(buf, cap, &pos, "payload-slice 2 1 0 %zu\n", ov)) { return -1; }
        } else if (measured_payload(buf, cap, &pos, 2, ov, prefix, prefix_len)) { return -1; }
        if (append_fmt(buf, cap, &pos, "seqovl payload=2 poison=0\n")) { return -1; }
    }
    /* Only disorder splits at +1; plain overlap is one raw send. */
    if (disorder &&
        append_fmt(buf, cap, &pos, "split payload_start +1\n")) { return -1; }
    if ((disorder || between) &&
        append_fmt(buf, cap, &pos, "split payload_start +%zu\n", mid)) { return -1; }
    /* Семейство C: прямой разрез настоящей нагрузки после серии фальшивок,
       порядок прямой (голова первой). Составной template-план семейства C
       обработан выше; здесь общий фиксированный разрез. */
    if (a->split_pos &&
        append_fmt(buf, cap, &pos, "split payload_start +%u\n", a->split_pos)) { return -1; }
    if (fake || between) {
        if (append_fmt(buf, cap, &pos,
            "fake payload=1 poison=1 repeats=%u gap_us=%u place=%s\n",
            a->repeats ? a->repeats : 1u, between ? 0u : a->gap_ms * 1000u,
            between ? "between" : "before")) { return -1; }
    }
    if (append_fmt(buf, cap, &pos, "order %s\n", disorder ? "reverse" : "forward")) { return -1; }
    if ((disorder || between) && append_fmt(buf, cap, &pos, "pace 12000\n")) { return -1; }
    if (fake && append_fmt(buf, cap, &pos, "settle 15000\n")) { return -1; }
    return 0;
}

int d2k_arm_plan_measured(const d2k_arm *a, const d2k_arm_input *in,
                          char *buf, size_t cap) {
    return d2k_arm_plan_measured_cap(a, in, 0, buf, cap);
}
