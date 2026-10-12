/* QUIC wire adapters. d2k_quic_original_measure and d2k_quic_strategy_measure
 * are the runtime adapters for the arm control flow in quicarms.c; no arm
 * ladder lives in this file. The legacy derived-fake picker that used to sit
 * below (d2k_quic_pick_arm, with its own 1..255 TTL sweep and separate-IP
 * confirmation) had no production caller and is gone — the runtime ladder is
 * quicarms.c, four TTL values and D2K_QUIC_ARM_QUESTIONS_MAX questions.
 * Original fragment transport is quicprobe.c + ipfrag.c. The midpoint
 * builder below is legacy test code, not the runtime fragment question. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE /* IP_TTL/IP_HDRINCL на macOS — см. тот же приём в quicprobe.c */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "d2k_quicprobe.h"
/* d2k_quic_hello_rename — единственный источник приманки (см. ниже). */
#include "d2k_quichello.h"
#include "d2k_quic_arms.h"

typedef struct {
    uint16_t port;
    char target_sni[256];
    const char *path;
    uint32_t wait_ms, mark;
} original_wire;

static d2k_tally original_probe(const d2k_quic_arm_question *q, void *user, int *sent) {
    original_wire *w=user;
    /* Fragment survival (q->control) asks on NO caller name: donor
       arms.go:204-205 calls buildInitial(neutralName(), ...) inside the
       per-attempt closure, so every repeat gets its own fresh
       z<10 hex>.example.com. The wire hook draws them (quic_ask_arm); the
       control snapshot's name (the scheduler decoy) is never reused here. */
    const char *sni=q->control?NULL:w->target_sni;
    return d2k_quic_ask_arm_hook(q,sni,w->port,w->wait_ms,w->mark,sent);
}

/* Task 39: the arm's data stage on the same address, name and action. */
static d2k_quic_arm_data original_data(const d2k_quic_arm_question *q, void *user) {
    original_wire *w=user;
    return d2k_quic_arm_data_hook(q,w->target_sni,w->path,w->port,w->wait_ms,w->mark);
}

static d2k_quic_arm wire_measure(d2k_quic_arm (*run)(d2k_quic_arm_context *),
    d2k_quic_arm_context *ctx, uint16_t port, d2k_hello trigger, d2k_hello control,
    uint32_t wait_ms, uint32_t mark) {
    original_wire wire={.port=port,.wait_ms=wait_ms,.mark=mark,.path=ctx?ctx->path:NULL};
    if(d2k_quic_sni(trigger.bytes,trigger.len,wire.target_sni,sizeof wire.target_sni)!=0) {
        wire.target_sni[0]='\0';
        /* У буквальной IP-цели donor ClientHello не содержит SNI, но askArms
           всё равно строит каждый Initial для host. pool[0] — именно
           закреплённый исходный IP (не rotated spare и не SNI контроля). */
        if(ctx && ctx->pool && ctx->n_pool > 0) {
            struct in_addr target_ip;
            if(inet_pton(AF_INET,ctx->pool[0],&target_ip)==1) {
                snprintf(wire.target_sni,sizeof wire.target_sni,"%s",ctx->pool[0]);
            }
        }
    }
    /* The control snapshot does not name the survival question (see
       original_probe); it stays in the signature for the Run caller. */
    (void)control;
    d2k_quic_arm_context local=*ctx;
    local.probe=original_probe; local.user=&wire;
    local.data=original_data; local.data_user=&wire;
    d2k_quic_arm r=run(&local);
    if(ctx->path) snprintf(r.probe_path,sizeof r.probe_path,"%s",ctx->path);
    ctx->next=local.next; ctx->marked=local.marked;
    return r;
}

d2k_quic_arm d2k_quic_original_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark) {
    return wire_measure(d2k_quic_original_arms,ctx,port,trigger,control,wait_ms,mark);
}

/* Задача 40: рабочий путь подбора — сначала вопросы стратегии, перебор
   askArms только запасной (d2k_quic_strategy_arms); провод и этап данных
   те же. */
d2k_quic_arm d2k_quic_strategy_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark) {
    return wire_measure(d2k_quic_strategy_arms,ctx,port,trigger,control,wait_ms,mark);
}

/* Legacy transport test helper. The runtime preserves original fake bytes. */

int d2k_quic_decoy_from_trigger(d2k_hello trigger, const char *decoy_sni,
                                uint8_t *out, size_t cap, size_t *out_len) {
    if (!trigger.bytes || trigger.len == 0 || !decoy_sni || !decoy_sni[0] ||
        !out || cap == 0 || !out_len) {
        return -1;
    }
    /* Ровно та же пересборка, которой собирается контрольный зонд: одна
       реализация на обе надобности (§2.5). Свежие идентификаторы соединения
       она ставит сама — новому соединению они и положены (RFC 9000 §7.2). */
    return d2k_quic_hello_rename(trigger.bytes, trigger.len, decoy_sni,
                                 out, cap, out_len);
}

/* =========================================================================
 * Сборка IP-фрагментов — чистые вычисления, без сокетов (см. контракт в
 * d2k_quicprobe.h). Тестируется напрямую в test_quic_arms.c.
 * ========================================================================= */

/* RFC 1071. Сумма 16-битных слов big-endian, с переносом; len нечётной длины
   — последний байт дополняется нулём справа (стандартный приём). */
static uint16_t ip_checksum16(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1u) {
        sum += (uint32_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t udp_checksum(uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
                              uint16_t udp_len, const uint8_t *payload, size_t payload_len) {
    /* Псевдозаголовок UDP (RFC 768): src(4) dst(4) zero(1) proto(1) len(2). */
    uint8_t buf[12 + 8];
    memcpy(buf, &src_be, 4);
    memcpy(buf + 4, &dst_be, 4);
    buf[8] = 0;
    buf[9] = 17; /* IPPROTO_UDP */
    buf[10] = (uint8_t)(udp_len >> 8);
    buf[11] = (uint8_t)(udp_len & 0xFF);
    buf[12] = (uint8_t)(sport >> 8);
    buf[13] = (uint8_t)(sport & 0xFF);
    buf[14] = (uint8_t)(dport >> 8);
    buf[15] = (uint8_t)(dport & 0xFF);
    buf[16] = (uint8_t)(udp_len >> 8);
    buf[17] = (uint8_t)(udp_len & 0xFF);
    buf[18] = 0; /* контрольная сумма при подсчёте — ноль */
    buf[19] = 0;

    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < sizeof buf; i += 2) {
        sum += ((uint32_t)buf[i] << 8) | buf[i + 1];
    }
    for (i = 0; i + 1 < payload_len; i += 2) {
        sum += ((uint32_t)payload[i] << 8) | payload[i + 1];
    }
    if (payload_len & 1u) {
        sum += (uint32_t)payload[payload_len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    uint16_t csum = (uint16_t)~sum;
    /* RFC 768: "If the computed checksum is zero, it is transmitted as all
       ones" — ноль в поле суммы у UDP означает "сумма не считалась". */
    return (csum == 0) ? 0xFFFFu : csum;
}

size_t d2k_quic_build_frag2(const uint8_t *udp_payload, size_t udp_payload_len, uint32_t src_ip_be,
                             uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, uint16_t ip_id,
                             uint8_t ttl, uint8_t frag1[D2K_QUIC_FRAG_MAX], size_t *frag1_len,
                             uint8_t frag2[D2K_QUIC_FRAG_MAX], size_t *frag2_len) {
    *frag1_len = 0;
    *frag2_len = 0;
    if (!udp_payload || udp_payload_len < 16) {
        return 0; /* короче попросту нечего делить на два непустых фрагмента */
    }

    size_t udp_total = 8u + udp_payload_len; /* UDP-заголовок + данные — это и есть то, что фрагментируется */
    /* Смещение фрагмента — в 8-байтных единицах (RFC 791 §3.2): середина,
       округлённая ВНИЗ до кратного 8, и не меньше 8, чтобы весь UDP-заголовок
       (ровно 8 байт) целиком уместился в первый фрагмент — если бы он тоже
       делился между фрагментами, второй фрагмент было бы нечем связать с
       UDP-портами при разборе (реальные стеки не пересобирают L4-заголовок
       из кусков поперёк IP-фрагментов). */
    size_t split = (udp_total / 2) & ~(size_t)7;
    if (split < 8) {
        split = 8;
    }
    if (split >= udp_total) {
        return 0; /* вырожденный случай — не должен случаться при payload>=16, но проверка не лишняя */
    }
    size_t frag1_ip_payload = split;
    size_t frag2_ip_payload = udp_total - split;
    if (20 + frag1_ip_payload > D2K_QUIC_FRAG_MAX || 20 + frag2_ip_payload > D2K_QUIC_FRAG_MAX) {
        return 0; /* буфер вызывающего мал для такого payload */
    }

    uint16_t udp_len_field = (uint16_t)udp_total;
    uint16_t csum = udp_checksum(src_ip_be, dst_ip_be, src_port, dst_port, udp_len_field, udp_payload,
                                  udp_payload_len);
    uint8_t udp_hdr[8];
    udp_hdr[0] = (uint8_t)(src_port >> 8);
    udp_hdr[1] = (uint8_t)(src_port & 0xFF);
    udp_hdr[2] = (uint8_t)(dst_port >> 8);
    udp_hdr[3] = (uint8_t)(dst_port & 0xFF);
    udp_hdr[4] = (uint8_t)(udp_len_field >> 8);
    udp_hdr[5] = (uint8_t)(udp_len_field & 0xFF);
    udp_hdr[6] = (uint8_t)(csum >> 8);
    udp_hdr[7] = (uint8_t)(csum & 0xFF);

    /* ---- фрагмент 1: IP(20) + UDP-заголовок(8) + начало данных ---- */
    memset(frag1, 0, 20);
    frag1[0] = 0x45; /* version=4, IHL=5 (20 байт, без опций) */
    uint16_t totlen1 = (uint16_t)(20 + frag1_ip_payload);
    frag1[2] = (uint8_t)(totlen1 >> 8);
    frag1[3] = (uint8_t)(totlen1 & 0xFF);
    frag1[4] = (uint8_t)(ip_id >> 8);
    frag1[5] = (uint8_t)(ip_id & 0xFF);
    frag1[6] = 0x20; /* MF=1, смещение=0 (флаги — верхние 3 бита этого поля) */
    frag1[7] = 0x00;
    frag1[8] = ttl;
    frag1[9] = 17; /* IPPROTO_UDP */
    memcpy(frag1 + 12, &src_ip_be, 4);
    memcpy(frag1 + 16, &dst_ip_be, 4);
    uint16_t hcsum1 = ip_checksum16(frag1, 20);
    frag1[10] = (uint8_t)(hcsum1 >> 8);
    frag1[11] = (uint8_t)(hcsum1 & 0xFF);
    memcpy(frag1 + 20, udp_hdr, 8);
    memcpy(frag1 + 28, udp_payload, split - 8);
    *frag1_len = 20 + frag1_ip_payload;

    /* ---- фрагмент 2: IP(20) + хвост данных, БЕЗ своего UDP-заголовка ---- */
    memset(frag2, 0, 20);
    frag2[0] = 0x45;
    uint16_t totlen2 = (uint16_t)(20 + frag2_ip_payload);
    frag2[2] = (uint8_t)(totlen2 >> 8);
    frag2[3] = (uint8_t)(totlen2 & 0xFF);
    frag2[4] = (uint8_t)(ip_id >> 8);
    frag2[5] = (uint8_t)(ip_id & 0xFF);
    uint16_t frag_off_units = (uint16_t)(split / 8); /* MF=0 — старшие 3 бита нулевые */
    frag2[6] = (uint8_t)(frag_off_units >> 8);
    frag2[7] = (uint8_t)(frag_off_units & 0xFF);
    frag2[8] = ttl;
    frag2[9] = 17;
    memcpy(frag2 + 12, &src_ip_be, 4);
    memcpy(frag2 + 16, &dst_ip_be, 4);
    uint16_t hcsum2 = ip_checksum16(frag2, 20);
    frag2[10] = (uint8_t)(hcsum2 >> 8);
    frag2[11] = (uint8_t)(hcsum2 & 0xFF);
    memcpy(frag2 + 20, udp_payload + (split - 8), frag2_ip_payload);
    *frag2_len = 20 + frag2_ip_payload;

    return *frag1_len + *frag2_len;
}

/* =========================================================================
 * Реальный отправитель фрагментации (сырой сокет, IP_HDRINCL) — умолчание
 * d2k_quic_ask_frag_hook. НЕ протестирован на проводе в этом дереве: сырой
 * сокет требует CAP_NET_RAW, а `make check` обязан быть зелёным и без него
 * (тот же приём, что d2k_mark_hook в d2k_meas.h) — тест подставляет свой хук
 * и проверяет ДИСЦИПЛИНУ ЛЕСТНИЦЫ, не эту функцию; построение самих байт
 * (d2k_quic_build_frag2 выше) проверено отдельно и без сокетов.
 * ========================================================================= */

static d2k_tally frag_fail(int repeats, uint32_t mark, int *sent_out) {
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.err = repeats;
    t.fail = repeats;
    t.marked = (mark == 0);
    if (sent_out) {
        *sent_out = 0;
    }
    return t;
}

static d2k_tally frag_real(const char *addr, uint16_t port, d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                            int repeats, int *sent_out) {
    if (repeats <= 0) {
        repeats = D2K_QUIC_REPEATS;
    }
    if (repeats > D2K_QUIC_MAX_ADDRS) {
        /* Тот же приём, что и quic_ask_ex в quicprobe.c: нарушение контракта
           отклоняет опыт целиком, а не молча ужимает repeats. */
        return frag_fail(repeats, mark, sent_out);
    }
    if (!addr || !msg.bytes || msg.len == 0) {
        return frag_fail(repeats, mark, sent_out);
    }

    /* Шаг 1: узнать локальный адрес/порт и ИЗМЕРЕННЫЙ (не изобретённый) TTL
       маршрута — тем же способом, каким это выбрала бы обычная отправка:
       обычный подключенный UDP-сокет, ничего по нему не посылаем. */
    int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_fd < 0) {
        return frag_fail(repeats, mark, sent_out);
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &dst.sin_addr) != 1 || connect(probe_fd, (struct sockaddr *)&dst, sizeof dst) != 0) {
        close(probe_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    struct sockaddr_in local;
    socklen_t local_len = sizeof local;
    if (getsockname(probe_fd, (struct sockaddr *)&local, &local_len) != 0) {
        close(probe_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    int ttl_int = 64; /* умолчание на случай, если getsockopt откажет — тот же порядок, что qp_send_one */
    socklen_t ttl_len = sizeof ttl_int;
    (void)getsockopt(probe_fd, IPPROTO_IP, IP_TTL, &ttl_int, &ttl_len);
    close(probe_fd);

    /* Шаг 2: реальный ответ слушаем ОБЫЧНЫМ UDP-сокетом, забинденным на тот
       же локальный адрес/порт, что "занял" зонд выше, — сырой сокет отдаёт
       IP-пакеты как есть и не даёт ядру собрать UDP-ответ для recv(). Порт
       зонда уже освобождён (probe_fd закрыт) к моменту bind — но ЭТО и есть
       порт, который мы впишем как исходный в самодельный UDP-заголовок ниже,
       так что ответ сервера придёт именно на него. */
    int rx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rx_fd < 0) {
        return frag_fail(repeats, mark, sent_out);
    }
    int reuse = 1;
    (void)setsockopt(rx_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    if (bind(rx_fd, (struct sockaddr *)&local, sizeof local) != 0) {
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    if (mark != 0 && d2k_mark_hook(rx_fd, mark) != 0) {
        /* Отказ пометить не отменяет опыт — та же дисциплина, что qp_send_one
           (marked отражает факт подтверждения, а не блокирует отправку). */
    }

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        /* НЕТ CAP_NET_RAW — опыт не состоялся, наша сторона, тот же класс,
           что и сбой socket() в qp_send_one. */
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }
    int hdrincl = 1;
    (void)setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof hdrincl);

    uint8_t frag1[D2K_QUIC_FRAG_MAX], frag2[D2K_QUIC_FRAG_MAX];
    size_t f1len = 0, f2len = 0;
    uint16_t ip_id = (uint16_t)(local.sin_port); /* повторяемо в пределах одного вызова, не для секретности */
    size_t built = d2k_quic_build_frag2(msg.bytes, msg.len, local.sin_addr.s_addr, dst.sin_addr.s_addr,
                                         ntohs(local.sin_port), port, ip_id, (uint8_t)ttl_int, frag1, &f1len,
                                         frag2, &f2len);
    if (built == 0) {
        close(raw_fd);
        close(rx_fd);
        return frag_fail(repeats, mark, sent_out);
    }

#ifdef __APPLE__
    /* Известная особенность BSD/Darwin raw-сокетов с IP_HDRINCL: ip_len и
       ip_off ядро ожидает в ХОСТОВОМ порядке байт (оно само переводит их в
       сетевой перед отправкой) — на Linux те же поля обязаны быть уже в
       сетевом порядке, как их и строит d2k_quic_build_frag2. Это
       задокументированное расхождение, не догадка (см. исторические man-
       страницы ip(4) BSD-семейства); НЕ проверено эмпирически в этой песочнице
       — сырой сокет здесь недоступен без привилегии, см. шапку файла. */
    uint8_t *apple_fixup[2];
    apple_fixup[0] = frag1;
    apple_fixup[1] = frag2;
    for (int fi = 0; fi < 2; fi++) {
        uint8_t *f = apple_fixup[fi];
        uint16_t totlen = (uint16_t)((f[2] << 8) | f[3]);
        uint16_t offflags = (uint16_t)((f[6] << 8) | f[7]);
        f[2] = (uint8_t)(totlen & 0xFF);
        f[3] = (uint8_t)(totlen >> 8);
        f[6] = (uint8_t)(offflags & 0xFF);
        f[7] = (uint8_t)(offflags >> 8);
    }
#endif

    struct sockaddr_in raw_dst;
    memset(&raw_dst, 0, sizeof raw_dst);
    raw_dst.sin_family = AF_INET;
    raw_dst.sin_port = htons(port);
    raw_dst.sin_addr.s_addr = dst.sin_addr.s_addr;

    int sent = 0;
    struct timespec sent_at[8];
    int fds_marker[8]; /* фиктивный — recv идёт с ОДНОГО rx_fd, но время отправки нужно на каждую попытку */
    (void)fds_marker;
    for (int i = 0; i < repeats; i++) {
        ssize_t r1 = sendto(raw_fd, frag1, f1len, 0, (struct sockaddr *)&raw_dst, sizeof raw_dst);
        ssize_t r2 = sendto(raw_fd, frag2, f2len, 0, (struct sockaddr *)&raw_dst, sizeof raw_dst);
        if (r1 >= 0 && r2 >= 0) {
            clock_gettime(CLOCK_MONOTONIC, &sent_at[sent < 8 ? sent : 7]);
            sent++;
        }
    }
    close(raw_fd);

    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = 1;
    int not_sent = repeats - sent;
    t.err += not_sent;
    t.fail += not_sent;

    if (sent > 0) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        uint32_t w = (wait_ms == 0) ? D2K_QUIC_RTT_WAIT_FLOOR_MS : wait_ms;
        deadline.tv_sec += (time_t)(w / 1000u);
        deadline.tv_nsec += (long)(w % 1000u) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        int got = 0;
        while (got < sent) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long remain_ms =
                (long)(deadline.tv_sec - now.tv_sec) * 1000L + (deadline.tv_nsec - now.tv_nsec) / 1000000L;
            if (remain_ms <= 0) {
                break;
            }
            struct pollfd pfd = {rx_fd, POLLIN, 0};
            int pr = poll(&pfd, 1, (int)remain_ms);
            if (pr <= 0) {
                break;
            }
            uint8_t buf[2048];
            ssize_t n = recv(rx_fd, buf, sizeof buf, 0);
            if (n <= 0) {
                break;
            }
            /* СЧИТАЕМ ТОЛЬКО ПОДТВЕРЖДЁННЫЕ, а неподтверждённую датаграмму
               НЕ засчитываем попыткой вовсе — тот же дефект, что был у
               оракула вопросов и разобран замером 17.09
               (docs/field/2026-09-17-quic-oracle-first-datagram.md): сервер,
               получивший несколько Initial, отвечает СНАЧАЛА подтверждением,
               а ServerHello шлёт следом. Прежняя редакция съедала первым
               `ACK` слот попытки и записывала его в неудачу, а разведочный
               зонд фрагментации ходит ОДНОЙ попыткой — то есть кончался на
               первом же `ACK`, не увидев настоящего ответа. */
            if (d2k_quic_verify_response(buf, (size_t)n, msg) == 0 && got < sent) {
                got++;
                t.pass++;
            }
        }
        t.fail += (sent - got); /* тайм-аут без подтверждённого ответа на остальные попытки */
    }
    close(rx_fd);

    if (sent_out) {
        *sent_out = sent;
    }
    return t;
}

d2k_quic_ask_frag_fn d2k_quic_ask_frag_hook = frag_real;
