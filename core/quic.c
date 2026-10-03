/* quic.c — разбор QUIC Initial: узнавание, снятие защиты, имя.
 *
 * Как и datapath/tls.c, этот файл отвечает на один вопрос — что здесь лежит
 * и где в этом имя — и разбирает чужие байты с явной границей на КАЖДОМ шаге:
 * поле, не помещающееся в объявленную (кем-то на проводе) длину, —
 * противоречие; не помещающееся в то, что реально пришло, — обрывок. Смешивать
 * эти два случая нельзя: первое — подделка или баг отправителя, второе —
 * нормальная недостача данных (например, обрезанный вход при тестировании
 * границ под ASan).
 *
 * ТРИ ЛОВУШКИ, КУПЛЕННЫЕ ЗАМЕРОМ ДОНОРА (z2k-detect/internal/quicprobe).
 *
 * 1. Биты типа длинного заголовка (маска 0x30 первого байта) защитой
 *    заголовка НЕ закрыты (RFC 9001 §5.4.1 защищает только младшие 4 бита и
 *    номер пакета). На этом стоит d2k_quic_is_initial — узнать Initial можно
 *    БЕЗ вывода ключей и без расшифровки.
 *
 * 2. Версия 2 (RFC 9369) — не экзотика, а отдельный, специально
 *    сконструированный «трудный случай»: другая соль вывода ключей (§3.3.1),
 *    другие метки HKDF («quicv2 key/iv/hp» вместо «quic key/iv/hp», §3.3.2) и
 *    ДРУГАЯ нумерация типа пакета (Initial=1, а не 0, §3.2). Коробка,
 *    зашитая на v1, здесь не расшифрует ничего и даже не опознает тип; этот
 *    разбор различает версию по полю Version и не предполагает v1 умолчанием
 *    ни в одном месте. Обе версии проверены отдельными байтовыми векторами
 *    (test_quic.c: RFC 9001 A.2 для v1, RFC 9369 A.2 для v2 — тот же самый
 *    ClientHello, разные соль/метки/номер версии, что и задумано авторами
 *    RFC 9369 для лёгкой сверки реализаций).
 *
 * 3. Пакет, ПОХОЖИЙ на нужный, но не расшифровавшийся этими ключами, —
 *    НЕ доказательство: у донора был замер, где такой пакет приходил дважды
 *    из двух с задержкой как у живого ответа, и это не засчиталось успехом
 *    (см. бриф задачи). Здесь то же самое правило работает в обратную
 *    сторону: d2k_quic_sni возвращает имя ТОЛЬКО если шифротекст прошёл
 *    проверку тега AEAD (d2k_aes128_gcm_decrypt, d2k_crypto.h) — структурно
 *    похожий, но не аутентифицированный пакет имени не даёт никогда.
 *
 * СБОРКА ПОТОКА CRYPTO. Кадры внутри одного Initial-пакета — это ломтики
 * потока байт ClientHello, каждый со своим смещением; реальные браузеры (не
 * только эвазивные инструменты) режут ClientHello на несколько кадров CRYPTO
 * в одном и том же пакете, и кадры НЕ ОБЯЗАНЫ идти по возрастанию смещения.
 * Гадать о длине кадра НЕИЗВЕСТНОГО типа нельзя (в Initial разрешены только
 * PADDING/PING/ACK/CRYPTO/CONNECTION_CLOSE-0x1c, RFC 9000 §17.2.2) — на первом
 * непризнанном байте разбор кадров останавливается насовсем, но уже собранные
 * куски CRYPTO остаются в силе (см. collect_crypto_frames). Реассемблируются
 * куски в буфер фиксированного размера БЕЗ выделений памяти. Карта занятых
 * байтов учитывает все кадры независимо от порядка; наружу отдаётся только
 * непрерывный префикс от нуля. Пропуск не заполняется догадками.
 *
 * БЕЗ ВЫДЕЛЕНИЙ ПАМЯТИ. Обе функции вызываются на каждом UDP-пакете в
 * горячем пути датапата (задача 4 этой же вертикали, ещё не написана) — вся
 * работа целиком на стеке, буферы фиксированного размера, см.
 * D2K_QUIC_MAX_DGRAM ниже.
 */
#include <string.h>

#include "d2k_quic.h"
#include "d2k_quicwire.h"

/* ---------------------------------------------------------------------
 * Константы протокола. Каждая — из текста RFC, а не «на вкус».
 * --------------------------------------------------------------------- */

#define D2K_QUIC_V1 0x00000001u /* RFC 9000 */
#define D2K_QUIC_V2 0x6b3343cfu /* RFC 9369 §3.1 — первые 4 байта sha256("QUICv2 version number") */

/* Обе соли — 20 байт (RFC 9001 §5.2 и RFC 9369 §3.3.1 задают одну и ту же
 * длину), поэтому один именованный размер на обе — decrypt_initial ниже
 * передаёт его в d2k_hkdf_extract независимо от того, какая соль выбрана. */
#define D2K_QUIC_SALT_LEN 20

/* RFC 9000 §17.2: длина DCID/SCID в длинном заголовке — 8-битное число, но
 * "MUST NOT exceed 20 bytes... Endpoints that receive a ... value larger than
 * 20 MUST drop the packet". Это не граница буфера (любое значение 0..255
 * технически ПОМЕЩАЕТСЯ в однобайтовое поле) — это требование стандарта,
 * нарушение которого само по себе говорит «не наш Initial». Действует для
 * обеих версий: RFC 9369 не меняет этот пункт. */
#define D2K_QUIC_CID_MAX 20

/* Наибольшая датаграмма, которую готов держать разбор. Функции этого модуля
 * не выделяют память (задача 4 зовёт их на каждом UDP-пакете в горячем пути)
 * — значит буферы фиксированного размера, а не по размеру входа. Нижняя
 * граница задана стандартом: RFC 9000 §14.1 требует от клиента дополнять
 * Initial минимум до 1200 байт (см. protected_packet в test_crypto.c и оба
 * вектора в test_quic.c — ровно 1200). Верхняя граница стандартом не
 * зафиксирована («MAY exceed 1200 bytes if the sender believes the network
 * path... support the size», §14.1) — берётся размер кадра Ethernet (1500,
 * IEEE 802.3), с которым такая датаграмма проходит без фрагментации почти
 * везде, включая WAN Keenetic (PPPoE даже режет до 1492). Датаграмма крупнее
 * этого предела — не типичный браузерный Initial, и не в этом её отвергать
 * ЖИЗНЕННО: разбор просто честно не пытается её понять (см. parse_initial_header). */
#define D2K_QUIC_MAX_DGRAM 1500

/* ---------------------------------------------------------------------
 * Мелкие читалки. rd16/rd32 — big-endian, как весь QUIC (RFC 9000 §17).
 * --------------------------------------------------------------------- */

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}


/* Переменная длина QUIC (RFC 9000 §16): два старших бита ПЕРВОГО байта задают
 * ширину поля (1/2/4/8 байт) — а значит ширину можно узнать только прочитав
 * этот байт, и лишь ПОСЛЕ этого проверять, что она умещается в avail. Именно
 * в такой последовательности, а не наоборот: прочитать "на всякий случай"
 * 8 байт нельзя — за пришедшими n байт может не быть ничего. val/width не
 * трогаются при отказе (obryvok — не хватило байт даже на объявленную ширину,
 * это не наша забота отличать от "поле неверно устроено": и то и другое
 * означает "здесь нечего читать дальше"). */
static int read_varint(const uint8_t *p, size_t avail, uint64_t *val, size_t *width) {
    if (avail < 1) {
        return -1;
    }
    size_t w = (size_t)1 << (p[0] >> 6);
    if (avail < w) {
        return -1;
    }
    uint64_t v = (uint64_t)(p[0] & 0x3f);
    for (size_t i = 1; i < w; i++) {
        v = (v << 8) | p[i];
    }
    *val = v;
    *width = w;
    return 0;
}

/* ---------------------------------------------------------------------
 * Версия: соль и метки. "client in"/"server in" ОБЩИЕ для v1 и v2 — RFC 9369
 * меняет только метки пакетной защиты и защиты заголовка (§3.3.2), метки
 * извлечения секрета уровня не трогает. Здесь нужна только клиентская сторона
 * ("client in"): этот модуль расшифровывает ПАКЕТ КЛИЕНТА (ClientHello — то,
 * что клиент посылает серверу), а не ответ сервера — это другая точка
 * наблюдения и задача другого модуля (core/quicprobe.c, ещё не написан).
 * --------------------------------------------------------------------- */

/* ---------------------------------------------------------------------
 * Разбор заголовка Initial — общий для d2k_quic_is_initial и d2k_quic_sni,
 * чтобы у них не было шанса разойтись в том, что считать Initial. НЕ трогает
 * ключи и шифр вовсе — только структура заголовка и границы.
 * --------------------------------------------------------------------- */

typedef struct {
    uint32_t version;
    size_t dcid_off, dcid_len;
    size_t pn_offset;      /* где начинается (ещё защищённый) номер пакета */
    size_t length_claimed; /* поле Length: номер пакета + payload + тег AEAD */
} quic_hdr;

static int parse_initial_header(const uint8_t *p, size_t n, quic_hdr *h) {
    if (!p) {
        return -1; /* проверяется здесь один раз, а не в каждом из двух публичных входов */
    }
    if (n > D2K_QUIC_MAX_DGRAM) {
        return -1; /* см. комментарий у константы: за этим пределом разбор сознательно не пытается */
    }
    /* РАЗБОР — ОБЩИЙ (core/quicwire.c), а не свой. Копия этого кода уже жила
       здесь и в quicprobe.c, и копии успели разойтись: одна знала версию 2,
       другая нет. Здесь остаются только требования, которые предъявляет
       ИМЕННО ЭТОТ путь — пакетный, где нас интересует ровно клиентский
       Initial известной версии. */
    d2k_qw_hdr qh;
    if (d2k_qw_hdr_parse(p, n, 0, &qh) != 0) {
        return -1;
    }
    if (!qh.long_hdr) {
        return -1; /* короткий заголовок — до него в Initial-пространстве дело не доходит */
    }
    if (qh.version != D2K_QW_V1 && qh.version != D2K_QW_V2) {
        return -1; /* неизвестная версия — честно не наш Initial */
    }
    if (qh.type != D2K_QW_LT_INITIAL) {
        return -1; /* тот же длинный заголовок, но 0-RTT/Handshake/Retry */
    }
    h->version = qh.version;
    h->dcid_off = qh.dcid_off;
    h->dcid_len = qh.dcid_len;
    h->pn_offset = qh.pn_offset;
    h->length_claimed = qh.length_claimed;
    return 0;
}

int d2k_quic_is_initial(const uint8_t *p, size_t n) {
    quic_hdr h;
    return parse_initial_header(p, n, &h) == 0;
}

/* ---------------------------------------------------------------------
 * Снятие защиты заголовка, вывод ключей, расшифровка.
 * --------------------------------------------------------------------- */

static int decrypt_initial(const uint8_t *p, const quic_hdr *h, uint8_t *plain, size_t *plain_len) {
    /* Ключи и снятие защиты — ОБЩИЕ (core/quicwire.c). Здесь остаётся только
       то, что знает этот путь: сторона клиентская, а номер пакета в начале
       соединения мал, и наибольшего принятого у пакетного разбора нет —
       состояния между вызовами у него не бывает по устройству. */
    uint8_t secret[32];
    if (d2k_qw_initial_secret(h->version, p + h->dcid_off, h->dcid_len,
                              D2K_QW_CLIENT, secret) != 0) {
        return -1;
    }
    d2k_qw_keys k;
    if (d2k_qw_keys_from_secret(h->version, secret, &k) != 0) {
        return -1;
    }
    d2k_qw_hdr qh;
    memset(&qh, 0, sizeof qh);
    qh.long_hdr = 1;
    qh.version = h->version;
    qh.type = D2K_QW_LT_INITIAL;
    qh.dcid_off = h->dcid_off;
    qh.dcid_len = h->dcid_len;
    qh.pn_offset = h->pn_offset;
    qh.length_claimed = h->length_claimed;
    qh.packet_len = h->pn_offset + h->length_claimed;
    return d2k_qw_open(&k, &qh, p, 0, plain, plain_len, NULL);
}

/* ---------------------------------------------------------------------
 * Кадры внутри расшифрованного payload. Разрешены (RFC 9000 §17.2.2, дословно
 * «CRYPTO frame(s)... ACK frames... PING, PADDING, and CONNECTION_CLOSE
 * frames of type 0x1c are also permitted»): PADDING(0x00), PING(0x01),
 * ACK(0x02/0x03), CRYPTO(0x06), CONNECTION_CLOSE-0x1c(0x1c). Заявление 0x1d
 * (закрытие уровня приложения) явно НЕ входит в этот список — и правда,
 * RFC 9000 §19.19: "The application-specific variant of CONNECTION_CLOSE
 * (type 0x1d) can only be sent using 0-RTT or 1-RTT packets" — то есть 0x1d
 * в Initial есть нарушение протокола, и разбор останавливается на нём точно
 * так же, как на любом другом неразрешённом здесь типе.
 * --------------------------------------------------------------------- */

/* Собирает CRYPTO по смещениям и возвращает длину непрерывного префикса.
 * Кадры читаются в порядке передачи, байты кладутся по смещению в потоке.
 * На первом нераспознанном или сломанном
 * (объявленная кадром длина не помещается в payload) байте разбор кадров
 * останавливается насовсем — гадать, где начинается следующий кадр, нельзя
 * ни для неизвестного типа, ни для битого известного: оба случая одинаково
 * лишают нас точки, откуда продолжать. */
static size_t collect_crypto_frames(const uint8_t *plain, size_t plen,
                                     uint8_t *stream, uint8_t *seen,
                                     size_t cap) {
    /* Цена ограничена байтами, не произвольным числом кадров. Клиент вправе
       прислать сотни однобайтовых CRYPTO в обратном порядке: прежние восемь
       слотов теряли SNI в совершенно корректном Initial. Карта занятости
       позволяет собрать все кадры за один проход без массива на каждый. */
    if (cap > D2K_QUIC_ASSEMBLY_MAX) { cap = D2K_QUIC_ASSEMBLY_MAX; }
    size_t i = 0;
    while (i < plen) {
        uint8_t t = plain[i];

        if (t == 0x00) { /* PADDING — просто нулевые байты, длина в кадре не хранится */
            while (i < plen && plain[i] == 0x00) {
                i++;
            }
            continue;
        }
        if (t == 0x01) { /* PING — без данных */
            i++;
            continue;
        }
        if (t == 0x02 || t == 0x03) { /* ACK / ACK_ECN, RFC 9000 §19.3-19.3.2 */
            size_t j = i + 1;
            size_t w;
            uint64_t largest, delay, range_count, first_range;
            if (read_varint(plain + j, plen - j, &largest, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &delay, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &range_count, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &first_range, &w) != 0) {
                break;
            }
            j += w;
            int ranges_ok = 1;
            /* range_count заявлен отправителем и может быть сколь угодно
             * большим (до 2^62-1) — но каждая итерация обязана прочитать ещё
             * хотя бы 2 варинта, а payload не больше D2K_QUIC_MAX_DGRAM,
             * поэтому read_varint откажет самое позднее через ~plen/2
             * итераций независимо от того, что заявляет range_count. Отдельный
             * потолок на сам range_count не нужен: буфер уже его ставит. */
            for (uint64_t r = 0; r < range_count; r++) {
                uint64_t gap, range_len;
                if (read_varint(plain + j, plen - j, &gap, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &range_len, &w) != 0) {
                    ranges_ok = 0;
                    break;
                }
                j += w;
            }
            if (!ranges_ok) {
                break;
            }
            if (t == 0x03) { /* ECN-счётчики есть только у типа 0x03 */
                uint64_t ect0, ect1, ecn_ce;
                if (read_varint(plain + j, plen - j, &ect0, &w) != 0) {
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &ect1, &w) != 0) {
                    break;
                }
                j += w;
                if (read_varint(plain + j, plen - j, &ecn_ce, &w) != 0) {
                    break;
                }
                j += w;
            }
            i = j;
            continue;
        }
        if (t == 0x06) { /* CRYPTO, RFC 9000 §19.6 */
            size_t j = i + 1;
            size_t w;
            uint64_t foff, flen;
            if (read_varint(plain + j, plen - j, &foff, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &flen, &w) != 0) {
                break;
            }
            j += w;
            if (flen > (uint64_t)(plen - j)) {
                break; /* кадр заявляет больше данных, чем есть в расшифрованном payload, — противоречие кадра */
            }
            if (foff < (uint64_t)cap) {
                size_t off = (size_t)foff;
                size_t take = (size_t)flen;
                if (take > cap - off) { take = cap - off; }
                for (size_t k = 0; k < take; k++) {
                    size_t pos = off + k;
                    uint8_t bit = (uint8_t)(1u << (pos % 8));
                    if (!(seen[pos / 8] & bit)) {
                        stream[pos] = plain[j + k];
                        seen[pos / 8] |= bit;
                    }
                }
            }
            j += (size_t)flen;
            i = j;
            continue;
        }
        if (t == 0x1c) { /* CONNECTION_CLOSE транспортного уровня, RFC 9000 §19.19 */
            size_t j = i + 1;
            size_t w;
            uint64_t err_code, frame_type, reason_len;
            if (read_varint(plain + j, plen - j, &err_code, &w) != 0) {
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &frame_type, &w) != 0) { /* только у 0x1c */
                break;
            }
            j += w;
            if (read_varint(plain + j, plen - j, &reason_len, &w) != 0) {
                break;
            }
            j += w;
            if (reason_len > (uint64_t)(plen - j)) {
                break;
            }
            j += (size_t)reason_len;
            i = j;
            continue;
        }

        /* Сюда попадают ДВА разных случая, и у них РАЗНЫЕ причины отказа —
         * путать их нельзя (ревью 2026-09-06: прежняя редакция валила обе
         * причины в одну "длину не угадать", что для второго случая неверно).
         *
         * Случай 1 — тип НЕИЗВЕСТЕН вовсе (не из Table 3 RFC 9000 §12.4).
         * Действительно "длину не угадать": формат тела кадра неизвестен, а
         * RFC 9000 §12.4 отдельно требует трактовать это как FRAME_ENCODING_ERROR.
         *
         * Случай 2 — тип ИЗВЕСTEН (это 0x1d, CONNECTION_CLOSE прикладного
         * уровня), и длина его тела ВЫЧИСЛИМА — формат тот же, что у 0x1c,
         * только без поля Frame Type. Отказ здесь НЕ из-за длины, а из-за
         * ПРОСТРАНСТВА НОМЕРОВ ПАКЕТОВ: 0x1d в Initial запрещён целиком, и
         * это подтверждено трижды независимо (сноска к Table 3 в §12.4:
         * "Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial
         * or Handshake packets"; §12.5: "CONNECTION_CLOSE frames signaling
         * application errors (type 0x1d) MUST only appear in the application
         * data packet number space"; §19.19, уже процитировано выше) — RFC
         * requires PROTOCOL_VIOLATION здесь, а не FRAME_ENCODING_ERROR, ровно
         * потому что кадр разобрать МОЖНО, просто ему сюда нельзя. Цена этой
         * строгости для настоящего браузера — нулевая: это разбор ПЕРВОГО
         * пакета КЛИЕНТА, а клиент физически не кладёт в Initial кадр
         * прикладной ошибки (донор трактует 0x1d так же, как 0x1c, — это
         * недосмотр донора, а не намеренная терпимость к живому трафику: его
         * же комментарий в parse.go говорит "только разрешённые в Initial
         * типы", а код принимает оба).
         *
         * Практическое следствие ОБЩЕЕ для обоих случаев: раз длина текущего
         * кадра (случай 1) или сама применимость типа (случай 2) не даёт
         * продолжить, гадать, где начинается следующий кадр, нельзя —
         * разбор кадров прекращается насовсем. Уже собранные куски CRYPTO
         * (если есть) остаются в силе: каждый прошёл свою собственную
         * проверку границ независимо от того, что случилось позже в payload. */
        break;
    }
    size_t filled = 0;
    while (filled < cap && (seen[filled / 8] & (1u << (filled % 8)))) { filled++; }
    return filled;
}

/* ---------------------------------------------------------------------
 * ClientHello внутри собранного потока CRYPTO. QUIC передаёт содержимое
 * Handshake-сообщений TLS БЕЗ записи TLS: "QUIC takes the unprotected content
 * of TLS handshake records as the content of CRYPTO frames. TLS record
 * protection is not used by QUIC" (RFC 9001 §4.1.3). Поэтому здесь нет ни
 * REC_HDR, ни проверки типа/версии записи — сразу заголовок Handshake
 * (тип + 3-байтная длина), как в datapath/tls.c сразу ПОСЛЕ снятия записи.
 * Дальше — тот же приём: claimed (что заявляет длина Handshake) и avail (что
 * реально собралось в stream) — разные границы, и путать их нельзя.
 * --------------------------------------------------------------------- */

#define HS_HDR 4
#define HS_CLIENT_HELLO 0x01
#define EXT_SERVER_NAME 0x0000
#define SNI_HOST_NAME 0x00

static int skip_u8_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 1 > len) {
        return -1;
    }
    size_t n = b[*off];
    if (*off + 1 + n > len) {
        return -1;
    }
    *off += 1 + n;
    return 0;
}

static int skip_u16_vec(const uint8_t *b, size_t len, size_t *off) {
    if (*off + 2 > len) {
        return -1;
    }
    size_t n = rd16(b + *off);
    if (*off + 2 + n > len) {
        return -1;
    }
    *off += 2 + n;
    return 0;
}

static int find_sni(const uint8_t *b, size_t exts_off, size_t exts_end,
                     size_t *sni_off, size_t *sni_len) {
    size_t off = exts_off;
    while (off + 4 <= exts_end) {
        uint16_t type = rd16(b + off);
        size_t elen = rd16(b + off + 2);
        off += 4;
        if (off + elen > exts_end) {
            return -1;
        }
        if (type == EXT_SERVER_NAME) {
            size_t p = off;
            if (p + 2 > off + elen) {
                return -1;
            }
            size_t list_len = rd16(b + p);
            p += 2;
            if (p + list_len > off + elen) {
                return -1;
            }
            size_t list_end = p + list_len;
            while (p + 3 <= list_end) {
                uint8_t nt = b[p];
                size_t nlen = rd16(b + p + 1);
                p += 3;
                if (p + nlen > list_end) {
                    return -1;
                }
                if (nt == SNI_HOST_NAME) {
                    if (nlen == 0) {
                        return -1; /* пустое имя — это не имя */
                    }
                    *sni_off = p;
                    *sni_len = nlen;
                    return 0;
                }
                p += nlen;
            }
            return -1;
        }
        off += elen;
    }
    return -1;
}

static int find_client_hello_sni(const uint8_t *stream, size_t filled,
                                  size_t *sni_off, size_t *sni_len) {
    if (filled < HS_HDR) {
        return -1;
    }
    if (stream[0] != HS_CLIENT_HELLO) {
        return -1; /* на уровне Initial клиент шлёт единственное сообщение — ClientHello (RFC 9001 §4.1.3) */
    }
    size_t hs_len = (size_t)stream[1] << 16 | (size_t)stream[2] << 8 | stream[3];
    size_t claimed = HS_HDR + hs_len;
    size_t avail = filled;
    size_t end = claimed < avail ? claimed : avail;

    size_t off = HS_HDR;
    if (off + 2 + 32 > end) { /* client_version(2) + random(32) */
        return -1;
    }
    off += 2 + 32;
    if (skip_u8_vec(stream, end, &off) != 0) {  /* legacy_session_id */
        return -1;
    }
    if (skip_u16_vec(stream, end, &off) != 0) { /* cipher_suites */
        return -1;
    }
    if (skip_u8_vec(stream, end, &off) != 0) {  /* compression_methods */
        return -1;
    }
    if (off + 2 > end) {
        return -1; /* расширений нет вовсе — законный ClientHello, но имени тогда нет */
    }
    size_t exts_len = rd16(stream + off);
    off += 2;
    if (off + exts_len > claimed) {
        return -1; /* блок расширений врёт даже в рамках заявленной длины Handshake — противоречие */
    }
    size_t exts_end = off + exts_len;
    if (exts_end > avail) {
        exts_end = avail; /* влезает в заявленное, но не в то, что реально собралось, — читаем что есть */
    }

    return find_sni(stream, off, exts_end, sni_off, sni_len);
}

/* ---------------------------------------------------------------------
 * Публичный вход.
 * --------------------------------------------------------------------- */

/* Общая часть d2k_quic_sni и d2k_quic_client_hello: из защищённой датаграммы
 * — собранный поток CRYPTO. Возвращает длину собранного (0 — не вышло). */
static size_t crypto_stream_of(const uint8_t *p, size_t n,
                               uint8_t *stream, size_t cap) {
    quic_hdr h;
    if (parse_initial_header(p, n, &h) != 0) {
        return 0;
    }
    uint8_t plain[D2K_QUIC_MAX_DGRAM];
    size_t plain_len;
    if (decrypt_initial(p, &h, plain, &plain_len) != 0) {
        return 0;
    }
    uint8_t seen[(D2K_QUIC_MAX_DGRAM + 7) / 8] = {0};
    return collect_crypto_frames(plain, plain_len, stream, seen, cap);
}

int d2k_quic_client_hello(const uint8_t *p, size_t n,
                          uint8_t *out, size_t cap, size_t *out_len) {
    if (!p || !out || !out_len) {
        return -1;
    }
    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(p, n, stream, sizeof stream);
    if (filled < HS_HDR || stream[0] != HS_CLIENT_HELLO) {
        return -1;
    }
    size_t claimed = ((size_t)stream[1] << 16) | ((size_t)stream[2] << 8) | stream[3];
    size_t whole = HS_HDR + claimed;
    /* ЦЕЛИКОМ — по СОБСТВЕННОЙ заявленной длине, а не «сколько собралось».
       Тот же разбор границ, что и всюду в этом файле: claimed и filled —
       разные величины, и отдать вызывающему обрывок как приветствие значило
       бы отдать ему пакет, который никто не примет. */
    if (whole > filled || whole > cap) {
        return -1;
    }
    memcpy(out, stream, whole);
    *out_len = whole;
    return 0;
}

int d2k_quic_hello_incomplete(const uint8_t *p, size_t n) {
    if (!p) {
        return 0;
    }
    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(p, n, stream, sizeof stream);
    if (filled < HS_HDR || stream[0] != HS_CLIENT_HELLO) {
        return 0;
    }
    size_t claimed = ((size_t)stream[1] << 16) | ((size_t)stream[2] << 8) | stream[3];
    /* Тот же признак, что в d2k_quic_client_hello: заявлено больше, чем
       собралось из этой датаграммы. */
    return HS_HDR + claimed > filled ? 1 : 0;
}

int d2k_quic_sni(const uint8_t *p, size_t n, char *out, size_t cap) {
    if (!p || !out || cap == 0) {
        return -1;
    }

    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(p, n, stream, sizeof stream);

    size_t sni_off, sni_len;
    if (find_client_hello_sni(stream, filled, &sni_off, &sni_len) != 0) {
        return -1;
    }
    if (sni_len + 1 > cap) {
        return -1; /* не помещается в буфер вызывающего целиком — режем молча только по прямому запросу, не здесь */
    }

    memcpy(out, stream + sni_off, sni_len);
    out[sni_len] = '\0';
    return 0;
}

void d2k_quic_assembly_init(d2k_quic_assembly *a) {
    if (a) { memset(a, 0, sizeof *a); }
}

int d2k_quic_assembly_feed(d2k_quic_assembly *a, const uint8_t *p, size_t n,
                           char *out, size_t cap) {
    if (!a || !p || !out || cap == 0) { return -1; }

    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(p, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL || h.dcid_len > D2K_QW_CID_MAX ||
        h.packet_len > n) {
        return -1;
    }

    d2k_quic_assembly next;
    int fresh = !a->active;
    if (a->active && (a->version != h.version || a->dcid_len != h.dcid_len ||
                      memcmp(a->dcid, p + h.dcid_off, h.dcid_len) != 0)) {
        /* QUIC Retry starts a new Initial flight with a new DCID. Treat it as
         * a new bounded assembly generation rather than poisoning the flow
         * with the old keys; a failed decrypt below still leaves the caller's
         * previous context untouched. */
        fresh = 1;
    }
    if (fresh) {
        memset(&next, 0, sizeof next);
        next.version = h.version;
        next.dcid_len = h.dcid_len;
        memcpy(next.dcid, p + h.dcid_off, h.dcid_len);
        uint8_t secret[32];
        if (d2k_qw_initial_secret(h.version, next.dcid, next.dcid_len,
                                  D2K_QW_CLIENT, secret) != 0 ||
            d2k_qw_keys_from_secret(h.version, secret, &next.keys) != 0) {
            return -1;
        }
        next.active = 1;
    } else {
        next = *a;
    }

    uint8_t plain[D2K_QW_MAX_DGRAM];
    size_t plain_len = 0;
    uint64_t pn = 0;
    if (d2k_qw_open(&next.keys, &h, p,
                    next.have_pn ? next.largest_pn : 0,
                    plain, &plain_len, &pn) != 0) {
        return -1;
    }
    if (!next.have_pn || pn > next.largest_pn) {
        next.largest_pn = pn;
        next.have_pn = 1;
    }
    (void)collect_crypto_frames(plain, plain_len, next.stream, next.seen,
                                sizeof next.stream);
    *a = next;

    size_t sni_off = 0, sni_len = 0;
    size_t filled = 0;
    while (filled < sizeof a->stream &&
           (a->seen[filled / 8] & (uint8_t)(1u << (filled % 8)))) {
        filled++;
    }
    if (find_client_hello_sni(a->stream, filled, &sni_off, &sni_len) != 0) {
        return 0;
    }
    if (sni_len + 1 > cap) { return -1; }
    memcpy(out, a->stream + sni_off, sni_len);
    out[sni_len] = '\0';
    return 1;
}

/* ---------------------------------------------------------------------
 * Разрез ClientHello на кадры CRYPTO (задача 40).
 *
 * Пакет раскрывается ключами из своего же DCID, кадры CRYPTO
 * перекладываются, пакет запечатывается заново ТЕМИ ЖЕ ключами с ТЕМ ЖЕ
 * номером и той же длиной. Повтор одноразового вектора GCM здесь ничего не
 * раскрывает: ключи Initial публичны по построению (RFC 9001 §5.2), а
 * исходник на провод не уходит — уходит только переложенный.
 *
 * Разрез — посередине имени, если имя собирается из CRYPTO этой датаграммы,
 * иначе посередине самого длинного кадра. Хвост первым: RFC 9000 §19.6 не
 * требует возрастания смещений внутри пакета, сервер собирает поток по
 * смещениям, а коробка, читающая кадры по одному, видит обрывок имени.
 * Место под заголовок второго кадра берётся из PADDING; его нет — отказ,
 * удлинять датаграмму здесь нельзя (длина — тоже форма, и её никто не мерил).
 * --------------------------------------------------------------------- */

#define SPLIT_MAX_FRAMES 64

typedef struct {
    uint64_t off;
    size_t len;
    size_t data; /* смещение данных в plain */
} split_frame;

static int put_split_frame(uint8_t *body, size_t cap, size_t *pos,
                           uint64_t off, const uint8_t *data, size_t len) {
    size_t b = *pos;
    if (b >= cap) { return -1; }
    body[b++] = 0x06;
    size_t w = d2k_qw_varint_write(body + b, cap - b, off);
    if (w == 0) { return -1; }
    b += w;
    w = d2k_qw_varint_write(body + b, cap - b, (uint64_t)len);
    if (w == 0) { return -1; }
    b += w;
    if (len > cap - b) { return -1; }
    memcpy(body + b, data, len);
    *pos = b + len;
    return 0;
}

int d2k_quic_initial_split_crypto(const uint8_t *in, size_t n,
                                  uint8_t *out, size_t cap, size_t *out_len) {
    if (!in || !out || !out_len || cap < n) { return -1; }
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(in, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL ||
        (h.version != D2K_QUIC_V1 && h.version != D2K_QUIC_V2) ||
        h.packet_len > n || h.packet_len > D2K_QUIC_MAX_DGRAM) {
        return -1;
    }
    uint8_t secret[32];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(h.version, in + h.dcid_off, h.dcid_len,
                              D2K_QW_CLIENT, secret) != 0 ||
        d2k_qw_keys_from_secret(h.version, secret, &k) != 0) {
        return -1;
    }
    uint8_t plain[D2K_QUIC_MAX_DGRAM];
    size_t plain_len = 0;
    uint64_t pn = 0;
    if (d2k_qw_open(&k, &h, in, 0, plain, &plain_len, &pn) != 0) { return -1; }
    if (h.length_claimed < plain_len + 16) { return -1; }
    size_t pn_len = h.length_claimed - plain_len - 16;
    if (pn_len < 1 || pn_len > 4) { return -1; }

    split_frame fr[SPLIT_MAX_FRAMES];
    size_t nfr = 0, pings = 0;
    for (size_t i = 0; i < plain_len;) {
        uint8_t t = plain[i];
        if (t == 0x00) { i++; continue; }          /* PADDING */
        if (t == 0x01) { pings++; i++; continue; } /* PING */
        if (t != 0x06 || nfr == SPLIT_MAX_FRAMES) {
            return -1; /* ACK, CONNECTION_CLOSE и прочее не перекладываем */
        }
        i++;
        uint64_t off = 0, len = 0;
        size_t w = 0;
        if (read_varint(plain + i, plain_len - i, &off, &w) != 0) { return -1; }
        i += w;
        if (read_varint(plain + i, plain_len - i, &len, &w) != 0) { return -1; }
        i += w;
        if (len > plain_len - i) { return -1; }
        fr[nfr].off = off;
        fr[nfr].len = (size_t)len;
        fr[nfr].data = i;
        nfr++;
        i += (size_t)len;
    }
    if (nfr == 0) { return -1; }

    /* Где резать: середина имени в координатах потока CRYPTO. */
    size_t target = SPLIT_MAX_FRAMES, cut = 0;
    uint8_t stream[D2K_QUIC_MAX_DGRAM];
    size_t filled = crypto_stream_of(in, h.packet_len, stream, sizeof stream);
    size_t sni_off = 0, sni_len = 0;
    if (filled && find_client_hello_sni(stream, filled, &sni_off, &sni_len) == 0 &&
        sni_len >= 2) {
        uint64_t mid = (uint64_t)sni_off + sni_len / 2;
        for (size_t f = 0; f < nfr; f++) {
            if (fr[f].off < mid && mid < fr[f].off + fr[f].len) {
                target = f;
                cut = (size_t)(mid - fr[f].off);
                break;
            }
        }
    }
    if (target == SPLIT_MAX_FRAMES) {
        size_t best = 0;
        for (size_t f = 0; f < nfr; f++) {
            if (fr[f].len > best) { best = fr[f].len; target = f; }
        }
        if (best < 2) { return -1; }
        cut = best / 2;
    }

    uint8_t body[D2K_QUIC_MAX_DGRAM];
    size_t b = 0;
    const split_frame *tf = &fr[target];
    if (put_split_frame(body, plain_len, &b, tf->off + cut, plain + tf->data + cut,
                        tf->len - cut) != 0 ||
        put_split_frame(body, plain_len, &b, tf->off, plain + tf->data, cut) != 0) {
        return -1;
    }
    for (size_t f = 0; f < nfr; f++) {
        if (f != target &&
            put_split_frame(body, plain_len, &b, fr[f].off, plain + fr[f].data, fr[f].len) != 0) {
            return -1;
        }
    }
    if (pings > plain_len - b) { return -1; }
    memset(body + b, 0x01, pings);
    b += pings;
    memset(body + b, 0x00, plain_len - b); /* PADDING до прежней длины */

    /* Заголовок до номера пакета — дословно; первый байт без защиты:
       старшие биты как на проводе, зарезервированные — нули, длину номера
       допишет d2k_qw_seal. */
    uint8_t hdr[D2K_QUIC_MAX_DGRAM];
    memcpy(hdr, in, h.pn_offset);
    hdr[0] = (uint8_t)(in[0] & 0xf0u);
    size_t made = d2k_qw_seal(&k, 1, hdr, h.pn_offset, pn, pn_len, body, plain_len,
                              out, cap);
    if (made != h.packet_len) { return -1; }
    if (n > h.packet_len) {
        memcpy(out + h.packet_len, in + h.packet_len, n - h.packet_len);
    }
    *out_len = n;
    return 0;
}
