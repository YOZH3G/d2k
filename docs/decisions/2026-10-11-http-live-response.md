# HTTP: полнота ответа конкретного живого запроса

База `29506b1`, main. Продолжение HTTP binding; общий goal не закрыт.
Обоснование поля — первый chunked-ответ fast-torrent целиком (~24 КБ), затем
302→lawfilter на повторном запросе. Полнота первого ответа не подтверждает второй.

## Что воспроизведено

`http80` покидал REQUEST после первого сегмента ответа. Разделённая TCP-сегментами
строка Location терялась. Новый пакетный тест на неизменённом 29506b1 дал два
CHECK (IPv4/IPv6): `split Location portal remains observable`, exit 2 у make,
`/tmp/d2k-http-response-red.log`. Это дефект наблюдателя, не доказанный механизм
полевого обхода.

Другой предел — правила `files/S99d2k` после начального окна передавали в очередь
лишь PSH-сегменты HTTP. Это не покрытие тела: обычный сегмент без PSH мог отсутствовать
в наблюдении. Изолированные iptables/nft doubles с новым требованием упали на старых
правилах: `/tmp/d2k-http-observation-iptables-red.log` и
`/tmp/d2k-http-observation-nft-red.log`, exit 1. На живую сеть правила не ставились.

## Реализация и смысл результата

`datapath/include/d2k_http_response.h` разбирает последовательные байты HTTP/1:
заголовки, Content-Length, chunked с расширениями/трейлерами, закрытие по FIN,
HEAD, 204/304, промежуточные 1xx. Синтаксис и границы сверены с
[RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) и
[§7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).
Дублирующийся Content-Length и неподдержанные transfer codings консервативно unknown.
Заголовок ограничен 8192 байтами, chunk/trailer line — 512; превышение — unknown,
не «DPI блокирует». Тело потоковое, без такого ограничения и без хранения целиком.
На native ABI sizeof наблюдателя — 1 383 496 байт (128 потоков),
10 280 байт на flow; это размер памяти, не измерение производительности роутера.

`http80.c` связывает разбор с направлением, TCP sequence, точным запросом и снимком
завершённого исполнения. Полностью старые повторы не удваивают тело. Новый FIN на
повторённых байтах обрабатывается отдельно. Разрыв/частичное перекрытие, RST,
неполное тело при FIN и неоднозначное framing дают unknown и прекращают
положительную атрибуцию этого соединения до нового SYN. ACK клиента не выдаётся
за доказательство неизвестной границы HTTP-ответа.

Распознанный портал с быстрым первым сегментом сохраняет прежний сигнал инъекции.
Если заголовок был разрезан, уже доставленный префикс не заменяется новым 307.
Поздний известный 30x→портал тоже нарушает критерий класса, но не объявляется
доказанной по времени инъекцией.

Новая `d2k_http80_delivered` вызывается из d2kd после результата реального
NFQUEUE-вердикта. Ошибка выпуска любого наблюдавшегося response payload лишает
ответ свидетельства полноты. До этого `response` — только подготовленное наблюдение.
Портальные отрицательные свидетельства не зависят от того, доставлен ли портал:
они сообщают, что воздействие не устранило ответ этого класса на пути.

Control **v18** переносит HTTP_RESPONSE: прежний снимок исполнения/привязки,
исход (complete framing / unknown / portal), HTTP status, body bytes и ordinal
запроса. Смешанная пара d2kc/d2kd не совместима. Consumer проверяет своё ACK-владение,
plan ID, отсутствие pending SET, trial ID и контекст до приписывания наблюдения.
Поздний портал отзывает ровно свою установку прежним условным удалением.

Журнал d2kc получает строку `HTTP live target=… request=… execution=… plan=…
generation=… outcome=response-complete|unknown status=… body=…; scope=request,
connection=pending`. Это наблюдение полного framing конкретного ответа,
не подтверждение содержимого приложения, не клиентский ACK и не постоянный PASS
всех будущих запросов. Код 4xx/5xx остаётся видимым; полнота framing его не повышает
до успеха приложения. Зонд, исполнение запроса и ответ хранят разный смысл.

В локальном `S99d2k` поздний TCP/80 наблюдается полностью в обе стороны, включая
non-PSH/ACK/FIN; остальные протоколы здесь не расширялись. Обновлены health-проверка,
iptables/nft doubles и отдельный Docker check_firewall. Цена — больше очереди/CPU
на открытом HTTP; пропускную способность и нагрузку проверяет координатор.

## Регрессы и границы

После добавления интерфейса наблюдения (нулевые поля, прежний алгоритм) тесты
Content-Length/chunked/FIN дали 14 CHECK вместе с разрезанным порталом:
`/tmp/d2k-http-complete-red.log`. Финальный файл теста с новым API не заявляется
компилируемым неизменённым на старом HEAD; исходный segmented-portal тест компилировался.

Дополнительные красные→зелёные регрессы:

- ошибка доставки заголовка/финального тела — `/tmp/d2k-http-delivery-red.log`;
- поздний портал — `/tmp/d2k-http-late-portal-red.log`;
- bare CR/LF, malformed chunk extension/trailer — `/tmp/d2k-http-framing-red.log`;
- FIN на повторённых байтах — `/tmp/d2k-http-fin-red.log`;
- ложное восстановление границы после gap — `/tmp/d2k-http-gap-resync-red.log`;
- control wire fixture/усечения — `/tmp/d2k-http-response-link-red.log`;
- production HTTP consumer через реальный control socket —
  `/tmp/d2k-http-response-consumer-red.log` (четыре CHECK).

Пакетная фикстура 24 КБ chunked → повторный запрос → портал проходит в IPv4/IPv6,
с non-PSH сегментами, изменением binding и отсутствующим исполнением второго запроса.
Это синтетический сценарий по описанию владельца; полевой pcap не получен.
Тест control consumer использует фактический Session execution и сериализацию,
но его response event — детерминированная фикстура; packet monitor проверяется
отдельно. Физический NFQUEUE verdict/macOS тестами не воспроизводится.

Свежая отдельная сборка старого `http80.c` и старого набора с добавленным
segmented-portal регрессом: compile 0, test 1, два CHECK,
`/tmp/d2k-http-response-baseline-fresh.log`. Checkout/старые объектники не использованы.
Мутация нового parser (complete сразу после Content-Length заголовка) тоже
падает: compile 0, test 1, `/tmp/d2k-http-response-early-mutant.log`.
Она доказывает, что тест замечает именно преждевременное подтверждение ответа.

## Следующий результат

Проверить поле на новых наблюдениях: каждый GET, его COMPLETE/SKIPPED, response
ordinal/status/body и связанный portal/unknown. Для fast-torrent сравнить один
и тот же повторный запрос на новой связи и keep-alive с тем же исполненным
воздействием. Нужны исходные длины/границы запросов браузера, а не только URL
собственного зонда. Полевой pcap/pcapng — оба направления от SYN с payload,
отметкой LAN/WAN, журналом и ревизией/планом; координатор снимает его сам.

Успех обхода fast-torrent этим изменением не доказан. Запросы, не разобранные
целиком (например, много сегментов заголовка запроса), pipelining/Upgrade,
потеря наблюдения/вытеснение и неувиденный FIN остаются без положительного
свидетельства. Зашифрованные TLS/QUIC требуют своих наблюдений; их приложению
HTTP-полнота открытого порта 80 не приписывается. mailsuite и QUIC-поиск не закрыты.

## Проверки и handoff

На финальном коде завершились с exit 0:

- `make -C core check` — `/tmp/d2k-http-response-core-check.log`, включая
  временную release-линковку arm64/mipsel, probe-plan 0 mismatches,
  HTTP runtime/live IPv4/IPv6, UDP 198 full-packet cases / 53 actual questions,
  QUIC actual first-send;
- `make -C detect check cross` — `/tmp/d2k-http-response-detect-check.log`,
  TCP runtime equality: C + 84 hypotheses, 6 lengths, IPv4/IPv6;
- `make -C datapath check cross` — `/tmp/d2k-http-response-datapath-check.log`,
  включая полную Linux-службу aarch64/mipsel;
- свежая сборка `test_http80` с ASan/UBSan —
  `/tmp/d2k-http-response-san.log`;
- iptables/nft doubles, `sh -n scripts/check_firewall.sh files/S99d2k`,
  `git diff --check`.

Docker `check_firewall.sh` обновлён, но не запускался. NFQUEUE на роутере,
реальная доставка клиенту, нагрузка и открытие сайтов не проверялись.
Новые response-события требуют совместной версии d2kc/d2kd (wire=18) и
нового S99d2k; старое PSH-ограничение не покрывает полный ответ.

Два чужих dirty-артефакта `builds/d2kc-linux-arm64` и
`builds/d2kd-linux-arm64` не менялись и не включены в коммит. SHA-256:
`5a8b19aa4deaa891da0094e53704f870d4f7f3027c2c2ad0f3131394b7a40194` и
`179c59ee5fdfc5e51877daf39ea79bfa316edafdf8a0e2a4e0db80bd6e30301e`.
Роутер, поле и push не затрагивались. Общая задача остаётся активной;
этот шаг не заявляет сдвиг полевой таблицы замер/перебор/время.
