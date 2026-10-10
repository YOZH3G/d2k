# Один исполняемый вопрос: аудит TCP, QUIC, HTTP и voice

Продолжение требования владельца после четырёх классов e/f. База нового
этапа — `7ac234a` (`main`); предыдущий этап начинался с `e5e7529`.
Точные итоговые ревизии и проверки — ниже. Роутер, полевые сценарии, сайты,
службы z2k и push не запускались. MVP и браузерная приёмка остаются открытыми.

## Что теперь является доказательством

Измеритель QUIC/voice строит Plan тем же компилятором, что экспортирует
найденное решение: `core/udpplan.c`. `core/udpruntime.c` загружает канонический
TLV и вызывает **тот же `d2k_plan_apply` и существующие wire/fragment builders**,
что живой datapath. Прежде чем отправить первую датаграмму, строится весь
результат и проверяется его выполнимость. Собственной сборки prefix/split/
фрагментов в `quicprobe.c` больше нет. Локальная ошибка не включает другой
способ обхода и не считается ответом сети.

Обычный подключённый UDP-сокет остаётся отправляющим адаптером: он получает
из готового результата payload, TTL/hop limit и задержку. **Ядро ОС создаёт
его IP/UDP-заголовки.** Полное побайтное сравнение ниже относится к двум
локальным runtime при одинаковом явно заданном контексте, а не к физическому
pcap обычного сокета. Отдельный syscall capture проверяет, что адаптер не
потерял смещение, длину, число датаграмм, TTL и паузу. Kernel IPID/flow label,
NFQUEUE/NAT, интерфейс и фактический выход на линию этим не доказаны.

Для фрагментов передаются полные IP-пакеты. До первой отправки подготавливаются
все raw-посылки; при отказе нет fallback на целую UDP-датаграмму. IPv6
использует существующий общий `d2k_ip6frag_send.h`. Синхронизированный
fragment-ID счётчик с random seed сохранён: UDP-порты не входят в ключ
IP reassembly. Возможность опустить неподдерживаемую порчу IPID закрыта
отказом до отправки. Предел результата 26 посылок общий с datapath; это
существующая вместимость исполнителя, не новый бюджет поиска.

## Доказанные дефекты и исправления

| Дефект | Исправление и регрессия |
|---|---|
| Voice измерял одну копию, экспортировал две | Сохраняется ровно измеренное число; `test_voice` реально падал на базе |
| Voice измерял без settle, план имел 15 мс | Измеритель исполняет тот же voice Plan, включая 15 мс; это изменённый полевой вопрос, не заранее известный успех |
| QUIC fake+split успевал отправить fake до отказа неразбираемого split | Весь Plan строится до первого send; `test_quic_sink` на базе фиксирует 11 уже ушедших prefix |
| Failed prefix send оставлял укороченный TTL сокета | Восстановление происходит и после ошибки; отдельный red `test_quic_sink` |
| Generic junk спрашивал одну датаграмму, экспортировал две | Вопрос и план содержат одну |
| Независимые YES превращались в fake×length, junk×length или fragment×junk без вопроса произведению | Экспортируется ровно один измеренный вопрос; новое произведение требует отдельного вопроса |
| Generic length измерял 1300 с padding внутри Initial, экспортировал append100 снаружи | Вопрос теперь выполняет runtime `udplen 100` после fresh-CID сборки; loopback проверяет длину пакета и 100 нулей после него |
| Generic CRYPTO question пересобирал воздействие отдельно от executor | После построения свежего обычного Initial применяется тот же Plan `quicsplit 1` |
| TCP split измерял socket-write границы, экспортировал packet split | Production detect исполняет pure split через существующий raw PlanApply; общий `d2k_tcp_split_plan` задаёт segment/wire/pace для измерения и экспорта |
| Legacy/default TCP и legacy QUIC могли экспортировать неподтверждённый runtime | Scheduler без detect runtime отказывает; bridge не экспортирует socket-only split; QUIC compiler отказывает `!arm.original` |

Порог C 3/3 не менялся. Подбор белого имени по цели не изменялся. Второго
TCP raw-сборщика не добавлено. Работающий прямой трафик не запускает поиск.

## Карта всех путей

| Путь | Исполнение обхода и локальная проверка | Граница |
|---|---|---|
| TCP raw poisons, C и compound ECH | `detect/raw.c` → measured Plan → PlanApply → wire; общий full-packet gate `detect/test_raw.c`, каталог автоматически | Linux raw/NFQUEUE и приложение отдельно |
| TCP SYN-data, raw SYN/ACK control | Собственный transport sender остаётся; SYN-data исключён из bridge `plannable_hit`, не экспортирует обходной Plan | Диагностика/transport control, не покрытый каталогом packet program |
| TCP pure split, включая prefix binary search | Тот же raw путь; один builder измерителю и `sched.c`; полный packet/delay regression | Прежние socket-split полевые находки перепроверить: способ исполнения изменился |
| TCP `no_raw`/unsupported и `core/meas.c`/`verdict.c` | Диагностические socket writes остаются; bridge запрещает их экспорт, неинициализированный scheduler fail-closed | Это не доказательство runtime и не скрытый production fallback |
| QUIC original arms, стратегия, fake×split, data-stage | Общие `udpplan.c` + `udpruntime.c`; actual quicarms question → exported arm → Session full-packet gate | Filter и data-stage разные свежие соединения; разные hello — разные контексты, не объявляются равными байтами |
| QUIC generic junk, length, CRYPTO frames | Junk через тот же question compiler; length/frames через Plan после fresh-CID; отдельный loopback длины | Старые length/junk/combined результаты требуют повторного измерения |
| QUIC protocol generation и Retry/PTO | `quicconn.c` строит обычные protocol packets; эффект только first_send через общий runtime | Повторный Initial следует существующей политике без воздействия; loopback Retry и Session same-flow gate, поле отдельно |
| QUIC delay plan и core properties под установленным планом | Проба посылает обычный protocol request; сам обход исполняет Session | Одномоторный путь; Linux очередь и выпуск отдельно |
| QUIC version/fixed-bit/source-port/two-datagram диагностические вопросы | Изменяется протокольный запрос; эти свойства не экспортируются самостоятельным bypass Plan | Не считать положительный diagnostic ответ доказанным устанавливаемым обходом |
| Legacy `d2k_quic_pick_arm` / `props.c frag_real` | Production callsites отсутствуют; прежние диагностические тесты остаются, `!original` arm не экспортируется | Собственный legacy fragment sender не выдаётся за рабочий production engine |
| HTTP portal, включая split/checksum/product | Trial и permanent устанавливаются одним `hs_hex` в Session; зонд отправляет исходный GET | `test_http_runtime` сравнивает реальные callbacks и весь каталог, IPv4/6; ответ пока только headers |
| TCP property probes / `props_contact_on_family` | Ставят Plan, посылают исходный hello; сегментацию делает Session | Собственного bypass builder нет |
| STUN voice | STUN generator/parser только протокол; fake/copies/pace — общий UDP Plan runtime | Copies1/6 и voice Plan10 в gate; успех STUN не равен звуку |
| Discord IP Discovery | Первый request через общий voice Plan, следующие запросы обычные | Gate Discovery74 и same-flow no-reapply; приложение/звук отдельно |
| Безымянный произвольный UDP | Session не применяет этот обход, если нет QUIC Initial/voice признака | Второго обходного движка нет; домен для IP не выдумывается |
| TLS12/13 volume/verify | Обычный запрос через установленный datapath Plan | Нет независимого построения bypass packets |
| DNS в verify и relay-enroll | Протокольные DNS/ECH/resolution запросы; Plan не порождают | Не обходной sender |
| Netlink/NFQUEUE control, route/MTU/getsockname | Управление/локальный контекст, не обходной пользовательский трафик | Не смешивается с packet-runtime свидетельством |

## Общие ворота для новых гипотез

`datapath/test_runtime_trace.h` сравнивает непустые трассы: число и порядок,
полный `memcmp` каждого IP-пакета, его длину и задержку. Никаких исправлений
checksum, ID или нормализации байтов перед сравнением нет.

- TCP gate проходит реальный каталог raw hypotheses, pure split и C на
  нескольких входных размерах, IPv4/6. Измерительный sender и runtime
  сравниваются на одном явном transport context. Отдельный `test_probe_plan`:
  12 inputs, 85 catalog hypotheses, 12 questions, 31 skipped, 0 mismatches
  (`/tmp/d2k-runtime-probe-plan-final.log`); skipped SYN-data не выдаётся
  за покрытую runtime-гипотезу.
- UDP gate вызывает настоящий `quicarms`: **каждый фактически заданный
  уникальный вопрос**, включая NO, автоматически попадает в сравнитель.
  Отдельно успешный вопрос сравнивается с реально экспортированным arm,
  поэтому ошибки copies/TTL/добавленной оси не скрываются построением
  одного и того же плана в обеих ветках. Есть all-NO проход, четыре
  strategy/compound маршрута, 1200/1300-byte Initial, все fragment shapes,
  STUN и Discovery. На текущем каталоге — 53 разных вопроса и 198 полных
  сравнений IPv4/6. Новые ветви, которые требуют нового условия входа,
  требуют также сценария этого условия; один all-NO их не заменяет.
- UDP full-packet результат сравнивается с настоящим `session.c`, а не с
  результатом отдельно вызванного QUIC transform. Затем проверяется
  фактическая отправляющая оболочка: обычные send/TTL/wait и raw prepare/send.
  Raw I/O seams в тесте подменены: реальные Linux socket options, SO_MARK,
  route/neighbor/интерфейс здесь не исполняются.
- HTTP gate берёт trial/permanent тексты из настоящих callback установки
  трёх property маршрутов и автоматически проходит каждый элемент каталога.
  Оба входа исполняются настоящей Session с SYN-контекстом, IPv4/6.
- Изменённые byte/count/delay отвергаются. `test_udp_runtime --diverge` и
  `test_http_runtime --diverge` действительно завершаются exit1; обычные
  запуски — exit0. Это проверка чувствительности ворот, не red продукта.
- `test_quic_sink` отдельно вызывает настоящий first-send entry point.
  Bad split/invalid Plan не посылает prefix; failed TTL send восстанавливает
  значение. Raw prepare/send refusal не включает альтернативную отправку.

## Red/green, ревизии и состояние

Логические коммиты нового этапа:

- `7c46a01`: TCP split через существующий raw executor и общий builder.
- `2b2d8d9`: scheduler без измерительного runtime не использует socket fallback.
- `a5e3e3a`: запрет bridge export socket-only split.
- `34d4495`, `e5da19f`: общая trace-проверка TCP/HTTP и весь HTTP-каталог.
- `6ac8be9`: общий UDP compiler/runtime/sink и регрессии.
- `264b18b`: scheduler test проверяет измеренный junk×1 вместо старого×2.
- `08de70b`: UDP sources объявлены до раскрытия Makefile prerequisites.
- `d64de8e`: native UDP objects/archive отслеживают shared runtime headers.

Для UDP создан новый `git archive 7ac234a`, не использовались старые бинарники.
Перенесены окончательные тесты, Makefile и новые test-support/runtime units
для сравнения. **Сам baseline `quicprobe.c`, `voice.c`, `compose.c` не
исправлялся**: sink regression вызывает его старый first_send; compiler
regression отдельно линкует именно baseline composer, не новый udpplan.
Общие тестовые заголовки только задают тот же предел26 и сравнитель.
Выполнен touch входов и свежая сборка.

| Red на 7ac234a | Build | Run | Что реально падает |
|---|---:|---:|---|
| test_quic_sink | 0 | 1 | Prefix до invalid split; TTL после failed send |
| test_voice | 0 | 1 | Измеренная1 экспортируется2 |
| test_udp_compose_exact | 0 | 1 | Junk copies, неизмеренные комбинации, legacy export |

Путь: `/tmp/d2k-runtime-red-final-path`; manifest:
`/tmp/d2k-runtime-red-final-results.json`; отдельные build/run логи
`/tmp/d2k-runtime-red-final-*.log`. CHECK накопительный, зачтён exit процесса.
Отдельный свежий TCP archive7ac234a: `/tmp/d2k-tcp-runtime-red-path`,
manifest `/tmp/d2k-tcp-runtime-red-results.json`. Все четыре теста
`test_raw`, `test_repeats`, `test_bridge`, `test_sched_default` имеют
build0/run1 после touch; логи `/tmp/d2k-tcp-runtime-red-*.log`.
Для standalone scheduler явно собраны три отсутствовавшие в старом Makefile
зависимости; текущий Makefile теперь перечисляет их.

TCP red на 7ac234a: реальный `test_raw` терял split delay; `test_repeats`
показывал socket вместо raw entry. Дополнительно red local raw send failure
→ FLAKY. Legacy scheduler red на 7c46a01 и bridge red на версии до guard
подтверждают отказ экспортировать socket-only результат. HTTP byte defect
не найден: его одномоторность подтверждена gate, не выдуман production red.

Production C-код — `6ac8be9`; итоговая сборочная ревизия — `d64de8e`.
Между ними исправлены устаревший oracle/comment в `test_sched.c` и порядок
объявлений и header dependencies Makefile. Окончательный документационный коммит меняет только
handoff/report/checklist файлы.

| Итоговая команда | Результат |
|---|---|
| make -C core check | exit0 |
| make -C detect check | exit0 |
| make -C datapath check | exit0 |
| make -C core cross | exit0 |
| make -C core san-udp-runtime | exit0 |
| git diff --check | exit0 |

Логи `/tmp/d2k-runtime-{core,detect,datapath,cross}-final.log`,
`/tmp/d2k-runtime-san-final.log`. Прерванный устаревший core-прогон не зачтён;
итоговый запуск сделан после стабилизации production-кода. Первый полный
проход выявил устаревший scheduler oracle, требовавший junk×2 вместо
измеренного junk×1; исправлен только CHECK/комментарий и повторён полный
core check. Его исходный fail сохранён в
`/tmp/d2k-runtime-core-stale-oracle-red.log`. Следующий проход прошёл весь
scheduler, но выявил настоящий build fail `test_catalog_sync`: позднее
`SRC +=` добавляло UDP objects в recipe, но не в уже раскрытые prerequisites.
Объявление перенесено до правил; targeted catalog и весь оставшийся хвост
собраны/пройдены exit0, затем снова выполнен полный core check. Red сохранён
в `/tmp/d2k-runtime-core-catalog-build-red.log`, green —
`/tmp/d2k-runtime-catalog-build-green.log` и
`/tmp/d2k-runtime-core-tail-green.log`. Дополнительно `make -n -W
include/d2k_udpruntime.h udpplan.o udpruntime.o` сначала ошибочно считал
объекты актуальными, после dependency fix назначает обе компиляции;
`/tmp/d2k-runtime-header-deps-{red,green}.log`. Этот последний dependency-only
fix не менял C-код, заголовки или входы уже идущего полного прогона. timeout/gtimeout
не использовались. Независимое read-only review выявило и помогло закрыть
fragment-ID regression и неподдерживаемую sink-порчу; финальное review
новых блокеров не нашло. Перед документационным коммитом dirty — только
перечисленная документация; финальный HEAD определяется этим коммитом.

## Что теперь повторить в поле — только координатору

Сначала записать точный HEAD/dirty, существующие D2K службы/правила/марки,
маршрут, каталог и восстановление. Использовать ограниченный собственный
trial/временный каталог, не стирать подтверждённые решения. `field-observe.sh`
может менять роутер: прочитать его заголовок и аргументы перед запуском.

Первый общий опыт — равенство исполнения на Linux: один и тот же
hypothesis/input/context на свежих эквивалентных потоках measurement и
установленного Plan. Снять pcap с реального выходного интерфейса, время,
полный 5-tuple, family, IP/NAT context, generation/trial/plan, APPLIED.
Для обычного socket отдельно учитывать принадлежащие ОС IPID/flow label;
сверять payload, datagram lengths/order, TTL, паузы и корректные checksum,
не выдавая разные исходные transport contexts за расхождение Plan.
Для фрагментов сверять shape/order/overlap, общий nonzero ID внутри
датаграммы и source/NAT tuple; отказ prepare не должен выпускать целый
Initial вместо фрагментов. Затем Retry/PTO и повторный запрос той же связи:
нового fake-префикса быть не должно по текущей once-per-flow политике.

После этой проверки повторить четыре класса из [этапа g](2026-10-11g-four-measured-classes.md):

1. **Katzauction/spzh**: direct второй request cut против quic5×2 TTL3,
   одинаковое hello/имя/IP/окно, полные ответы и бюджет повторных streams.
   Поле f действительно подтвердило e0d1dad8 на шести запросах, но это
   исторический успех, не приёмка нового measurement/runtime. Ожидание нового
   классификатора — свойство до fallback; не объявлять физическую причину cut.
2. **Nnmclub QUIC**: direct, fake×11, plain split и адаптивное произведение
   на свежих flow. Partial1–2/3 допускает вопрос произведению, не его принятие;
   требуется собственное3/3+data. Эффективность нового произведения неизвестна.
   Рабочий TCP680fbe00 остаётся отдельным опытом. Все прежние TCP pure-split
   находки также перепроверить: socket writes заменены raw packet execution.
3. **Fast-torrent HTTP80**: baseline portal, split-alone NO (в f — silence),
   pure checksum NO, product×два полных header response. Plan trial/permanent
   теперь локально сверены; HTTP200 headers всё ещё не полный HTML/ресурсы.
   Браузер с отключённым кешем должен завершить тело, redirect и ресурсы;
   логировать bytes тела/Content-Length или завершение chunked и отказы имён.
4. **Flibusta**: transient base dial timeout должен приводить к свежей полной
   базе, а target CH silence/control pass — к измеренному SNI-hiding вопросу.
   Не менять white-name по цели, не объявлять IP block или прокси. Смешанный
   свежий «один dial timeout + два silent CH» остаётся консервативным и не
   превращён в3/3; seed retry и этот остаточный случай не смешивать.

Дополнительно voice/STUN/Discovery, generic junk/length и любые старые
сохранённые комбинации независимо проверенных осей требуют нового опыта.
Изменённый вопрос с точным runtime не доказывает свою эффективность заранее.
Окончательный приоритет — все цели и их ресурсы в браузере, а не единичный
ответ собственного зонда. Linux/NFQUEUE, физический провод, полная страница,
QUIC application и голос остаются внешней приёмкой.
