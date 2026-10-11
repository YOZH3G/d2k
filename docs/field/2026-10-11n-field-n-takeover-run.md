# Полевой прогон 11.10.2026 (n): eaf4bdb против базы j

Сборка `main eaf4bdb`: 16 коммитов Astra после bbd8dca (HTTP keep-alive
границы и доказательства, RX partial, восстановление raw-замера, #14,
строка «итог поиска», QUIC length-before-fallback) плюс уступка слота QUIC
(`7a9835b`). arm64 собраны координатором из этой ревизии. Роутер Keenetic
aarch64, пустой каталог, дир `/opt/d2k/field-1011n-eaf4bdb`, 23:01–23:13.
Откат на прод 65e7488 выполнен, rollback-rc=0, очередь 2000 на месте.

Артефакты: `scratchpad/run-n/{d2kc.log,d2kd-live.log,ftn.pcap,ftn2.pcap,table.md}`.
Таблица — `scripts/field-table.py` той же командой и тем же списком сайтов,
что база в `2026-10-11m`. Браузерные выводы ниже — по заголовкам вкладок
Safari, снятым координатором, а не глазами владельца.

## Итог против базы j

| Показатель | j (bbd8dca) | n (eaf4bdb) |
|---|---|---|
| Медиана до подтверждения зондом | 129 с | 75 с |
| Максимум до подтверждения зондом | 786 с | 239 с |
| Цели из 19 с 10-мин штрафом «неубедителен» | 2 (rutracker, fost) | 0 |
| «Очередь заполнена» за прогон | 42 | 19 |
| QUIC-переборов / успешных / опытов | 15 / 2 / 687 | 7 / 1 / 336 |
| Уступок слота QUIC → TCP | — | 12, все возобновлены |
| RSS d2kc / d2kd после прогона | не снимали | 9,7 / 15,6 МБ (пик d2kc 13,3 МБ) |
| load average до / после | — | 1,25 / 1,25 |

Окна прогонов разной длины: j 16 мин, n 10 мин. Счётчики очереди и
переборов сравнивать с этой оговоркой.

## По целям

- **rutracker.org TCP:** 10 мин 51 с → 96 с. Штрафа FLAKY нет.
- **fost.club TCP:** 10 мин 31 с → 78 с.
- **rutracker.org QUIC:** в j перебор провалился; в n подтверждён своим
  планом plan-389a3920. Этот план нашёл перебор за 33 опыта на
  test-gateway.instagram.com, затем он подошёл rutracker.org, static.rutracker.cc,
  rua.gr, adguard.com, facebook.com. Путь — перебор, переиспользованный, а не замер.
- **fast-torrent.ru — впервые открыт с измеренным критерием.** Новый зонд с
  повтором keep-alive отверг прежний `fake-badsum-whole` («вставка провайдера»)
  и выбрал `fake-badsum` (разрез + checksum-приманка): «2 опыта подряд с двумя
  полными ответами keep-alive». Захват `ftn2.pcap` после установки:

  ```
  :50265  GET /opensearch.xml          → HTTP/1.1 200 OK            (ttl 56)
  :50264  GET /?n2=1                   → HTTP/1.1 200 OK            (ttl 56)
  :50264  GET /False/   (keep-alive)   → HTTP/1.1 500 Internal Server Error (ttl 56)
  ```

  Перед каждым запросом приманка `Host: disk.rzd.ru`, Host запроса разрезан.
  Ни одного `Location: lawfilter` после установки. В h/k именно keep-alive
  `/False/` получал портал 302; 500 — собственный ответ сайта на этот путь.
  d2kd: оба запроса соединения COMPLETE, planned=3 raw_sent=3. Живая приёмка
  d2kc: `request=1 status=200 body=13839 outcome=unknown connection=pending` —
  консервативно, соединение было открыто. Заголовок вкладки — настоящий сайт
  в двух загрузках подряд.
- **mailsuite.com — распознан как объёмный обрыв.** «identity (около 13 КБ) и
  gzip оборвались на одном бюджете: ~26 пакетов с данными на поток» →
  белое имя «9gag.com» → plan-9d543a55, бюджет потока пройден 115 пакетов из
  52 нужных. В j классификатор здесь сдавался. Первые две попытки — «очередь
  заполнена», отсюда 3 мин 59 с до подтверждения; сам поиск 24 с. Живой поток
  браузера через полосу обрыва не измерен; качество отрисовки — к владельцу.
- **flibusta.is — не открылась.** Блокировка подтверждена прямым замером,
  оба выведенных плана не дошли до TLS (plan-02dfb78d, который открыл её в j,
  и plan-2c117efa — RST), «выведенные планы исчерпаны», отдых 10 мин, запасной
  перебор не запускался. Совпадает с прежним «блок непостоянен», но это
  отрицательный результат относительно j.
- **QUIC-класс «фрагменты не доживают»** (fost, kinozal, lostfilm, nnmclub)
  по-прежнему проваливает перебор. Сайты открываются через TCP.

## Браузер (Safari, заголовки вкладок)

Первый проход 23:02–23:05: не открылись rutracker, nnmclub, flibusta,
fast-torrent (портал «Доступ закрыт» — до установки плана). Остальные 15
открылись, romfea — промежуточная страница Cloudflare, как в j. Окно прогона
закрылось до перезагрузки; повтор упавших в отдельном окне 23:07: rutracker,
nnmclub, fast-torrent, mailsuite открылись, flibusta нет. По заголовкам — 18
из 19; требуется подтверждение владельца глазами, особенно mailsuite.

## Непроверенное

- Живой критерий TLS/QUIC/voice по-прежнему unknown во всех строках.
- Прод 65e7488 на этих 19 в тот же день не прогонялся.
- Поведение fast-torrent на будущих запросах вне 40-секундного захвата.
- Причина отказа flibusta в этот раз: транспорт или сменившийся класс.

## Приложение: таблица `scripts/field-table.py`

| Цель | Протокол | Первое | Подтверждено зондом | Время | Путь | План | Поисков | Ед. зондов | QUIC-перебор (провал/всего, опытов) | Штрафов 10 мин (цель) | Исходы | live |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| adguard.com | quic | 23:02:27 | 23:03:37 | 70 с | own-plan | plan-389a3920 | 3 | 76 | — | — | probe-confirmed,queue-full | unknown |
| adguard.com | tcp | 23:02:27 | 23:03:43 | 76 с | own-plan | plan-680fbe00 | 7 | 5 | — | — | probe-confirmed,queue-full | unknown |
| cloudflare.com | tcp | 23:03:02 | — | — | none | — | 1 | — | — | — | inconclusive | unknown |
| enimerosi.com | quic | 23:02:17 | 23:03:23 | 66 с | property | plan-e0d1dad8 | 3 | 38 | — | — | probe-confirmed | unknown |
| facebook.com | quic | 23:02:24 | 23:03:26 | 62 с | own-plan | plan-389a3920 | 4 | 124 | 1/1, 48 | 2 | failed,probe-confirmed | unknown |
| facebook.com | tcp | 23:02:24 | 23:02:59 | 35 с | own-plan | plan-02dfb78d | 7 | 72 | — | 2 | failed,probe-confirmed,queue-full | unknown |
| fast-torrent.ru | http | 23:06:59 | 23:07:07 | 8 с | property | fake-badsum | — | — | — | — | — | unknown |
| flibusta.is | tcp | 23:02:22 | — | — | failed | — | 1 | 26 | — | 1 | failed | unknown |
| fost.club | quic | 23:02:13 | — | — | failed | — | 1 | 76 | 1/1, 54 | 1 | failed | unknown |
| fost.club | tcp | 23:02:13 | 23:03:31 | 78 с | own-plan | plan-680fbe00 | 3 | 26 | — | 1 | probe-confirmed,queue-full | unknown |
| katzauction.com | quic | 23:02:21 | 23:03:31 | 70 с | own-plan | plan-e0d1dad8 | 1 | 12 | — | — | probe-confirmed | unknown |
| kinozal.me | quic | 23:02:12 | — | — | failed | — | 1 | 72 | 1/1, 51 | 1 | failed | unknown |
| kinozal.me | tcp | 23:02:12 | 23:03:28 | 76 с | property | plan-680fbe00 | 1 | 22 | — | 1 | probe-confirmed | unknown |
| lostfilm.tv | quic | 23:02:13 | — | — | failed | — | 1 | 72 | 1/1, 51 | 1 | failed | unknown |
| lostfilm.tv | tcp | 23:02:13 | 23:03:33 | 80 с | own-plan | plan-680fbe00 | 1 | 22 | — | 1 | probe-confirmed | unknown |
| mailsuite.com | tcp | 23:02:31 | 23:06:30 | 3 мин 59 с | property | plan-9d543a55 | 4 | 5 | — | — | probe-confirmed,queue-full | unknown |
| nnmclub.to | quic | 23:05:48 | — | — | failed | — | 1 | 74 | 1/1, 51 | 1 | failed | unknown |
| nnmclub.to | tcp | 23:05:48 | 23:05:57 | 9 с | own-plan | plan-680fbe00 | 1 | 4 | — | 1 | probe-confirmed | unknown |
| romfea.gr | quic | 23:02:19 | 23:03:27 | 68 с | own-plan | plan-e0d1dad8 | 1 | 12 | — | — | probe-confirmed | unknown |
| rua.gr | quic | 23:02:14 | 23:03:21 | 67 с | own-plan | plan-389a3920 | 1 | 12 | — | — | probe-confirmed | unknown |
| rutracker.cc | quic | 23:02:16 | 23:03:53 | 97 с | own-plan | plan-389a3920 | 1 | 76 | — | — | probe-confirmed | unknown |
| rutracker.cc | tcp | 23:02:16 | 23:04:26 | 2 мин 10 с | property | plan-680fbe00 | 1 | 23 | — | — | probe-confirmed | unknown |
| rutracker.org | quic | 23:02:12 | 23:03:39 | 87 с | own-plan | plan-389a3920 | 1 | 73 | — | — | probe-confirmed | unknown |
| rutracker.org | tcp | 23:02:12 | 23:03:48 | 96 с | own-plan | plan-680fbe00 | 2 | 8 | — | — | probe-confirmed,queue-full | unknown |
| spzh.eu | quic | 23:02:23 | 23:03:38 | 75 с | property | plan-e0d1dad8 | 1 | 13 | — | — | probe-confirmed | unknown |

Итого строк по пути: failed=5, none=1, own-plan=13, property=6
Время до подтверждения зондом: медиана 75 с, максимум 239 с, n=19
