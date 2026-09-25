# Передача: свежий QUIC ClientHello между arm-вопросами — 25.09.2026

## Что изменено

Оригинальный Go `internal/quicprobe/arms.go:askArms` вызывает `buildInitial`
внутри builder каждого отдельного arm-вопроса. C runtime раньше подавал один
`trigger` на все эти вопросы; нижний транспорт обновлял QUIC CID, но TLS
ClientHello (включая `client_random` и X25519 key share) оставался прежним.

`core/props.c:original_probe` теперь извлекает исходные и контрольные SNI и
для каждого вопроса строит новый Initial через `d2k_quic_probe_initial` — C
порт профиля измерительного `buildInitial`. Неудача извлечения SNI или сборки
считается незаданным/неизмеренным вопросом (`sent=0`), без fallback к старому
снимку. Байт-в-байт сохранённые arm blob/copy count передаются как раньше.

## Регрессия

`core/test_quic_run_order.c` снимает расшифрованный ClientHello на входе
измерительного хука. До правки `make test-quic-run-order` завершался ошибкой:
все arm-вопросы несли одинаковое приветствие, несмотря на различающийся CID.
После правки проверка проходит и видит разные ClientHello.

## Что всё ещё не перенесено

Три параллельные отправки одного arm-вопроса получают отдельные QUIC CID через
`d2k_quic_hello_recid`, но остаются одним TLS ClientHello: random и key share
на этих повторах не создаются заново. Оригинальный `buildInitial` создаёт
ClientHello на каждый повтор. Нельзя считать свежесть QUIC-повторов полностью
закрытой или приписывать этому тесту доказательство всего Run.

Также открыты таймауты/пауза и полный порядок остальных вопросов свойства. Поле,
реальное QUIC-приложение, сквозная установка и приёмка пользователя этой правкой
не проверялись.

## Проверки

- Красный/зелёный: `make test-quic-run-order` — красная проверка повторного
  ClientHello до правки, затем `original Run order: passed`.
- `make test-quic-original-arms test-quichello test-quicprobe
  test-quic-run-order` — все четыре прошли после реализации.
- `make cross` сначала выявил отсутствующие `voice.c`/`stun.c` в cross-link
  рецептах `test_sched` и `d2kc`; рецепты исправлены для обоих CPU и static ARM64.
- После исправления recipes `make cross` прошёл: ARM64 musl и MIPS little-endian
  собираются/линкуются. Это не запуск тестов на целевых CPU и не поле.
- `make d2kc-linux-arm64 d2kc test-quic-original-arms test-quichello
  test-quicprobe test-quic-run-order` — прошли; ARM64 binary собран statically.
- Полный `make check` — все core тесты прошли, включая compose, scheduler и
  измеренное исполнение Plan. Долгие compose/scheduler сценарии завершились;
  полного `make check` нельзя прерывать через первые 1–2 минуты.
- Эти проверки не запускают бинарник на Keenetic и не заменяют Linux wire/lab,
  реальный QUIC app либо полевую приёмку.

Связанный актуальный статус — [MVP_CHECKLIST.md](../../MVP_CHECKLIST.md), QUIC
подпункт «Свежесть каждого QUIC-опыта».
