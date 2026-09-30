# Learned Domain Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Обучать суффиксные области и немедленно применять их планы новым поддоменам без предварительных проб.

**Architecture:** C-модуль обучения сохраняет доказательства/группы в каталоге. Controller синхронизирует суффиксные правила и точечные исключения; datapath выбирает их на первом подходящем потоке без обращения к controller. Панель показывает обученные области вместо разрастания списка CDN-хостов.

**Tech Stack:** C99, существующий JSON catalog и ctl protocol, HTML/CSS/JS панели; локальный versioned PSL.

**Spec:** `docs/superpowers/specs/2026-09-30-learned-domain-groups-design.md`

## Global Constraints

- Нет хардкода сервисов, ручного ввода групп, ИИ/runtime-запросов и нового дерева измерителя.
- Группа действует сразу, без suspect/очереди/verifier для нового поддомена.
- TLS1.2/TLS1.3/QUIC/ECH, IPv4/IPv6, probe_path и ECH-origin не смешиваются.
- Начальная гипотеза: три различных доказанных проблемных имени с одним проверенным планом.
- Максимум64 группы и256 наблюдений; переполнение не стирает отрицательные улики.
- Работать в feat/telegram-tunnel; .impeccable/ и PRODUCT.md не трогать.
- Не запускать Docker; использовать существующие native/cross инструменты.

## Review Focus

- Public/private suffix: общий хостинг не получает одно правило всем арендаторам.
- Исключение/bypass: точный чистый хост не падает обратно на родительскую группу.
- Измерительные марки: wildcard не загрязняет прямые baseline-зонды.
- Фрагментированный hello: группа работает после сборки, не теряет ECH-изоляцию.
- Несовместимые версии controller/datapath: отказ без частичного некорректного sync.

---

### Task 1: Суффиксные границы и обучение

**Files:** Create `core/domain.c`, `core/groups.c`, `core/include/d2k_domain.h`, `core/include/d2k_groups.h`, `core/test_domain.c`, `core/test_groups.c`, `core/data/public_suffix_list.dat`, `scripts/build-psl-index.py`; Modify `core/Makefile`.

**Interfaces:** `d2k_domain_base(const char *name, char out[256])` возвращает0 для допустимого registrable domain, иначе-1. `d2k_domain_member(name, suffix)` проверяет корень/поддомены по границе labels. `d2k_group_key` содержит transport/family/shape/probe_path/ech_origin; `d2k_group_observation` — name/key/plan_id/evidence/time. `d2k_group_learn(state, observation)` возвращает1 при изменении,0 без изменения,-1 при локальной ошибке; `d2k_group_match(state,name,key)` возвращает наиболее узкую активную группу либоNULL.

- [ ] Написать падающие тесты co.uk, private suffix, wildcard/exception, trailing-dot/case, IP, invalid label и неизвестного suffix; один meet не создаёт группу, повтор одного имени не даёт три голоса.
- [ ] Запустить `make -C core test-domain test-groups`, зафиксировать ожидаемые ошибки отсутствующих реализаций.
- [ ] Внести PSL из официального publicsuffix/list с лицензией и SHA256 snapshot; собрать индекс механическим script. Реализовать учёт положительных/чистых/неопределённых наблюдений, снизу-вверх выбор области, порог3 и бюджеты64/256. Нехватка места запрещает новые обобщения, не разрушает прежние.
- [ ] Проверить общий кандидат на трёх именах, разные контексты, clean-соседа, freeze при overflow; `test-domain test-groups` должны exit0. Коммит `[Sol]`.

### Task 2: Сохранение обучения

**Files:** Modify `core/include/d2k_catalog.h`, `core/catalog.c`, `core/test_catalog.c`; add `core/test_groups_catalog.c`, Makefile target `test-groups-catalog`.

**Interfaces:** Каталог владеет `d2k_group_state`; load/save/free включают optional `domain_groups` и `domain_observations`. Группы ссылаются на существующий plan_id; отсутствующий/выключенный план не активируется. Старый JSON без новых полей сохраняет точные привязки как есть.

- [ ] Написать падающий roundtrip: группа/отрицательная улика/исключение/контексты переживают save/load; старые level3 не становятся BLOCKED_CONFIRMED автоматически.
- [ ] Добавить ограниченный parser/writer/free. Тестировать malformed/oversized/unknown enum, dangling plan, выделения при ошибке и полный unknown-old JSON.
- [ ] `make -C core test-catalog test-groups-catalog` exit0; sanitizer новой модели без утечек. Коммит `[Sol]`.

### Task 3: Суффиксное исполнение и ctl

**Files:** Modify `datapath/plans.c`, `datapath/include/d2k_plans.h`, `datapath/include/d2k_ctl.h`, `datapath/ctlsrv.c`, `datapath/session.c`, `core/link.c`, `core/include/d2k_link.h`, tests plans/ctl/session/link.

**Interfaces:** `d2k_plantab_set_suffix_family(tab,name,len,now_ns,plan,shape,family)` принимает ownership плана на успехе по существующей convention; `d2k_plantab_del_suffix_family(tab,name,len,transport,shape,family)` удаляет только этот ключ. `d2k_plantab_set_bypass_family(tab,name,len,transport,shape,family)` — точное явное исключение. Добавить SET_SUFFIX/DEL_SUFFIX/SET_BYPASS/DEL_BYPASS и helpers link с теми же полями. SET_SUFFIX wire: length/name/shape/family/TLV; delete/bypass: length/name/transport/shape/family. Использовать свободные номера после сверки enum, не менять смысл старых команд.

- [ ] Падающие тесты: ранее не виденный rr получает план сразу, без нового slot на имя; evilgooglevideo.com не совпадает; exact override/bypass выше suffix; самый длинный suffix побеждает; root coverage явно включена.
- [ ] Добавить отдельную ограниченную таблицу групп без malloc на пакетном пути. Ownership/free/revision и ошибки ACK покрываются тестами. Exact trial выше точного правила и группы; baseline-mark пакеты обходят постоянные правила как прежде.
- [ ] Включить matcher в обычный и stream-candidate lookup. Тестировать fragmented modern/legacy/ECH, IPv6 и QUIC; no-SNI не наследует по CDN-IP.
- [ ] `make -C datapath test-plans test-ctl test-session test-quic-session` и `make -C core test-link` exit0. Несовместимый ctl должен явно отказать, не отправлять ложное подтверждение. Коммит `[Sol]`.

### Task 4: Обучение из реальных исходов и lifecycle

**Files:** Modify `core/sched.c`, `core/include/d2k_sched.h`, `core/test_sched.c`, `core/test_catalog_sync.c`.

**Interfaces:** Существующие точки `verify_confirm`, ветка CLEAR и `d2k_sched_sync_step` вызывают Task1/2. BLOCKED_CONFIRMED получает только доказанную блокировку и собственный APPLIED плюс принятый прикладной verifier; DIRECT_CLEAR — успешный прямой опыт, не один внешний TLS record. При формировании группы controller синхронизирует suffix; новый член не создаёт задачу или запись каталога от факта наследования.

- [ ] Падающий сценарий3 целей обучает группу; четвёртая проходит first-flow без вызова measure/verify; после нового sched+sync пятая также проходит немедленно.
- [ ] Подключить исходы, атомарное сохранение и очередной sync. Не превращать исторический успех кандидата без block proof в учебный голос. Не добавлять фоновое массовое измерение.
- [ ] На фактическом suspect/refused наследованного плана использовать прежнюю точную диагностику; результаты создают точный override/bypass, не DEL_SUFFIX. Inconclusive/transient не стирает группу. Повторяемый отказ сужает область с учётом отрицательных улик.
- [ ] Прогоны `test-sched test-catalog-sync test-groups` exit0: clean sibling, исключение, обновление плана, неполный hello, wrong-family, shutdown при trial и сохранность чужих привязок. Коммит `[Sol]`.

### Task 5: Отображение групп

**Files:** Modify `core/sched.c` live JSON writer, `internal/web/assets/panel.js`, `internal/web/assets/panel.css`, `panel/test_ui.cjs`, `panel/test_server.c`.

**Interfaces:** Optional knowledge.groups: suffix/context/plan_id/evidence_count/exceptions. Отсутствующее поле обратно совместимо. Карточка области не перечисляет каждый наследованный CDN-хост и не называет их независимо подтверждёнными. Исключения и активные поиски остаются видимы.

- [ ] Написать UI-тест группы+исключения, old snapshot, пустого/некорректного JSON, escaping имени и сохранности кнопок управления.
- [ ] Реализовать минимальное представление в существующем дизайне, без новых библиотек/картинок. Точные учебные свидетельства не дублировать в основном списке, раскрывать деталями.
- [ ] Запустить существующие panel UI/server tests по текущему Makefile; проверить rendered панель. Коммит `[Sol]`.

### Task 6: Сборка и полевая приёмка

**Files:** Existing builds/scripts; результаты в существующем field-файле либо одном новом кратком отчёте.

- [ ] Проверить полные `core/datapath/panel` checks и переносимость ARM64/MIPS/MIPSEL существующими инструментами. Собрать runtime из текущего HEAD без Docker.
- [ ] Подготовить проверенный restore старых бинарников/catalog и независимый ограниченный watchdog. Deploy согласованных CT/DP/panel; network rules/DNS вне scope. Не принимать таймер поздним marker.
- [ ] Установить автообученную группу только через реальные наблюдения, не ручное wildcard-правило. Захватить первый подходящий поток нового члена: план применён без предыдущих probes, записи отдельного хоста и полного замера. Сравнить задержку с прежними минутами из журнала.
- [ ] Проверить restart+ещё новый хост, точечное исключение и изоляцию контекстов; Google/Яндекс, YouTube TLS1.2/TLS1.3/HTTP3, Instagram и RuTracker. При проблеме restore; никакого скрытого сброса остальных обходов.
- [ ] Зафиксировать ограничения, значения бюджетов и измеренный эффект; коммит сборок/результатов `[Sol]`, push feat/telegram-tunnel. Goal закрывается только после сквозной проверки, не по количеству коммитов.
