#!/usr/bin/env python3
"""Сводка полевого прогона по журналу d2kc: цель → путь → стоимость → время.

Инструмент координатора, не продуктовый runtime. Читает журнал d2kc (как его
отдаёт `logread`/файл службы, с NUL-байтами и обрезанными строками) и печатает
таблицу Markdown: для каждой цели и протокола — первое упоминание, первое
ПОДТВЕРЖДЕНО собственным зондом, полное время между ними, путь находки
(property / own-plan / fallback), число поисков, единицы зондов, опыты
запасного QUIC-перебора, десятиминутные штрафы «результат неубедителен».

Подтверждение зондом — это НЕ успех живого потока: колонка live всегда
unknown, пока журнал не даёт живого критерия. Время считается от первого
упоминания цели в журнале, а не от допуска очередного поиска, поэтому
cooldown и очередь входят в него.

Понимает старые строки (прогон 11.10j) и строку «итог поиска» (3d67d66).

    scripts/field-table.py d2kc.log [--sites rutracker.org fost.club ...]
                                    [--no-h3 имя,имя | --no-h3-file файл]

`--no-h3` — ОПРОВЕРГАТЕЛЬ ДЛЯ УЧЁТА, а не новый зонд. Если цель не объявляет
h3, то долг по QUIC, записанный на неё, беспредметен: браузер туда по QUIC не
пойдёт. Такая строка quic помечается в таблице и НЕ идёт в «Долг замера».
Список приходит ТОЛЬКО извне, из прочитанного alt-svc: в коде его нет, по имени
он не угадывается, и без аргумента поведение таблицы не меняется ни в чём.
Пример и измеренные 12.10.2026 числа — docs/design/2026-10-12-alt-svc-disprover.md.
"""
import argparse
import re
import sys
from collections import OrderedDict

TS = r"(\d\d):(\d\d):(\d\d)"
RE_PO = re.compile(r"^" + TS + r" по (\S+)")
RE_HTTP = re.compile(r"^" + TS + r" HTTP (\S+?):")
RE_PROTO = re.compile(r"^" + TS + r" по (\S+) \((TCP|QUIC)\)")
RE_CONF = re.compile(r"\((TCP|QUIC)\) ПОДТВЕРЖДЕНО собственным зондом: (\S+) \(путь: ([^)]+)\)")
RE_FB = re.compile(r"\(QUIC\) плечо (подобрано|не нашлось) за (\d+) опыт")
RE_PENALTY = re.compile(r"результат неубедителен — повторный замер отложен|новый поиск отложен на 10 мин")
RE_DIRECT = re.compile(r"прямой замер не подтвердил блокировку \(([^:]+):")
RE_HTTP_FOUND = re.compile(r"обход найден — «([^»]+)»")
RE_SUMMARY = re.compile(r"итог поиска: (.*)")
# Строка «итог поиска» не начинается с «по <цель>»: цель берётся из target=.
RE_SUMMARY_TARGET = re.compile(r"^" + TS + r" итог поиска: search=\S+ target=(\S+)")
RE_YIELD = re.compile(r"\(QUIC\) вопрос завершён: уступаю слот")

# ЧТО ЗАМЕР УСПЕЛ СКАЗАТЬ О ЦЕЛИ (12.10.2026). Мерило прогона — не «открылось
# 19 из 19», а «19 из 19 ЗАМЕРОМ, перебора нуль»: каждая цель, ушедшая в
# перебор, это отчёт о том, чего классификатор ещё не знает. Чтобы отчёт был
# читаемым, таблица печатает измеренные признаки класса «отказ после первого
# пакета» (core/quicprobe.c): направление обрыва, ответ контроля коротким
# ответом и на чём сошлись числа остановки. Пусто — замер об этом не сказал
# ничего, и это первое, что надо разбирать.
MEASURED_TAGS = [
    (re.compile(r"наши пакеты (?:до сервера )?не доходят|наше исходящее заглушено"),
     "исходящее-заглушено"),
    (re.compile(r"короткий ответ тоже встал"), "режется-поток"),
    (re.compile(r"короткий ответ дошёл, сошлись и байты, и пакеты"), "байты+пакеты"),
    (re.compile(r"короткий ответ дошёл, сошлись байты"), "байты"),
    (re.compile(r"короткий ответ дошёл, сошлись пакеты"), "пакеты"),
    (re.compile(r"короткий ответ дошёл, не сошлись"), "величина-не-повторяется"),
    (re.compile(r"сервер молчит: два PING без ответа"), "тишина-обе-стороны"),
]

# ALT-SVC КАК ОПРОВЕРГАТЕЛЬ (12.10.2026). Проактивно спрашивать по QUIC из-за
# alt-svc НЕ НАДО: поиски QUIC и так ограничены наблюдённым трафиком (в прогоне
# j строки quic есть ровно у тех имён, чей QUIC шёл по проводу, а у flibusta.is
# и www.tampermonkey.net их нет вовсе), а добавлять работу по заголовку — это
# ровно то, что запрещает §0 ТЗ: «рабочий прямой трафик не запускает подбор».
# Полезно обратное направление: заголовок ОПРОВЕРГАЕТ ДОЛГ. Нет h3 — нет и
# предмета у записанного на цель долга по QUIC.
#
# ФАКТ ВНЕШНИЙ И СКОРОПОРТЯЩИЙСЯ, поэтому только аргументом, никогда из кода:
#   * alt-svc живёт ma секунд и может появиться позже — «не объявляет» верно
#     на момент чтения, а не навсегда;
#   * он приходит ВНУТРИ TLS, то есть его читает свой зонд, а датапат не видит
#     его вовсе и опираться на него в проводе не может;
#   * он может указывать другой порт (h3=":8443") — тогда QUIC не беспредметен,
#     он просто не на 443.
MOOT_PROTOS = ("quic",)
MOOT_MARK = "(беспредметно: h3 не объявлен)"
MOOT_NOTE = (
    "ВНЕШНИЙ ФАКТ на момент замера: список «h3 не объявляет» задан аргументом, "
    "журнал его не содержит, в коде его нет.\n"
    "  alt-svc живёт ma секунд и может появиться позже; приходит внутри TLS "
    "(его читает свой зонд, датапат не видит);\n"
    "  может указывать другой порт (h3=\":8443\") — тогда QUIC не беспредметен, "
    "а идёт не по 443.")
RE_NAME_SEP = re.compile(r"[,\s]+")

PATH_CLASS = {
    "свойство": "property",
    "вывод из замера": "property",
    "приём замера": "property",
    "свой план": "own-plan",
    "перебор": "fallback",
    "RX-лестница": "fallback",
}


def secs(m):
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def hms(t):
    t %= 86400
    return "%02d:%02d:%02d" % (t // 3600, t // 60 % 60, t % 60)


def dur(a, b):
    if a is None or b is None:
        return "—"
    d = b - a
    return "%d с" % d if d < 120 else "%d мин %02d с" % (d // 60, d % 60)


def new_row():
    return {"first": None, "confirmed": None, "plan": None, "path": None,
            "searches": 0, "probe_units": 0, "fb_runs": 0, "fb_failed": 0,
            "fb_trials": 0, "outcomes": [], "yields": 0, "measured": []}


def site_of(name, sites):
    if not sites:
        return name
    for s in sites:
        if name == s or name.endswith("." + s):
            return s
    return None


def load_no_h3(values, path):
    """Имена, которые на момент замера НЕ объявляли h3 в alt-svc.

    Только то, что дал оператор: ни одного имени не добавляется по догадке, по
    зоне или по виду имени. Сравнение ТОЧНОЕ по имени строки таблицы —
    поддомен к сайту не сворачивается: alt-svc читается у origin, и «www.X без
    h3» ничего не говорит про X и про другие имена под X.
    """
    names = []
    for v in values or []:
        names += [x for x in RE_NAME_SEP.split(v) if x]
    if path:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0]
                names += [x for x in RE_NAME_SEP.split(line) if x]
    return list(OrderedDict.fromkeys(n.lower().rstrip(".") for n in names))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log")
    ap.add_argument("--sites", nargs="*", default=None,
                    help="ограничить целями (поддомены сворачиваются к сайту)")
    ap.add_argument("--no-h3", action="append", metavar="ИМЯ[,ИМЯ...]",
                    help="ВНЕШНИЙ ФАКТ: имена, не объявлявшие h3 в alt-svc на "
                         "момент замера. Их строки quic помечаются "
                         "беспредметными и не идут в долг замера. Без "
                         "аргумента поведение не меняется")
    ap.add_argument("--no-h3-file", metavar="ФАЙЛ",
                    help="тот же список файлом: имя на строку, «#» — коммент")
    a = ap.parse_args()
    no_h3 = load_no_h3(a.no_h3, a.no_h3_file)

    def is_moot(site, proto):
        return bool(no_h3) and proto in MOOT_PROTOS and site.lower() in no_h3

    raw = open(a.log, "rb").read().replace(b"\0", b"")
    lines = raw.decode("utf-8", "replace").splitlines()

    rows = OrderedDict()      # (site, proto) -> row
    first = {}                # site -> first mention seconds
    penalty = {}              # site -> count
    direct = {}               # site -> last direct verdict text
    day = 0
    last_t = None

    def row(site, proto):
        return rows.setdefault((site, proto), new_row())

    for line in lines:
        m = RE_PO.match(line) or RE_HTTP.match(line) or RE_SUMMARY_TARGET.match(line)
        if not m:
            continue
        t = secs(m)
        if last_t is not None and t + 3600 < last_t:
            day += 86400          # журнал перешёл полночь
        last_t = t
        t += day
        site = site_of(m.group(4), a.sites)
        if not site:
            continue
        first.setdefault(site, t)
        is_http = line[9:13] == "HTTP"
        pm = RE_PROTO.match(line)
        proto = "http" if is_http else (pm.group(5).lower() if pm else None)

        # Признаки замера собираются со ВСЕХ строк цели: они приходят и в
        # причине вердикта, и в трассе шага плеча, и строка при этом может
        # нести ещё и подтверждение — поэтому не continue.
        for rx, tag in MEASURED_TAGS:
            if rx.search(line):
                r = row(site, proto or "quic")
                if tag not in r["measured"]:
                    r["measured"].append(tag)

        c = RE_CONF.search(line)
        if c:
            r = row(site, c.group(1).lower())
            if r["confirmed"] is None:
                r["confirmed"], r["plan"] = t, c.group(2)
                r["path"] = PATH_CLASS.get(c.group(3), c.group(3))
            continue
        f = RE_FB.search(line)
        if f:
            r = row(site, "quic")
            r["fb_runs"] += 1
            r["fb_trials"] += int(f.group(2))
            if f.group(1) == "не нашлось":
                r["fb_failed"] += 1
            elif r["confirmed"] is None:
                r["confirmed"], r["path"] = t, "fallback"
            continue
        if RE_PENALTY.search(line):
            penalty[site] = penalty.get(site, 0) + 1
            continue
        d = RE_DIRECT.search(line)
        if d:
            direct[site] = d.group(1)
            continue
        if RE_YIELD.search(line):
            row(site, "quic")["yields"] += 1
            continue
        h = RE_HTTP_FOUND.search(line) if is_http else None
        if h:
            r = row(site, "http")
            if r["confirmed"] is None:
                r["confirmed"], r["plan"], r["path"] = t, h.group(1), "property"
            continue
        s = RE_SUMMARY.search(line)
        if s:
            kv = dict(p.split("=", 1) for p in s.group(1).split() if "=" in p)
            r = row(site, kv.get("protocol", proto or "?"))
            r["searches"] += 1
            try:
                r["probe_units"] += int(kv.get("probe_units", "0"))
            except ValueError:
                pass
            r["outcomes"].append(kv.get("outcome", "?"))
            if r["path"] is None and kv.get("path") not in (None, "none"):
                r["path"] = kv["path"]

    # Цели без единого события поиска — только прямой вердикт.
    for site in first:
        if not any(k[0] == site for k in rows) and site in direct:
            row(site, "?")

    print("| Цель | Протокол | Первое | Подтверждено зондом | Время | Путь | План |"
          " Поисков | Ед. зондов | QUIC-перебор (провал/всего, опытов) |"
          " Штрафов 10 мин (цель) | Замер сказал | Исходы | live |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    count = {}
    moot = []
    for (site, proto), r in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        f0 = first.get(site)
        if is_moot(site, proto):
            moot.append((site, proto, r))
            proto = proto + " " + MOOT_MARK
        path = r["path"] or ("failed" if r["fb_failed"] and not r["confirmed"] else
                             ("direct:" + direct[site] if site in direct and not r["confirmed"] else "none"))
        if r["confirmed"] is None and "failed" in r["outcomes"] and "probe-confirmed" not in r["outcomes"]:
            path = "failed"
        count[path.split(":")[0]] = count.get(path.split(":")[0], 0) + 1
        fb = "%d/%d, %d" % (r["fb_failed"], r["fb_runs"], r["fb_trials"]) if r["fb_runs"] else "—"
        outs = ",".join(sorted(set(r["outcomes"]))) or "—"
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | unknown |" % (
            site, proto, hms(f0) if f0 is not None else "—",
            hms(r["confirmed"]) if r["confirmed"] is not None else "—",
            dur(f0, r["confirmed"]), path, r["plan"] or "—",
            r["searches"] or "—", r["probe_units"] or "—", fb,
            penalty.get(site, 0) or "—", ",".join(r["measured"]) or "—", outs))
    print()
    print("Итого строк по пути: " + ", ".join("%s=%d" % kv for kv in sorted(count.items())))
    # ДОЛГ КЛАССИФИКАТОРА, НАЗВАННЫЙ ЧИСЛОМ. Цель, взятая перебором или не
    # взятая вовсе, и есть то, чего замер не смог; рядом печатается, что он
    # всё-таки успел измерить, — с этого и начинается следующий разбор.
    # Беспредметная строка в долг НЕ идёт: у цели без h3 долга по QUIC нет.
    debt = [(s, p, r) for (s, p), r in sorted(rows.items())
            if ((r["path"] or "") .startswith("fallback") or r["path"] in (None, "none")
                or (r["confirmed"] is None)) and not is_moot(s, p)]
    if debt:
        print()
        print("Долг замера (%d из %d строк%s) — цели, которые замер не закрыл:" % (
            len(debt), len(rows),
            ", беспредметных %d не в счёт" % len(moot) if moot else ""))
        for s, p, r in debt:
            print("  %s (%s): замер сказал %s; исходы %s" % (
                s, p, ",".join(r["measured"]) or "ничего",
                ",".join(sorted(set(r["outcomes"]))) or "—"))
    if no_h3:
        print()
        if moot:
            # Беспредметно — не значит бесплатно: работа по QUIC уже потрачена
            # на имя, которым браузер по QUIC не ходит. Это отчёт о лишнем
            # зонде, а не о долге классификатора.
            print("Беспредметно по QUIC — строк: %d. h3 не объявлен, долга по "
                  "QUIC нет:" % len(moot))
            for s, p, r in moot:
                print("  %s (%s): замер сказал %s; исходы %s; ед. зондов %s — "
                      "работа потрачена, долг не записан" % (
                          s, p, ",".join(r["measured"]) or "ничего",
                          ",".join(sorted(set(r["outcomes"]))) or "—",
                          r["probe_units"] or 0))
        else:
            print("Беспредметно по QUIC: 0 строк — ни по одному имени из списка "
                  "строк quic в журнале нет, опровергать нечего.")
        unseen = [n for n in no_h3 if not any(s.lower() == n for s, _ in rows)]
        if unseen:
            print("  В журнале нет целей: %s — имя сравнивается точно; при "
                  "--sites строка могла свернуться к другому имени." % ", ".join(unseen))
        print("  " + MOOT_NOTE)
    conf = [(first[s], r["confirmed"]) for (s, _), r in rows.items()
            if r["confirmed"] is not None and s in first]
    if conf:
        ds = sorted(b - a for a, b in conf)
        print("Время до подтверждения зондом: медиана %d с, максимум %d с, n=%d"
              % (ds[len(ds) // 2], ds[-1], len(ds)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
