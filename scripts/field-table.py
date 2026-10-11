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
RE_PENALTY = re.compile(r"результат неубедителен — повторный замер отложен")
RE_DIRECT = re.compile(r"прямой замер не подтвердил блокировку \(([^:]+):")
RE_HTTP_FOUND = re.compile(r"обход найден — «([^»]+)»")
RE_SUMMARY = re.compile(r"итог поиска: (.*)")
RE_YIELD = re.compile(r"\(QUIC\) вопрос завершён: уступаю слот")

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
            "fb_trials": 0, "outcomes": [], "yields": 0}


def site_of(name, sites):
    if not sites:
        return name
    for s in sites:
        if name == s or name.endswith("." + s):
            return s
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log")
    ap.add_argument("--sites", nargs="*", default=None,
                    help="ограничить целями (поддомены сворачиваются к сайту)")
    a = ap.parse_args()
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
        m = RE_PO.match(line) or RE_HTTP.match(line)
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
          " Штрафов 10 мин (цель) | Исходы | live |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    count = {}
    for (site, proto), r in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        f0 = first.get(site)
        path = r["path"] or ("failed" if r["fb_failed"] and not r["confirmed"] else
                             ("direct:" + direct[site] if site in direct and not r["confirmed"] else "none"))
        count[path.split(":")[0]] = count.get(path.split(":")[0], 0) + 1
        fb = "%d/%d, %d" % (r["fb_failed"], r["fb_runs"], r["fb_trials"]) if r["fb_runs"] else "—"
        outs = ",".join(sorted(set(r["outcomes"]))) or "—"
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | unknown |" % (
            site, proto, hms(f0) if f0 is not None else "—",
            hms(r["confirmed"]) if r["confirmed"] is not None else "—",
            dur(f0, r["confirmed"]), path, r["plan"] or "—",
            r["searches"] or "—", r["probe_units"] or "—", fb,
            penalty.get(site, 0) or "—", outs))
    print()
    print("Итого строк по пути: " + ", ".join("%s=%d" % kv for kv in sorted(count.items())))
    conf = [(first[s], r["confirmed"]) for (s, _), r in rows.items()
            if r["confirmed"] is not None and s in first]
    if conf:
        ds = sorted(b - a for a, b in conf)
        print("Время до подтверждения зондом: медиана %d с, максимум %d с, n=%d"
              % (ds[len(ds) // 2], ds[-1], len(ds)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
