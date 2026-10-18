#!/usr/bin/env python3
"""Сводка полевых прогонов по версиям: для каждого из 19 сайтов — когда найден
первый подтверждённый план (с от t0, отдельно TCP/QUIC), провалы и переборы;
по прогону — итоги, переборы, единицы зондов, самая длинная пауза журнала
контроллера, curl против VPS. Только чтение готовых журналов.

runs-audit.py [ROOT] [--window S] [--json OUT]
"""
import json, os, re, sys

ROOT = "/Library/Zapret2/d2k-field-runs"
WINDOW = 300
SITES = [
    ("rutracker", ["rutracker.org"]),
    ("fost", ["fost.club"]),
    ("nnmclub", ["nnmclub.to"]),
    ("fast-torrent", ["www.fast-torrent.ru", "media5.cdnbase.com"]),
    ("lostfilm", ["lostfilm.tv", "www.lostfilm.tv"]),
    ("kinozal", ["kinozal.me"]),
    ("bible-center", ["bible-center.ru", "www.bible-center.ru"]),
    ("numista", ["ru.numista.com"]),
    ("rua", ["rua.gr"]),
    ("enimerosi", ["enimerosi.com", "cdn.enimerosi.com", "cdnb.enimerosi.com"]),
    ("romfea", ["romfea.gr", "www.romfea.gr"]),
    ("katz", ["katzauction.com"]),
    ("spzh", ["spzh.eu"]),
    ("flibusta", ["flibusta.is"]),
    ("facebook", ["web.facebook.com", "www.facebook.com"]),
    ("adguard", ["adguard.com"]),
    ("mailsuite", ["mailsuite.com"]),
    ("cloudflare", ["cloudflare.com", "www.cloudflare.com"]),
    ("speed-cf", ["speed.cloudflare.com"]),
    ("cf-ech", ["cloudflare-ech.com"]),
]
TS = re.compile(r"^(\d\d):(\d\d):(\d\d) ")
OUT = re.compile(r"итог поиска: .*?target=(\S+) protocol=(\S+) .*?outcome=(\S+) path=(\S+) probe_units=(\d+)")
CONF = re.compile(r"по (\S+) \((TCP|QUIC|HTTP)[^)]*\) ПОДТВЕРЖДЕНО")
HTTPOK = re.compile(r"HTTP (\S+): обход найден")


def secs(h, m, s):
    return int(h) * 3600 + int(m) * 60 + int(s)


def site_of(name):
    for key, names in SITES:
        if name in names:
            return key
    return None


def audit(run):
    t0f = os.path.join(run, "t0.txt")
    logf = os.path.join(run, "d2kc.log")
    if not (os.path.isfile(t0f) and os.path.isfile(logf)):
        return None
    lines = open(t0f, errors="replace").read().split("\n")
    m = TS.match(lines[0] + " ")
    if not m:
        return None
    t0 = secs(*m.groups())
    rel = lines[1].strip() if len(lines) > 1 else "?"
    res = {"run": os.path.basename(run.rstrip("/")), "release": rel, "t0": lines[0].strip(),
           "sites": {k: {"tcp": None, "quic": None, "http": None, "failed": 0, "fallback": 0,
                         "fb_ok": 0} for k, _ in SITES},
           "outcomes": 0, "fallback": 0, "units": 0, "max_gap": 0, "gap_at": ""}
    prev = None
    for raw in open(logf, errors="replace"):
        m = TS.match(raw)
        if not m:
            continue
        t = secs(*m.groups())
        if t < t0:
            t += 86400 if t0 - t > 43200 else 0
        rel_t = t - t0
        if rel_t < 0 or rel_t > WINDOW:
            continue
        if prev is not None and t - prev > res["max_gap"]:
            res["max_gap"], res["gap_at"] = t - prev, raw[:8]
        prev = t
        o = OUT.search(raw)
        if o:
            name, proto, outcome, path, units = o.groups()
            res["outcomes"] += 1
            res["units"] += int(units)
            if path == "fallback":
                res["fallback"] += 1
            k = site_of(name)
            if k:
                s = res["sites"][k]
                if outcome == "failed":
                    s["failed"] += 1
                if path == "fallback":
                    s["fallback"] += 1
                    if outcome.endswith("confirmed"):
                        s["fb_ok"] += 1
                if outcome.endswith("confirmed"):
                    p = "quic" if proto == "quic" else "tcp"
                    if s[p] is None:
                        s[p] = rel_t
            continue
        c = CONF.search(raw)
        if c:
            k = site_of(c.group(1))
            if k:
                p = {"TCP": "tcp", "QUIC": "quic", "HTTP": "http"}[c.group(2)]
                if res["sites"][k][p] is None:
                    res["sites"][k][p] = rel_t
            continue
        h = HTTPOK.search(raw)
        if h:
            k = site_of(h.group(1))
            if k and res["sites"][k]["http"] is None:
                res["sites"][k]["http"] = rel_t
    curl = {}
    cf = os.path.join(run, "curl2.txt")
    if os.path.isfile(cf):
        for raw in open(cf, errors="replace"):
            parts = raw.rsplit("|", 1)
            if len(parts) == 2:
                curl[parts[1].strip()] = raw.startswith("да")
    res["curl2"] = curl
    return res


def cell(s):
    best = [v for v in (s["tcp"], s["quic"], s["http"]) if v is not None]
    txt = str(min(best)) if best else "-"
    if s["failed"]:
        txt += "f%d" % s["failed"]
    if s["fallback"]:
        txt += "p%d" % s["fallback"]
    return txt


def main(argv):
    global WINDOW
    root, out = ROOT, None
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--window":
            WINDOW = int(args.pop(0))
        elif a == "--json":
            out = args.pop(0)
        else:
            root = a
    runs = []
    for d in sorted(os.listdir(root)):
        r = audit(os.path.join(root, d))
        if r:
            runs.append(r)
    runs.sort(key=lambda r: os.path.getmtime(os.path.join(root, r["run"], "t0.txt")))
    print("сайт".ljust(13) + "".join(r["run"][:10].ljust(11) for r in runs))
    print("версия".ljust(13) + "".join(r["release"].replace("lab-", "")[-10:].ljust(11) for r in runs))
    for k, _ in SITES:
        print(k.ljust(13) + "".join(cell(r["sites"][k]).ljust(11) for r in runs))
    for key in ("outcomes", "fallback", "units", "max_gap"):
        print(key.ljust(13) + "".join(str(r[key]).ljust(11) for r in runs))
    if out:
        json.dump(runs, open(out, "w"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(sys.argv[1:])
