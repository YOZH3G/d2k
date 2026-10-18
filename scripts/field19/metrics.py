#!/usr/bin/env python3
# metrics.py <run-dir> [<run-dir> ...] : одинаковые метрики журнала d2kc для
# сравнения сборок одним и тем же полевым прогоном (round-clear.sh).
# Окно — от t0 прогона до конца журнала, который снял round-clear.sh.
import re
import sys
from collections import Counter

SITES = ["rutracker.org", "fost.club", "nnmclub.to", "www.fast-torrent.ru",
         "lostfilm.tv", "kinozal.me", "bible-center.ru", "ru.numista.com",
         "rua.gr", "enimerosi.com", "romfea.gr", "katzauction.com", "spzh.eu",
         "flibusta.is", "web.facebook.com", "adguard.com", "mailsuite.com",
         "cloudflare.com", "speed.cloudflare.com"]
OUT = re.compile(r"^(\d\d:\d\d:\d\d) итог поиска: search=\d+ target=(\S+) "
                 r"protocol=(\w+) family=(\d) outcome=(\S+) path=(\S+) "
                 r"probe_units=(\d+).*elapsed_ms=(\d+)")


def secs(t):
    h, m, s = t.split(":")
    return int(h) * 3600 + int(m) * 60 + int(s)


def run(d):
    lines = open(f"{d}/d2kc.log", encoding="utf-8", errors="replace").read().splitlines()
    t0, rid = open(f"{d}/t0.txt").read().split()[:2]
    # Журнал многодневный: round-clear.sh отбирает строки по времени строкой,
    # и вчерашние строки позже t0 попадают внутрь. Прогон — хвостовой кусок
    # журнала, где время не меньше t0.
    # Граница вчерашнего куска — последний скачок времени назад.
    k, nxt = len(lines), None
    while k > 0:
        t = lines[k - 1][:8]
        if re.match(r"\d\d:\d\d:\d\d", t):
            if t < t0 or (nxt is not None and t > nxt):
                break
            nxt = t
        k -= 1
    lines = lines[k:]
    times = [line[:8] for line in lines if re.match(r"\d\d:\d\d:\d\d", line)]
    span = secs(times[-1]) - secs(times[0]) if times else 0
    outs = [m.groups() for m in map(OUT.match, lines) if m]
    oc = Counter(o[4] for o in outs)
    path = Counter(o[5] for o in outs)
    cf = [o for o in outs if o[1] == "cloudflare-ech.com"]
    canon = [o for o in outs if o[1] in SITES]
    qfull = sum("ограниченная очередь заполнена" in x for x in lines)
    qfull_canon = sum("ограниченная очередь заполнена" in x and
                      any(f" по {s} " in x for s in SITES) for x in lines)
    print(f"== {d.rsplit('/', 1)[-1]}  {rid}  окно {span // 60} мин {span % 60} с")
    print(f"  итогов поиска: {len(outs)}  units всего: {sum(int(o[6]) for o in outs)}")
    print(f"  исходы: {dict(oc.most_common())}")
    print(f"  пути:   {dict(path.most_common())}")
    print(f"  очередь заполнена: {qfull} (по 19 целям: {qfull_canon})")
    print(f"  cloudflare-ech.com: {len(cf)} итогов; "
          f"TCP {sum(o[2] == 'tcp' for o in cf)}, QUIC {sum(o[2] == 'quic' for o in cf)}; "
          f"direct {sum(o[4] == 'probe-direct' for o in cf)}, "
          f"queue-full {sum(o[4] == 'queue-full' for o in cf)}")
    print(f"  по 19 целям: {len(canon)} итогов, "
          f"fallback {sum(o[5] == 'fallback' for o in canon)}, "
          f"confirmed {sum(o[4] == 'probe-confirmed' for o in canon)}")
    for s in SITES:
        mine = [f"{o[2]}/v{o[3]}:{o[4]}:{o[5]}" for o in canon if o[1] == s]
        if mine:
            print(f"    {s:22} {' '.join(mine)}")


for d in sys.argv[1:]:
    run(d.rstrip("/"))
