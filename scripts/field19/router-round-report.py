#!/usr/bin/env python3
"""Отчёт router-round.sh (curl-impersonate на роутере): по каждой цели и входу
(chrome — Chrome 150 с ECH, safari — Safari 26, h3 — HTTP/3, http) обучающие
ответы и контрольный. ok = curl rc 0 и HTTP-код сервера; иначе провал с кодом
curl (28 — таймаут, 35 — TLS, 56 — сброс при приёме, 18 — неполное тело).
Плюс итоги поиска из d2kc.log.
router-round-report.py RUN_DIR [RUN_DIR2 ...]"""
import json, os, re, sys

CURL = {6: "dns", 7: "connect", 18: "неполное тело", 28: "таймаут", 35: "TLS",
        52: "пустой ответ", 55: "отправка", 56: "сброс при приёме", 95: "HTTP/3"}


def load(path):
    rows = {}
    if not os.path.isfile(path):
        return rows
    for line in open(path, errors="replace"):
        parts = line.strip().split(" ", 2)
        if len(parts) < 3:
            continue
        try:
            j = json.loads(re.sub(r'"code":0+(\d)', r'"code":\1', parts[2]))
        except ValueError:
            continue
        rows.setdefault((j.get("name", "?"), j.get("mode", "?")), []).append(j)
    return rows


PORTAL = ("lawfilter", "warning.rt.ru", "blocked", "zapret", "eais", "rkn")


def ok(j):
    # Редирект на страницу блокировки провайдера — провал, а не ответ сайта.
    if any(m in (j.get("loc") or "").lower() for m in PORTAL):
        return False
    return j.get("rc") == 0 and j.get("code", 0) > 0


def verdict(j):
    if ok(j):
        # Ответ сервера, но не страница: 4xx/5xx или уход на проверку. Это не
        # провал обхода и не доказанная загрузка (ревью Astra 17.10) — помечаем.
        weak = j["code"] >= 400 or "challenge" in (j.get("loc") or "").lower()
        return "ok%s %d %s %dB" % ("?" if weak else "", j["code"], j.get("ver", ""),
                                   j.get("size", 0))
    rc = j.get("rc", -1)
    if any(m in (j.get("loc") or "").lower() for m in PORTAL):
        return "FAIL заглушка %s" % j.get("loc")
    err = (j.get("err") or "").strip()
    return "FAIL rc%d %s %dB%s" % (rc, CURL.get(rc, ""), j.get("size", 0),
                                  (" | " + err[:60]) if err else "")


def summary(run):
    out = {"outcomes": 0, "fallback": 0, "units": 0}
    log = os.path.join(run, "d2kc.log")
    if os.path.isfile(log):
        for line in open(log, errors="replace"):
            m = re.search(r"итог поиска: .*?path=(\S+) probe_units=(\d+)", line)
            if m:
                out["outcomes"] += 1
                out["units"] += int(m.group(2))
                out["fallback"] += m.group(1) == "fallback"
    return out


def report(run):
    learn = load(os.path.join(run, "learn.jsonl"))
    control = load(os.path.join(run, "control.jsonl"))
    late = load(os.path.join(run, "late.jsonl"))
    keys = []
    for line in open(os.path.join(run, "targets.txt")).read().split("\n"):
        if line:
            h, modes, _ = line.split("|", 2)
            keys += [(h, m) for m in modes.split(",")]
    res = {}
    for k in keys:
        lv = "".join("+" if ok(j) else "x" for j in learn.get(k, []))
        c = control.get(k, [])
        res[k] = (lv, verdict(c[-1]) if c else "FAIL нет ответа")
        lt = late.get(k, [])
        if lt:
            # «Как в браузере»: тот же сайт через LATE с, каталог не стёрт.
            res[k] = (lv, res[k][1] + " | позже: " + ("ok" if ok(lt[-1]) else verdict(lt[-1])))
    return keys, res


def main(argv):
    runs = argv[1:]
    data = [report(r) for r in runs]
    keys = data[0][0]
    print("цель / вход".ljust(28) + "".join(os.path.basename(r.rstrip("/")).ljust(42) for r in runs))
    fails = [0] * len(runs)
    lfails = [0] * len(runs)
    lruns = [0] * len(runs)
    for k in keys:
        row = ("%s %s" % (k[0][:20], k[1])).ljust(28)
        for i, (_, res) in enumerate(data):
            lv, cv = res.get(k, ("", "—"))
            fails[i] += cv.startswith("FAIL")
            if "| позже:" in cv:
                lruns[i] += 1
                lfails[i] += "| позже: FAIL" in cv
            row += ("%s → %s" % (lv, cv)).ljust(42)
        print(row)
    for i, r in enumerate(runs):
        s = summary(r)
        if lruns[i] == 0:
            late_str = "позже: не измерено"
        elif lruns[i] < len(keys):
            late_str = "позже (неполный %d/%d) провалов %d" % (lruns[i], len(keys), lfails[i])
        else:
            late_str = "позже (как в браузере) провалов %d/%d" % (lfails[i], lruns[i])
        print("%s: контроль провалов %d/%d; %s; итогов %d, "
              "единиц %d, перебор %d" % (
            os.path.basename(r.rstrip("/")), fails[i], len(keys), late_str, s["outcomes"],
            s["units"], s["fallback"]))


if __name__ == "__main__":
    main(sys.argv)
