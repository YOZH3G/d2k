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


def probe_row(j, directory):
    """Decode saved stdout on the report host; never parse JSON with sed."""
    if "probe_file" not in j:
        return j  # historical curl/d2kfetch records
    j = dict(j)
    try:
        filename = j["probe_file"]
        if not isinstance(filename, str) or os.path.basename(filename) != filename:
            raise ValueError("invalid probe filename")
        with open(os.path.join(directory, filename)) as f:
            probe = json.load(f)
        if not isinstance(probe, dict) or probe.get("schema") != 2:
            raise ValueError("unsupported d2kfetch schema (expected 2)")
        if probe.get("name") != j["name"]:
            raise ValueError("probe target differs from index")
        if probe.get("shape") == "dns_failed":
            if j["rc"] != 2 or probe.get("measured") is not False:
                raise ValueError("DNS result contradicts process status")
            j.update(collection_error="dns_failed", measured=False,
                     err="адрес не разрешился", ip=None)
            return j
        if probe.get("shape") != "quic" or probe.get("body_bytes") is not None:
            raise ValueError("expected QUIC stream measurement")
        for key, typ in (("http_status", int),
                         ("response_complete", bool), ("local_refusal", bool),
                         ("measured", bool), ("name_ok", int), ("level", int), ("ip", str)):
            if type(probe.get(key)) is not typ:
                raise ValueError("missing/invalid " + key)
        body = probe.get("body_bytes")
        stream = probe.get("quic_stream_bytes")
        if type(body) is not int and type(stream) is not int:
            raise ValueError("missing byte count")
        j.update(ip=probe["ip"], name_ok=probe["name_ok"], level=probe["level"],
                 response_complete=probe["response_complete"], code=probe["http_status"], size=body if type(body) is int else stream,
                 size_kind="body" if type(body) is int else "stream", ver="3",
                 headers_inspected=probe.get("headers_inspected", False),
                 loc=probe.get("location", ""), err=probe.get("reason", ""),
                 elapsed_ms=probe.get("elapsed_ms"),
                 local_refusal=probe["local_refusal"], measured=probe["measured"],
                 cloudflare_challenge=probe.get("cloudflare_challenge", False))
        if j["rc"] not in (0, 1, 2):
            raise ValueError("d2kfetch exit %s" % j["rc"])
        if j["rc"] == 0 and (not probe["response_complete"] or not probe["measured"]):
            raise ValueError("exit 0 contradicts probe result")
        if j["rc"] == 1 and probe["response_complete"]:
            raise ValueError("exit 1 contradicts complete response")
    except FileNotFoundError:
        j.update(collection_error="missing_probe", measured=False,
                 err="результат зонда не доставлен")
    except (OSError, ValueError, TypeError, KeyError) as e:
        j.update(instrument_error=str(e), measured=False)
    return j


def load(path, errors=None):
    rows = {}
    if not os.path.isfile(path):
        return rows
    with open(path, errors="replace") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            parts = line.strip().split(" ", 2)
            try:
                if len(parts) != 3:
                    raise ValueError("missing record prefix")
                # Historical curl emits HTTP code 000; accept that one legacy form.
                j = json.loads(re.sub(r'"code":0+(\d)', r'"code":\1', parts[2]))
                if not isinstance(j, dict) or not isinstance(j.get("name"), str) or not isinstance(j.get("mode"), str):
                    raise ValueError("missing target")
                j = probe_row(j, os.path.dirname(path))
                if type(j.get("rc")) is not int or type(j.get("code", 0)) is not int:
                    raise ValueError("invalid process/HTTP code")
                if type(j.get("size", 0)) is not int or not isinstance(j.get("err") or "", str):
                    raise ValueError("invalid size/error")
                if not isinstance(j.get("loc") or "", str):
                    raise ValueError("invalid location")
                rows.setdefault((j["name"], j["mode"]), []).append(j)
            except (ValueError, TypeError) as e:
                if errors is not None:
                    errors.append("%s:%d: %s" % (path, number, e))
                else:
                    print("повреждённая строка %s:%d: %s" % (path, number, e), file=sys.stderr)
    return rows


def unmeasured(j):
    return bool(j.get("instrument_error") or j.get("local_refusal") or
                j.get("measured") is False or
                (j.get("instrument") == "d2kfetch" and j.get("rc") not in (0, 1)))


PORTAL = ("lawfilter", "warning.rt.ru", "blocked", "zapret", "eais", "rkn")


def ok(j):
    if unmeasured(j):
        return False
    # Редирект на страницу блокировки провайдера — провал, а не ответ сайта.
    if any(m in (j.get("loc") or "").lower() for m in PORTAL):
        return False
    return j.get("rc") == 0 and j.get("code", 0) > 0


def verdict(j):
    text = result_text(j)
    details = []
    for key in ("ip", "name_ok", "level", "elapsed_ms"):
        if j.get(key) is not None:
            details.append("%s=%s" % (key, j[key]))
    return text + (" [" + ", ".join(details) + "]" if details else "")


def weak(j):
    return ok(j) and (j.get("headers_inspected") is False or
                     j.get("cloudflare_challenge", False) or j["code"] >= 400 or
                     "challenge" in (j.get("loc") or "").lower())


def result_text(j):
    if unmeasured(j):
        return "НЕ ИЗМЕРЕНО: " + str(j.get("instrument_error") or j.get("err") or "локальный отказ")
    if ok(j):
        # Ответ сервера, но не страница: 4xx/5xx или уход на проверку. Это не
        # провал обхода и не доказанная загрузка (ревью Astra 17.10) — помечаем.
        label = "ответ H3 (заголовки не проверены)" if j.get("headers_inspected") is False else "ok?" if weak(j) else "ok"
        return "%s %d %s %dB%s" % (label, j["code"], j.get("ver", ""),
                                      j.get("size", 0), " потока H3" if j.get("size_kind") == "stream" else "")
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


def counts(rows, keys):
    measured = errors = missing = failed = collection = weak_count = 0
    for k in keys:
        records = rows.get(k, [])
        if not records:
            missing += 1
        elif records[-1].get("collection_error"):
            collection += 1
        elif unmeasured(records[-1]):
            errors += 1
        else:
            measured += 1
            failed += not ok(records[-1])
            weak_count += weak(records[-1])
    return measured, errors, missing, failed, collection, weak_count


def report(run):
    errors = []
    learn = load(os.path.join(run, "learn.jsonl"), errors)
    control = load(os.path.join(run, "control.jsonl"), errors)
    late = load(os.path.join(run, "late.jsonl"), errors)
    keys = []
    with open(os.path.join(run, "targets.txt")) as f:
        for line in f:
            if line.strip():
                h, modes, _ = line.strip().split("|", 2)
                keys += [(h, m) for m in modes.split(",")]
    res = {}
    for k in keys:
        lv = "".join("?" if unmeasured(j) else "+" if ok(j) else "x" for j in learn.get(k, []))
        c = control.get(k, [])
        cv = verdict(c[-1]) if c else "НЕ ИЗМЕРЕНО: нет результата"
        lt = late.get(k, [])
        if lt:
            cv += " | позже: " + verdict(lt[-1])
        res[k] = (lv, cv)
    return keys, res, counts(control, keys), counts(late, keys), errors


def main(argv):
    runs = argv[1:]
    data = [report(r) for r in runs]
    keys = list(dict.fromkeys(k for d in data for k in d[0]))
    print("цель / вход".ljust(28) + "".join(os.path.basename(r.rstrip("/")).ljust(42) for r in runs))
    for k in keys:
        row = ("%s %s" % (k[0][:20], k[1])).ljust(28)
        for d in data:
            lv, cv = d[1].get(k, ("", "не запланировано"))
            row += ("%s → %s" % (lv, cv)).ljust(42)
        print(row)
    for r, d in zip(runs, data):
        s = summary(r)
        n = len(d[0])
        measured, errors, missing, failed, collection, weak_count = d[2]
        lm, le, ln, lf, lc, lw = d[3]
        late_str = "позже: не измерено" if lm + le + lc == 0 else (
            "позже: измерено %d/%d, провалов %d/%d, ошибок инструмента %d, нет результатов %d"
            % (lm, n, lf, lm, le, ln))
        print("%s: контроль измерено %d/%d, провалов %d/%d; ошибок инструмента %d, "
              "нет результатов %d, повреждённых строк %d; %s; итогов %d, единиц %d, перебор %d" % (
                  os.path.basename(r.rstrip("/")), measured, n, failed, measured,
                  errors, missing, len(d[4]), late_str, s["outcomes"], s["units"], s["fallback"]))
        print("  сбоев сбора %d; ответов без доказанной загрузки %d; позже: сбоев сбора %d, слабых ответов %d" % (collection, weak_count, lc, lw))
        for filename in ("t0.txt", "instrument.txt", "collection-error.txt"):
            path = os.path.join(r, filename)
            if os.path.isfile(path):
                with open(path, errors="replace") as f:
                    print("  " + filename + ": " + " | ".join(f.read().splitlines()))
        for error in d[4]:
            print("  ошибка данных: " + error)


if __name__ == "__main__":
    main(sys.argv)
