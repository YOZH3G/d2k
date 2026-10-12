#!/usr/bin/env python3
"""quic-proof-margin.py — ЗАПАС ОКНА у прикладного доказательства QUIC.

ЗАЧЕМ ОН ЕСТЬ. Датапат считает поток QUIC вышедшим за рукопожатие по первому
КОРОТКОМУ заголовку от сервера (datapath/session.c, quic_app_proof: старший
бит 0, фиксированный 1, RFC 9000 §17.3). Видит он только начальное окно
очереди — `--connbytes 0:8 --connbytes-dir reply --connbytes-mode packets`
(files/S99d2k:386), то есть первые ВОСЕМЬ обратных датаграмм. Замер 12.10
дал первый короткий заголовок обратной датаграммой НОМЕР 7, пять рукопожатий
из пяти, — запас в ОДИН пакет. Но все пять были Google и Apple. Сервер с
длинной цепочкой сертификатов, другой стек или переупорядочивание выталкивают
короткий заголовок за восьмую датаграмму, и тогда здоровый поток даёт ложное
«доказательства нет» (это повод спросить, не вердикт, — но повод ложный).

ЧТО ОН МЕРИТ. По каждому сеансу QUIC настоящего браузера: номер обратной
датаграммы, НЕСУЩЕЙ ПЕРВЫЙ КОРОТКИЙ ЗАГОЛОВОК, и сколько обратных датаграмм
было всего. Считает он ровно то же, что датапат, и это важно в двух местах:
  - ДАТАГРАММЫ, а не пакеты QUIC: counter conntrack считает датаграммы, а в
    одну датаграмму сервер вправе склеить несколько пакетов (RFC 9000 §12.2);
  - ПЕРВЫЙ пакет в датаграмме: датапат читает ОДИН байт по смещению нагрузки
    (session.c:827), поэтому склейка «Handshake + 1-RTT» доказательством НЕ
    становится — первый байт там длинный заголовок. Скрипт берёт первое
    событие заголовка после каждой датаграммы и игнорирует остальные.

ОТКУДА ДАННЫЕ. netlog самого Chrome (`--log-net-log`): события
QUIC_SESSION_PACKET_RECEIVED (одно на принятую датаграмму) и
QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED (header_format =
IETF_QUIC_SHORT_HEADER_PACKET / ..._LONG_...). Не tcpdump: он на macOS требует
sudo, а netlog даёт форму заголовка так, как её разобрал настоящий клиент, и
имя узла сеанса (QUIC_SESSION.host) — без него сеанс не к чему привязать.

ЧЕГО ЭТОТ ЗАМЕР НЕ ЗНАЕТ. Счёт идёт на машине замера, а окно очереди считает
РОУТЕР. Датаграмма, потерянная между роутером и Wi-Fi, роутером посчитана, а
Chrome её не видел: номер на роутере ВСЕГДА больше или равен нашему. Значит
здешний номер — НИЖНЯЯ граница, и «уже здесь больше восьми» доказывает
промах окна, а «здесь семь» его не опровергает. Частоту событий в минуту
живого браузинга этот скрипт тоже не даёт: он даёт её на ЗАГРУЗКУ страницы,
а сколько страниц в минуту открывает человек — не наше измерение.

ЗАПУСК (Chrome настоящий, не headless — §«Поле и UI — только браузерами»):
    python3 scripts/quic-proof-margin.py            # список по умолчанию
    python3 scripts/quic-proof-margin.py nnmclub.to fost.club
    python3 scripts/quic-proof-margin.py --netlog <файл>   # только разбор
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PORT = 9334
WINDOW = 8  # --connbytes 0:8, files/S99d2k:386

# Полевые имена, по которым прогоны j/n видели h3, плюс нарочно ДРУГИЕ стеки
# QUIC и тяжёлые цепочки: окно проверяется не на одном производителе (замер
# 12.10 оттого и остался неполным).
HOSTS = [
    # поле
    "enimerosi.com", "romfea.gr", "katzauction.com", "nnmclub.to", "fost.club",
    "9gag.com", "adguard.com", "rutracker.org", "kinozal.me", "soundcloud.com",
    # другие реализации QUIC
    "www.google.com",          # Google quiche
    "cloudflare-quic.com",     # Cloudflare quiche
    "www.facebook.com",        # mvfst
    "www.litespeedtech.com",   # LiteSpeed lsquic
    "quic.nginx.org",          # nginx
    "nghttp2.org",             # ngtcp2
    "www.microsoft.com",       # msquic
    "www.akamai.com",          # Akamai
    "vk.com", "ya.ru", "mail.ru",  # российские стеки
]


def chrome_get(path):
    with urllib.request.urlopen(f"http://localhost:{PORT}{path}", timeout=10) as r:
        return r.read().decode()


def chrome_put(path):
    req = urllib.request.Request(f"http://localhost:{PORT}{path}", method="PUT")
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode()


def visit(hosts, netlog, dwell=7.0, passes=2):
    """Два прохода: alt-svc Chrome узнаёт ТОЛЬКО из ответа, поэтому по QUIC он
    идёт со второго посещения (та же причина, что в live-protocol.mjs)."""
    profile = tempfile.mkdtemp(prefix="d2k-quic-margin-")
    proc = subprocess.Popen(
        [CHROME, f"--user-data-dir={profile}", "--no-first-run",
         "--no-default-browser-check", f"--remote-debugging-port={PORT}",
         f"--log-net-log={netlog}", "--net-log-capture-mode=everything",
         "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                chrome_get("/json/version")
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("Chrome не поднял отладочный порт")
        started = time.time()
        for p in range(passes):
            for h in hosts:
                try:
                    tab = json.loads(chrome_put(f"/json/new?https://{h}/"))
                except Exception as e:
                    print(f"  {h}: вкладка не открылась: {e}", file=sys.stderr)
                    continue
                time.sleep(dwell)
                try:
                    chrome_get(f"/json/close/{tab['id']}")
                except Exception:
                    pass
                print(f"  проход {p + 1}: {h}", file=sys.stderr)
        return time.time() - started
    finally:
        subprocess.run(["osascript", "-e",
                        'tell application "Google Chrome" to quit'],
                       capture_output=True)
        time.sleep(4)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        time.sleep(2)
        shutil.rmtree(profile, ignore_errors=True)


def parse(path):
    """Сеансы QUIC: имя, обратные датаграммы и ДВА номера датаграммы с первым
    коротким заголовком — по двум правилам чтения:

      proof_first — короткий заголовок стоит ПЕРВЫМ пакетом датаграммы. Так
        читала прежняя редакция датапата: один байт по смещению нагрузки.
      proof_any   — короткий заголовок ЕСТЬ в датаграмме, хотя бы и за
        склейкой. Так читает проход по полям Length (session.c,
        quic_server_short_header). Короткий заголовок не несёт длины и обязан
        быть последним (RFC 9000 §12.2), поэтому «есть в датаграмме» и «найдён
        проходом» — одно и то же, пока длины разбираются.

    netlog незакрытого Chrome — обрезанный JSON; хвост достраивается, потому
    что потерять последние события дешевле, чем потерять весь замер."""
    raw = open(path, encoding="utf-8", errors="replace").read()
    if not raw.rstrip().endswith("}"):
        raw = raw.rstrip().rstrip(",") + "]}"
    doc = json.loads(raw)
    types = {v: k for k, v in doc["constants"]["logEventTypes"].items()}
    sess = {}
    for e in doc["events"]:
        name = types.get(e["type"], "")
        sid = e.get("source", {}).get("id")
        if sid is None:
            continue
        if name == "QUIC_SESSION" and e.get("params", {}).get("host"):
            s = sess.setdefault(sid, {})
            s.setdefault("host", e["params"]["host"])
        elif name == "QUIC_SESSION_PACKET_RECEIVED":
            s = sess.setdefault(sid, {})
            s["dgrams"] = s.get("dgrams", 0) + 1
            s["first_in_dgram"] = True
            s.setdefault("peer", e.get("params", {}).get("peer_address"))
        elif name == "QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED":
            s = sess.setdefault(sid, {})
            at = s.get("dgrams", 0)
            if not at:
                continue
            was_first = s.pop("first_in_dgram", False)
            short = "SHORT" in e.get("params", {}).get("header_format", "")
            if short and "proof_any" not in s:
                s["proof_any"] = at
            if short and was_first and "proof_first" not in s:
                s["proof_first"] = at
    return [s for s in sess.values() if s.get("dgrams")]

def report(sessions, seconds, loads):
    rows = sorted(sessions, key=lambda s: (s.get("proof_any") or 10 ** 6,
                                           s.get("host") or ""))
    print(f"\nОкно очереди: первые {WINDOW} обратных датаграмм "
          f"(--connbytes 0:{WINDOW} --connbytes-dir reply)\n")
    print(f"{'имя':34} {'обр.дг':>7} {'первым':>8} {'в склейке':>10} {'в окно':>13}")
    print("-" * 76)
    stat = {"inside": 0, "outside": 0, "never": 0, "saved": 0, "earlier": 0}
    for s in rows:
        any_at, first_at = s.get("proof_any"), s.get("proof_first")
        host = (s.get("host") or "?")[:34]
        if any_at is not None and (first_at is None or any_at < first_at):
            stat["earlier"] += 1        # склейка: проход нашёл раньше
        if any_at is None:
            verdict = "НЕТ ВОВСЕ"
            stat["never"] += 1
        elif any_at <= WINDOW:
            verdict = "да"
            stat["inside"] += 1
            if first_at is None or first_at > WINDOW:
                stat["saved"] += 1      # спасено проходом по склейке
        else:
            verdict = "НЕТ (промах)"
            stat["outside"] += 1
        print(f"{host:34} {s['dgrams']:>7} "
              f"{('дг ' + str(first_at)) if first_at else '—':>8} "
              f"{('дг ' + str(any_at)) if any_at else '—':>10} {verdict:>13}")
    total = len(rows)
    print("-" * 76)
    print(f"сеансов QUIC: {total}; доказательство в окне: {stat['inside']}; "
          f"позже окна: {stat['outside']}; не пришло ни разу: {stat['never']}")
    print(f"проход по склейке нашёл доказательство РАНЬШЕ, чем чтение "
          f"первого байта: {stat['earlier']} сеансов")
    print(f"из них ПЕРЕВЕДЕНО В ОКНО (первым байтом промах, проходом — "
          f"попадание): {stat['saved']}")
    got = sorted(s["proof_any"] for s in rows if s.get("proof_any"))
    if got:
        print(f"номер датаграммы с доказательством: мин {got[0]}, "
              f"медиана {got[len(got) // 2]}, макс {got[-1]}")
        print(f"ЗАПАС ОКНА по худшему наблюдению: {WINDOW - got[-1]} пак.")
    asks = stat["outside"] + stat["never"]
    print(f"\nповодов спросить (доказательства нет к концу окна): {asks} "
          f"на {total} сеансов")
    if loads:
        print(f"то же на загрузку страницы: {asks / loads:.2f} "
              f"({loads} загрузок за {seconds / 60:.1f} мин)")
    print("\nНИЖНЯЯ ГРАНИЦА: роутер считает и потерянные по пути датаграммы, "
          "его номер ≥ нашего (см. шапку).")

def main():
    args = [a for a in sys.argv[1:]]
    netlog = None
    if "--netlog" in args:
        i = args.index("--netlog")
        netlog = args[i + 1]
        del args[i:i + 2]
    hosts = args or HOSTS
    seconds, loads = 0.0, 0
    if netlog is None:
        netlog = os.path.join(tempfile.mkdtemp(prefix="d2k-netlog-"), "n.json")
        print(f"netlog: {netlog}", file=sys.stderr)
        seconds = visit(hosts, netlog)
        loads = len(hosts) * 2
    report(parse(netlog), seconds, loads)


if __name__ == "__main__":
    main()
