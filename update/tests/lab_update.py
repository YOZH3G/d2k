#!/usr/bin/env python3
"""Драйвер лаборатории обновлений D2K (см. scripts/lab-update.sh).

Два режима. На хосте (`orchestrate`) — готовит закрытый контейнер с настоящей
плоской установкой A, переводит её в управляемую подписанным bootstrap-ом A,
снимает образ «после потери питания» и запускает каждый case в своём
контейнере (`--network none`, только loopback; NET_ADMIN/NET_RAW ради
настоящего netfilter; SYS_PTRACE ради strace-инъекций). Внутри контейнера
(`case NAME`) — настоящие бинарники выпуска, настоящий S98/S99, настоящий
HTTPS-feed на 127.0.0.1 с одноразовым ТЕСТОВЫМ ключом.

Единственная подмена — источник сведений о синхронизации часов (seccomp в
update/tests/fault_matrix.c): Docker-VM не считает свои часы
синхронизированными, а менять их запрещено. Стена, монотонные часы и /etc/TZ
настоящие; окно здоровья 120 с идёт по CLOCK_MONOTONIC.

«Перезагрузка» здесь — SIGKILL всех процессов установки, сброс netfilter и
/tmp и повторный запуск init-скриптов. Это не потеря питания на флеш-памяти.
summary.json пишется отдельно от stdout и не содержит секретов.
"""
import argparse, base64, concurrent.futures, hashlib, http.client, http.server, json, os, pathlib, re, shutil, signal, socket, ssl, subprocess, sys, threading, time, urllib.request

ROOT = pathlib.Path('/opt/d2k')
INIT98, INIT99 = '/opt/etc/init.d/S98d2k-update', '/opt/etc/init.d/S99d2k'
FM = '/usr/local/bin/fault_matrix'
FX = pathlib.Path('/fx')
FEED = pathlib.Path('/feed')
EV = pathlib.Path('/evidence')
LAN = '192.168.77.1'
PANEL = f'http://{LAN}:8090'
FEED_PORT = 8443
ROLES = {'dp': ('d2kd.pid', 1), 'core': ('d2k.pid', 2), 'panel': ('d2k-panel.pid', 4), 'tg': ('d2ktg.pid', 8)}
PHASES = {1: 'checking', 2: 'available', 3: 'downloading', 4: 'verifying', 5: 'prepared', 6: 'stopping', 7: 'switching',
          8: 'starting', 9: 'validating', 10: 'committed', 11: 'rolling_back', 12: 'rolled_back', 13: 'recovery_failed'}
HEALTH_MS = 120000


class Fail(Exception):
    pass


def sh(cmd, check=True, timeout=600, env=None, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout, env=env, **kw)
    if check and r.returncode:
        raise Fail(f'command failed ({r.returncode}): {cmd}\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}')
    return r


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def now_ms():
    return int(time.monotonic() * 1000)


# ---------------------------------------------------------------- feed (TLS)
class Feed:
    """Loopback HTTPS: статические файлы выпуска + ловушки для негативных case."""

    def __init__(self):
        self.log, self.hold, self.fault, self.lock = [], {}, {}, threading.Lock()
        FEED.mkdir(exist_ok=True)
        feed = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def do_GET(self):
                path = self.path.lstrip('/')
                entry = {'t': now_ms(), 'path': path, 'bytes': 0, 'status': 0}
                with feed.lock:
                    feed.log.append(entry)
                ev = feed.hold.get(path.rsplit('/', 1)[-1]) or feed.hold.get(path)
                if ev:
                    ev.wait(900)
                fault = feed.fault.get(path.rsplit('/', 1)[-1])
                f = FEED / path
                if fault == 'redirect-http':
                    self.send_response(302); self.send_header('Location', 'http://localhost:8080/' + path)
                    self.send_header('Content-Length', '0'); self.end_headers(); entry['status'] = 302; return
                if not f.is_file():
                    self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers(); entry['status'] = 404; return
                data = f.read_bytes()
                if fault == 'flip':
                    data = bytes([data[0] ^ 1]) + data[1:]
                if fault == 'oversize':
                    data = data + b'\0' * (2 << 20)
                length = len(data)
                if fault == 'truncate':
                    data = data[: length // 2]
                self.send_response(200); self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(length)); self.end_headers()
                half = feed.hold.get('half:' + path.rsplit('/', 1)[-1])
                if half:
                    self.wfile.write(data[: length // 2]); self.wfile.flush(); entry['bytes'] = length // 2
                    half.wait(900)
                    data = data[length // 2:]
                try:
                    self.wfile.write(data); entry['bytes'] += len(data); entry['status'] = 200
                except BrokenPipeError:
                    entry['status'] = -1
                if fault == 'truncate':
                    self.close_connection = True

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(FX / 'TEST-ca.pem'), str(FX / 'TEST-tls-key.pem'))
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', FEED_PORT), H)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def publish(self, rid, sequence, issued=None, expires=None, src=None):
        """Выложить выпуск rid и подписанный указатель канала (ТЕСТОВЫЙ ключ)."""
        src = src or FX / rid
        d = FEED / rid
        d.mkdir(exist_ok=True)
        for name in ('manifest.json', 'manifest.json.sig', 'd2k-runtime-arm64.tar'):
            if not (d / name).exists():
                os.link(src / name, d / name)
        now = int(time.time())
        index = {'schema': 1, 'channel': 'stable', 'sequence': sequence, 'issued_at': issued or now - 30,
                 'expires_at': expires or now + 3600, 'release_id': rid, 'manifest_sha256': sha(src / 'manifest.json')}
        ch = FEED / 'd2k-channel-stable'
        ch.mkdir(exist_ok=True)
        data = json.dumps(index, separators=(',', ':'), sort_keys=True).encode()
        (ch / 'stable.json.new').write_bytes(data)
        sh(['openssl', 'pkeyutl', '-sign', '-inkey', str(FX / 'TEST-signing.pem'), '-rawin', '-in', str(ch / 'stable.json.new'),
            '-out', str(ch / 'stable.json.sig.new')])
        os.replace(ch / 'stable.json.sig.new', ch / 'stable.json.sig')
        os.replace(ch / 'stable.json.new', ch / 'stable.json')
        return index

    def requests(self, suffix=None, since=0):
        with self.lock:
            return [e for e in self.log if e['t'] >= since and (suffix is None or e['path'].endswith(suffix))]


PROBE_IP = '149.154.167.99'  # адрес зонда сторожа Telegram, внутри netns


def probe_server():
    """Заглушка внешнего зонда сторожа (HTTPS 200), ТЕСТОВЫЙ сертификат в CA контейнера."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(FX / 'TEST-probe-cert.pem'), str(FX / 'TEST-probe-key.pem'))
    srv = http.server.ThreadingHTTPServer((PROBE_IP, 443), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------ installation
def read_json(p):
    return json.loads(pathlib.Path(p).read_text())


def manifest_files(rid):
    m = read_json(FX / rid / 'manifest.json')
    return {f['path']: f['sha256'] for p in m['packages'] if p['abi'] == 'arm64' for f in p['files']}, m


def procs():
    """Все процессы: exe, cmdline, start ticks, VmRSS (кБ)."""
    out = {}
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        pid = int(d)
        try:
            exe = os.readlink(f'/proc/{pid}/exe')
        except OSError:
            exe = ''
        try:
            cmd = open(f'/proc/{pid}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace').strip()
            stat = open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()
            rss = 0
            for line in open(f'/proc/{pid}/status'):
                if line.startswith('VmRSS:'):
                    rss = int(line.split()[1])
        except OSError:
            continue
        out[pid] = {'exe': exe, 'cmd': cmd, 'start': int(stat[19]), 'rss_kb': rss}
    return out


def pidfile(name):
    try:
        return int((ROOT / 'run' / name).read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0


def alive(pid):
    return pid > 0 and os.path.isdir(f'/proc/{pid}')


def worker_bin():
    p = ROOT / 'current/d2k-update'
    return str(p) if p.exists() else str(ROOT / 'boot/d2k-update-first')


def cli(*args, check=False, timeout=30):
    r = subprocess.run([worker_bin(), '--root', str(ROOT), *args], capture_output=True, text=True, timeout=timeout)
    try:
        js = json.loads(r.stdout)
    except ValueError:
        js = None
    if check and r.returncode:
        raise Fail(f'd2k-update {args}: rc={r.returncode} {r.stdout[:400]} {r.stderr[:400]}')
    return r.returncode, js


def status():
    rc, js = cli('status')
    return js if js else {'state': 'unavailable', 'phase': 0, 'busy': False, 'current': {'release_id': ''}, 'rc': rc}


def wait_for(pred, timeout, step=0.2, what='condition'):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = status()
        if pred(last):
            return last
        time.sleep(step)
    raise Fail(f'timeout waiting for {what}; last status {json.dumps(last)[:600]}')


def api(method, path, body=None, origin=PANEL, headers=None, timeout=10):
    c = http.client.HTTPConnection(LAN, 8090, timeout=timeout)
    h = {'Content-Type': 'application/json'}
    if origin:
        h['Origin'] = origin
    h.update(headers or {})
    c.request(method, path, body=None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode()), headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        js = json.loads(data)
    except ValueError:
        js = None
    return r.status, js, data


def tcp_open(host, port, timeout=0.05):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def rules_dump():
    lines = []
    for fam in ('iptables', 'ip6tables'):
        for table in ('raw', 'mangle', 'nat', 'filter'):
            r = subprocess.run([fam, '-t', table, '-S'], capture_output=True, text=True)
            lines += [f'{fam} -t {table} {l}' for l in r.stdout.splitlines()]
    return lines


def ipset_dump(own_prefix='d2k_'):
    r = subprocess.run(['ipset', 'save'], capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if own_prefix not in l]


def rid_of(path):
    m = re.search(r'/opt/d2k/releases/([^/ ]+)/', path + '/')
    return m.group(1) if m else None


class Lab:
    def __init__(self, name):
        self.name = name
        EV.mkdir(exist_ok=True)
        self.results = []
        self.notes = []
        self.ids = read_json(FX / 'fixtures.json')
        self.A, self.B = self.ids['A'], self.ids['B']
        self.prepared = read_json('/lab/prepared.json')
        self.feed = None
        self.r0 = self.own = self.ipset0 = None
        self.seq = 10

    # -- результаты ---------------------------------------------------------
    def record(self, case, status, **detail):
        detail = {k: v for k, v in detail.items()}
        self.results.append({'case': case, 'status': status, 'group': self.name, 't_ms': now_ms(), **detail})
        (EV / f'{self.name}.json').write_text(json.dumps(self.results, indent=1, default=str))
        print(f'[{self.name}] {case}: {status} {json.dumps(detail, default=str)[:300]}', flush=True)

    def run_case(self, case, fn, *a, **kw):
        try:
            detail = fn(*a, **kw) or {}
            self.record(case, 'PASS', **detail)
        except Fail as e:
            self.record(case, 'FAIL', error=str(e)[:3000])
        except Exception as e:  # noqa: BLE001 — ошибка драйвера тоже не PASS
            self.record(case, 'FAIL', error='driver exception: ' + repr(e)[:3000])

    # -- «загрузка» установки -----------------------------------------------
    def netns_sentinels(self):
        sh(f'ip link add br0 type dummy 2>/dev/null; ip addr replace {LAN}/24 dev br0; ip addr replace {PROBE_IP}/32 dev br0; ip link set br0 up')
        if not getattr(self, 'probe', None):
            self.probe = probe_server()
        for fam in ('iptables', 'ip6tables'):
            for table, chain in (('mangle', 'PREROUTING'), ('nat', 'POSTROUTING'), ('filter', 'INPUT')):
                sh(f'{fam} -t {table} -N LAB_SENTINEL_{table} 2>/dev/null; {fam} -t {table} -F LAB_SENTINEL_{table}; '
                   f'{fam} -t {table} -A LAB_SENTINEL_{table} -p tcp --dport 9 -j RETURN; '
                   f'{fam} -t {table} -C {chain} -j LAB_SENTINEL_{table} 2>/dev/null || {fam} -t {table} -I {chain} -j LAB_SENTINEL_{table}')
        sh('ipset create lab_sentinel hash:ip 2>/dev/null; ipset add lab_sentinel 203.0.113.9 -exist')

    def reboot(self, start=True, tz=None):
        """SIGKILL всему D2K, сброс netfilter и /tmp, затем init как при загрузке."""
        for pid, p in procs().items():
            if pid == os.getpid():
                continue
            if '/opt/d2k' in p['exe'] or '/opt/d2k' in p['cmd'] or '/opt/sbin/d2k' in p['cmd']:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        time.sleep(0.5)
        for fam in ('iptables', 'ip6tables'):
            for table in ('raw', 'mangle', 'nat', 'filter'):
                sh(f'{fam} -t {table} -F; {fam} -t {table} -X', check=False)
        sh('for s in $(ipset list -n); do ipset destroy $s; done', check=False)
        shutil.rmtree('/tmp/d2k', ignore_errors=True)
        self.netns_sentinels()
        self.r0 = rules_dump()
        self.ipset0 = ipset_dump()
        if tz is not None:
            pathlib.Path('/etc/TZ').write_text(tz + '\n')
        if not self.feed:
            self.feed = Feed()
        if start:
            self.t_boot = now_ms()
            self.s98 = self.init(INIT98, 'start', timeout=400)
            self.s99 = self.init(INIT99, 'start', timeout=300)

    def init(self, script, action, timeout=120):
        """Init-скрипты с выводом в файл: фоновые демоны наследуют stdio, и
        закрытый pipe драйвера убил бы супервизор; журнал остаётся свидетельством."""
        self.boots = getattr(self, 'boots', 0) + 1
        log = EV / f'{self.name}-init-{self.boots}-{os.path.basename(script)}-{action}.log'
        if os.environ.get('D2K_LAB_BOOTLOG') == '1' and os.path.basename(script) == 'S98d2k-update':
            # Отладка: start-stop-daemon -b отдаёт вывод супервизора в /dev/null;
            # dpkg-овский --output направляет его в evidence/boot.log.
            t = pathlib.Path(script).read_text()
            t = t.replace('start-stop-daemon -S -b -m -p', f'start-stop-daemon -S -b --output {EV}/{self.name}-boot.log -m -p')
            pathlib.Path(script).write_text(t)
        with open(log, 'w') as f:
            r = subprocess.run([FM, 'sync-exec', script, action], stdout=f, stderr=subprocess.STDOUT, timeout=timeout)
        r.stdout = log.read_text()[-2000:]
        r.stderr = ''
        return r

    def boot(self, mask=15, tz=None):
        self.reboot(tz=tz)
        if self.s98.returncode:
            raise Fail(f'S98 start failed: {self.s98.stderr[-500:]}')
        if self.s99.returncode:
            raise Fail(f'S99 start failed: {self.s99.stdout[-500:]} {self.s99.stderr[-500:]}')
        wait_for(lambda s: s['state'] != 'unavailable', 30, what='daemon socket')
        self.wait_roles(mask)
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(self.A, mask, 'after-boot')

    def wait_handoff(self, rid, timeout=120):
        """Секунды без сокета, пока супервизор поднимает обновлятор выпуска rid."""
        want = str(ROOT / 'releases' / rid / 'd2k-update')
        return wait_for(lambda s: s['state'] != 'unavailable' and (s.get('current') or {}).get('release_id') == rid
                        and any('--boot-worker' in p['cmd'] and p['exe'] == want for p in procs().values()),
                        timeout, what=f'updater handoff to {rid}')

    def wait_roles(self, mask, timeout=60):
        """Роли стартуют асинхронно после возврата init: дождаться их по маске."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ps = procs()
            if all(alive(pidfile(pf)) and rid_of(ps.get(pidfile(pf), {}).get('exe', '')) for role, (pf, bit) in ROLES.items() if mask & bit):
                time.sleep(1)
                return
            time.sleep(0.3)

    # -- общий оракул ---------------------------------------------------------
    def oracle(self, rid, mask, tag, own=True, updater=True, allow_phase=None):
        """Нет смешанного выпуска; изменены только свои правила; роли по маске."""
        ev = {'tag': tag, 'expect': rid, 'mask': mask, 't_ms': now_ms()}
        problems = []
        cur = os.readlink(ROOT / 'current') if (ROOT / 'current').is_symlink() else None
        ev['current'] = cur
        if cur != f'releases/{rid}':
            problems.append(f'current={cur}')
        files, _ = manifest_files(rid)
        if rid == self.A:
            files = self.prepared['release_files']
        bad = [p for p, h in files.items() if not (ROOT / 'releases' / rid / p).is_file() or sha(ROOT / 'releases' / rid / p) != h]
        if bad:
            problems.append(f'release files differ from signed inventory: {bad[:5]}')
        ps = procs()
        live = {}
        for pid, p in ps.items():
            r = rid_of(p['exe']) or rid_of(p['cmd'])
            if r:
                live.setdefault(r, []).append((pid, p['exe'] or p['cmd'][:80]))
            if '(deleted)' in p['exe'] and '/opt/d2k' in p['exe']:
                problems.append(f'pid {pid} runs a deleted executable {p["exe"]}')
        ev['live_releases'] = {k: len(v) for k, v in live.items()}
        for other in live:
            if other != rid:
                problems.append(f'processes of foreign release {other}: {live[other][:3]}')
        roles = {}
        for role, (pf, bit) in ROLES.items():
            pid = pidfile(pf)
            ok = alive(pid) and rid_of(ps.get(pid, {}).get('exe', '')) == rid
            roles[role] = {'pid': pid, 'alive': alive(pid), 'ok': ok}
            if mask & bit and not ok:
                problems.append(f'role {role} expected alive from {rid}: {roles[role]}')
            if not mask & bit and alive(pid):
                problems.append(f'disabled role {role} is running pid {pid}')
        ev['roles'] = roles
        sup = [pid for pid, p in ps.items() if p['exe'].endswith('/boot/d2k-update-boot') and '--daemon' in p['cmd']]
        wexe = str(ROOT / 'releases' / rid / 'd2k-update')
        if not os.path.exists(wexe):
            wexe = str(ROOT / 'boot/d2k-update-first')
        workers = [pid for pid, p in ps.items() if '--boot-worker' in p['cmd'] and 'sync-exec' not in p['cmd']]
        ev['supervisor'] = sup
        ev['workers'] = [(w, ps[w]['exe']) for w in workers]
        if updater:
            if len(sup) != 1:
                problems.append(f'supervisor count {len(sup)}')
            if len(workers) != 1 or ps[workers[0]]['exe'] != wexe:
                problems.append(f'worker expected {wexe}: {ev["workers"]}')
        st = status()
        ev['status'] = {k: st.get(k) for k in ('state', 'phase', 'busy', 'operation_id', 'last_result', 'last_error')}
        ev['status']['current'] = st.get('current', {}).get('release_id')
        if updater and st.get('current', {}).get('release_id') != rid:
            problems.append(f'status current {st.get("current")}')
        if allow_phase is not None and st.get('phase') not in allow_phase:
            problems.append(f'phase {st.get("phase")} not in {allow_phase}')
        if mask & 4:
            try:
                code, js, _ = api('GET', '/api/status', origin=None)
                ev['panel_http'] = code
                if code != 200:
                    problems.append(f'panel /api/status {code}')
            except OSError as e:
                problems.append(f'panel unreachable: {e}')
        if mask & 3:
            r = sh([INIT99, 'status'], check=False, timeout=60).stdout
            ev['init_status'] = [l.strip() for l in r.splitlines()[1:8]]
            for key in ('датапат: работает', 'контроллер: работает', 'правила: стоят'):
                if key not in r:
                    problems.append(f'init status lacks "{key}"')
        rules = rules_dump()
        missing = [l for l in self.r0 if l not in rules]
        delta = [l for l in rules if l not in self.r0]
        ev['rules_delta'] = len(delta)
        if missing:
            problems.append(f'unrelated sentinel rules changed/missing: {missing[:4]}')
        if own and mask:
            if self.own is not None and sorted(delta) != sorted(self.own):
                extra = [l for l in delta if l not in self.own][:4]
                lost = [l for l in self.own if l not in delta][:4]
                problems.append(f'own rules differ from healthy baseline: extra={extra} lost={lost}')
        elif not own and delta:
            problems.append(f'own interception still present ({len(delta)} rules) {delta[:3]}')
        if ipset_dump() != self.ipset0:
            problems.append('unrelated ipset changed')
        for name, h in self.prepared['personal'].items():
            p = ROOT / name
            if not p.exists() or sha(p) != h:
                problems.append(f'personal file changed: {name}')
        ev['problems'] = problems
        self.notes.append(ev)
        (EV / f'{self.name}-oracle.json').write_text(json.dumps(self.notes, indent=1, default=str))
        if problems:
            raise Fail(f'oracle[{tag}] expecting {rid}/mask {mask}: ' + '; '.join(problems))
        return ev

    # -- действия ---------------------------------------------------------
    def publish(self, rid, **kw):
        self.seq += 1
        return self.feed.publish(rid, self.seq, **kw)

    def check(self, force=True, opid=None):
        args = ['check'] + (['--force'] if force else []) + (['--operation-id', opid] if opid else [])
        for attempt in range(5):
            wait_for(lambda s: not s['busy'], 120, what='idle daemon before check')
            rc, js = cli(*args)
            if rc == 4 and not opid:  # присоединились к чужой проверке (ночная/при старте): подождать и повторить
                wait_for(lambda s: not s['busy'], 120, what='joined check completion')
                continue
            if rc not in (0, 4):
                raise Fail(f'check rc={rc} {js}')
            return wait_for(lambda s: not s['busy'], 120, what='check completion')
        raise Fail('check kept conflicting with another operation')

    def available(self, rid):
        st = self.check()
        av = st.get('available') or {}
        if av.get('release_id') != rid or not av.get('compatible'):
            raise Fail(f'expected available {rid}: {av} state={st["state"]} err={st.get("last_error")}')
        return av

    def install(self, rid, opid=None, via='cli'):
        av = self.available(rid)
        opid = opid or f'lab-{self.name}-{rid[-6:]}-{now_ms()}'
        self.t_install = now_ms()
        if via == 'http':
            code, js, _ = api('POST', '/api/update/install', {'release_id': rid, 'manifest_sha256': av['manifest_sha256'], 'operation_id': opid})
            if code != 202:
                raise Fail(f'install POST {code} {js}')
        else:
            rc, js = cli('install', rid, av['manifest_sha256'], '--operation-id', opid)
            if rc:
                raise Fail(f'install rc={rc} {js}')
        return opid, av

    def wait_phase(self, phases, timeout, step=0.03):
        return wait_for(lambda s: s.get('phase') in phases, timeout, step, what=f'phase in {phases}')

    def wait_terminal(self, timeout=400):
        # После commit обновлятор передаёт работу обновлятору нового выпуска:
        # сокет на секунды пропадает, и «unavailable» — не итог операции.
        # Отказ до остановки служб (сеть, место, подпись) оставляет фазу
        # загрузки с state=error: операция тоже закончена.
        return wait_for(lambda s: s['state'] != 'unavailable' and not s['busy'] and (s.get('phase') in (10, 12, 13, 0) or s['state'] == 'error'),
                        timeout, what='terminal phase')

    def kill_all_updater(self):
        for pid, p in procs().items():
            if p['exe'].endswith('d2k-update-boot') or '--boot-worker' in p['cmd'] or '--boot-probe' in p['cmd']:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        time.sleep(0.3)

    def sampler_start(self):
        self.samples, self.rss, self._stop = [], {}, threading.Event()

        def run():
            tick = 0
            while not self._stop.is_set():
                ps = procs()
                s = {'t': now_ms()}
                for role, (pf, bit) in ROLES.items():
                    pid = pidfile(pf)
                    s[role] = rid_of(ps.get(pid, {}).get('exe', '')) if alive(pid) else None
                s['panel'] = tcp_open(LAN, 8090) and s['panel']
                s['tg_listen'] = tcp_open('127.0.0.1', 1443)
                if tick % 5 == 0:
                    s['rules'] = subprocess.run(['iptables', '-t', 'mangle', '-S', 'D2K_OUT'], capture_output=True).returncode == 0
                    total = 0
                    for pid, p in ps.items():
                        if '/opt/d2k' in p['exe'] and 'fault_matrix' not in p['exe']:
                            key = re.sub(r'/opt/d2k/releases/[^/]+/', 'release/', p['exe'])
                            self.rss[key] = max(self.rss.get(key, 0), p['rss_kb'])
                            total += p['rss_kb']
                    self.rss['__total_max'] = max(self.rss.get('__total_max', 0), total)
                    try:
                        st = status()
                        s['phase'] = st.get('phase')
                    except Exception:  # noqa: BLE001
                        pass
                self.samples.append(s)
                tick += 1
                time.sleep(0.1)
        self.sampler_thread = threading.Thread(target=run, daemon=True)
        self.sampler_thread.start()

    def sampler_stop(self):
        self._stop.set()
        self.sampler_thread.join(5)
        return self.samples

    def downtime(self, samples, t0, mask, new_rid):
        out = {}
        for role, (pf, bit) in ROLES.items():
            if not mask & bit:
                continue
            down = next((s['t'] for s in samples if s['t'] >= t0 and s[role] != self.A), None)
            up = next((s['t'] for s in samples if down and s['t'] >= down and s[role] == new_rid), None)
            out[role] = {'down_at_ms': down - t0 if down else None, 'up_at_ms': up - t0 if up else None,
                         'downtime_ms': up - down if down and up else None}
        down = next((s['t'] for s in samples if s['t'] >= t0 and any(s[r] != self.A for r, (pf, b) in ROLES.items() if mask & b)), None)
        up = next((s['t'] for s in samples if down and s['t'] >= down and all(s[r] == new_rid for r, (pf, b) in ROLES.items() if mask & b)
                   and s.get('panel') and s.get('rules', True)), None)
        out['whole'] = {'down_at_ms': down - t0 if down else None, 'healthy_at_ms': up - t0 if up else None,
                        'downtime_ms': up - down if down and up else None, 'sample_interval_ms': 100}
        return out

    def io_counters(self, pid):
        try:
            return {l.split(':')[0]: int(l.split(':')[1]) for l in open(f'/proc/{pid}/io')}
        except OSError:
            return {}

    # ================================================================= cases
    def case_aba(self):
        self.boot()
        st = status()
        tg_status = (ROOT / 'state/telegram.status').read_text().strip() if (ROOT / 'state/telegram.status').exists() else ''
        self.publish(self.B)
        self.sampler_start()
        (ROOT / 'state/lab-before').write_text('v1\n')
        worker = next(pid for pid, p in procs().items() if '--boot-worker' in p['cmd'] and 'sync-exec' not in p['cmd'])
        io0 = self.io_counters(worker)
        feed_t0 = now_ms()
        opid, av = self.install(self.B, via='http')
        # Отказ панели во время перезапуска не должен ломать клиента: просто читаем состояние.
        st = self.wait_terminal(500)
        t_term = now_ms()
        if st.get('phase') != 10:
            raise Fail(f'install B did not commit: {st}')
        samples = self.sampler_stop()
        # Передача работы обновлятору B: супервизор перезапускает рабочий
        # процесс уже из нового выпуска, это секунды без сокета.
        self.wait_handoff(self.B)
        self.wait_roles(15)
        self.own = [l for l in rules_dump() if l not in self.r0]  # те же правила ожидаются и от B
        ev = self.oracle(self.B, 15, 'B-committed')
        # previous пуст: A положен bootstrap-ом и своего обновлятора не имеет.
        if st['current']['release_id'] != self.B or st.get('previous') is not None:
            raise Fail(f'status after commit: current={st["current"]} previous={st.get("previous")}')
        if st.get('last_installation', {}).get('completed_utc') in (None, 0):
            raise Fail(f'completed_utc missing after live commit: {st.get("last_installation")}')
        # Долговечность по ходу: журнал, prepared-package и персональные файлы.
        reqs = self.feed.requests(since=feed_t0)
        pkg = [r for r in reqs if r['path'].endswith('.tar')]
        meta = {'install_to_commit_ms': t_term - self.t_install, 'feed_requests': len(reqs), 'package_downloads': len(pkg),
                'package_bytes': sum(r['bytes'] for r in pkg), 'tg_status_before': tg_status,
                'worker_io_delta': {k: v - io0.get(k, 0) for k, v in self.io_counters(worker).items()} if alive(worker) else 'worker exited (handoff)',
                'downtime': self.downtime(samples, self.t_install, 15, self.B), 'rss_max_kb': self.rss,
                'phases_seen': sorted({s.get('phase') for s in samples if s.get('phase')})}
        self.record('signed-success-A-B', 'PASS', **meta)
        self.record('active-all', 'PASS', mask_after=int((ROOT / 'update-state/enabled').read_text()), roles=ev['roles'])
        tgs = (ROOT / 'state/telegram.status').read_text().strip() if (ROOT / 'state/telegram.status').exists() else ''
        if tgs == 'connected':
            raise Fail('lab relay is closed; telegram.status must not be connected')
        self.record('relay-down', 'PASS', telegram_status=tgs, tg_listener=tcp_open('127.0.0.1', 1443),
                    note='closed local relay, healthy listener/process: commit happened; no application success claimed')
        self.record('measurements-runtime', 'PASS', **{k: meta[k] for k in ('downtime', 'rss_max_kb', 'package_downloads', 'package_bytes', 'worker_io_delta')})
        # A — выпуск, положенный bootstrap-ом из плоской установки: своего
        # обновлятора у него нет (его обслуживал boot/d2k-update-first, снятый
        # после первого подписанного обновления). Вернуться на него нельзя:
        # статус его не предлагает, ручной откат отказывает до остановки служб.
        prev = st.get('previous')
        if prev:
            raise Fail(f'status offers rollback to a bootstrap release without its own updater: {prev}')
        pids = {r: pidfile(pf) for r, (pf, b) in ROLES.items()}
        rc, js = cli('rollback', self.A, sha(FX / self.A / 'manifest.json'), '--operation-id', f'lab-rb-{now_ms()}')
        st = wait_for(lambda s: s['state'] != 'unavailable' and not s['busy'], 60, what='rollback refusal')
        if st['current']['release_id'] != self.B or not st.get('last_error'):
            raise Fail(f'rollback to bootstrap A was not refused: rc={rc} {js} {st}')
        if {r: pidfile(pf) for r, (pf, b) in ROLES.items()} != pids:
            raise Fail('refused rollback restarted services')
        self.oracle(self.B, 15, 'B-after-refused-rollback')
        self.record('late-rollback-refused', 'PASS', rc=rc, note='bootstrap release A has no updater; nothing stopped')
        self.reboot()
        wait_for(lambda s: s['state'] != 'unavailable', 30)
        self.wait_roles(15)
        self.oracle(self.B, 15, 'B-after-reboot')
        return {'note': 'A->B with real 120 s health window; rollback to bootstrap A refused; B survives reboot'}

    def _install_then(self, phase, action, expect_rid, expect_phase, mask=15, tag='after-action', via='cli', timeout=500):
        self.boot(mask)
        self.publish(self.B)
        opid, av = self.install(self.B, via=via)
        st = self.wait_phase([phase] if isinstance(phase, int) else phase, 240)
        t_action = now_ms()
        info = action(st) or {}
        st = self.wait_terminal(timeout)
        if st.get('phase') != expect_phase:
            raise Fail(f'expected terminal phase {PHASES.get(expect_phase)}: {st}')
        self.wait_roles(mask)
        self.oracle(expect_rid, mask, tag)
        return dict(info, phase_hit=PHASES.get(st.get('phase')), action_phase=PHASES.get(phase if isinstance(phase, int) else phase[0]),
                    terminal_after_ms=now_ms() - t_action, last_error=st.get('last_error'), quarantine=st.get('quarantine'),
                    last_installation=st.get('last_installation'))

    def case_bad_role(self, role, how='kill'):
        def act(st):
            pid = pidfile(ROLES[role][0])
            if not alive(pid):
                raise Fail(f'{role} not running at validating')
            os.kill(pid, signal.SIGKILL if how == 'kill' else signal.SIGSTOP)
            return {'killed_pid': pid, 'signal': how}
        d = self._install_then(9, act, self.A, 12, tag=f'rolled-back-after-{role}-{how}')
        q = d.get('quarantine') or {}
        if not q.get('active'):
            raise Fail(f'quarantine not active after failed B: {q}')
        self.kill_all_updater()  # повторный запуск демона: карантин долговечен
        self.init(INIT98, 'start')
        st = wait_for(lambda s: s['state'] != 'unavailable', 30)
        if not (st.get('quarantine') or {}).get('active') or not st.get('last_installation'):
            raise Fail(f'quarantine/last_installation not retained across daemon restart: {st}')
        return d

    def case_bad_updater(self, how):
        def act(st):
            probe = [pid for pid, p in procs().items() if '--boot-probe' in p['cmd']]
            if not probe:
                raise Fail('no candidate probe at validating')
            os.kill(probe[0], signal.SIGKILL if how == 'kill' else signal.SIGSTOP)
            return {'probe_pid': probe[0], 'signal': how}
        return self._install_then(9, act, self.A, 12, tag=f'rolled-back-after-probe-{how}')

    def case_missing_own_rule(self):
        def act(st):
            rule = next(l for l in self.own if ' -A D2K_OUT ' in l and 'NFQUEUE' in l)
            sh(rule.replace(' -A ', ' -D ', 1))
            return {'deleted_rule': rule}
        return self._install_then(9, act, self.A, 12, tag='rolled-back-after-rule-loss')

    def case_stale_heartbeat(self):
        def act(st):
            pid = pidfile('d2k.pid')
            os.kill(pid, signal.SIGSTOP)
            return {'frozen_controller': pid}
        return self._install_then(9, act, self.A, 12, tag='rolled-back-after-stale-heartbeat')

    def case_inactive_mask(self, action, mask):
        self.boot()
        r = self.init(INIT99, action)
        if r.returncode:
            raise Fail(f'{action} failed: {r.stdout[-300:]}')
        time.sleep(2)
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(self.A, mask, f'A-{action}')
        self.publish(self.B)
        self.install(self.B)
        st = self.wait_terminal(500)
        if st.get('phase') != 10:
            raise Fail(f'install with mask {mask} failed: {st}')
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(self.B, mask, f'B-{action}')
        self.reboot()
        wait_for(lambda s: s['state'] != 'unavailable', 30)
        self.wait_roles(mask)
        self.oracle(self.B, mask, f'B-{action}-after-reboot')
        return {'mask': mask, 'enabled_file': (ROOT / 'update-state/enabled').read_text().strip()}

    def case_boot_phase(self, phase):
        self.boot()
        self.publish(self.B)
        if phase == 3:
            self.feed.hold['half:d2k-runtime-arm64.tar'] = threading.Event()
        self.install(self.B)
        st = self.wait_phase([phase], 300, step=0.01)
        seen = st['phase']
        expect = self.B if phase == 10 else self.A
        self.reboot()
        for ev in list(self.feed.hold.values()):
            ev.set()
        self.feed.hold.clear()
        wait_for(lambda s: s['state'] != 'unavailable', 60)
        st = wait_for(lambda s: not s['busy'], 400)
        self.wait_roles(15)
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(expect, 15, f'after-reboot-from-{PHASES[seen]}')
        # Повторное восстановление идемпотентно.
        self.reboot()
        wait_for(lambda s: s['state'] != 'unavailable', 60)
        self.wait_roles(15)
        self.oracle(expect, 15, f'second-reboot-from-{PHASES[seen]}')
        if phase == 10 and not st.get('last_installation'):
            raise Fail(f'last_installation lost after reboot from committed: {st}')
        return {'interrupted_at': PHASES[seen], 'restored': expect, 'status_phase': PHASES.get(st.get('phase')),
                'last_installation': st.get('last_installation'), 'note': 'SIGKILL of all processes + netfilter/tmp reset, not flash power loss'}

    def case_supervisor_kill(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        sup = [pid for pid, p in procs().items() if p['exe'].endswith('/boot/d2k-update-boot') and '--daemon' in p['cmd']]
        os.kill(sup[0], signal.SIGKILL)
        time.sleep(2)
        workers = [pid for pid, p in procs().items() if '--boot-worker' in p['cmd']]
        r = self.init(INIT98, 'start', timeout=600)
        st = wait_for(lambda s: s['state'] != 'unavailable' and not s['busy'], 400)
        self.wait_roles(15)
        self.oracle(self.A, 15, 'after-supervisor-kill-recovery')
        return {'supervisor_killed': sup[0], 'workers_after_kill': workers, 's98_rc': r.returncode, 'phase': PHASES.get(st.get('phase'))}

    def case_handoff_kill(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([10], 300, step=0.01)
        # Сразу после COMMITTED супервизор заменяет worker на B: убиваем нового.
        time.sleep(1.5)
        for pid, p in procs().items():
            if '--boot-worker' in p['cmd'] and rid_of(p['exe']) == self.B:
                os.kill(pid, signal.SIGKILL)
        time.sleep(3)
        self.kill_all_updater()
        self.init(INIT98, 'start', timeout=600)
        st = wait_for(lambda s: s['state'] != 'unavailable' and not s['busy'], 400)
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(self.B, 15, 'B-after-handoff-kill')
        return {'phase': PHASES.get(st.get('phase'))}

    def _snapshot_opt(self):
        sh('rm -rf /lab/opt-snap; cp -a /opt/d2k /lab/opt-snap')

    def _restore_opt(self):
        sh('rm -rf /opt/d2k; cp -a /lab/opt-snap /opt/d2k')

    def case_boot_recovery_child_kill(self):
        """strace-инъекция: SIGKILL на N-м fsync настоящего --recover, N по всем шагам."""
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        self.kill_all_updater()
        for pid, p in procs().items():
            if '/opt/d2k' in p['exe'] or '/opt/d2k' in p['cmd']:
                os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
        self._snapshot_opt()
        r = sh(['strace', '-f', '-e', 'trace=fsync,fdatasync', '-o', '/tmp/rec-uncut.log', FM, 'sync-exec', ROOT / 'boot/d2k-update-boot', '--root', str(ROOT), '--recover'], check=False, timeout=600)
        total = sum(1 for l in open('/tmp/rec-uncut.log') if 'sync(' in l and 'resumed' not in l)
        if total < 3:
            raise Fail(f'uncut recovery shows only {total} sync calls (rc {r.returncode})')
        results = []
        for n in range(1, total + 1):
            self.reboot(start=False)
            self._restore_opt()
            cut = sh(['strace', '-f', '-e', 'trace=fsync,fdatasync', '-e', f'inject=fsync,fdatasync:signal=SIGKILL:when={n}', '-o', f'/tmp/rec-cut-{n}.log',
                      FM, 'sync-exec', ROOT / 'boot/d2k-update-boot', '--root', str(ROOT), '--recover'], check=False, timeout=600)
            again = sh([FM, 'sync-exec', ROOT / 'boot/d2k-update-boot', '--root', str(ROOT), '--recover'], check=False, timeout=600)
            self.s98 = self.init(INIT98, 'start', timeout=400)
            self.s99 = self.init(INIT99, 'start', timeout=300)
            wait_for(lambda s: s['state'] != 'unavailable' and not s['busy'], 300)
            self.wait_roles(15)
            self.own = [l for l in rules_dump() if l not in self.r0]
            self.oracle(self.A, 15, f'recover-cut-{n}')
            results.append({'n': n, 'cut_rc': cut.returncode, 'again_rc': again.returncode})
            for pid, p in procs().items():
                if '/opt/d2k' in p['exe'] or '/opt/d2k' in p['cmd']:
                    os.kill(pid, signal.SIGKILL)
        return {'sync_barriers': total, 'results': results}

    def case_damaged_journal(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        self.kill_all_updater()
        journals = sorted((ROOT / 'update-state').glob('journal.[0-9]'))
        if not journals:
            raise Fail('no journal generations found')
        for j in journals:
            data = bytearray(j.read_bytes())
            for i in range(0, len(data), 7):
                data[i] ^= 0x5a
            j.write_bytes(bytes(data))
        self.reboot()
        rc1 = self.s98.returncode
        time.sleep(5)
        ps = procs()
        live = {rid_of(p['exe']) for p in ps.values() if rid_of(p['exe'])}
        delta = [l for l in rules_dump() if l not in self.r0]
        missing = [l for l in self.r0 if l not in rules_dump()]
        self.reboot()
        rc2 = self.s98.returncode
        time.sleep(3)
        live2 = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        problems = []
        if rc1 == 0 or rc2 == 0:
            problems.append(f'S98 accepted damaged journals (rc {rc1}/{rc2})')
        if live or live2:
            problems.append(f'runtime started with damaged journal: {live} {live2}')
        if delta:
            problems.append(f'own interception present: {delta[:3]}')
        if missing:
            problems.append('sentinel rules lost')
        if not all(j.exists() for j in journals) or not (ROOT / 'releases' / self.A).is_dir():
            problems.append('journal/backup not retained')
        if problems:
            raise Fail('; '.join(problems))
        return {'s98_rc': [rc1, rc2], 'journals': [j.name for j in journals], 'live_after': sorted(live | live2)}

    def case_failed_rollback(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        os.chmod(ROOT / 'releases' / self.A / 'd2kd', 0o600)  # старый runtime не сможет стартовать
        pid = pidfile('d2k-panel.pid')
        os.kill(pid, signal.SIGKILL)
        st = self.wait_terminal(500)
        if st.get('phase') != 13:
            raise Fail(f'expected recovery_failed: {st}')
        time.sleep(3)
        live = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        delta = [l for l in rules_dump() if l not in self.r0]
        problems = []
        if live:
            problems.append(f'runtime processes after recovery_failed: {live}')
        if delta:
            problems.append(f'own interception after recovery_failed: {delta[:3]}')
        if [l for l in self.r0 if l not in rules_dump()]:
            problems.append('sentinel rules lost')
        self.reboot()
        time.sleep(5)
        st2 = status()
        live2 = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        if live2:
            problems.append(f'reboot restarted runtime after recovery_failed: {live2}')
        if problems:
            raise Fail('; '.join(problems))
        return {'last_error': st.get('last_error'), 's98_after_rc': self.s98.returncode, 'status_after_reboot': st2.get('state'),
                'phase_after_reboot': PHASES.get(st2.get('phase')), 'snapshots': [p.name for p in (ROOT / 'snapshots').glob('*')]}

    def case_torn_snapshot(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        self.kill_all_updater()
        snaps = list((ROOT / 'snapshots').glob('*'))
        if not snaps:
            raise Fail('no snapshot directory')
        target = next((p for p in snaps[0].rglob('*') if p.is_file() and p.name not in ('inventory', 'seal')), None)
        if not target:
            raise Fail('snapshot has no entries')
        target.write_bytes(b'torn' + target.read_bytes()[4:])
        cfg = sha(ROOT / 'config')
        self.reboot()
        time.sleep(5)
        st = status()
        live = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        problems = []
        if self.B in live:
            problems.append('new release started after torn snapshot')
        if sha(ROOT / 'config') != cfg:
            problems.append('live config overwritten from torn snapshot')
        if problems:
            raise Fail('; '.join(problems))
        return {'s98_rc': self.s98.returncode, 'phase': PHASES.get(st.get('phase')), 'live': sorted(live), 'tampered': str(target.relative_to(ROOT))}

    def case_concurrency(self):
        self.boot()
        self.publish(self.B)
        opid, av = self.install(self.B)
        self.wait_phase([9], 300)
        t0 = now_ms()
        outs = {}

        def run(name, cmd):
            outs[name] = {'start': now_ms() - t0}
            r = sh(cmd, check=False, timeout=600)
            outs[name].update(rc=r.returncode, end=now_ms() - t0, out=(r.stdout + r.stderr)[-300:])
        ts = [threading.Thread(target=run, args=a) for a in [
            ('manual-restart', [FM, 'sync-exec', INIT99, 'restart']),
            ('ndm-hook', f'{FM} sync-exec sh /opt/etc/ndm/netfilter.d/001-d2k.sh'),
            ('watchdog-heal', f'{FM} sync-exec sh {ROOT}/current/d2k-fw-heal.sh')]]
        for t in ts:
            t.start()
        code2, js2, _ = api('POST', '/api/update/install', {'release_id': self.B, 'manifest_sha256': av['manifest_sha256'], 'operation_id': 'lab-second-install'})
        code3, js3, _ = api('POST', '/api/update/install', {'release_id': self.B, 'manifest_sha256': av['manifest_sha256'], 'operation_id': opid})
        code4, js4, _ = api('POST', '/api/update/settings', {'enabled': False})
        st = self.wait_terminal(500)
        for t in ts:
            t.join(600)
        if st.get('phase') != 10:
            raise Fail(f'install under contention did not commit: {st}')
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(self.B, 15, 'B-after-contention')
        problems = []
        if code2 != 409:
            problems.append(f'conflicting second install got {code2} {js2}')
        if code3 not in (202, 200) or (js3 or {}).get('operation_id') != opid:
            problems.append(f'idempotent replay got {code3} {js3}')
        if any(o['end'] < st.get('t', 0) for o in outs.values()):
            pass
        if problems:
            raise Fail('; '.join(problems))
        return {'contenders': outs, 'settings_code': code4, 'settings_enabled_after': status().get('settings', {}).get('enabled')}

    def case_http(self):
        self.boot()
        self.publish(self.B)
        # Две вкладки присоединяются к одной проверке, пока лента держит ответ.
        self.feed.hold['stable.json'] = threading.Event()
        t0 = now_ms()
        res = {}

        def tab(name):
            res[name] = api('POST', '/api/update/check', {'force': True, 'operation_id': f'tab-{name}'})[:2]
        ts = [threading.Thread(target=tab, args=(n,)) for n in ('one', 'two')]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        time.sleep(1)
        held = self.feed.requests('stable.json', since=t0)
        self.feed.hold.pop('stable.json').set()
        st = wait_for(lambda s: not s['busy'], 120)
        ops = {res[n][1].get('operation_id') for n in res if res[n][1]}
        if len(held) != 1 or len(ops) != 1 or any(res[n][0] not in (200, 202) for n in res):
            raise Fail(f'two tabs: feed requests {len(held)}, ops {ops}, codes {[res[n][0] for n in res]}')
        n0 = len(self.feed.requests('stable.json'))
        code, js, _ = api('POST', '/api/update/check', {'force': False})
        wait_for(lambda s: not s['busy'], 60)
        cached = len(self.feed.requests('stable.json')) - n0
        code, js, _ = api('POST', '/api/update/check', {'force': True})
        wait_for(lambda s: not s['busy'], 60)
        forced = len(self.feed.requests('stable.json')) - n0 - cached
        if cached != 0 or forced != 1:
            raise Fail(f'cache: ordinary check made {cached} feed requests, force made {forced}')
        if any(r['path'].endswith('.tar') for r in self.feed.requests()):
            raise Fail('check downloaded a package')
        self.record('real-http-two-tabs-check', 'PASS', joined_operation=list(ops), feed_requests_while_held=len(held), cached_requests=cached, forced_requests=forced)
        # Закреплённая установка: вкладка видит B, канал уходит на A (другой выпуск/хеш).
        code, js, _ = api('GET', '/api/update', origin=None)
        shown = js['available']
        self.publish(self.A)
        code, js2, _ = api('POST', '/api/update/install', {'release_id': shown['release_id'], 'manifest_sha256': shown['manifest_sha256'], 'operation_id': 'lab-pinned'})
        st = wait_for(lambda s: not s['busy'], 120)
        if code == 202 and st['current']['release_id'] != self.A:
            raise Fail(f'pinned install of stale B proceeded against changed channel: {st}')
        if st['current']['release_id'] != self.A:
            raise Fail('current changed')
        self.oracle(self.A, 15, 'pinned-no-substitution', allow_phase=None)
        self.record('real-http-pinned-install', 'PASS', shown=shown['release_id'], install_code=code, result=js2 and {k: js2.get(k) for k in ('state', 'last_error', 'operation_id')},
                    note='changed channel pointer: exact B request not substituted by latest')
        # Негативные HTTP-случаи и отсутствие секретов.
        checks = {}
        checks['no-origin'] = api('POST', '/api/update/check', {'force': True}, origin=None)[0]
        checks['bad-origin'] = api('POST', '/api/update/check', {'force': True}, origin='http://evil.example')[0]
        checks['get-on-post'] = api('GET', '/api/update/check', origin=None)[0]
        checks['malformed'] = api('POST', '/api/update/check', b'{"force":', )[0]
        checks['unknown-field'] = api('POST', '/api/update/check', {'force': True, 'url': 'https://x'})[0]
        checks['oversize'] = api('POST', '/api/update/check', b'{"force":true,"pad":"' + b'a' * 20000 + b'"}')[0]
        checks['install-no-id'] = api('POST', '/api/update/install', {})[0]
        self.kill_all_updater()
        time.sleep(1)
        checks['daemon-unavailable'] = api('GET', '/api/update', origin=None)[0]
        checks['daemon-unavailable-body'] = (api('GET', '/api/update', origin=None)[1] or {}).get('state')
        self.init(INIT98, 'start')
        wait_for(lambda s: s['state'] != 'unavailable', 30)
        expect = {'no-origin': 403, 'bad-origin': 403, 'get-on-post': 405, 'malformed': 400, 'unknown-field': 400, 'oversize': 413, 'install-no-id': 400, 'daemon-unavailable': 503}
        wrong = {k: (checks[k], v) for k, v in expect.items() if checks[k] != v}
        canaries = [(ROOT / 'state/tg.identity').read_bytes()[:40]] if (ROOT / 'state/tg.identity').exists() else []
        for line in (ROOT / 'config').read_text().splitlines():
            if '=' in line and any(w in line.upper() for w in ('SECRET', 'TOKEN', 'KEY')) and len(line.split('=', 1)[1]) > 8:
                canaries.append(line.split('=', 1)[1].encode())
        body = api('GET', '/api/update', origin=None)[2] + api('GET', '/api/status', origin=None)[2]
        leak = [c[:6] for c in canaries if c and c in body]
        if wrong or leak:
            raise Fail(f'http negative: wrong={wrong} leaked={bool(leak)}')
        self.record('http-negative-and-redaction', 'PASS', codes=checks, canaries_checked=len(canaries),
                    note='daemon-unavailable state must not read as current' if checks['daemon-unavailable-body'] != 'current' else 'UNAVAILABLE READ AS CURRENT')
        return {}

    def case_feed_negative(self):
        self.boot()
        before = {'current': os.readlink(ROOT / 'current'), 'receipt': sha(ROOT / 'releases' / self.A / '.d2ku-receipt')}
        idx = self.publish(self.B)
        st = self.available(self.B)
        accepted = st['settings']
        results = {}

        def attempt(name, expect_ok=False):
            st = self.check()
            results[name] = {'result': st['check'].get('result'), 'state': st['state'], 'error': st.get('last_error'), 'available': (st.get('available') or {}).get('release_id')}
            if (st['check'].get('result') == 0) != expect_ok:
                raise Fail(f'{name}: expected {"OK" if expect_ok else "rejection"} got {results[name]}')
        self.feed.fault['stable.json.sig'] = 'flip'; attempt('bad-signature'); self.feed.fault.clear()
        self.feed.fault['manifest.json'] = 'flip'; attempt('manifest-hash-mismatch'); self.feed.fault.clear()
        self.feed.publish(self.B, self.seq - 1); attempt('lower-sequence-replay')
        self.feed.publish(self.B, self.seq + 5, expires=int(time.time()) - 5); attempt('expired-index')
        self.feed.publish(self.B, self.seq + 6, issued=int(time.time()) + 86400); attempt('future-issued')
        self.feed.fault['stable.json'] = 'redirect-http'; attempt('redirect-to-http'); self.feed.fault.clear()
        self.publish(self.B); attempt('recovered-coherent-pair', expect_ok=True)
        # Испорченный архив: отказ до остановки служб.
        for fault in ('flip', 'truncate', 'oversize'):
            self.feed.fault['d2k-runtime-arm64.tar'] = fault
            av = self.available(self.B)
            rc, js = cli('install', self.B, av['manifest_sha256'], '--operation-id', f'lab-archive-{fault}')
            st = self.wait_terminal(300)
            self.feed.fault.clear()
            results['archive-' + fault] = {'rc': rc, 'phase': PHASES.get(st.get('phase')), 'error': st.get('last_error'), 'result': st.get('last_result')}
            if st.get('phase') in (6, 7, 8, 9, 10) or st.get('last_result') == 0 or os.readlink(ROOT / 'current') != before['current']:
                raise Fail(f'archive fault {fault} was not rejected before stop: {results}')
            self.oracle(self.A, 15, f'after-archive-{fault}')
        if sha(ROOT / 'releases' / self.A / '.d2ku-receipt') != before['receipt']:
            raise Fail('active receipt changed')
        return {'results': results, 'note': 'all rejections before stopping; A untouched'}

    def case_window(self, kind):
        """/etc/TZ выбирается так, чтобы ЛОКАЛЬНОЕ время попало в нужную точку; часы не трогаются."""
        target = {'in': 4 * 60 + 50, 'past05': 5 * 60 + 1, 'daytime': 12 * 60}[kind]
        utc = time.gmtime()
        off = (utc.tm_hour * 60 + utc.tm_min) - target  # минут к западу
        off = (off + 720) % 1440 - 720
        tz = f'LAB{"+" if off >= 0 else "-"}{abs(off) // 60}:{abs(off) % 60:02d}'
        self.boot(tz=tz)
        st = status()
        self.publish(self.B)
        local = st['settings']
        if kind == 'in':
            st = wait_for(lambda s: s.get('phase') in (10, 12, 13) and not s['busy'], 15 * 60, step=1, what='automatic nightly install')
            if st['current']['release_id'] != self.B:
                raise Fail(f'auto install did not commit B: {st}')
            self.own = [l for l in rules_dump() if l not in self.r0]
            self.oracle(self.B, 15, 'B-auto-installed')
            # Второй попытки в ту же дату нет: перезапуск демона в окне и новый выпуск A.
            self.publish(self.A)
            self.kill_all_updater()
            self.init(INIT98, 'start')
            st2 = wait_for(lambda s: s['state'] != 'unavailable', 30)
            time.sleep(90)
            st2 = status()
            if st2['current']['release_id'] != self.B or st2['busy']:
                raise Fail(f'second automatic attempt in the same local date: {st2}')
            return {'tz': tz, 'settings': local, 'selected_minute': local.get('selected_minute'), 'second_attempt': 'none in 90 s'}
        time.sleep(180)
        st = status()
        if st['current']['release_id'] != self.A or st.get('phase') in (3, 4, 5, 6, 7, 8, 9):
            raise Fail(f'automatic install outside window: {st}')
        self.oracle(self.A, 15, f'no-auto-{kind}')
        return {'tz': tz, 'settings': local, 'checked': st['check'], 'observed_s': 180}

    def case_cache(self):
        self.boot()
        self.publish(self.B)
        self.available(self.B)
        t0 = time.monotonic()
        n0 = len(self.feed.requests('stable.json'))
        self.feed.fault['stable.json.sig'] = 'flip'
        st = self.check()
        err = st['check']
        self.feed.fault.clear()
        n1 = len(self.feed.requests('stable.json'))
        st = self.check(force=False)
        n2 = len(self.feed.requests('stable.json'))
        if n2 != n1 or st['check'].get('cached') is not True:
            raise Fail(f'error result not cached for ordinary check: {st["check"]} reqs {n1}->{n2}')
        if not st['check'].get('last_success_utc'):
            raise Fail('last successful check time lost after cached error')
        t_last = time.monotonic()
        time.sleep(895)  # 895 с от последней проверки: ещё внутри TTL 900 с
        st = self.check(force=False)
        n3 = len(self.feed.requests('stable.json'))
        time.sleep(12)
        st2 = self.check(force=False)
        n4 = len(self.feed.requests('stable.json'))
        if n3 != n2:
            raise Fail(f'ordinary check at <900 s refetched ({n2}->{n3})')
        if n4 != n3 + 1:
            raise Fail(f'ordinary check after 900 s did not refetch ({n3}->{n4})')
        self.kill_all_updater()
        self.init(INIT98, 'start')
        st3 = wait_for(lambda s: s['state'] != 'unavailable', 30)
        if st3['check'].get('fresh'):
            raise Fail(f'cache fresh after daemon restart: {st3["check"]}')
        return {'error_cached': err, 'requests': [n0, n1, n2, n3, n4], 'after_restart': st3['check'], 'note': 'daemon restart, not a boot_id change (container cannot reboot)'}

    def case_enospc(self):
        self.boot()
        self.publish(self.B)
        self.feed.hold['half:d2k-runtime-arm64.tar'] = threading.Event()
        self.install(self.B)
        self.wait_phase([3], 120)
        time.sleep(1)
        filled = sh([FM, 'fill', str(ROOT / 'update-state/lab-fill')]).stdout.strip()
        self.feed.hold.pop('half:d2k-runtime-arm64.tar').set()
        st = self.wait_terminal(300)
        problems = []
        if st.get('phase') in (6, 7, 8, 9, 10) or st.get('last_result') == 0:
            problems.append(f'download under ENOSPC did not fail before stop: {st}')
        os.unlink(ROOT / 'update-state/lab-fill')
        self.oracle(self.A, 15, 'A-after-download-enospc')
        # Второй сценарий: место кончается после preflight, во время остановки/снимка.
        self.feed.hold.clear()
        self.install(self.B)
        self.wait_phase([6, 7], 300, step=0.01)
        filled2 = sh([FM, 'fill', str(ROOT / 'update-state/lab-fill')]).stdout.strip()
        st2 = self.wait_terminal(500)
        phase2 = st2.get('phase')
        os.unlink(ROOT / 'update-state/lab-fill')
        # Журнал не записать, пока место занято: восстановление в процессе
        # обрывается (фаза остаётся незавершённой, службы стоят) и доводится
        # загрузчиком после освобождения места и перезагрузки. Проверяется,
        # что рабочий выпуск и снимок не потеряны, а не то, что службы
        # поднялись сами без перезагрузки.
        if phase2 not in (10, 12):
            self.reboot()
            wait_for(lambda s: s['state'] != 'unavailable', 60)
            st3 = wait_for(lambda s: not s['busy'], 300)
        else:
            st3 = st2
        if st3['current']['release_id'] != self.A and phase2 != 10:
            problems.append(f'after ENOSPC during stop: {st3}')
        if problems:
            raise Fail('; '.join(problems))
        self.own = [l for l in rules_dump() if l not in self.r0]
        self.oracle(st3['current']['release_id'], 15, 'after-enospc-after-preflight')
        return {'filled_bytes': [filled, filled2], 'phase_after_fill': PHASES.get(phase2), 'final': st3['current']['release_id'],
                'note': 'tmpfs /opt filled by an owned file; freeing it enabled recovery'}

    def case_remove_during_install(self):
        self.boot()
        self.publish(self.B)
        self.install(self.B)
        self.wait_phase([9], 300)
        t0 = now_ms()
        r = sh([FM, 'sync-exec', ROOT / 'boot/d2k-service-adapter', '--root', str(ROOT), 'service', 'uninstall'], check=False, timeout=600)
        t1 = now_ms()
        st = status()
        live = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        delta = [l for l in rules_dump() if l not in self.r0]
        problems = []
        if r.returncode:
            problems.append(f'uninstall during install rc={r.returncode}: {(r.stdout + r.stderr)[-300:]}')
        if live:
            problems.append(f'runtime still alive after uninstall: {live}')
        if delta:
            problems.append(f'own rules after uninstall: {delta[:3]}')
        if [l for l in self.r0 if l not in rules_dump()]:
            problems.append('sentinel rules lost')
        r98 = self.init(INIT98, 'start')
        r99 = self.init(INIT99, 'start')
        time.sleep(3)
        live2 = {rid_of(p['exe']) for p in procs().values() if rid_of(p['exe'])}
        if live2:
            problems.append(f'start after remove resurrected runtime: {live2}')
        if problems:
            raise Fail('; '.join(problems))
        self.record('start-after-remove', 'PASS', s98_rc=r98.returncode, s99_rc=r99.returncode)
        return {'uninstall_waited_ms': t1 - t0, 'status_after': st.get('state'), 'kept_state': (ROOT / 'state').exists()}

    def case_module_linux(self):
        """Повтор модульных наборов внутри Linux (ядро/NFQUEUE-путь): make check + supervised + startup-fence."""
        env = dict(os.environ, CFLAGS='-O2 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -Wno-misleading-indentation -Wno-format-truncation')
        out = {}
        for target in ('check', 'check-supervised', 'check-startup-fence'):
            r = subprocess.run(['make', '-C', '/work/src/update', 'BUILD=/work/build/update', target], capture_output=True, text=True, env=env, timeout=3600)
            (EV / f'module-{target}.log').write_text(r.stdout + r.stderr)
            out[target] = r.returncode
            self.record(f'module-linux-{target}', 'PASS' if r.returncode == 0 else 'FAIL', rc=r.returncode, log=f'module-{target}.log')
        return out


GROUPS = {
    'aba': lambda L: L.run_case('signed-success-A-B-A', L.case_aba),
    'bad-panel': lambda L: L.run_case('bad-panel', L.case_bad_role, 'panel'),
    'bad-core': lambda L: L.run_case('bad-core', L.case_bad_role, 'core'),
    'bad-dp': lambda L: L.run_case('bad-dp', L.case_bad_role, 'dp'),
    'bad-tg': lambda L: L.run_case('bad-tg', L.case_bad_role, 'tg'),
    'bad-updater-exit': lambda L: L.run_case('bad-updater-exit', L.case_bad_updater, 'kill'),
    'bad-updater-freeze': lambda L: L.run_case('bad-updater-freeze', L.case_bad_updater, 'freeze'),
    'missing-own-rule': lambda L: L.run_case('missing-own-rule', L.case_missing_own_rule),
    'stale-heartbeat': lambda L: L.run_case('stale-heartbeat', L.case_stale_heartbeat),
    'inactive-mask-tg': lambda L: L.run_case('inactive-mask-tg', L.case_inactive_mask, 'telegram-disable', 7),
    'inactive-mask-engine': lambda L: L.run_case('inactive-mask-engine', L.case_inactive_mask, 'engine-stop', 12),
    'boot-phase-downloading': lambda L: L.run_case('boot-phase-downloading', L.case_boot_phase, 3),
    'boot-phase-stopping': lambda L: L.run_case('boot-phase-stopping', L.case_boot_phase, 6),
    'boot-phase-starting': lambda L: L.run_case('boot-phase-starting', L.case_boot_phase, 8),
    'boot-phase-validating': lambda L: L.run_case('boot-phase-validating', L.case_boot_phase, 9),
    'boot-phase-committed': lambda L: L.run_case('boot-phase-committed', L.case_boot_phase, 10),
    'supervisor-kill': lambda L: L.run_case('supervisor-kill', L.case_supervisor_kill),
    'handoff-kill': lambda L: L.run_case('handoff-kill', L.case_handoff_kill),
    'boot-recovery-child-kill': lambda L: L.run_case('boot-recovery-child-kill', L.case_boot_recovery_child_kill),
    'damaged-journal': lambda L: L.run_case('damaged-journal', L.case_damaged_journal),
    'failed-rollback': lambda L: L.run_case('failed-rollback', L.case_failed_rollback),
    'torn-snapshot': lambda L: L.run_case('torn-snapshot', L.case_torn_snapshot),
    'concurrency': lambda L: L.run_case('restart-manual-night-ndm', L.case_concurrency),
    'http': lambda L: L.run_case('http-group', L.case_http),
    'feed-negative': lambda L: L.run_case('metadata-transport-package', L.case_feed_negative),
    'window-in': lambda L: L.run_case('window-in', L.case_window, 'in'),
    'window-past05': lambda L: L.run_case('window-past05', L.case_window, 'past05'),
    'window-daytime': lambda L: L.run_case('window-daytime', L.case_window, 'daytime'),
    'cache-900': lambda L: L.run_case('cache-900-error-reboot', L.case_cache),
    'enospc': lambda L: L.run_case('enospc-after-preflight', L.case_enospc),
    'remove-during-install': lambda L: L.run_case('remove-during-install', L.case_remove_during_install),
    'module-linux': lambda L: L.run_case('module-linux', L.case_module_linux),
}
# Обязательный по умолчанию набор: обновление, сломанный выпуск, обрыв
# питания посреди проверки, кончившееся место. Остальные группы — по
# D2K_LAB_GROUPS=имя,... или all; они написаны, но не все доведены.
CORE_GROUPS = ('aba', 'bad-core', 'boot-phase-validating', 'enospc')

# Строки матрицы (task-11-preparation.md) → группы/подслучаи.
REQUIRED = {
    'signed-success-A-B-A': 'aba', 'signed-success-A-B': 'aba', 'active-all': 'aba', 'relay-down': 'aba', 'late-rollback-refused': 'aba', 'measurements-runtime': 'aba',
    'bad-panel': 'bad-panel', 'bad-core': 'bad-core', 'bad-dp': 'bad-dp', 'bad-tg': 'bad-tg', 'bad-updater-exit': 'bad-updater-exit', 'bad-updater-freeze': 'bad-updater-freeze',
    'wire-mismatch': None, 'wrong-inode': None, 'stale-heartbeat': 'stale-heartbeat', 'missing-own-rule': 'missing-own-rule',
    'inactive-mask-tg': 'inactive-mask-tg', 'inactive-mask-engine': 'inactive-mask-engine',
    'boot-phase-downloading': 'boot-phase-downloading', 'boot-phase-stopping': 'boot-phase-stopping', 'boot-phase-starting': 'boot-phase-starting',
    'boot-phase-validating': 'boot-phase-validating', 'boot-phase-committed': 'boot-phase-committed',
    'io-write-sync-rename-matrix': None, 'supervisor-kill': 'supervisor-kill', 'boot-recovery-child-kill': 'boot-recovery-child-kill', 'handoff-kill': 'handoff-kill',
    'enospc-after-preflight': 'enospc', 'damaged-journal': 'damaged-journal', 'torn-snapshot': 'torn-snapshot', 'failed-rollback': 'failed-rollback',
    'stop-save-failure': None, 'forced-stop': None, 'rotating-log-writer': None,
    'legacy-bootstrap-cut': None, 'legacy-first-failure-phase': None, 'legacy-active-panel-tg-recovery': None, 'legacy-helper-ndm-race': None,
    'restart-manual-night-ndm': 'concurrency', 'remove-during-install': 'remove-during-install', 'start-after-remove': 'remove-during-install',
    'real-http-two-tabs-check': 'http', 'real-http-pinned-install': 'http', 'real-ui-reconnect-close': None, 'http-negative-and-redaction': 'http',
    'cache-900-error-reboot': 'cache-900', 'window-in': 'window-in', 'window-past05': 'window-past05', 'window-daytime': 'window-daytime',
    'window-dst-backward-jump': None, 'download-cross05-reboot': None, 'auto-disabled-quarantine': None, 'outcome-crash-retention': None,
    'metadata-transport-package': 'feed-negative', 'full-build-tool-gates': 'host', 'own-firewall-install': 'host',
    'module-linux-check': 'module-linux', 'module-linux-check-supervised': 'module-linux', 'module-linux-check-startup-fence': 'module-linux',
}


def container_main(args):
    L = Lab(args.group)
    try:
        GROUPS[args.group](L)
    finally:
        if L.feed:
            L.feed.server.shutdown()
    return 0 if all(r['status'] == 'PASS' for r in L.results) and L.results else 1


# ================================================================== host side
def host_prepare_image(repo, fixtures, image, tag, workdir):
    """Плоская установка A в закрытом контейнере, подписанный bootstrap, снимок «после потери питания»."""
    name = f'd2ku-t11-base-{tag}'
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sh(['docker', 'run', '-d', '--name', name, '--init', '--network', 'none', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', image, 'sleep', '86400'])
    sh(['docker', 'exec', name, 'mkdir', '-p', '/fx', '/lab', '/etc/d2k-lab', '/work/src', '/evidence'])
    env = dict(os.environ, COPYFILE_DISABLE='1')
    tar = subprocess.Popen(['tar', '-C', str(fixtures), '-cf', '-', '--exclude', 'work-*', '.'], stdout=subprocess.PIPE, env=env)
    sh(['docker', 'exec', '-i', name, 'tar', '--no-same-owner', '-C', '/fx', '-xf', '-'], stdin=tar.stdout)
    files = subprocess.run(['git', '-C', str(repo), 'ls-files', '-co', '--exclude-standard', '-z'], capture_output=True, check=True).stdout
    src = subprocess.Popen(['tar', '-C', str(repo), '--null', '-T', '-', '-cf', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    threading.Thread(target=lambda: (src.stdin.write(files), src.stdin.close())).start()
    sh(['docker', 'exec', '-i', name, 'tar', '-C', '/work/src', '-xf', '-'], stdin=src.stdout)
    sh(['docker', 'cp', str(pathlib.Path(__file__).resolve()), f'{name}:/lab/lab_update.py'])
    r = subprocess.run(['docker', 'exec', name, 'python3', '/lab/lab_update.py', 'prepare'], capture_output=True, text=True, timeout=1800)
    (workdir / 'prepare.log').write_text(r.stdout + r.stderr)
    if r.returncode:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL)
        raise SystemExit(f'lab preparation failed (exit {r.returncode}); see {workdir}/prepare.log')
    prepared = f'd2ku-t11-prepared:{tag}'
    sh(['docker', 'commit', '-c', 'CMD ["sleep","86400"]', name, prepared])
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL)
    return prepared


def prepare_main():
    """Внутри базового контейнера."""
    A = read_json(FX / 'fixtures.json')['A']
    sh(f'cc -O2 -Wall -Wextra -Werror -o {FM} /work/src/update/tests/fault_matrix.c')
    sh('cp /fx/TEST-ca.pem /etc/d2k-lab/TEST-ca.pem; chmod 644 /etc/d2k-lab/TEST-ca.pem')
    sh('cp /fx/TEST-probe-cert.pem /usr/local/share/ca-certificates/d2k-lab-probe.crt && update-ca-certificates >/dev/null')
    flat = FX / A / 'flat'
    sh(f"sed -i 's|^TG_RELAY_URL=.*|TG_RELAY_URL=wss://127.0.0.1:11443/ws|; s/^TG_ENROLL_PORT=.*/TG_ENROLL_PORT=11444/' {flat}/files/config")
    sh(f"sed -i 's|^PROBE_URL=.*|PROBE_URL=https://127.0.0.1:11443/|; s/^PROBE_IP=.*/PROBE_IP=127.0.0.1/' {flat}/files/d2k-tg-watchdog.sh")
    sh(f'ip link add br0 type dummy; ip addr add {LAN}/24 dev br0; ip addr add {PROBE_IP}/32 dev br0; ip link set br0 up')
    probe_server()
    sh('mkdir -p /opt/etc/init.d /opt/etc/ndm/netfilter.d /opt/sbin')
    r = sh(f'cd {flat} && D2K_LOCAL={flat} sh scripts/install.sh', timeout=600)
    print(r.stdout[-1500:])
    st = sh([INIT99, 'status'], check=False).stdout
    if 'датапат: работает' not in st or 'контроллер: работает' not in st:
        raise SystemExit('flat installation did not start: ' + st)
    personal = {n: sha(ROOT / n) for n in ('config', 'state/tg.identity') if (ROOT / n).exists()}
    r = sh([str(FX / A / 'bootstrap/d2k-update-boot'), '--root', str(ROOT), '--bootstrap', str(FX / A / 'bootstrap')], timeout=900, cwd='/')
    print(r.stdout[-800:], r.stderr[-800:])
    if not (ROOT / 'update-state/bootstrap.done').exists() or os.readlink(ROOT / 'current') != f'releases/{A}':
        raise SystemExit('bootstrap did not complete')
    files = {str(p.relative_to(ROOT / 'releases' / A)): sha(p) for p in (ROOT / 'releases' / A).rglob('*') if p.is_file() and p.name != '.d2ku-receipt'}
    st = sh([INIT99, 'status'], check=False).stdout
    if 'датапат: работает' not in st:
        raise SystemExit('managed installation not running after bootstrap: ' + st)
    pathlib.Path('/lab/prepared.json').write_text(json.dumps({'A': A, 'personal': personal, 'release_files': files, 'enabled': (ROOT / 'update-state/enabled').read_text().strip()}, indent=1))
    sh('tar -C / -cpf /lab/opt.tar opt')
    print('prepared: flat A installed, bootstrapped to managed, mask', (ROOT / 'update-state/enabled').read_text().strip())


def host_main(args):
    repo = pathlib.Path(args.repo).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    tag = time.strftime('%Y%m%d-%H%M%S')
    head = sh(['git', '-C', str(repo), 'rev-parse', 'HEAD']).stdout.strip()
    dirty = sh(['git', '-C', str(repo), 'status', '--porcelain']).stdout.splitlines()
    fixtures = pathlib.Path(args.fixtures).resolve()
    ids = read_json(fixtures / 'fixtures.json')
    summary = {'head': head, 'dirty': dirty, 'fixtures': {k: read_json(fixtures / v / 'fixture.json') if (fixtures / v / 'fixture.json').exists() else None for k, v in ids.items()},
               'image': args.image, 'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'scope': {
                   'time_source': 'seccomp: adjtimex/clock_adjtime answered 0 (synchronized); wall/monotonic/TZ real',
                   'reboot': 'SIGKILL of all installation processes + netfilter/ipset/tmp reset + init scripts; not flash power loss',
                   'network': '--network none; loopback TLS feed with TEST key; closed Telegram relay'}, 'cases': []}
    wanted = args.groups.split(',') if args.groups else list(CORE_GROUPS)
    groups = list(GROUPS) if wanted == ['all'] else [g for g in wanted if g in GROUPS]
    unknown = [g for g in wanted if g != 'all' and g not in GROUPS]
    if unknown:
        raise SystemExit(f'unknown lab groups: {unknown}')
    image = host_prepare_image(repo, fixtures, args.image, tag, out)
    summary['prepared_image'] = image
    evdir = out / 'evidence'
    evdir.mkdir(exist_ok=True)

    def run_group(g):
        name = f'd2ku-t11-{g}-{tag}'
        t0 = time.monotonic()
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        extra = ['--tmpfs', '/opt:exec,size=160m'] if g == 'enospc' else []
        cmd = ['docker', 'run', '-d', '--name', name, '--init', '--network', 'none', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--cap-add', 'SYS_PTRACE', *extra, image, 'sleep', '86400']
        res = {'group': g, 'container': name}
        try:
            sh(cmd)
            if g == 'enospc':  # tmpfs скрывает /opt образа: развернуть снимок установки на tmpfs
                sh(['docker', 'exec', name, 'tar', '-C', '/', '-xpf', '/lab/opt.tar'])
            r = subprocess.run(['docker', 'exec', '-e', f'D2K_LAB_BOOTLOG={os.environ.get("D2K_LAB_BOOTLOG", "")}', name,
                                'python3', '/lab/lab_update.py', 'case', g], capture_output=True, text=True, timeout=args.timeout)
            (evdir / f'{g}.log').write_text(r.stdout + r.stderr)
            res['exit'] = r.returncode
            subprocess.run(['docker', 'cp', f'{name}:/evidence/.', str(evdir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                res['results'] = read_json(evdir / f'{g}.json')
            except (OSError, ValueError):
                res['results'] = []
        except subprocess.TimeoutExpired:
            res['exit'] = 'timeout'
            res['results'] = []
        except Fail as e:
            res['exit'] = 'setup-failure'
            res['error'] = str(e)[:1000]
            res['results'] = []
        finally:
            if os.environ.get('D2K_LAB_KEEP') != '1':  # отладка: оставить контейнер для осмотра
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        res['elapsed_s'] = round(time.monotonic() - t0, 1)
        print(f'group {g}: exit {res["exit"]} in {res["elapsed_s"]} s', flush=True)
        return res

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        runs = list(pool.map(run_group, groups))
    if os.environ.get('D2K_LAB_KEEP') != '1':
        subprocess.run(['docker', 'rmi', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Хостовые строки.
    gates = {}
    for k, v in ids.items():
        work = fixtures / f'work-{v}' / 'build'
        gates[v] = {abi: read_json(work / f'gates-{abi}.json')['tests'] for abi in 'arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64'.split()
                    if (work / f'gates-{abi}.json').exists()} if work.exists() else None
    host_cases = [{'case': 'full-build-tool-gates', 'status': 'PASS' if all(g and len(g) == 9 and all(v == 0 for t in g.values() for v in t.values()) for g in gates.values()) else 'FAIL',
                   'gates': {k: (sorted(v) if v else None) for k, v in gates.items()}}]
    for script in ('lab-install.sh', 'check_firewall.sh'):
        if args.skip_install_labs or wanted != ['all']:
            host_cases.append({'case': 'own-firewall-install', 'status': 'NOT-RUN', 'script': script})
            continue
        r = subprocess.run(['sh', str(repo / 'scripts' / script)], capture_output=True, text=True, timeout=3600)
        (out / f'{script}.log').write_text(r.stdout + r.stderr)
        host_cases.append({'case': 'own-firewall-install', 'script': script, 'status': 'PASS' if r.returncode == 0 else 'FAIL', 'exit': r.returncode})
    executed = {}
    for run in runs:
        for r in run['results']:
            executed.setdefault(r['case'], []).append(r)
        if run['exit'] in ('timeout', 'setup-failure'):
            executed.setdefault(run['group'] + ':group', []).append({'status': run['exit'], 'group': run['group'], 'error': run.get('error')})
    for hc in host_cases:
        executed.setdefault(hc['case'], []).append(hc)
    rows = []
    for case, group in REQUIRED.items():
        # Итог требует только строки выбранных групп; хостовые строки — только
        # если их просили (полный прогон).
        if group not in groups and not (group == 'host' and wanted == ['all']):
            continue
        got = executed.get(case, [])
        if group is None:
            rows.append({'case': case, 'status': 'NOT-IMPLEMENTED', 'group': None})
        elif not got:
            run = next((r for r in runs if r['group'] == group), None)
            rows.append({'case': case, 'status': 'MISSING' if run is None else ('TIMEOUT' if run['exit'] == 'timeout' else 'FAIL'), 'group': group, 'exit': run and run['exit']})
        else:
            rows.append({'case': case, 'status': 'PASS' if all(r['status'] == 'PASS' for r in got) else 'FAIL', 'group': group, 'detail': got})
    summary['cases'] = rows
    summary['groups'] = [{k: v for k, v in r.items() if k != 'results'} for r in runs]
    summary['counts'] = {s: sum(1 for r in rows if r['status'] == s) for s in ('PASS', 'FAIL', 'NOT-IMPLEMENTED', 'MISSING', 'TIMEOUT')}
    summary['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    text = json.dumps(summary, indent=1, default=str)
    for secret in ('TEST-signing', 'BEGIN PRIVATE KEY'):
        if secret in text:
            raise SystemExit('summary would contain a secret marker')
    (out / 'summary.json').write_text(text)
    print(f'summary: {summary["counts"]} -> {out}/summary.json')
    return 0 if rows and summary['counts']['PASS'] == len(rows) else 1


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('case'); c.add_argument('group')
    sub.add_parser('prepare')
    h = sub.add_parser('orchestrate')
    h.add_argument('--repo', required=True); h.add_argument('--fixtures', required=True); h.add_argument('--out', required=True)
    h.add_argument('--image', default='d2k-update-lab:t11'); h.add_argument('--jobs', type=int, default=4); h.add_argument('--groups', default='')
    h.add_argument('--timeout', type=int, default=3000); h.add_argument('--skip-install-labs', action='store_true')
    args = p.parse_args()
    if args.cmd == 'case':
        raise SystemExit(container_main(args))
    if args.cmd == 'prepare':
        prepare_main()
        return
    raise SystemExit(host_main(args))


if __name__ == '__main__':
    main()
