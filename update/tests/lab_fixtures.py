#!/usr/bin/env python3
"""Хостовая подготовка фикстур лаборатории обновлений (scripts/lab-update.sh).

Собирает из ЧИСТОГО клона указанной ревизии полный выпуск на девять ABI тем же
путём, что и выпускной конвейер (build-router.sh, build-router-tests.sh,
check-router-builds.sh в закрытом контейнере, package-update.py, sign-update.sh),
и складывает в каталог фикстур только то, что нужно лаборатории arm64.

Ключ подписи и TLS-сертификат — одноразовые, явно ТЕСТОВЫЕ. Ничего не
публикуется; общий builds/ рабочего дерева не трогается; сеть не используется.
Сбой здесь — сбой подготовки, а не дефект продукта: код выхода 3.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, time

ABIS = 'arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64'.split()
IMAGE = 'd2k-update-lab:bookworm'
FEED_PORT = 8443
CA_PATH = '/etc/d2k-lab/TEST-ca.pem'


def run(argv, **kw):
    return subprocess.run([str(a) for a in argv], check=True, **kw)


def out(argv, **kw):
    return subprocess.run([str(a) for a in argv], check=True, stdout=subprocess.PIPE, text=True, **kw).stdout.strip()


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def openssl():
    brew = pathlib.Path('/opt/homebrew/opt/openssl@3/bin/openssl')
    return os.environ.get('D2K_OPENSSL') or (str(brew) if brew.exists() else 'openssl')


def clone(repo, commit, dest):
    run(['git', 'clone', '-q', '--no-hardlinks', repo, dest])
    run(['git', '-C', dest, 'checkout', '-q', '--detach', commit])
    if out(['git', '-C', dest, 'status', '--porcelain']):
        raise SystemExit('fixture clone is not clean')


def keys(base):
    """Одноразовые ТЕСТОВЫЕ ключ подписи и TLS-сертификат localhost."""
    key = base / 'TEST-signing.pem'
    if not key.exists():
        run([openssl(), 'genpkey', '-algorithm', 'ED25519', '-out', key])
    os.chmod(key, 0o600)
    der = subprocess.run([openssl(), 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'], check=True, stdout=subprocess.PIPE).stdout
    (base / 'TEST-public.raw').write_bytes(der[-32:])
    if not (base / 'TEST-ca.pem').exists():
        run([openssl(), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', base / 'TEST-tls-key.pem',
             '-out', base / 'TEST-ca.pem', '-subj', '/CN=localhost', '-days', '30',
             '-addext', 'subjectAltName=DNS:localhost'], stderr=subprocess.DEVNULL)
        os.chmod(base / 'TEST-tls-key.pem', 0o600)
    if not (base / 'TEST-probe-cert.pem').exists():
        # Заглушка внешнего зонда сторожа Telegram (core.telegram.org) на
        # частном адресе внутри netns: иначе без сети сторож через три тика
        # перезапускает d2ktg посреди окна проверки.
        run([openssl(), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', base / 'TEST-probe-key.pem',
             '-out', base / 'TEST-probe-cert.pem', '-subj', '/CN=core.telegram.org', '-days', '30',
             '-addext', 'subjectAltName=DNS:core.telegram.org'], stderr=subprocess.DEVNULL)
        os.chmod(base / 'TEST-probe-key.pem', 0o600)
    return key


def build(args):
    base = pathlib.Path(args.out).resolve()
    base.mkdir(parents=True, exist_ok=True)
    work = base / ('work-' + args.id)
    if work.exists():
        raise SystemExit('work directory exists; immutable fixture IDs are not rebuilt in place')
    work.mkdir()
    src = work / 'source'
    clone(args.repo, args.commit, src)
    commit = out(['git', '-C', src, 'rev-parse', 'HEAD'])
    epoch = out(['git', '-C', src, 'log', '-1', '--format=%ct'])
    bdir = work / 'build'
    env = dict(os.environ, DEPS_PROVENANCE=args.deps, OUT=str(bdir), TEST_OUT=str(bdir / 'tests'),
               RELEASE_ID=args.id, SOURCE_DATE_EPOCH=epoch, ZIG=args.zig, ZIG_MIPS64EL=args.zig_mips64el, JOBS='2')
    logs = work / 'logs'
    logs.mkdir()
    for abi in ABIS:
        env['ARCHES'] = abi
        for script in ('build-router.sh', 'build-router-tests.sh'):
            with open(logs / f'{abi}-{script}.log', 'wb') as log:
                r = subprocess.run(['sh', str(src / 'scripts' / script)], cwd=src, env=env, stdout=log, stderr=subprocess.STDOUT)
            if r.returncode:
                raise SystemExit(f'fixture build failed: {abi} {script} (see {logs})')
        print('built', args.id, abi, flush=True)
    # Linux/QEMU-ворота в закрытом контейнере без сети.
    name = 'd2ku-t11-gates-' + args.id.lower().replace('.', '-').replace('_', '-')
    gsrc = work / 'gsrc'
    clone(str(src), commit, gsrc)
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', IMAGE, 'sleep', '7200'], stdout=subprocess.DEVNULL)
    try:
        run(['docker', 'exec', name, 'mkdir', '-p', '/g'])
        tar = subprocess.Popen(['tar', '-C', str(work), '-cf', '-', 'gsrc', 'build'], stdout=subprocess.PIPE, env=dict(os.environ, COPYFILE_DISABLE='1'))
        run(['docker', 'exec', '-i', name, 'tar', '-C', '/g', '-xf', '-'], stdin=tar.stdout)
        if tar.wait():
            raise SystemExit('fixture transfer failed')
        with open(work / 'gates.log', 'wb') as log:
            r = subprocess.run(['docker', 'exec', '-e', 'RELEASE_ID=' + args.id, '-e', 'SOURCE_DATE_EPOCH=' + epoch,
                                '-e', 'OUT=/g/build', '-e', 'TEST_OUT=/g/build/tests', name, 'sh', '-c',
                                "git config --global --add safe.directory '*'; cd /g/gsrc && git status --short && sh scripts/check-router-builds.sh"],
                               stdout=log, stderr=subprocess.STDOUT)
        if r.returncode:
            raise SystemExit(f'fixture Linux gates failed (see {work}/gates.log)')
        for abi in ABIS:
            run(['docker', 'cp', f'{name}:/g/build/gates-{abi}.json', str(bdir / f'gates-{abi}.json')], stdout=subprocess.DEVNULL)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(gsrc)
    release = work / 'release'
    release.mkdir()
    penv = dict(os.environ, PATH=str(pathlib.Path(openssl()).parent) + ':' + os.environ['PATH'])
    pkg = ['python3', str(src / 'scripts/package-update.py'), '--root', str(src), '--build-dir', str(bdir), '--release', args.id]
    for abi in ABIS:
        run(pkg + ['--arch', abi, '--built-at', epoch, '--out', str(release)], cwd=src, env=penv, stdout=subprocess.DEVNULL)
    run(pkg + ['--out', str(release), '--finalize'], cwd=src, env=penv, stdout=subprocess.DEVNULL)
    key = keys(base)
    run(['sh', str(src / 'scripts/sign-update.sh'), release / 'manifest.json', release / 'manifest.json.sig'],
        cwd=src, env=dict(penv, D2K_SIGNING_KEY=str(key)))
    export(base, args.id, src, bdir, release, commit, epoch, 'lab-built from clean clone', bootstrap=args.bootstrap)
    print('fixture release', args.id, 'commit', commit, 'ready', flush=True)


def export(base, rid, src, bdir, release, commit, epoch, origin, bootstrap):
    """Свести выпуск к тому, что нужно лаборатории arm64, и записать происхождение."""
    dest = base / rid
    dest.mkdir()
    for name in ('manifest.json', 'manifest.json.sig', 'd2k-runtime-arm64.tar'):
        shutil.copyfile(release / name, dest / name)
    sizes = {}
    for abi in ABIS:
        runtime = release / f'd2k-runtime-{abi}.tar'
        sizes[abi] = {'runtime_bytes': runtime.stat().st_size, 'runtime_sha256': sha(runtime),
                      'binaries': {n: (bdir / f'{n}-linux-{abi}').stat().st_size for n in
                                   ('d2kd', 'd2kc', 'd2kpanel', 'd2ktg', 'd2k-update', 'd2k-update-boot', 'd2k-service-adapter')}}
        boot = release / f'd2k-bootstrap-{abi}.tar'
        if boot.exists():
            sizes[abi].update(bootstrap_bytes=boot.stat().st_size, bootstrap_sha256=sha(boot))
    info = {'release_id': rid, 'commit': commit, 'built_at': int(epoch), 'origin': origin,
            'manifest_sha256': sha(dest / 'manifest.json'), 'sizes': sizes}
    if bootstrap is not None:
        # Плоская исходная установка и подписанный загрузочный комплект с
        # лабораторной public-конфигурацией (loopback-лента, тестовый CA и ключ).
        key = keys(base)
        public = (base / 'TEST-public.raw').read_bytes().hex()
        extra = ''.join(f'key={pathlib.Path(p).read_bytes().hex()} 1 9223372036854775807\n' for p in bootstrap if p)
        conf = base / f'public-{rid}.conf'
        conf.write_text(f'D2KU-CONFIG-1\nfeed=https://localhost:{FEED_PORT}\nca={CA_PATH}\nabi=arm64\nbuild={epoch}\n'
                        f'host=localhost\nkey={public} 1 9223372036854775807\n{extra}')
        os.chmod(conf, 0o600)
        penv = dict(os.environ, PATH=str(pathlib.Path(openssl()).parent) + ':' + os.environ['PATH'])
        lab = base / ('work-' + rid) / 'lab-bootstrap'
        lab.mkdir(parents=True)
        run(['python3', str(src / 'scripts/package-update.py'), '--root', str(src), '--build-dir', str(bdir), '--arch', 'arm64',
             '--release', rid, '--built-at', epoch, '--out', str(lab), '--bootstrap', '--public-config', str(conf)],
            cwd=src, env=penv, stdout=subprocess.DEVNULL)
        run(['sh', str(src / 'scripts/sign-update.sh'), lab / 'bootstrap-arm64.json', lab / 'bootstrap-arm64.json.sig'],
            cwd=src, env=dict(penv, D2K_SIGNING_KEY=str(key)))
        stage = dest / 'bootstrap'
        stage.mkdir(mode=0o700)
        # Проверка подписи/архива/состава тем же доверенным инструментом, что и у оператора.
        run(['python3', str(src / 'scripts/package-update.py'), '--verify-bootstrap', lab / 'bootstrap-arm64.json',
             '--signature', lab / 'bootstrap-arm64.json.sig', '--archive', lab / 'd2k-bootstrap-arm64.tar',
             '--public-key', base / 'TEST-public.raw', '--arch', 'arm64', '--stage', stage], cwd=src, env=penv, stdout=subprocess.DEVNULL)
        info['lab_bootstrap'] = {'bytes': (lab / 'd2k-bootstrap-arm64.tar').stat().st_size,
                                 'sha256': sha(lab / 'd2k-bootstrap-arm64.tar'), 'files': len(list(stage.iterdir()))}
        # Плоская установка = вывод той же сборки + исходники той же ревизии.
        flat = dest / 'flat'
        (flat / 'builds').mkdir(parents=True)
        for n in ('d2kd', 'd2kc', 'd2kpanel', 'd2ktg'):
            shutil.copy2(bdir / f'{n}-linux-arm64', flat / 'builds' / f'{n}-linux-arm64')
        for part in ('files', 'scripts', 'internal/web/assets'):
            shutil.copytree(src / part, flat / part)
    (dest / 'fixture.json').write_text(json.dumps(info, indent=1, sort_keys=True) + '\n')


def adopt(args):
    """Принять уже собранный и подписанный выпуск Task 8, не изменяя его."""
    base = pathlib.Path(args.out).resolve()
    base.mkdir(parents=True, exist_ok=True)
    t8 = pathlib.Path(args.task8).resolve()
    meta = json.loads((t8 / 'release-build.json').read_text())
    rid, commit, epoch = meta['release_id'], meta['commit'], str(meta['epoch'])
    release = t8 / 'rt/release'
    if not (release / 'manifest.json.sig').exists() or 'Traceback' in (t8 / 'package.log').read_text():
        raise SystemExit('Task 8 output is incomplete')
    # Тестовый ключ Task 8 становится ключом лаборатории: выпуск остаётся нетронутым.
    if not (base / 'TEST-signing.pem').exists():
        shutil.copyfile(t8 / 'rt/FIXTURE-only.pem', base / 'TEST-signing.pem')
    work = base / ('work-' + rid)
    work.mkdir()
    src = work / 'source'
    clone(args.repo, commit, src)
    export(base, rid, src, t8 / 'build', release, commit, epoch, 'Task 8 final output, consumed unmodified: ' + str(t8), bootstrap=[])
    print('adopted Task 8 release', rid, flush=True)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--repo', required=True); b.add_argument('--commit', required=True); b.add_argument('--id', required=True)
    b.add_argument('--out', required=True); b.add_argument('--deps', required=True); b.add_argument('--zig', required=True)
    b.add_argument('--zig-mips64el', required=True); b.add_argument('--bootstrap', action='store_const', const=[], default=None)
    a = sub.add_parser('adopt')
    a.add_argument('--repo', required=True); a.add_argument('--task8', required=True); a.add_argument('--out', required=True)
    args = p.parse_args()
    try:
        {'build': build, 'adopt': adopt}[args.cmd](args)
    except subprocess.CalledProcessError as e:
        print('fixture preparation failed:', e, file=sys.stderr)
        raise SystemExit(3)


if __name__ == '__main__':
    main()
