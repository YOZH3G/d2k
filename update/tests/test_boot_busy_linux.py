#!/usr/bin/env python3
"""Linux: загрузка при занятой блокировке обслуживания. S99 boot-start держит
maintenance несколько секунд, пока S98 уже запустил супервизор: тот обязан
дождаться, а не выйти с BUSY и оставить обновлятор мёртвым до перезагрузки.
Частный корень, настоящие boot/daemon, без сети и служб."""
import fcntl, os, pathlib, shutil, subprocess, sys, tempfile, time
if sys.platform != 'linux':
    raise SystemExit('run inside the isolated Linux fixture')
worker, boot, adapter = (pathlib.Path(p).resolve() for p in sys.argv[1:4])
with tempfile.TemporaryDirectory(prefix='d2ku-busy-', dir='/tmp') as tmp:
    root = pathlib.Path(tmp).resolve()
    for p in ('boot', 'state', 'run', 'releases/old', 'update-state'):
        (root / p).mkdir(parents=True, mode=0o700)
    (root / 'current').symlink_to('releases/old')
    shutil.copy2(worker, root / 'releases/old/d2k-update')
    shutil.copy2(adapter, root / 'boot/d2k-service-adapter')
    (root / 'config').write_text(f'MODE=off\nPANEL_ENABLED=0\nD2K_RUNTIME_DIR={root}/run\nSTATE_DIR={root}/state\n')
    (root / 'boot/update.conf').write_text('D2KU-CONFIG-1\nfeed=https://updates.invalid\nhost=updates.invalid\nca=/nonexistent/fixture-ca\nabi=arm64\nbuild=4102444800\nkey=' + '01' + '00' * 31 + ' 1 4102444801\n')
    (root / 'boot/update.conf').chmod(0o600)
    lock = os.open(root / 'update-state/maintenance.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX)
    # Синхронное восстановление S98 при занятом обслуживании (NDM, ручной restart).
    rec = subprocess.Popen([boot, '--root', root, '--recover'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    assert rec.poll() is None, f'--recover gave up while maintenance was busy: {rec.communicate()}'
    fcntl.flock(lock, fcntl.LOCK_UN)
    assert rec.wait(timeout=30) == 0, rec.communicate()
    fcntl.flock(lock, fcntl.LOCK_EX)
    proc = subprocess.Popen([boot, '--root', root, '--daemon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(3)
        assert proc.poll() is None, f'supervisor gave up while maintenance was busy: {proc.communicate()}'
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
        for _ in range(150):
            if (root / 'update-state/updater.sock').exists():
                break
            assert proc.poll() is None, f'supervisor exited after maintenance was released: {proc.communicate()}'
            time.sleep(0.1)
        else:
            raise AssertionError('updater socket never appeared')
        r = subprocess.run([worker, '--root', root, 'status'], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0 and '"unchecked"' in r.stdout, r.stdout + r.stderr
    finally:
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=15)
    print('boot under busy maintenance: supervisor waited and published the updater: PASS')
