#!/usr/bin/env python3
"""Linux: стабильный супервизор — subreaper для всего, что запускает транзакция.
Демоны служб (start-stop-daemon -b) усыновляются им и после завершения обязаны
быть собраны: зомби с его PPID считаются «живыми» проверкой running в S99d2k,
управляемая остановка ждёт, добивает SIGKILL и объявляет отказ (recovery_failed).
Частный корень, фиктивный worker с протоколом heartbeat, без сети и служб."""
import os, pathlib, subprocess, sys, tempfile, time
if sys.platform != 'linux':
    raise SystemExit('subreaper semantics are Linux only')
boot = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='d2ku-reap-', dir='/tmp') as tmp:
    root = pathlib.Path(tmp).resolve()
    for p in ('boot', 'state', 'run', 'releases/old'):
        (root / p).mkdir(parents=True, mode=0o700)
    (root / 'current').symlink_to('releases/old')
    (root / 'config').write_text(f'MODE=off\nPANEL_ENABLED=0\nD2K_RUNTIME_DIR={root}/run\nSTATE_DIR={root}/state\n')
    worker = root / 'worker.sh'
    # Двойной fork: внук теряет родителя и усыновляется ближайшим subreaper.
    worker.write_text('#!/bin/sh\nprintf "D2KU1 READY\\n" >&3\n( ( sleep 0.3 ) & )\ni=0\nwhile [ $i -lt 5 ]; do printf "D2KU1 PULSE\\n" >&3; sleep 1; i=$((i+1)); done\nexit 0\n')
    worker.chmod(0o700)
    proc = subprocess.Popen([boot, '--root', root, '--supervise', worker], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(2.5)
        zombies = []
        for d in os.listdir('/proc'):
            if not d.isdigit():
                continue
            try:
                fields = dict(l.split(':', 1) for l in open(f'/proc/{d}/status') if ':' in l)
            except OSError:
                continue
            if fields.get('State', '').strip().startswith('Z') and int(fields.get('PPid', '0')) == proc.pid:
                zombies.append((int(d), fields.get('Name', '').strip()))
        assert not zombies, f'supervisor left adopted zombies: {zombies}'
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)
    print('supervisor reaps adopted descendants: no zombies under the subreaper: PASS')
