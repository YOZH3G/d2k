#!/usr/bin/env python3
"""Private roots; test-build pipe barriers pause real processes. No live network.
Run with D2KU_TEST_STARTUP binaries. The remover invokes only owned fixture code.
"""
import json, os, pathlib, select, shutil, subprocess, sys, tempfile, time
if sys.platform != 'linux': raise SystemExit('startup/remover integration requires isolated Linux')
worker, boot, adapter = [pathlib.Path(p).resolve() for p in sys.argv[1:4]]
mode = sys.argv[4] if len(sys.argv) > 4 else 'serve'
with tempfile.TemporaryDirectory(prefix='d2ku-startup-', dir='/tmp') as tmp:
    root = pathlib.Path(tmp).resolve()
    for p in ['boot','state','run','releases/old']:
        (root/p).mkdir(parents=True, mode=0o700)
    (root/'current').symlink_to('releases/old')
    shutil.copy2(worker, root/'releases/old/d2k-update')
    shutil.copy2(adapter, root/'boot/d2k-service-adapter')
    (root/'config').write_text(f'MODE=off\nPANEL_ENABLED=0\nD2K_RUNTIME_DIR={root}/run\nSTATE_DIR={root}/state\n')
    (root/'boot/update.conf').write_text('D2KU-CONFIG-1\nfeed=https://updates.invalid\nhost=updates.invalid\nca=/nonexistent/test-ca\nabi=arm64\nbuild=4102444800\nkey='+'01'+'00'*31+' 1 4102444801\n')
    (root/'boot/update.conf').chmod(0o600)
    service = root/'releases/old/S99d2k'
    service.write_text('#!/bin/sh\n[ "$2" = uninstall ] || exit 1\n[ "$(cut -d " " -f2 "$D2K_DIR/update-state/lifecycle")" = 1 ] || exit 2\nrm "$D2K_RELEASE_ROOT/d2k-update"\nprintf removed > "$D2K_DIR/removal"\n')
    service.chmod(0o700)
    script = root/'fixture-worker'
    script.write_text(f'#!/bin/sh\nprintf resurrected > "{root}/resurrected"\nexit 0\n'); script.chmod(0o700)
    # Keep barrier descriptors outside protocol fd3/root4/control5.
    hold = [os.open('/dev/null', os.O_RDONLY) for _ in range(6)]
    ready_r, ready_w = os.pipe(); resume_r, resume_w = os.pipe()
    args = [worker,'--root',root,'serve'] if mode == 'serve' else [boot,'--root',root,'--'+mode]
    if mode == 'supervise': args += [script]
    env = dict(os.environ, D2KU_TEST_STARTUP_ROLE='daemon' if mode == 'serve' else 'supervisor',
               D2KU_TEST_STARTUP_FDS=f'{ready_w}:{resume_r}')
    process = subprocess.Popen(args,env=env,pass_fds=(ready_w,resume_r),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.close(ready_w); os.close(resume_r)
    try:
        assert select.select([ready_r],[],[],5)[0], process.poll()
        assert os.read(ready_r,1) == b'R'
        removed = subprocess.run([adapter,'--root',root,'service','uninstall'],capture_output=True,text=True,timeout=15)
        assert removed.returncode == 0, (removed.stdout,removed.stderr)
        assert (root/'removal').read_text() == 'removed'
        assert (root/'update-state/lifecycle').read_text().startswith('D2KL1 1 ')
        os.write(resume_w,b'G')
        try: result = process.wait(timeout=5)
        except subprocess.TimeoutExpired: raise AssertionError('paused starter resumed serving after uninstall')
        assert result != 0, process.communicate()
        assert not (root/'update-state/updater.sock').exists()
        assert not (root/'resurrected').exists()
        assert not (root/'update-state'/('daemon.lock' if mode=='serve' else 'supervisor.lock')).exists()
        print(f'startup fence {mode}: paused process cannot claim ownership or publish after stopped ACK: PASS')
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
        for fd in [ready_r,resume_w,*hold]: os.close(fd)
