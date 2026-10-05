#!/usr/bin/env python3
"""Linux: isolated private filesystem and real boot/daemon/adapter; no network.
Service fixture deletes only its private updater after quiescence acknowledgement.
"""
import fcntl,json,os,pathlib,shutil,subprocess,sys,tempfile,time
if sys.platform!='linux':raise SystemExit('run supervised integration inside isolated Linux fixture')
worker,boot,adapter=map(lambda x:pathlib.Path(x).resolve(),sys.argv[1:4])
with tempfile.TemporaryDirectory(prefix='d2ku-supervised-') as tmp:
    root=pathlib.Path(tmp);(root/'boot').mkdir();(root/'state').mkdir();(root/'run').mkdir(mode=0o700);(root/'releases/old').mkdir(parents=True)
    (root/'current').symlink_to('releases/old');shutil.copy2(worker,root/'releases/old/d2k-update');shutil.copy2(adapter,root/'boot/d2k-service-adapter')
    (root/'config').write_text(f'MODE=off\nPANEL_ENABLED=0\nD2K_RUNTIME_DIR={root}/run\nSTATE_DIR={root}/state\n')
    (root/'boot/update.conf').write_text('D2KU-CONFIG-1\nfeed=https://updates.invalid\nhost=updates.invalid\nca=/nonexistent/fixture-ca\nabi=arm64\nbuild=4102444800\nkey='+'01'+'00'*31+' 1 4102444801\n')
    (root/'boot/update.conf').chmod(0o600)
    service=root/'releases/old/S99d2k'
    service.write_text('#!/bin/sh\n[ "$2" = uninstall ] || exit 1\n[ "$(cut -d " " -f2 "$D2K_DIR/update-state/lifecycle")" = 1 ] || exit 2\nrm "$D2K_RELEASE_ROOT/d2k-update"\nprintf removed > "$D2K_DIR/removal"\n');service.chmod(0o700)
    proc=subprocess.Popen([boot,'--root',root,'--daemon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(150):
            if (root/'update-state/updater.sock').exists():break
            if proc.poll() is not None:raise AssertionError(proc.communicate())
            time.sleep(.02)
        p=subprocess.run([worker,'--root',root,'status'],capture_output=True,text=True,check=True);assert json.loads(p.stdout)['state']=='unchecked'
        p=subprocess.run([adapter,'--root',root,'service','check'],capture_output=True,text=True,timeout=5);assert p.returncode==0,(p.stdout,p.stderr)
        p=subprocess.run([adapter,'--root',root,'service','install'],capture_output=True,text=True);assert p.returncode==2 and 'not installed' in p.stderr
        time.sleep(.2)
        p=subprocess.run([adapter,'--root',root,'service','uninstall'],capture_output=True,text=True,timeout=15)
        assert p.returncode==0,(p.stdout,p.stderr)
        assert proc.wait(timeout=5)==0,proc.communicate()
        assert (root/'removal').read_text()=='removed' and not (root/'releases/old/d2k-update').exists()
        assert (root/'update-state/lifecycle').read_text().startswith('D2KL1 1 ')
        # Reboot/second entry must never resurrect or recover the removed runtime.
        assert subprocess.run([boot,'--root',root,'--daemon'],capture_output=True,timeout=5).returncode!=0
        assert subprocess.run([adapter,'--root',root,'service','start'],capture_output=True,timeout=5).returncode!=0
    finally:
        if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
    print('supervised updater: real heartbeat/SCM held maintenance/quiesce ACK/delete/reboot guard: PASS')
