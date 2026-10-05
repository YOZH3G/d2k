#!/usr/bin/env python3
"""ISOLATED LINUX CONTAINER ONLY (D2KU_LEGACY_LAB=1), no host mounts/network.
Arguments: BOOT ADAPTER HISTORICAL_DIR. Historical binaries only perform offline
CLI during the first fixture. Follow-on lifecycle uses private root/listeners.
The harness never invokes router scripts outside its private root.
"""
import os,pathlib,shutil,subprocess,sys,tempfile,time
assert sys.platform=='linux' and os.environ.get('D2KU_LEGACY_LAB')=='1','isolated container required'
boot,adapter,old=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:4]);repo=pathlib.Path(__file__).resolve().parents[2]
helpers=['d2k-fw-heal.sh','d2k-tg-firewall.sh','d2k-tg-watchdog.sh','d2k-ppe-deoffload.sh','d2k-instagram-dns.sh','d2k-instagram-dns-scheduler.sh','d2k-log-maintenance.sh']
with tempfile.TemporaryDirectory(prefix='d2ku-wire12-') as temporary:
    tmp=pathlib.Path(temporary);prefix=tmp/'opt';root=prefix/'d2k';bundle=tmp/'bundle'
    for directory in [root/'state',root/'panel',root/'files',prefix/'sbin',prefix/'etc/init.d',prefix/'etc/ndm/netfilter.d',bundle]:directory.mkdir(parents=True,mode=0o700)
    for name in ['d2kd','d2kc','d2kpanel','d2ktg']:shutil.copy2(old/(name+'-linux-arm64'),prefix/'sbin'/name)
    for name in helpers:
        shutil.copy2(repo/'files'/name,root/name);shutil.copy2(repo/'files'/name,bundle/name)
    shutil.copy2(repo/'files/S99d2k',prefix/'etc/init.d/S99d2k');shutil.copy2(repo/'files/001-d2k.sh',prefix/'etc/ndm/netfilter.d/001-d2k.sh')
    for name in ['S99d2k','S98d2k-update','001-d2k.sh']:shutil.copy2(repo/'files'/name,bundle/name)
    shutil.copy2(repo/'scripts/uninstall.sh',bundle/'uninstall.sh');shutil.copy2(boot,bundle/'d2k-update-boot');shutil.copy2(adapter,bundle/'d2k-service-adapter')
    (root/'config').write_text(f'MODE=off\nTG_ENABLED=0\nSTATE_DIR={root}/state\nD2K_RUNTIME_DIR={tmp}/runtime\nD2K_PPE_DEOFFLOAD=0\n');(root/'config').chmod(0o600)
    (root/'state/catalog.json').write_text('personal learned data\n');(root/'state/tg.identity').write_text('private fixture\n');(root/'files/asset').write_text('historical resource\n')
    before={name:(root/name).read_bytes() for name in ['config','state/catalog.json','state/tg.identity','files/asset']}
    # Explicit disabled intent must not bypass binding a live stale/wrong PID.
    (root/'run').mkdir(mode=0o700);(root/'update-state').mkdir(mode=0o700);(root/'update-state/enabled').write_text('0\n')
    foreign=subprocess.Popen(['sleep','30'])
    (root/'run/d2kd.pid').write_text(str(foreign.pid)+'\n')
    refused=subprocess.run([boot,'--root',root,'--bootstrap',bundle],capture_output=True,timeout=25)
    assert refused.returncode!=0 and b'result=10' in refused.stderr and foreign.poll() is None and not (root/'current').exists(),refused.stderr
    foreign.terminate();foreign.wait();(root/'run/d2kd.pid').unlink()
    if (old/'wire13-d2kc').exists():
        shutil.copy2(old/'wire13-d2kc',prefix/'sbin/d2kc')
        refused=subprocess.run([boot,'--root',root,'--bootstrap',bundle],capture_output=True,timeout=25)
        assert refused.returncode!=0 and b'result=5' in refused.stderr and not (root/'current').exists(),'mixed wire13 controller admitted as wire12'
        shutil.copy2(old/'d2kc-linux-arm64',prefix/'sbin/d2kc')
    (root/'files/.bootstrap-123-4').write_text('legitimate but reserved source name')
    refused=subprocess.run([boot,'--root',root,'--bootstrap',bundle],capture_output=True,timeout=25)
    assert refused.returncode!=0 and b'result=5' in refused.stderr and not (root/'current').exists(),refused.stderr
    assert (root/'files/.bootstrap-123-4').read_text()=='legitimate but reserved source name'
    (root/'files/.bootstrap-123-4').unlink()
    if len(sys.argv)>4:
        subprocess.run([str(pathlib.Path(sys.argv[4]).resolve()),root,bundle],check=True,timeout=360)
    # Actual historical panel and TG stay inside this network-none container.
    # No browser/API calls; TG registration can only reach a closed loopback port.
    (root/'log').mkdir(mode=0o700,exist_ok=True)
    (tmp/'runtime').mkdir(mode=0o700,exist_ok=True)
    (root/'config').write_text((root/'config').read_text().replace('TG_ENABLED=0', 'TG_ENABLED=1'))
    with (root/'config').open('a') as f:
        f.write(f'PANEL_LISTEN=127.0.0.1:18090\nTG_RELAY_URL=wss://127.0.0.1:1/ws\nTG_RELAY_SECRET=private-test-only\nTG_PORT=1443\nTG_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nTG_IDENTITY={root}/state/active.identity\nTG_STATUS={root}/state/telegram.status\n')
    before['config']=(root/'config').read_bytes()
    panel_args=['serve','--config',str(root/'config'),'--live',str(tmp/'runtime/live.json'),'--assets',str(root/'panel'),'--listen','127.0.0.1:18090','--state-dir',str(root/'state'),'--mode','off','--queue','2000','--service',str(prefix/'etc/init.d/S99d2k'),'--engine-pid',str(root/'run/d2kd.pid'),'--controller-pid',str(root/'run/d2k.pid'),'--telegram-pid',str(root/'run/d2ktg.pid'),'--telegram-status',str(root/'state/telegram.status'),'--log',str(root/'log/panel.log')]
    for option in ['--state-dir','--assets','--service','--telegram-status']:
        divergent=panel_args.copy();divergent[divergent.index(option)+1]=str(tmp/'outside')
        (tmp/'outside').mkdir(exist_ok=True)
        panel=subprocess.Popen([prefix/'sbin/d2kpanel',*divergent],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            (root/'run/d2k-panel.pid').write_text(str(panel.pid)+'\n');time.sleep(.1)
            assert panel.poll() is None,('divergent historical fixture exited',option)
            refused=subprocess.run([boot,'--root',root,'--bootstrap',bundle],capture_output=True,timeout=25)
            assert refused.returncode!=0 and b'result=10' in refused.stderr and not (root/'current').exists(),('unpreserved panel resource admitted',option,refused.stderr)
            assert panel.poll() is None,'refusal stopped old process'
        finally:
            panel.terminate();panel.wait(timeout=10);(root/'run/d2k-panel.pid').unlink()
    panel=subprocess.Popen([prefix/'sbin/d2kpanel',*panel_args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tg=subprocess.Popen([prefix/'sbin/d2ktg','--config',root/'config','--log',root/'log/telegram.log'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        (root/'run/d2k-panel.pid').write_text(str(panel.pid)+'\n')
        (root/'run/d2ktg.pid').write_text(str(tg.pid)+'\n')
        for _ in range(100):
            assert panel.poll() is None and tg.poll() is None,('historical active fixture exited',panel.poll(),tg.poll(),[(p.name,p.read_text()) for p in (root/'log').glob('*')])
            if (root/'state/telegram.status').exists():break
            time.sleep(.05)
        assert (root/'state/telegram.status').read_text().strip()=='connecting'
        completed=subprocess.run([boot,'--root',root,'--bootstrap',bundle],text=True,capture_output=True,timeout=25)
        assert completed.returncode==0,('active historical panel/TG admission',completed.stdout,completed.stderr)
        assert panel.poll() is None and tg.poll() is None,'preparation stopped active runtime'
    finally:
        for process in [panel,tg]:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        (root/'run/d2k-panel.pid').unlink();(root/'run/d2ktg.pid').unlink()

    assert completed.returncode==0,(completed.stdout,completed.stderr)
    assert 'preparation only' in completed.stderr,completed.stderr
    release=root/(root/'current').readlink()
    assert (release/'.d2ku-legacy').read_text().startswith('D2KV1 flat-wire12-2026-10-04 ')
    assert not (release/'.d2ku-receipt').exists()
    assert (release/'.d2ku-legacy').read_bytes()==(root/'update-state/legacy-source').read_bytes()
    assert (root/'update-state/enabled').read_text()=='0\n'
    assert not (root/'update/legacy-personal').exists(),'live personal data falsely marked coherent'
    assert not (root/'update/legacy-flat/flat-config').exists(),'secret included in immutable code seal'
    for name,data in before.items():assert (root/name).read_bytes()==data,name
    command=subprocess.run([adapter,'--root',root,'service','status'],capture_output=True,text=True,timeout=10)
    assert command.returncode==0,(command.stdout,command.stderr)
    (release/'d2kd').write_bytes(b'tampered')
    command=subprocess.run([adapter,'--root',root,'service','status'],capture_output=True,timeout=10)
    assert command.returncode!=0,'unsealed code executed'
    command=subprocess.run([adapter,'--root',root,'--launch','d2kd','--help'],capture_output=True,timeout=10)
    assert command.returncode!=0,'unsealed binary alias executed'
print('historical wire12 CLI/bootstrap: safe preparation, typed local inventory, disabled intent, personal preservation, tamper refusal: PASS')
