#!/usr/bin/env python3
"""Only disposable --init --network none --cap-add NET_ADMIN Linux container.
Uses private container /opt (NO HOST MOUNT), actual historical ARM64 binaries,
private NFQUEUE/rules and ephemeral TEST Ed25519 signature. Takes BOOT ADAPTER
HISTORY_DIR TRANSACTION_TEST CANDIDATE. No external targets or router access.
"""
import hashlib,io,json,os,pathlib,shutil,subprocess,sys,tarfile,tempfile,threading,time
assert sys.platform=='linux' and os.environ.get('D2KU_LEGACY_LAB')=='1'
boot,adapter,old,test,candidate=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:6]);repo=pathlib.Path(__file__).resolve().parents[2]
root=pathlib.Path('/opt/d2k');assert not root.exists(),'fresh private container required'
helpers=['d2k-fw-heal.sh','d2k-tg-firewall.sh','d2k-tg-watchdog.sh','d2k-ppe-deoffload.sh','d2k-instagram-dns.sh','d2k-instagram-dns-scheduler.sh','d2k-log-maintenance.sh']
with tempfile.TemporaryDirectory(prefix='legacy-first-') as temporary:
    tmp=pathlib.Path(temporary);bundle=tmp/'bundle';signed=tmp/'signed'
    for d in [root/'state',root/'panel',root/'files',root/'run',root/'log',pathlib.Path('/opt/sbin'),pathlib.Path('/opt/etc/init.d'),pathlib.Path('/opt/etc/ndm/netfilter.d'),bundle,signed]:d.mkdir(parents=True,mode=0o700,exist_ok=True)
    for name in ['d2kd','d2kc','d2kpanel','d2ktg']:shutil.copy2(old/(name+'-linux-arm64'),pathlib.Path('/opt/sbin')/name)
    for name in helpers:
        shutil.copy2(repo/'files'/name,root/name);shutil.copy2(repo/'files'/name,bundle/name)
    for name in ['S99d2k','S98d2k-update','001-d2k.sh']:shutil.copy2(repo/'files'/name,bundle/name)
    shutil.copy2(repo/'files/S99d2k','/opt/etc/init.d/S99d2k');shutil.copy2(repo/'files/001-d2k.sh','/opt/etc/ndm/netfilter.d/001-d2k.sh')
    shutil.copy2(repo/'scripts/uninstall.sh',bundle/'uninstall.sh');shutil.copy2(boot,bundle/'d2k-update-boot');shutil.copy2(adapter,bundle/'d2k-service-adapter')
    (root/'config').write_text('MODE=observe\nTG_ENABLED=0\nQUEUE_NUM=30000\nD2K_PPE_DEOFFLOAD=0\nD2K_RUNTIME_DIR=/tmp/d2k\nLOG_EVERY=1\n');(root/'config').chmod(0o600)
    pathlib.Path('/tmp/d2k').mkdir(mode=0o700,exist_ok=True)
    (root/'state/catalog.json').write_text('{"boxes":[]}\n');(root/'state/tg.identity').write_text('private fixture\n');(root/'files/asset').write_text('retained old hardcoded resource\n')
    processes=[]
    def start(name,args,pidfile):
        p=subprocess.Popen(['/opt/sbin/'+name,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(p);(root/'run'/pidfile).write_text(str(p.pid)+'\n');return p
    dp=start('d2kd',['--queue','30000','--control',str(root/'run/d2kd.sock'),'--mode','observe','--stats','1','--log',str(root/'log/d2kd.log')],'d2kd.pid')
    for _ in range(100):
        if (root/'run/d2kd.sock').exists():break
        assert dp.poll() is None;time.sleep(.05)
    core=start('d2kc',['--control',str(root/'run/d2kd.sock'),'--catalog',str(root/'state/catalog.json'),'--live','/tmp/d2k/live.json','--log',str(root/'log/d2kc.log'),'--https-cache',str(root/'state/https-cache.json')],'d2k.pid')
    for _ in range(100):
        if pathlib.Path('/tmp/d2k/live.json').exists():break
        assert core.poll() is None;time.sleep(.05)
    assert '"linked": true' in pathlib.Path('/tmp/d2k/live.json').read_text()
    # Reap our original children while production stop waits for disappearance.
    old_helper=subprocess.Popen([root/'d2k-log-maintenance.sh','run'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(old_helper)
    (root/'run/d2k-log-maintenance.pid').write_text(str(old_helper.pid)+'\n')
    done=False
    def reaper():
        while not done:
            for p in processes:p.poll()
            time.sleep(.02)
    threading.Thread(target=reaper,daemon=True).start()
    subprocess.run([boot,'--root',root,'--bootstrap',bundle],check=True,timeout=30)
    release=root/(root/'current').readlink();assert (root/'update-state/enabled').read_text()=='3\n'
    assert dp.poll() is None and core.poll() is None,'preparation stopped old runtime'
    # Real signatures bind every candidate byte; deliberate start failure only.
    files={name:candidate.read_bytes() for name in ['d2kd','d2kc','d2kpanel','d2ktg','d2k-update']}
    files['S99d2k']=b'#!/bin/sh\ncase "$2" in start) exit 1;; *) exit 0;; esac\n'
    with tarfile.open(signed/'candidate.tar','w',format=tarfile.USTAR_FORMAT) as tar:
        for name,data in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755;info.uid=info.gid=0;tar.addfile(info,io.BytesIO(data))
    archive=(signed/'candidate.tar').read_bytes();now=int(time.time());key=signed/'TEST-key.pem'
    def openssl(*a):return subprocess.check_output(['openssl',*map(str,a)],stderr=subprocess.DEVNULL)
    openssl('genpkey','-algorithm','ED25519','-out',key);(signed/'TEST-public').write_bytes(openssl('pkey','-in',key,'-pubout','-outform','DER')[-32:])
    def seal(name,obj):
        path=signed/name;data=json.dumps(obj,separators=(',',':')).encode();path.write_bytes(data);openssl('pkeyutl','-sign','-inkey',key,'-rawin','-in',path,'-out',str(path)+'.sig');return data
    manifest=dict(schema=1,release_id='legacy-test-new',version='TEST',commit='a'*40,built_at=now-10,notes='Private signed failed-start candidate',min_updater=1,wire=13,state=1,packages=[dict(abi='arm64',artifact='candidate.tar',size=len(archive),sha256=hashlib.sha256(archive).hexdigest(),files=[dict(path=name,size=len(data),mode=493,sha256=hashlib.sha256(data).hexdigest()) for name,data in sorted(files.items())])])
    data=seal('manifest.json',manifest);seal('index.json',dict(schema=1,channel='stable',sequence=1,issued_at=now-5,expires_at=now+1800,release_id='legacy-test-new',manifest_sha256=hashlib.sha256(data).hexdigest()))
    result=subprocess.run([test,root,signed],timeout=210)
    done=True
    if result.returncode:
        for path in (root/'log').glob('*.log'):print(path, path.read_text(errors='replace')[-3000:],flush=True)
    assert result.returncode==0,result.returncode
    assert old_helper.poll() is not None,'pre-guard helper survived coherent snapshot'
    assert (root/'current').readlink()==release.relative_to(root)
    assert (root/'update-state/enabled').read_text()=='3\n'
    assert (root/'state/tg.identity').read_text()=='private fixture\n'
    assert not (root/'run/d2k-panel.pid').exists() and not (root/'run/d2ktg.pid').exists()
    from test_legacy_waiter_linux import stop_preserving_waiter
    stop_preserving_waiter(adapter,root)
print('historical active flat -> signed failed candidate -> actual legacy NFQUEUE recovery: PASS',flush=True)
