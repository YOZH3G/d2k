#!/usr/bin/env python3
"""ISOLATED LINUX CONTAINER ONLY (D2KU_LEGACY_LAB=1), no host mounts/network.
Arguments: BOOT ADAPTER HISTORICAL_DIR. Historical binaries only perform offline
CLI during the first fixture. Follow-on lifecycle uses private root/listeners.
The harness never invokes router scripts outside its private root.
"""
import os,pathlib,shutil,subprocess,sys,tempfile
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
    completed=subprocess.run([boot,'--root',root,'--bootstrap',bundle],text=True,capture_output=True,timeout=25)
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
