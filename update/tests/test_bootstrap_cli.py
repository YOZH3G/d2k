#!/usr/bin/env python3
"""Execute stable bootstrap against a private flat installation. Runtime binaries
are offline metadata fixtures; firewall commands are fixed failing boundaries.
No production directories, services, rules or external network are used.
"""
import pathlib, shutil, subprocess, sys, tempfile
boot=pathlib.Path(sys.argv[1]).resolve(); adapter=pathlib.Path(sys.argv[2]).resolve()
repo=pathlib.Path(__file__).resolve().parents[2]
helpers=['d2k-fw-heal.sh','d2k-tg-firewall.sh','d2k-tg-watchdog.sh','d2k-ppe-deoffload.sh','d2k-instagram-dns.sh','d2k-instagram-dns-scheduler.sh','d2k-log-maintenance.sh']
for wire in [12,13]:
    with tempfile.TemporaryDirectory(prefix='d2ku-bootstrap-cli-') as temp:
        temp=pathlib.Path(temp); prefix=temp/'opt'; root=prefix/'d2k'; bundle=temp/'bundle'; commands=temp/'commands'
        for directory in [root/'state',root/'panel',root/'files',prefix/'sbin',prefix/'etc'/'init.d',prefix/'etc'/'ndm'/'netfilter.d',bundle,commands]: directory.mkdir(parents=True,mode=0o700)
        for name in ['iptables','ip6tables','ipset','start-stop-daemon']:
            (commands/name).write_text('#!/bin/sh\ncase "$*" in *-S*) exit 0;; esac\nexit 1\n'); (commands/name).chmod(0o700)
        for name in ['d2kd','d2kc','d2kpanel','d2ktg']:
            (prefix/'sbin'/name).write_text(f'#!/bin/sh\nprintf "{name} self-check=ok release=fixture wire={wire}\\n"\n'); (prefix/'sbin'/name).chmod(0o700)
        for name in helpers:
            (root/name).write_text('#!/bin/sh\nexit 0\n'); (root/name).chmod(0o700)
            shutil.copyfile(repo/'files'/name,bundle/name); (bundle/name).chmod(0o700)
        for name in ['S99d2k','S98d2k-update','001-d2k.sh']:
            shutil.copyfile(repo/'files'/name,bundle/name); (bundle/name).chmod(0o700)
        shutil.copyfile(repo/'scripts'/'uninstall.sh',bundle/'uninstall.sh'); (bundle/'uninstall.sh').chmod(0o700)
        shutil.copy2(boot,bundle/'d2k-update-boot'); shutil.copy2(adapter,bundle/'d2k-service-adapter')
        (prefix/'etc'/'init.d'/'S99d2k').write_text('old init\n')
        (prefix/'etc'/'ndm'/'netfilter.d'/'001-d2k.sh').write_text('old ndm\n')
        (root/'panel'/'index.html').write_text('old panel\n'); (root/'files'/'tg-roots.pem').write_text('old public CA\n')
        (root/'config').write_text(f'MODE=off\nTG_ENABLED=0\nSTATE_DIR={root}/state\nD2K_RUNTIME_DIR={temp}/runtime\nFW_LOCK={temp}/fw.lock\nPATH={commands}:/usr/bin:/bin:/sbin\nD2K_PPE_DEOFFLOAD=0\n')
        (root/'config').chmod(0o600)
        (root/'state'/'catalog.json').write_text('learned\n'); (root/'state'/'tg.identity').write_text('fixture secret\n')
        before={name:(root/name).read_bytes() for name in ['config','state/catalog.json','state/tg.identity']}
        result=subprocess.run([boot,'--root',root,'--bootstrap',bundle],capture_output=True,text=True,timeout=20)
        if wire==12:
            assert result.returncode!=0 and not (root/'current').exists(),(result.stdout,result.stderr)
            assert (prefix/'etc'/'init.d'/'S99d2k').read_text()=='old init\n'
        else:
            assert result.returncode==0,(result.stdout,result.stderr)
            assert (root/'current').is_symlink() and (prefix/'etc'/'init.d'/'S98d2k-update').is_file()
            assert (root/'update-state'/'enabled').read_text()=='0\n'
            for name,data in before.items(): assert (root/name).read_bytes()==data,name
            retry=subprocess.run([boot,'--root',root,'--recover'],capture_output=True,text=True,timeout=10)
            assert retry.returncode==0,(retry.stdout,retry.stderr)
            missing=subprocess.run([boot,'--root',root,'--daemon'],capture_output=True,text=True,timeout=10)
            assert missing.returncode!=0 and 'unavailable' in missing.stderr
print('actual bootstrap CLI: rejects old wire before stop, migrates fixture, preserves personal files and disabled services, recovers, missing daemon explicit: PASS')
