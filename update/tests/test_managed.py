#!/usr/bin/env python3
"""Private filesystem only. Actual C lifecycle and shipped shell rule checks;
iptables/ipset command boundaries are snapshots, never host network mutations.
"""
import fcntl, http.server, os, pathlib, shutil, subprocess, sys, tempfile, threading, time
adapter=pathlib.Path(sys.argv[1]).resolve()
repo=pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='d2ku-managed-') as temp:
    root=pathlib.Path(temp); (root/'boot').mkdir(); (root/'update-state').mkdir(mode=0o700)
    (root/'releases'/'old').mkdir(parents=True); (root/'releases'/'new').mkdir(); (root/'commands').mkdir()
    shutil.copy2(adapter,root/'boot'/'d2k-service-adapter')
    for release in ['old','new']:
        for name in ['S99d2k','d2k-tg-firewall.sh','d2k-ppe-deoffload.sh']:
            shutil.copy2(repo/'files'/name,root/'releases'/release/name); (root/'releases'/release/name).chmod(0o700)
    (root/'current').symlink_to('releases/old')
    (root/'update-state'/'enabled').write_text('15\n'); (root/'update-state'/'enabled').chmod(0o600)
    (root/'config').write_text(f'PATH={root}/commands:/usr/bin:/bin\nMODE=apply\nTG_ENABLED=1\nSTATE_DIR={root}/state\nD2K_RUNTIME_DIR={root}/runtime\nD2K_PPE_DEOFFLOAD=0\n')
    (root/'config').chmod(0o600)
    for name in ['iptables','ip6tables','ipset']:
        (root/'commands'/name).write_text('''#!/bin/sh
[ "${1:-}" != -w ] || shift
line="${0##*/} $*"
printf '%s\\n' "$line" >> "$CALLS"
[ "$line" != "${MISSING:-}" ]
'''); (root/'commands'/name).chmod(0o700)
    lock=os.open(root/'update-state'/'maintenance.lock',os.O_CREAT|os.O_RDWR,0o600)
    if lock!=4: os.dup2(lock,4); os.close(lock)
    fcntl.flock(4,fcntl.LOCK_EX)
    env={**os.environ,'CALLS':str(root/'calls')}
    def internal(action='health-rules',mask='15',extra=None):
        return subprocess.run([adapter,'--root',root,'--maintenance-fd','4',action,'-',mask],pass_fds=(4,),env={**env,**(extra or {})},capture_output=True,text=True,timeout=10)
    result=internal(); assert result.returncode==0,(result.stdout,result.stderr)
    calls=set((root/'calls').read_text().splitlines())
    assert any('ipset test d2k_tg_dc6' in x for x in calls)
    assert any('iptables -t nat -C OUTPUT' in x and '--to-port 1443' in x for x in calls)
    assert any('ip6tables -C FORWARD' in x and 'tcp-reset' in x for x in calls)
    assert any('--queue-num 2000' in x for x in calls)
    assert all(' -C ' in x or ' test ' in x for x in calls),calls
    # Each exact mandatory expectation independently missing must fail health.
    # Broadcast has two equivalent representations and is excluded from the
    # single-missing enumeration; the existing S99 fixture covers that fallback.
    mandatory=[x for x in calls if 'BROADCAST' not in x]
    for line in mandatory:
        result=internal(extra={'MISSING':line}); assert result.returncode!=0,line
    # State is actual configured personal state, including shared-secret setups
    # that legitimately have no enrollment identity.
    (root/'state').mkdir()
    for name in ['catalog.json','tg.identity','telegram.status']:
        (root/'state'/name).write_text('fixture\n')
    assert internal('health-state').returncode==0
    for name in ['tg.identity','telegram.status']:
        (root/'state'/name).unlink(); assert internal('health-state').returncode!=0,name
        (root/'state'/name).write_text('fixture\n')
    # d2kc starts from an empty catalog when the file is absent and writes it
    # only after learning something: absence is valid state, a non-file is not.
    (root/'state'/'catalog.json').unlink(); assert internal('health-state').returncode==0
    (root/'state'/'catalog.json').mkdir(); assert internal('health-state').returncode!=0
    (root/'state'/'catalog.json').rmdir(); (root/'state'/'catalog.json').write_text('fixture\n')
    with (root/'config').open('a') as config: config.write('TG_RELAY_SECRET=fixture-only\n')
    (root/'state'/'tg.identity').unlink(); assert internal('health-state').returncode==0
    class HTTP(http.server.BaseHTTPRequestHandler):
        status=200
        def do_GET(self): self.send_response(self.status); self.end_headers()
        def log_message(self,*args): pass
    server=http.server.HTTPServer(('127.0.0.1',0),HTTP)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    with (root/'config').open('a') as config: config.write(f'PANEL_LISTEN=127.0.0.1:{server.server_port}\n')
    assert internal('health-http').returncode==0
    HTTP.status=503; assert internal('health-http').returncode!=0
    server.shutdown(); server.server_close(); thread.join()
    # Real external lifecycle waits for maintenance, then resolves current once.
    for release in ['old','new']:
        (root/'releases'/release/'S99d2k').write_text(f'#!/bin/sh\nprintf {release} > "{root}/selected"\n')
    waiter=subprocess.Popen([adapter,'--root',root,'service','heal'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    time.sleep(.2); assert waiter.poll() is None and not (root/'selected').exists()
    with (root/'config').open('a') as config: config.write(f'D2K_RUNTIME_DIR={root}/runtime-after-wait\n')
    (root/'next').symlink_to('releases/new'); os.replace(root/'next',root/'current')
    fcntl.flock(4,fcntl.LOCK_UN); os.close(4)
    stdout,stderr=waiter.communicate(timeout=5); assert waiter.returncode==0,(stdout,stderr)
    assert (root/'selected').read_text()=='new'
    assert (root/'runtime-after-wait').is_dir(), 'configuration must refresh after maintenance wait'
    (root/'releases'/'new'/'d2kc').write_text(f'#!/bin/sh\nprintf unsafe > "{root}/unmanaged-writer"\n')
    (root/'releases'/'new'/'d2kc').chmod(0o700)
    unmanaged=subprocess.run([adapter,'--root',root,'--launch','d2kc','--control',str(root/'run/socket')],capture_output=True)
    assert unmanaged.returncode!=0 and not (root/'unmanaged-writer').exists(), 'direct daemon launch bypassed maintenance lifecycle'

    # Re-enabling through restart must survive capture and the next boot start.
    (root/'releases'/'new'/'S99d2k').write_text(f'#!/bin/sh\nprintf "%s %s\\n" "$2" "$3" >> "{root}/intent"\n')
    for action, expected in [('engine-stop',12),('engine-restart',15),('boot-start',15)]:
        result=subprocess.run([adapter,'--root',root,'service',action],capture_output=True,text=True,timeout=10)
        assert result.returncode==0,(action,result.stderr)
        assert (root/'update-state'/'enabled').read_text()==f'{expected}\n',action
    assert (root/'intent').read_text().splitlines()==['engine-stop 12','engine-restart 15','start 15']

    # S98 reports daemon absence only on the missing executable branch.
    (root/'boot'/'d2k-update-boot').write_text('#!/bin/sh\nexit 0\n'); (root/'boot'/'d2k-update-boot').chmod(0o700)
    (root/'commands'/'start-stop-daemon').write_text('#!/bin/sh\nexit 0\n'); (root/'commands'/'start-stop-daemon').chmod(0o700)
    for present in [False,True]:
        if present:
            (root/'releases'/'new'/'d2k-update').write_text('#!/bin/sh\nexit 0\n'); (root/'releases'/'new'/'d2k-update').chmod(0o700)
        result=subprocess.run(['sh',repo/'files'/'S98d2k-update','start'],env={**env,'D2K_DIR':str(root),'PATH':str(root/'commands')+':/usr/bin:/bin'},capture_output=True,text=True)
        assert result.returncode==0
        assert ('daemon not installed' in result.stderr)==(not present),(present,result.stderr)

    bad=subprocess.run([adapter,'--root',root,'--maintenance-fd','4','start','new','15'],capture_output=True)
    assert bad.returncode!=0
    print(f'actual C service + {len(mandatory)} exact missing-rule cases + lock wait/current pin: PASS')
