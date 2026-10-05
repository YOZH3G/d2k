#!/usr/bin/env python3
"""No network: private roots, real Unix IPC, standalone CLI and probe pipe."""
import json,os,pathlib,signal,subprocess,sys,tempfile,time
binary=os.path.abspath(sys.argv[1])
with tempfile.TemporaryDirectory(prefix='d2ku-cli-',dir='/tmp') as tmp:
    root=pathlib.Path(tmp).resolve();(root/'boot').mkdir();(root/'run').mkdir(mode=0o700);(root/'state').mkdir();(root/'releases').mkdir()
    (root/'config').write_text(f'MODE=off\nD2K_RUNTIME_DIR={root}/run\nSTATE_DIR={root}/state\n')
    conf=root/'boot/update.conf';conf.write_text('D2KU-CONFIG-1\nfeed=https://updates.invalid\nhost=updates.invalid\nca=/nonexistent/fixture-ca\nabi=arm64\nbuild=4102444800\nkey='+'01'+'00'*31+' 1 4102444801\n');conf.chmod(0o600)
    proc=subprocess.Popen([binary,'--root',root,'serve'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if (root/'update-state/updater.sock').exists():break
            if proc.poll() is not None:raise AssertionError(proc.communicate())
            time.sleep(.02)
        def cli(*args):
            p=subprocess.run([binary,'--root',root,*args],capture_output=True,text=True,check=True);return json.loads(p.stdout)
        a=cli('status');assert a['state']=='unchecked' and not a['operation_id'];assert (root/'update-state/updater.sock').stat().st_mode&0o777==0o600
        a=cli('check','--force','--operation-id','client-check');assert a['operation_id']=='client-check'
        for _ in range(100):
            b=cli('status')
            if not b['busy']:break
            time.sleep(.02)
        assert b['last_result']==9 and b['state']=='error',b
        assert cli('status')['operation_id']==a['operation_id']
        assert cli('check','--force','--operation-id','client-check')['operation_id']=='client-check'
        assert subprocess.run([binary,'--root',root,'check','--operation-id','client-check'],capture_output=True).returncode==4
        assert subprocess.run([binary,'--root',root,'install'],capture_output=True).returncode==2
    finally:
        proc.terminate();proc.wait(timeout=5)
    assert subprocess.run([binary,'--boot-protocol'],capture_output=True,text=True).stdout=='1\n'
    assert subprocess.run([binary,'--self-check'],capture_output=True).returncode==0
    print('daemon CLI: real server, socket0600, passive status, async check, TIME, mandatory selection: PASS')
    # Candidate initializes real config/readers through ROOT fd4 without writes,
    # public socket, scheduler, or a second daemon instance.
    import fcntl,select
    before={str(p.relative_to(root)):(p.stat().st_size,p.stat().st_mtime_ns) for p in root.rglob('*') if p.is_file()}
    read,write=os.pipe();rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    child=os.fork()
    if child==0:
        os.close(read);a=fcntl.fcntl(write,fcntl.F_DUPFD,10);b=fcntl.fcntl(rootfd,fcntl.F_DUPFD,20)
        os.dup2(a,3);os.dup2(b,4);os.set_blocking(3,False);os.close(a);os.close(b)
        os.execv(binary,[binary,'--boot-probe','3','--root-fd','4'])
    os.close(write);os.close(rootfd)
    assert select.select([read],[],[],3)[0]
    pulse=os.read(read,4096);assert b'D2KU1 READY\n' in pulse,pulse
    if b'D2KU1 PULSE\n' not in pulse:
        assert select.select([read],[],[],2)[0];assert b'D2KU1 PULSE\n' in os.read(read,4096)
    os.close(read)
    for _ in range(50):
        got,status=os.waitpid(child,os.WNOHANG)
        if got:break
        time.sleep(.05)
    else:os.kill(child,signal.SIGKILL);os.waitpid(child,0);raise AssertionError('probe did not exit after heartbeat pipe closed')
    assert os.WIFEXITED(status)
    after={str(p.relative_to(root)):(p.stat().st_size,p.stat().st_mtime_ns) for p in root.rglob('*') if p.is_file()}
    assert before==after,'probe mutated installation'
    assert not (root/'update-state/updater.sock').exists()
    print('candidate probe: real readonly initialization, exact fd3/fd4, independent pulses, close exit: PASS')
