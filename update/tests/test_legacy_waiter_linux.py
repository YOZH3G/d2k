#!/usr/bin/env python3
"""Private isolated Linux container only. ADAPTER ROOT (previously prepared
wire12 fixture with running engine). Stops only that private fixture's services;
checks captured helper descendants and the actual installed independent waiter.
"""
import fcntl,os,pathlib,subprocess,sys,time

def stop_preserving_waiter(adapter,root):
    assert sys.platform=='linux' and os.environ.get('D2KU_LEGACY_LAB')=='1'
    root=pathlib.Path(root);adapter=pathlib.Path(adapter).resolve()
    release=(root/'current').readlink().name
    lock=os.open(root/'update-state/maintenance.lock',os.O_RDWR)
    fcntl.flock(lock,fcntl.LOCK_EX);os.dup2(lock,4)
    # Use the actual installed inode, just like init/NDM/helper entry points.
    independent=subprocess.Popen([root/'boot/d2k-service-adapter','--root',root,'service','status'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        time.sleep(1.2)  # Fixture LOG_EVERY=1 puts a helper child at this lock.
        assert independent.poll() is None
        subprocess.run([adapter,'--root',root,'--maintenance-fd','4','stop',release,'3'],pass_fds=(4,),check=True,timeout=30)
        assert independent.poll() is None,'unrelated lifecycle waiter was killed'
    finally:
        os.close(4)
        if lock!=4:os.close(lock)
    assert independent.wait(timeout=10)==0,independent.stderr.read()
    subprocess.run([adapter,'--root',root,'service','stop'],check=True,timeout=30)
    print('legacy stop: blocked helper descendants quiesced, installed independent waiter preserved, external stop: PASS',flush=True)

if __name__=='__main__':stop_preserving_waiter(*sys.argv[1:3])
