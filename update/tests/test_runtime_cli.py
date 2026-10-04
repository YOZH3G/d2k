#!/usr/bin/env python3
"""Offline modes must finish successfully without a working runtime/config."""
import pathlib, subprocess, sys, tempfile
bins = [pathlib.Path(p).resolve() for p in sys.argv[1:]]
with tempfile.TemporaryDirectory() as tmp:
    for binary in bins:
        for mode in ('--release-id', '--self-check'):
            result = subprocess.run([str(binary), mode], cwd=tmp, capture_output=True, timeout=5)
            assert result.returncode == 0, (binary, mode, result.returncode, result.stderr)
            assert result.stdout.strip(), (binary, mode, 'no identity')
        result = subprocess.run([str(binary), '--version'], cwd=tmp, capture_output=True, timeout=5)
        assert result.returncode == 0 and b'release=' in result.stdout, (binary, result.stdout)
        assert list(pathlib.Path(tmp).iterdir()) == [], (binary, 'offline mode wrote files')
print('runtime offline CLI: PASS')
# An untrusted/mixed greeting must never receive catalog commands.
import socket, struct, time
core = next((b for b in bins if b.name == 'd2kc'), None)
if core:
    release = subprocess.check_output([str(core), '--release-id']).strip()
    with tempfile.TemporaryDirectory() as tmp:
        server=socket.socket(socket.AF_UNIX); sockpath=tmp+'/control'
        server.bind(sockpath); server.listen(1); server.settimeout(5)
        child=subprocess.Popen([str(core),'--control',sockpath,'--catalog',tmp+'/catalog','--health-file',tmp+'/health'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peer_socket,_=server.accept()
        payload=bytes([4])+bytes(37)+struct.pack('!HI',13,1500)+bytes([len(release)])+release
        peer_socket.sendall(struct.pack('!IH',len(payload)+2,10)+payload)
        try:
            deadline=time.monotonic()+5
            while not pathlib.Path(tmp+'/health').exists() and child.poll() is None and time.monotonic()<deadline:
                time.sleep(.05)
            assert pathlib.Path(tmp+'/health').exists(), 'matching greeting never became ready'
            record=pathlib.Path(tmp+'/health').read_text().split()
            assert record[5].encode()==release and record[7].encode()==release and record[8:10]==['1','1']
        finally:
            child.terminate();child.communicate(timeout=5);peer_socket.close();server.close()
    for wire, peer, declared in ((12, release, len(release)), (13, b'other', 5), (13, b'', 0), (13, b'bad/id', 6)):
        with tempfile.TemporaryDirectory() as tmp:
            sockpath = str(pathlib.Path(tmp) / 'control')
            server = socket.socket(socket.AF_UNIX)
            server.bind(sockpath); server.listen(1); server.settimeout(5)
            child = subprocess.Popen([str(core), '--control', sockpath, '--catalog', tmp + '/catalog', '--health-file', tmp + '/health'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            peer_socket, _ = server.accept(); peer_socket.settimeout(5)
            payload = bytes([4]) + bytes(37) + struct.pack('!HI', wire, 1500) + bytes([declared]) + peer
            peer_socket.sendall(struct.pack('!IH', len(payload) + 2, 10) + payload)
            out, err = child.communicate(timeout=5)
            assert child.returncode == 1, (wire, peer, child.returncode, err)
            assert peer_socket.recv(1024) == b'', 'mixed peer received runtime command'
            assert not (pathlib.Path(tmp) / 'catalog').exists()
            assert not (pathlib.Path(tmp) / 'health').exists()
            peer_socket.close(); server.close()
    print('controller mixed release/wire handshake: PASS')
releases = [subprocess.check_output([str(b), '--release-id']).strip() for b in bins]
assert len(set(releases)) == 1, ('mixed coordinated build', releases)
print('coordinated runtime identity: PASS')
