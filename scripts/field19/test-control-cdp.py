#!/usr/bin/env python3
"""Exercise pass/fail and evidence preservation with no browser or network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(__file__).with_name('control-cdp.sh').resolve()
with tempfile.TemporaryDirectory(prefix='d2k-control-test-') as tmp:
    root = Path(tmp); tools = root/'tools'; tools.mkdir()
    for name, body in [('open', '#!/bin/sh\nexit 0\n'), ('pgrep', '#!/bin/sh\nexit 1\n')]:
        p = tools/name; p.write_text(body); p.chmod(0o755)
    node = tools/'node'
    node.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
from pathlib import Path
out=Path(sys.argv[3]);out.mkdir(parents=True,exist_ok=True)
url=json.loads(Path(sys.argv[4]).read_text())[0]
d={'url':url,'dom':{'url':url,'text':100,'styles':[]},'requests':[
 {'url':url,'type':'Document','status':200,'finished':True},
 {'url':'https://static.rutracker.cc/templates/v1/site.css','type':'Stylesheet','status':200,'finished':os.environ['CUT']=='0'}]}
(out/'1.json').write_text(json.dumps(d))
''')
    node.chmod(0o755)
    env = dict(os.environ, PATH=str(tools)+os.pathsep+os.environ['PATH'],
               D2K_FIELD_RUNS=str(root/'runs'), SITES='1', CONTROL_PASS='1', CUT='1')
    first = subprocess.run(['sh', str(script), 'fixture', '0'], env=env, capture_output=True, text=True)
    assert first.returncode == 1, first.stdout + first.stderr
    control = root/'runs/fixture/cdp'
    before = (control/'network-1/1.json').read_bytes()
    env.update(CUT='0', CONTROL_PASS='2')
    second = subprocess.run(['sh', str(script), 'fixture', '0'], env=env, capture_output=True, text=True)
    assert second.returncode == 0, second.stdout + second.stderr
    saved = list(control.parent.glob('cdp.previous-*'))
    assert len(saved) == 1 and (saved[0]/'network-1/1.json').read_bytes() == before
    assert 'control_pass=1' in (saved[0]/'control-context.txt').read_text()
    assert 'control_pass=2' in (control/'control-context.txt').read_text()
    assert 'failed=1' in (saved[0]/'resource-gate.txt').read_text()
    assert 'failed=0' in (control/'resource-gate.txt').read_text()
print('control-cdp: failure exit, separate success, original evidence preserved')
