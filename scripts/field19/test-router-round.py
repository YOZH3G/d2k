#!/usr/bin/env python3
"""Offline regression for collection → report; never contacts a router."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('report', HERE / 'router-round-report.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

class RoundContract(unittest.TestCase):
    def test_failed_router_run_still_collects_log_and_reports_incomplete(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); bindir = p / 'bin'; bindir.mkdir()
            stub = bindir / 'ssh'
            stub.write_text("""#!/bin/sh
case "$*" in
 *--version*) echo 'd2kfetch lab-test';;
 *sha256sum*) echo 'test-hash';;
 *'cat /opt/d2k/release-id'*) echo lab-test;;
 *'sh /tmp/rr-'*) exit 1;;
 *'cat /tmp/rr-'*/t0*) echo 12:00:00;;
 *'sh -s --'*) cat >/dev/null; printf 'DONE\\n';;
 *'awk -v t0='*) echo '12:00:01 preserved router log';;
 *'cat >'*) cat >/dev/null;;
 *'rm -rf'*) echo 'unexpected cleanup' >&2; exit 99;;
esac
""")
            stub.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                       D2K_FIELD_RUNS=str(p / 'runs'), EXPECT='lab-test')
            r = subprocess.run(['sh', str(HERE / 'router-round.sh'), 'fixture'],
                               env=env, capture_output=True, text=True, timeout=10)
            run = p / 'runs/fixture'
            self.assertEqual(r.returncode, 4, r.stdout+r.stderr)
            self.assertIn('preserved router log', (run / 'd2kc.log').read_text())
            self.assertTrue((run / 'report.txt').exists())
            self.assertTrue((run / 'collection-error.txt').exists())
            self.assertNotIn('unexpected cleanup', r.stderr)

    def test_transfer_empty_binary_and_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            src = p / 'src'; src.mkdir()
            dst = p / 'dst'; dst.mkdir()
            for content in (None, b'line\nDONE\n\x00binary\xff'):
                if content is not None:
                    (src / 'probe.raw').write_bytes(content)
                r = subprocess.run(['sh', str(HERE / 'd2kfetch-export.sh'), str(src)],
                                   capture_output=True, check=True)
                bundle = p / 'bundle'; bundle.write_bytes(r.stdout)
                subprocess.run(['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), str(dst)], check=True)
                if content is not None:
                    self.assertEqual((dst / 'probe.raw').read_bytes(), content)
            bundle.write_bytes(r.stdout[:-6])
            r = subprocess.run(['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), str(dst)], capture_output=True)
            self.assertNotEqual(r.returncode, 0)

    def test_truncated_transfer_is_atomic_and_is_collection_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            bundle = p / 'bundle'
            bundle.write_bytes(b'probe.raw 20\nshort')
            command = ['python3', str(HERE / 'd2kfetch-import.py'), str(bundle), tmp]
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse((p / 'probe.raw').exists())
            self.assertEqual(sorted(f.name for f in p.iterdir()), ['bundle'])
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=0,
                       probe_file='probe.raw')
            result = report.probe_row(row, tmp)
            self.assertEqual(result.get('collection_error'), 'missing_probe')
            self.assertNotIn('instrument_error', result)
            (p / 'probe.raw').write_bytes(b'previous complete result')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual((p / 'probe.raw').read_bytes(), b'previous complete result')
            self.assertEqual(sorted(f.name for f in p.iterdir()), ['bundle', 'probe.raw'])
            self.assertIn('instrument_error', report.probe_row(row, tmp))

    def test_schema_dns_and_target_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=2,
                       probe_file='probe.raw')
            probe = dict(schema=2, shape='dns_failed', measured=False,
                         reason='адрес не разрешился', name='a.example', ip=None)
            (p / 'probe.raw').write_text(json.dumps(probe))
            j = report.probe_row(row, tmp)
            self.assertEqual(j.get('collection_error'), 'dns_failed')
            self.assertNotIn('instrument_error', j)
            probe = dict(schema=2, shape='quic', name='a.example', ip='192.0.2.1',
                         http_status=200, response_complete=True, local_refusal=False,
                         measured=True, body_bytes=None, quic_stream_bytes=400,
                         headers_inspected=False, name_ok=1, level=3, elapsed_ms=120)
            row['rc'] = 0
            (p / 'probe.raw').write_text(json.dumps(probe))
            j = report.probe_row(row, tmp)
            self.assertEqual(j.get('ip'), '192.0.2.1')
            self.assertEqual(j.get('name_ok'), 1)
            self.assertEqual(j.get('level'), 3)
            self.assertIn('192.0.2.1', report.verdict(j))
            probe['schema'] = 1
            probe['body_bytes'] = 400
            (p / 'probe.raw').write_text(json.dumps(probe))
            self.assertIn('instrument_error', report.probe_row(row, tmp))

    def test_local_and_missing_are_not_network_failures_or_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|h3|/\nb.example|h3|/\nc.example|h3|/\n')
            rows = [dict(name='a.example', mode='h3', instrument='d2kfetch', rc=2,
                         local_refusal=True, measured=False, code=0, err='mark failed'),
                    dict(name='b.example', mode='h3', rc=0, code=200, size=20)]
            (p / 'control.jsonl').write_text(''.join('00:00:00 control '+json.dumps(r)+'\n' for r in rows))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report.main(['report', tmp])
            s = out.getvalue()
            self.assertIn('измерено 1/3', s)
            self.assertIn('провалов 0/1', s)
            self.assertIn('ошибок инструмента 1', s)
            self.assertIn('нет результатов 1', s)
            self.assertNotIn('FAIL rc2', s)

    def test_malformed_row_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'targets.txt').write_text('a.example|h3|/\n')
            (p / 'control.jsonl').write_text('00:00:00 control {"t":0,470}\n')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report.main(['report', tmp])
            self.assertIn('повреждённых строк 1', out.getvalue())

    def test_collector_preserves_stdout_stderr_and_exit(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            stub = p / 'fetch'
            stub.write_text("#!/bin/sh\nprintf '%s\\n' 'opaque stdout'\nprintf '%s\\n' 'local diagnostic' >&2\nexit 139\n")
            stub.chmod(0o755)
            env = dict(os.environ, D2KFETCH=str(stub))
            subprocess.run(['sh', str(HERE / 'd2kfetch-record.sh'), tmp,
                            'a.example', '127.0.0.1', '/', 'control'], env=env, check=True)
            row = json.loads((p / 'control.jsonl').read_text().split(' ', 2)[2])
            self.assertEqual(row['rc'], 139)
            self.assertEqual((p / row['probe_file']).read_text(),
                             subprocess.run([str(stub)], capture_output=True, text=True).stdout)
            self.assertEqual((p / (row['probe_file'] + '.err')).read_text(), 'local diagnostic\n')

    def test_partial_and_challenge_remain_distinct(self):
        self.assertIn('FAIL', report.verdict(dict(rc=1, code=200, size=5400)))
        self.assertTrue(report.verdict(dict(rc=0, code=403, size=2000)).startswith('ok?'))
        self.assertTrue(report.verdict(dict(rc=0, code=200, size=2000,
                                           cloudflare_challenge=True)).startswith('ok?'))

    def test_raw_probe_round_trip_and_real_process_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            reason = 'quote " and slash \\ and newline\nend'
            probe = dict(schema=2, shape="quic", name="a.example", ip="192.0.2.1", name_ok=1, level=3,
                         http_status=302, body_bytes=None, quic_stream_bytes=310, response_complete=True,
                         local_refusal=False, measured=True, location='/a?x="quoted"',
                         reason=reason, elapsed_ms=470, cloudflare_challenge=False)
            (p / 'probe.raw').write_text(json.dumps(probe))
            row = dict(name='a.example', mode='h3', instrument='d2kfetch', rc=0, probe_file='probe.raw')
            index = p / 'control.jsonl'
            index.write_text('00:00:00 control '+json.dumps(row)+'\n')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertEqual(j.get('size'), 310)
            self.assertEqual(j.get('err'), reason)
            self.assertEqual(j.get('loc'), probe['location'])
            self.assertTrue(report.ok(j))
            row['rc'] = 139
            index.write_text('00:00:00 control '+json.dumps(row)+'\n')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertFalse(report.ok(j))
            self.assertIn('НЕ ИЗМЕРЕНО', report.verdict(j))
            (p / 'probe.raw').write_text('not json')
            j = report.load(str(index))[('a.example','h3')][0]
            self.assertIn('НЕ ИЗМЕРЕНО', report.verdict(j))

if __name__ == '__main__':
    unittest.main()
