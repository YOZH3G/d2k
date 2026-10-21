"""Actual C serializer contract, not a reimplementation of its output."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
with tempfile.TemporaryDirectory() as directory:
    dest = Path(directory) / 'report.json'
    subprocess.run([str(Path(__file__).resolve().parent / 'test_diagnostics')],
                   env=dict(os.environ, D2K_TEST_DIAG_JSON=str(dest)), check=True)
    report = json.loads(dest.read_text())
    assert report['schema'] == 1 and report['enabled'] is True
    assert report['ring_bytes'] <= 128 * 1024
    sample = report['samples'][0]
    assert sample['mem_total_kib'] == 65536
    assert sample['processes'][0]['rss_kib'] == 1024
    assert sample['processes'][1]['rss_kib'] is None
    assert sample['datapath_flows'] is None
    assert sample['system_conntrack'] is None
print('diagnostics JSON: real serializer PASS')
