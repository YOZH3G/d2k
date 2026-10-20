#!/usr/bin/env python3
"""Local refused socket only: no external network or router access."""
import json
from pathlib import Path
import socket
import subprocess
import unittest

FETCH = Path(__file__).resolve().parents[2] / 'core/d2kfetch'

class FetchContract(unittest.TestCase):
    def test_explicit_empty_address_does_not_fall_back_to_system_dns(self):
        r = subprocess.run([str(FETCH), '--name', 'localhost', '--ip', '',
                            '--quic', '--json'], capture_output=True, text=True, timeout=3)
        j = json.loads(r.stdout)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(j['schema'], 2)
        self.assertEqual(j['shape'], 'dns_failed')
        self.assertFalse(j['measured'])

    def test_quic_does_not_mislabel_stream_bytes_or_unparsed_headers(self):
        r = subprocess.run([str(FETCH), '--name', 'stand.example', '--ip', '127.0.0.1',
                            '--port', '1', '--quic', '--deadline', '100', '--json'],
                           capture_output=True, text=True, timeout=10)
        j = json.loads(r.stdout)
        self.assertIsNone(j['body_bytes'])
        self.assertIsInstance(j['quic_stream_bytes'], int)
        self.assertFalse(j['headers_inspected'])
        self.assertIsNone(j['location'])

    def test_unreachable_ladder_retains_both_measurement_domains(self):
        # Bound but not listening: deterministic TCP refusal without a public target.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            r = subprocess.run([str(FETCH), '--name', 'stand.example', '--ip', '127.0.0.1',
                                '--port', str(sock.getsockname()[1]), '--ladder', '--json'],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2)
        j = json.loads(r.stdout)
        self.assertEqual(j['verdict'], 'unreachable')
        self.assertFalse(j['tx_passed'])
        for field in ('rx_cut', 'rx_short', 'rx_unmeasured', 'rx_direct_complete', 'rx_tls_unavailable'):
            self.assertIsInstance(j[field], bool)
        self.assertIsInstance(j['measured_path'], str)
        self.assertIsInstance(j['rx_reason'], str)

if __name__ == '__main__':
    unittest.main()
