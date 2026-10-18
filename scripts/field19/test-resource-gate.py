#!/usr/bin/env python3
"""Regression of the field acceptance check, without browser/network access."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('resource-gate.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class Acceptance(unittest.TestCase):
    def page(self):
        return {'url': 'http://www.fast-torrent.ru/',
                'dom': {'url': 'http://www.fast-torrent.ru/', 'text': 100, 'styles': []},
                'requests': [
                    {'url': 'http://www.fast-torrent.ru/', 'type': 'Document', 'status': 200, 'finished': True},
                    {'url': 'http://media5.cdnbase.com/media/theme/fast.5.css', 'type': 'Stylesheet',
                     'status': 200, 'dataBytes': 33120}]}

    def test_complete_html_does_not_hide_cut_css(self):
        errors = gate.check(self.page())
        self.assertTrue(any('fast.5.css' in e for e in errors))

    def test_second_success_does_not_change_first_observation(self):
        first = self.page()
        second = self.page()
        second['requests'][1].update(finished=True, dataBytes=106050)
        self.assertTrue(gate.check(first))
        self.assertEqual(gate.check(second), [])
        self.assertTrue(gate.check(first))

    def test_empty_render_is_not_success(self):
        d = self.page(); d['requests'][1]['finished'] = True; d['dom']['text'] = 0
        self.assertTrue(any('пуст' in e for e in gate.check(d)))

    def test_missing_required_resource_is_unknown(self):
        d = self.page(); d['requests'].pop()
        self.assertTrue(gate.check(d))

    def test_unrequested_lazy_image_is_not_a_measured_cut(self):
        d = self.page(); d['requests'][1]['finished'] = True
        d['dom']['images'] = ['https://example.org/lazy.jpg']
        self.assertEqual(gate.check(d), [])

    def test_ad_failure_does_not_mask_essential_resource_success(self):
        d = self.page(); d['requests'][1]['finished'] = True
        d['requests'].append({'url':'https://ads.example/ad.js','type':'Script','error':'net::ERR_CONNECTION_REFUSED'})
        self.assertEqual(gate.check(d), [])

if __name__ == '__main__': unittest.main()
