import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('dual',Path(__file__).resolve().parents[1]/'scripts/p4-dual-bench.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class RestoreTests(unittest.TestCase):
    def test_failed_link_preserves_partial_body_and_trace_failure(self):
        row = dict(complete=False, bytes=482552, mbps=None, error='timeout')
        class Board:
            def api(self, path): raise TimeoutError('diagnostics unavailable')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            with self.assertRaisesRegex(RuntimeError, 'RF link transfer failed'):
                m.save_link_attempt(p, 0, 'down', row, Board())
            self.assertEqual(json.loads((p/'link-0-down.json').read_text()), row)
            trace = json.loads((p/'ap-trace-0-down.json').read_text())
            self.assertFalse(trace['available'])
            self.assertIn('TimeoutError', trace['error'])

    def test_swapped_board_at_expected_ip_never_mutates(self):
        class Board:
            def __init__(self, address): self.address = address
            def api(self, path, body=None):
                assert path == '/api/status' and body is None
                return {'board': 'waveshare_esp32_p4_wifi6', 'net': {'usb_ip': self.address}}
        with tempfile.TemporaryDirectory() as d, patch.object(m.perf, 'Board', Board):
            with self.assertRaisesRegex(RuntimeError, 'identity'):
                m.run(SimpleNamespace(client='stamp',out=str(Path(d)/'run')))
            self.assertFalse((Path(d)/'run/restore.json').exists())

    def test_partial_wan_timeout_retains_bytes_without_success_rate(self):
        result = SimpleNamespace(returncode=28, stdout='200|449771|60.001', stderr='Operation timed out')
        with patch.object(m.subprocess,'run',return_value=result):
            row=m.wan_transfer('en19')
        self.assertFalse(row['complete']);self.assertIsNone(row['mbps'])
        self.assertEqual(row['bytes'],449771);self.assertEqual(row['seconds'],60.001)

    def test_full_wan_requires_success_exit_and_complete_body(self):
        for code, size, success in [(0,8388608,True),(28,8388608,False),(0,1024,False)]:
            with self.subTest(code=code,size=size), patch.object(m.subprocess,'run',return_value=
                    SimpleNamespace(returncode=code,stdout=f'200|{size}|8.0',stderr='')):
                row=m.wan_transfer('en19')
            self.assertEqual(row['complete'],success)
            self.assertEqual(row['mbps'] is not None,success)

    def test_crash_after_creation_preserves_existing_and_unrelated_profiles(self):
        journal=dict(board='board',address='192.168.12.1',original=dict(paused=False,profile_id=1,selection_id=0),
                     previous_ids=[1,2],temporary_ssid='peer',restored=False)
        calls=[]
        class Board:
            def api(self,path,body=None):
                calls.append((path,body))
                if path=='/api/status':return {'board':'board'}
                if path=='/api/wifi/profiles' and body is None:
                    return {'profiles':[dict(id=1,ssid='home'),dict(id=2,ssid='peer'),dict(id=3,ssid='peer'),dict(id=4,ssid='unrelated')]}
                return {}
        with tempfile.TemporaryDirectory() as d,patch.object(m.perf,'Board',return_value=Board()),patch.object(m,'wait'):
            p=Path(d)/'restore.json';m.restore(p,journal)
            self.assertTrue(json.loads(p.read_text())['restored'])
        self.assertEqual([b for a,b in calls if a=='/api/wifi/select'],[{'id':1}])
        self.assertEqual([b for a,b in calls if a=='/api/wifi/profiles' and b],[{'id':3,'delete':True}])
    def test_wrong_board_never_mutates(self):
        class Board:
            def api(self,path,body=None):
                assert body is None
                return {'board':'wrong'}
        with patch.object(m.perf,'Board',return_value=Board()):
            with self.assertRaisesRegex(RuntimeError,'identity'):
                m.restore(Path('/unused'),dict(address='192.168.12.1',board='right'))
    def test_restore_failure_does_not_mark_done(self):
        journal=dict(board='board',address='192.168.12.1',original=dict(paused=False,profile_id=1,selection_id=0),
                     previous_ids=[1],temporary_ssid='peer',restored=False)
        class Board:
            def api(self,path,body=None):
                if path=='/api/status':return {'board':'board'}
                if path=='/api/wifi/profiles':return {'profiles':[]}
                return {}
        with tempfile.TemporaryDirectory() as d,patch.object(m.perf,'Board',return_value=Board()),patch.object(m,'wait',side_effect=TimeoutError('unavailable')):
            p=Path(d)/'restore.json';m.save(p,journal)
            with self.assertRaises(TimeoutError):m.restore(p,journal)
            self.assertFalse(json.loads(p.read_text())['restored'])

if __name__=='__main__':unittest.main()
