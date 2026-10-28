import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('dual',Path(__file__).resolve().parents[1]/'scripts/p4-dual-bench.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class RestoreTests(unittest.TestCase):
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
