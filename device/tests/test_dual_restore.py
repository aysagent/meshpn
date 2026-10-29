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
    def test_radio_uses_board_listener_and_receiver_bytes(self):
        class Board:
            def __init__(self,server): self.server=server;self.calls=[]
            def api(self,path,body=None):
                self.calls.append((path,body))
                return dict(nonce=41,running=bool(body),listening=self.server and bool(body),
                            connected=True,error=0,bytes=800 if self.server else 1000)
        client,server=Board(False),Board(True)
        args=SimpleNamespace(repeats=1,rates=[],seconds=1,gap=0,client='stamp')
        with tempfile.TemporaryDirectory() as d,patch.object(m.time,'sleep'):
            m.radio_tests(args,Path(d),client,server,'192.168.11.2','192.168.11.1','waveshare')
            rows=json.loads((Path(d)/'result.json').read_text())
        self.assertEqual([r['receiver_mbps'] for r in rows],[.0064,.008])
        self.assertTrue(all(r['complete'] and r['client']=='stamp' for r in rows))
        for _,body in server.calls:
            if body:self.assertEqual((body['role'],body['interface'],body['target']),('server','ap','192.168.11.2'))
        for _,body in client.calls:
            if body:self.assertEqual((body['target'],body['nonce']),('192.168.11.1',41))

    def test_sta_radio_does_not_select_or_create_wifi_profile(self):
        class Board:
            def __init__(self,address): self.address=address
            def api(self,path,body=None):
                assert body is None, 'STA control must not mutate Wi-Fi'
                if path=='/api/wifi/profiles':return {'profiles':[{'id':1}]}
                assert path=='/api/status'
                stamp=self.address=='192.168.12.1'
                return dict(board='m5_stamp_p4_c6' if stamp else 'waveshare_esp32_p4_wifi6',
                    net=dict(usb_ip=self.address),vpn=dict(enabled=False),
                    wifi=dict(connected=True,paused=False,profile_id=1,ip='192.168.1.19' if stamp else '192.168.1.11'))
        with tempfile.TemporaryDirectory() as d,patch.object(m.perf,'Board',Board), \
                patch.object(m,'radio_tests') as radio,patch.object(m,'restore'):
            args=SimpleNamespace(client='stamp',role='radio',radio_interface='sta',out=str(Path(d)/'run'))
            m.run(args)
            self.assertEqual(radio.call_args.args[4:6],('192.168.1.19','192.168.1.11'))
            self.assertIsNone(json.loads((Path(d)/'run/restore.json').read_text())['temporary_ssid'])

    def test_pending_journals_include_nested_runs_but_not_other_lab_schemas(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);nested=root/'night'/'run';nested.mkdir(parents=True)
            journal=dict(board='board',address='192.168.12.1',original={},previous_ids=[],restored=False)
            (nested/'restore.json').write_text(json.dumps(journal))
            other=root/'vpn';other.mkdir();(other/'restore.json').write_text(json.dumps({'restored':False,'vpn':{}}))
            self.assertEqual(list(m.pending_journals(root)),[nested/'restore.json'])
            journal['restored']=True;(nested/'restore.json').write_text(json.dumps(journal))
            self.assertEqual(list(m.pending_journals(root)),[])

    def test_radio_sta_listener_interface(self):
        class Board:
            def __init__(self):self.started=[]
            def api(self,path,body=None):
                if body:self.started.append(body)
                return dict(nonce=41,running=bool(body),listening=True,connected=True,error=0,bytes=1000)
        client,server=Board(),Board()
        args=SimpleNamespace(repeats=1,rates=[],seconds=1,gap=0,client='stamp',radio_interface='sta')
        with tempfile.TemporaryDirectory() as d,patch.object(m.time,'sleep'):
            m.radio_tests(args,Path(d),client,server,'192.168.1.19','192.168.1.11','waveshare')
        self.assertTrue(all(b['interface']=='sta' for b in server.started))

    def test_radio_client_loss_still_cancels_server_and_keeps_failure(self):
        class LostClient:
            def api(self,path,body=None):
                if path=='/api/status':return {}
                raise TimeoutError('USB client unavailable')
        class Server:
            cancelled=False
            def api(self,path,body=None):
                if body and body.get('cancel'):self.cancelled=True
                return dict(nonce=42,running=True,listening=True)
        server=Server();args=SimpleNamespace(repeats=1,rates=[],seconds=1,gap=0,client='stamp')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(TimeoutError,'USB client'):
                m.radio_tests(args,Path(d),LostClient(),server,'192.168.11.2','192.168.11.1','waveshare')
            row=json.loads((Path(d)/'result.json').read_text())[0]
        self.assertTrue(server.cancelled);self.assertFalse(row['complete'])
        self.assertIsNone(row['receiver_mbps']);self.assertIn('USB client',row['error'])
        self.assertTrue(row['cleanup_errors'])

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

    def test_failed_link_keeps_both_sides_before_restoration(self):
        class Board:
            def api(self, path): return {'events': [{'seq': 123}], 'client': path.endswith('sta-tcp')}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            with self.assertRaises(RuntimeError):
                m.save_link_attempt(p, 0, 'down', {'complete': False}, Board(), Board())
            self.assertTrue(json.loads((p/'client-trace-0-down.json').read_text())['client'])
            self.assertFalse(json.loads((p/'ap-trace-0-down.json').read_text())['client'])

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
