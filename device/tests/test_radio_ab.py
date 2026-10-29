import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

base = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('radio_ab',base/'scripts/p4-radio-ab.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.a=self.build('a','n');self.b=self.build('b','y')
        self.args=SimpleNamespace(a_build=self.a,b_build=self.b,client='waveshare',radio_interface='sta',seconds=1,rates=[1],repeats=1)
    def tearDown(self):self.tmp.cleanup()
    def build(self,name,flag):
        p=self.root/name;p.mkdir()
        (p/'meshvpn-board.json').write_text(json.dumps(dict(board=m.dual.NAMES['waveshare'],target='esp32p4',profile='ncm')))
        (p/'sdkconfig').write_text('CONFIG_OTHER=y\n'+(m.FLAG+'=y\n' if flag=='y' else '# '+m.FLAG+' is not set\n'))
        (p/'flash_args').write_text('--flash_mode dio\n0x10000 meshvpn_device.bin\n')
        (p/'flasher_args.json').write_text(json.dumps({'extra_esptool_args':{'chip':'esp32p4'},'flash_files':{'0x10000':'meshvpn_device.bin'}}))
        (p/'meshvpn_device.bin').write_bytes(b'fixture-'+name.encode())
        (p/'project_description.json').write_text(json.dumps(dict(project_version='same',git_revision='v5.5.5')))
        return p
    def test_plan_and_frozen_hashes(self):
        j=m.plan(self.args);self.assertEqual(j['phases'],['A1','B','A2']);m.verify(j['a'])
        (self.a/'meshvpn_device.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'Frozen build'):m.verify(j['a'])
    def test_only_one_config_change(self):
        with (self.b/'sdkconfig').open('a') as f:f.write('CONFIG_UNRELATED=y\n')
        with self.assertRaisesRegex(ValueError,'differ only'):m.plan(self.args)
    def test_sdk_mismatch_or_missing_version_rejected(self):
        for sdk in ('v5.4.1', None):
            (self.b/'project_description.json').write_text(json.dumps(dict(project_version='same',git_revision=sdk)))
            with self.assertRaisesRegex(ValueError,'versions differ'):m.plan(self.args)
    def test_other_board_rejected(self):
        (self.b/'meshvpn-board.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'identity'):m.plan(self.args)
    def test_binding_derivation(self):
        self.assertEqual(m.bound_usb_mac({'serial':'0011223344FF'}),'02:11:22:33:44:00')
    def test_failed_b_restores_a_and_keeps_failure(self):
        j=m.plan(self.args);out=self.root/'run';calls=[];selected=[]
        binding={'serial':'001122334455'}
        class Board:
            def __init__(self,address):self.address=address
            def api(self,url,*args):
                board=m.dual.NAMES['waveshare' if self.address=='192.168.10.1' else 'stamp']
                return dict(board=board,net={'usb_ip':self.address,'interfaces':[{'ip':self.address,'mac':'02:11:22:33:44:56'}]},
                            vpn={'enabled':False},wifi={'connected':True,'profile_id':7,'radio':{'sta_protocol':{'available':True,'802_11ax':calls[-1]!='B' if calls else True}}})
        def flash(journal,item,path,label):calls.append(label)
        def select(journal):selected.append(journal['original_profile']);return Board(journal['address'])
        def bench(cmd):
            if calls[-1]=='B':raise RuntimeError('injected RF failure')
        with (self.root/'lock').open('w') as lock, patch.object(m.flash,'load_binding',return_value=binding), \
             patch.object(m.dual.perf,'Board',Board),patch.object(m,'select_original',select), \
             patch.object(m.signal,'signal'):
            # recover's default is bound at definition; inject the fake explicitly.
            recover=m.recover
            with patch.object(m,'recover',side_effect=lambda j,o,f:recover(j,o,f,select)):
                with self.assertRaisesRegex(RuntimeError,'injected RF'):m.run(j,out,lock,flash,bench)
        self.assertEqual(calls,['A1','B','restore-A']);self.assertEqual(selected,[7,7,7])
        saved=json.loads((out/'radio-ab.json').read_text())
        self.assertTrue(saved['restored']);self.assertIn('RF failure',saved['error'])
    def test_summary_does_not_hide_failed_runs(self):
        out=self.root/'report';(out/'A1').mkdir(parents=True)
        (out/'A1/result.json').write_text(json.dumps([
            dict(protocol='udp',direction='up',target_mbps=4,complete=True,receiver_mbps=3),
            dict(protocol='udp',direction='up',target_mbps=4,complete=False,receiver_mbps=0)]))
        row=m.summarize(out)[0];self.assertEqual(row['successful'],1);self.assertEqual(row['failed'],1);self.assertEqual(row['receiver_median'],3)
    def test_inherited_lock_rejects_different_inode(self):
        one=self.root/'one';two=self.root/'two';one.touch();two.touch()
        with one.open('a') as f,patch.dict(os.environ,{'MESHPN_DUAL_LOCK_FD':str(f.fileno())}):
            with self.assertRaisesRegex(RuntimeError,'does not match'):m.dual.acquire_lock(two)
    def test_comparison_requires_complete_aba(self):
        rows=[dict(phase=p,protocol='udp',direction='up',target_mbps=4,successful=3,failed=0,receiver_median=v)
              for p,v in [('A1',1),('B',3),('A2',1.1)]]
        self.assertEqual(m.comparisons(rows,3)[0]['b_over_a1'],3)
        rows[2]['failed']=1;self.assertFalse(m.comparisons(rows,3)[0]['eligible'])
    def test_busy_retry_only(self):
        j=m.plan(self.args);j['binding']={'serial':'001122334455'}
        busy=SimpleNamespace(returncode=1,stdout='',stderr='Resource busy')
        ok=SimpleNamespace(returncode=0,stdout='done',stderr='')
        with patch.object(m.flash,'load_binding',return_value=j['binding']),patch.object(m,'run_flash_command',side_effect=[busy,ok]) as run,patch.object(m.time,'sleep') as sleep:
            m.flash_build(j,j['a'],self.root,'test');self.assertEqual(run.call_count,2);sleep.assert_called_once_with(30)
        with patch.object(m.flash,'load_binding',return_value=j['binding']),patch.object(m,'run_flash_command',return_value=SimpleNamespace(returncode=1,stdout='',stderr='MAC mismatch')) as run,patch.object(m.time,'sleep') as sleep:
            with self.assertRaises(RuntimeError):m.flash_build(j,j['a'],self.root,'wrong')
            self.assertEqual(run.call_count,1);sleep.assert_not_called()

if __name__=='__main__':unittest.main()
