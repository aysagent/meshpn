import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ready_bind', pathlib.Path(__file__).parent / 'usb/ready-bind.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReadyBindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / 'UDC').write_text('')
        self.patches = [patch.object(m, 'GADGET', self.root), patch.object(m, 'prepared', return_value='test.udc')]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def test_check_never_binds(self):
        with patch.object(m, 'dhcp_ready', return_value=True):
            self.assertFalse(m.apply(check=True)['changed'])
        self.assertEqual((self.root / 'UDC').read_text(), '')

    def test_waits_for_dhcp_before_exposure(self):
        calls = []
        def ready():
            self.assertEqual((self.root / 'UDC').read_text(), '')
            calls.append(1)
            return len(calls) == 3
        with patch.object(m, 'dhcp_ready', side_effect=ready), patch.object(m.time, 'sleep'):
            self.assertEqual(m.apply()['status'], 'bound')
        self.assertEqual((self.root / 'UDC').read_text(), 'test.udc\n')

    def test_failed_dhcp_preserves_static_rescue(self):
        with patch.object(m, 'dhcp_ready', return_value=False), patch.object(m.time, 'monotonic', side_effect=[0,9]):
            self.assertEqual(m.apply()['status'], 'bound-rescue-dhcp-unavailable')

    def test_live_usb_is_not_rebound(self):
        (self.root / 'UDC').write_text('test.udc')
        with patch.object(m, 'dhcp_ready', return_value=False), patch.object(m.time, 'sleep') as sleep:
            self.assertFalse(m.apply()['changed'])
            sleep.assert_not_called()
        self.assertEqual((self.root / 'UDC').read_text(), 'test.udc')

    def test_foreign_controller_rejected(self):
        (self.root / 'UDC').write_text('foreign')
        with self.assertRaisesRegex(RuntimeError, 'controller_changed'):
            m.apply()

    def test_racing_binding_is_not_overwritten(self):
        def ready():
            (self.root / 'UDC').write_text('other')
            return True
        with patch.object(m, 'dhcp_ready', side_effect=ready):
            with self.assertRaisesRegex(RuntimeError, 'state_changed'): m.apply()
        self.assertEqual((self.root / 'UDC').read_text(), 'other')


if __name__ == '__main__': unittest.main()
