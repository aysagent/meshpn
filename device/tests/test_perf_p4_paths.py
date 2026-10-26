import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('p4paths', Path(__file__).parents[1] / 'scripts/perf-p4-paths.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Clock:
    value = 100
    def now(self): return self.value
    def wait(self, n): self.value += n


class Fake:
    def __init__(self, clock, failure=False, vpn=False, wrong=False):
        self.clock, self.failure = clock, failure
        self.calls = self.transfers = 0
        self.s = {'board': 'wrong' if wrong else 'waveshare_esp32_p4_wifi6', 'boot_count': 1,
                  'wifi': {'connected': True, 'ip': '192.168.1.11', 'password': 'SECRET'},
                  'vpn': {'enabled': vpn, 'private_key': 'SECRET'}}

    def api(self, path, data=None, timeout=15):
        self.clock.wait(.01)
        if path == '/api/diag/ap-forward':
            assert data == b''
            return {k: {'ok': not self.failure} for k in ['udp_dns', 'tcp_syn']}
        assert path == '/api/status'
        self.calls += 1
        # Model one spontaneous reboot; the runner must record, never reset it.
        self.s['boot_count'] = 1 if self.calls < 4 else 2
        return copy.deepcopy(self.s)

    def transfer(self, address, direction, deadline):
        self.transfers += 1
        self.clock.wait(1)
        return {'address': address, 'direction': direction, 'complete': not self.failure}


class Tests(unittest.TestCase):
    def execute(self, **kw):
        c = Clock()
        f = Fake(c, **kw)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        a = SimpleNamespace(out=Path(directory.name), minutes=.4, admin_ip='192.168.10.1', cycle_gap=1)
        with contextlib.redirect_stdout(io.StringIO()):
            result, root = m.run(a, f, c.now, c.wait)
        return result, root, f

    def test_bounds_without_network(self):
        for args in [['--minutes', '0'], ['--minutes', 'nan'], ['--cycle-gap', '0'],
                     ['--admin-ip', '8.8.8.8'], ['--admin-ip', '127.0.0.1']]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.options(args)

    def test_redaction(self):
        text = json.dumps(m.clean({'private_key': 'SECRET', 'wifi': {'password': 'SECRET'},
                                  'vpn': {'enabled': False, 'private_key': 'SECRET'}}))
        self.assertNotIn('SECRET', text)

    def test_schedule_artifacts_and_reboot_detection(self):
        r, root, f = self.execute()
        self.assertGreater(f.transfers, 0)
        self.assertEqual(r['boot_changes'], 1)
        self.assertEqual(r['status'], 'completed-with-warnings')
        self.assertLess(r['elapsed_s'], 25)
        self.assertNotIn('SECRET', (root / 'status.ndjson').read_text())
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual((root / 'result.json').stat().st_mode & 0o777, 0o600)
        self.assertTrue((root / 'after.json').exists())

    def test_failure_preserved_no_false_completion(self):
        r, root, _ = self.execute(failure=True)
        self.assertEqual(r['complete'], 0)
        self.assertIn('incomplete_transfers', r['warnings'])
        self.assertIn('failed_ap_forward_probes', r['warnings'])
        events = (root / 'events.ndjson').read_text()
        self.assertIn('probe_failure', events)
        self.assertIn('failure-before-any-reset', (root / 'status.ndjson').read_text())

    def test_wrong_board_or_enabled_vpn_never_generates_load(self):
        for args in [{'wrong': True}, {'vpn': True}]:
            r, _, f = self.execute(**args)
            self.assertEqual(r['status'], 'failed')
            self.assertEqual(f.transfers, 0)


if __name__ == '__main__':
    unittest.main()
