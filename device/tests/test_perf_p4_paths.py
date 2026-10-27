import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location('p4paths', Path(__file__).parents[1] / 'scripts/perf-p4-paths.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Clock:
    value = 100
    def now(self): return self.value
    def wait(self, n): self.value += n


class Fake:
    def __init__(self, clock, failure=False, vpn=False, wrong=False, trace_error=False, trace_mismatch=False):
        self.clock, self.failure = clock, failure
        self.calls = self.transfers = 0
        self.trace_calls = 0
        self.trace_error, self.trace_mismatch = trace_error, trace_mismatch
        self.s = {'board': 'wrong' if wrong else 'waveshare_esp32_p4_wifi6', 'boot_count': 1,
                  'wifi': {'connected': True, 'ip': '192.168.1.11', 'password': 'SECRET'},
                  'vpn': {'enabled': vpn, 'private_key': 'SECRET'}}

    def api(self, path, data=None, timeout=15):
        self.clock.wait(.01)
        if path == '/api/diag/ap-forward':
            assert data == b''
            return {k: {'ok': not self.failure} for k in ['udp_dns', 'tcp_syn']}
        if path == '/api/diag/sta-tcp':
            self.trace_calls += 1
            if self.trace_error:
                raise HTTPError('', 404, 'unavailable', {}, None)
            return {'peer': '192.168.1.4', 'local': self.s['wifi']['ip'],
                    'peer_port': 1235 if self.trace_mismatch else 1234,
                    'private_key': 'SECRET', 'events': [{'seq': 42, 'payload': 100, 'password': 'SECRET'}] * 100}
        assert path == '/api/status'
        self.calls += 1
        # Model one spontaneous reboot; the runner must record, never reset it.
        self.s['boot_count'] = 1 if self.calls < 4 else 2
        return copy.deepcopy(self.s)

    def transfer(self, address, direction, deadline):
        self.transfers += 1
        self.clock.wait(1)
        return {'address': address, 'direction': direction, 'complete': not self.failure,
                'source': '192.168.1.4', 'source_port': 1234}


class Tests(unittest.TestCase):
    def execute(self, trace=False, **kw):
        c = Clock()
        f = Fake(c, **kw)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        a = SimpleNamespace(out=Path(directory.name), minutes=.4, admin_ip='192.168.10.1', cycle_gap=1, sta_tcp_trace=trace)
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

    def test_login_one_bounded_rate_retry_and_no_password_retries(self):
        b = m.Board('192.168.10.1')
        with patch.object(b, 'api', side_effect=[HTTPError('', 429, '', {}, None), {'token': 'ok'}]) as api, patch.object(m.time, 'sleep') as wait:
            b.login()
            self.assertEqual(b.token, 'ok')
            self.assertEqual(api.call_count, 2)
            wait.assert_called_once_with(1.1)
        with patch.object(b, 'api', side_effect=HTTPError('', 401, '', {}, None)) as api, patch.object(m.time, 'sleep') as wait:
            with self.assertRaises(HTTPError):
                b.login()
            self.assertEqual(api.call_count, 1)
            wait.assert_not_called()

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

    def test_trace_capture_private_bounded_and_tuple_correlated(self):
        r, root, f = self.execute(trace=True)
        files = list(root.glob('sta-tcp-*.json'))
        self.assertTrue(files)
        self.assertEqual(r['sta_tcp_traces'], len(files))
        self.assertEqual(r['sta_tcp_trace_errors'], 0)
        for p in files:
            data = p.read_text()
            self.assertNotIn('SECRET', data)
            row = json.loads(data)
            self.assertTrue(row['tuple_matches'])
            self.assertLessEqual(len(row['trace']['events']), 64)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(f.trace_calls, len(files))

    def test_trace_unavailable_once_and_mismatch_explicit(self):
        r, root, f = self.execute(trace=True, trace_error=True)
        self.assertEqual(f.trace_calls, 1)
        self.assertEqual(r['sta_tcp_trace_errors'], 1)
        self.assertIn('sta_tcp_trace_issues', r['warnings'])
        self.assertIn('sta_tcp_trace_error', (root/'events.ndjson').read_text())
        r, root, f = self.execute(trace=True, trace_mismatch=True)
        self.assertGreater(r['sta_tcp_trace_errors'], 0)
        self.assertIn('sta_tcp_trace_tuple_mismatch', (root/'events.ndjson').read_text())
        self.assertTrue(all(json.loads(p.read_text())['tuple_matches'] is False for p in root.glob('sta-tcp-*.json')))

    def test_trace_does_not_copy_text_into_numeric_fields(self):
        trace = m.clean_sta_trace({'peer': 'SECRET', 'peer_port': 'SECRET', 'events': [{'seq': 'SECRET'}]})
        self.assertNotIn('SECRET', json.dumps(trace))

    def test_upload_progress_past_socket_timeout_and_total_deadline(self):
        for remaining, complete in [(35, True), (.2, False)]:
            with self.subTest(remaining=remaining):
                c = Clock()
                b = m.Board('192.168.10.1'); b.token = 'private-token'
                route, conn = MagicMock(), MagicMock()
                route.getsockname.return_value = ('192.168.1.4', 1234)
                conn.sock.getsockname.return_value = ('192.168.1.4', 4321)
                consumed = []
                def send(_method, _path, *, body, headers):
                    self.assertEqual(headers['Content-Length'], '1000000')
                    self.assertNotIn('Transfer-Encoding', headers)
                    for block in body:
                        self.assertLessEqual(len(block), 16384)
                        consumed.append(bytes(block)); c.wait(.1)
                conn.request.side_effect = send
                response = conn.getresponse.return_value
                response.status = 200
                response.read.return_value = b'{"bytes":1000000}'
                with patch.object(m.time, 'monotonic', c.now), \
                     patch.object(m.socket, 'socket', return_value=route), \
                     patch.object(m.http.client, 'HTTPConnection', return_value=conn):
                    row = b.transfer('192.168.1.11', 'up', c.now() + remaining)
                self.assertEqual(row['complete'], complete)
                route.close.assert_called_once(); conn.close.assert_called_once()
                if complete:
                    self.assertGreater(row['seconds'], 3)
                    self.assertEqual(b''.join(consumed), bytes(1000000))
                    self.assertEqual(row['bytes'], 1000000)
                else:
                    self.assertIn('transfer_deadline', row['error'])
                    self.assertLess(sum(map(len, consumed)), 1000000)
                    self.assertIsNone(row['mbps'])
                    conn.getresponse.assert_not_called()


if __name__ == '__main__':
    unittest.main()
