#!/usr/bin/env python3
"""Bounded, read-only P4 link/forwarding soak. Never resets or changes Wi-Fi/VPN.

Uses local USB admin, local USB/STA HTTP traffic and a small internet NAT probe.
AP echo requires a reachable UDP listener; zero replies are not an RF loss test
until a low-rate control succeeds. All result files are private and incremental.
"""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import time
import urllib.error
import urllib.request


def options(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--minutes', type=float, default=180)
    p.add_argument('--admin-ip', default='192.168.10.1')
    p.add_argument('--out', type=Path, default=Path(__file__).resolve().parents[1] / 'perf-results')
    p.add_argument('--cycle-gap', type=float, default=20)
    a = p.parse_args(argv)
    if not .1 <= a.minutes <= 240 or not 1 <= a.cycle_gap <= 300:
        p.error('minutes must be 0.1..240, cycle-gap 1..300')
    try:
        ip = ipaddress.IPv4Address(a.admin_ip)
        if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            raise ValueError()
    except ValueError:
        p.error('admin-ip must be a private local IPv4 address')
    return a


def clean(s):
    keep = ['board', 'build', 'idf', 'uptime_sec', 'boot_count', 'reset_reason_name',
            'temperature_c', 'memory', 'net', 'dns', 'usb', 'cpu']
    out = {k: s[k] for k in keep if k in s}
    w = s.get('wifi', {})
    out['wifi'] = {k: w[k] for k in ['state', 'connected', 'ip', 'rssi', 'disconnect_reason',
                                   'radio', 'tx', 'hosted'] if k in w}
    v = s.get('vpn', {})
    out['vpn'] = {k: v[k] for k in ['enabled', 'connected', 'state', 'transport'] if k in v}
    return out


def private_json(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as f:
        json.dump(data, f, indent=2)


class Board:
    def __init__(self, address):
        self.address = address
        self.token = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(self, path, data=None, timeout=15, retry=True):
        if self.token is None and path != '/api/login':
            self.login()
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        payload = data if isinstance(data, bytes) else None if data is None else json.dumps(data).encode()
        req = urllib.request.Request('http://' + self.address + path, data=payload, headers=headers)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 401 and retry and path != '/api/login':
                self.login()
                return self.api(path, data, timeout, False)
            raise

    def login(self):
        self.token = self.api('/api/login', {'password': os.environ.get('MESHPN_ADMIN_PASSWORD', 'admin')}, retry=False)['token']

    def transfer(self, address, direction, deadline):
        """Count only consumed response bytes; upload requires board receipt JSON."""
        row = {'address': address, 'direction': direction, 'complete': False, 'bytes': 0}
        started = time.monotonic()
        duration = min(35, deadline - started)
        if duration <= 0:
            return {**row, 'error': 'run_deadline', 'seconds': 0}
        route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn = None
        try:
            route.connect((address, 80))
            source = route.getsockname()[0]
            row['source'] = source
            conn = http.client.HTTPConnection(address, 80, timeout=min(5, duration), source_address=(source, 0))
            conn.connect()
            row['connect_s'] = time.monotonic() - started
            conn.sock.settimeout(min(3, duration))
            body = bytes(1000000) if direction == 'up' else b''
            conn.request('POST', '/api/diag/link-' + ('upload' if direction == 'up' else 'download'),
                         body=body, headers={'Authorization': 'Bearer ' + self.token, 'Connection': 'close'})
            response = conn.getresponse()
            row['http'] = response.status
            row['first_byte_s'] = time.monotonic() - started
            if direction == 'up':
                reply = json.loads(response.read(4096))
                row['receipt'] = reply
                row['bytes'] = reply.get('bytes', 0)
                row['complete'] = response.status == 200 and row['bytes'] == len(body)
            else:
                while time.monotonic() < min(started + duration, deadline):
                    try:
                        chunk = response.read1(65536)
                    except http.client.IncompleteRead as e:
                        row['bytes'] += len(e.partial)
                        raise
                    if not chunk:
                        row['complete'] = response.status == 200 and row['bytes'] == 8388608
                        break
                    row['bytes'] += len(chunk)
                if not row['complete']:
                    row['error'] = 'incomplete_body_or_deadline'
        except Exception as e:
            row['error'] = type(e).__name__ + ': ' + str(e)
        finally:
            route.close()
            if conn:
                conn.close()
        row['seconds'] = time.monotonic() - started
        row['mbps'] = row['bytes'] * 8 / row['seconds'] / 1e6 if row['complete'] else None
        return row


def run(a, board=None, clock=time.monotonic, wait=time.sleep):
    a.out.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='p4-paths-', dir=a.out)).resolve()
    os.chmod(root, 0o700)
    print('Artifacts:', root, flush=True)
    start = clock()
    end = start + a.minutes * 60
    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    previous = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    board = board or Board(a.admin_ip)
    result = {'status': 'running', 'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'minutes': a.minutes, 'scope': 'USB and STA plus synthetic AP NAT; no real AP RF benchmark; no automatic resets/settings changes',
              'transfers': 0, 'complete': 0, 'probe_pairs': 0, 'probe_pairs_ok': 0,
              'api_errors': 0, 'boot_changes': 0, 'offline_samples': 0}
    fds = {n: os.fdopen(os.open(root / (n + '.ndjson'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w', buffering=1)
           for n in ['status', 'measurements', 'events']}
    first = None
    last = None
    failures = 0
    def record(name, row):
        fds[name].write(json.dumps({'elapsed_s': clock() - start, **row}) + '\n')
    def snapshot(phase):
        nonlocal first, last
        t = clock()
        try:
            s = board.api('/api/status')
            if s.get('board') != 'waveshare_esp32_p4_wifi6':
                raise RuntimeError('wrong_board')
            if s.get('vpn', {}).get('enabled'):
                raise RuntimeError('VPN_enabled_stop_without_changing_it')
            if first is None:
                first = s
                private_json(root / 'before.json', clean(s))
            if last is not None and s.get('boot_count') != last.get('boot_count'):
                result['boot_changes'] += 1
                record('events', {'event': 'boot_changed', 'before': last.get('boot_count'), 'after': s.get('boot_count')})
            if not s['wifi']['connected']:
                result['offline_samples'] += 1
            last = s
            record('status', {'phase': phase, 'api_ms': (clock() - t) * 1000, 'status': clean(s)})
            return s
        except Exception as e:
            result['api_errors'] += 1
            record('events', {'event': 'api_error', 'phase': phase, 'error': str(e)})
            if str(e) in ['wrong_board', 'VPN_enabled_stop_without_changing_it']:
                raise
            return None
    try:
        initial = snapshot('initial')
        if initial is None:
            raise RuntimeError('No initial board status')
        cycle = 0
        while clock() < end and not stopped:
            s = snapshot('cycle-before')
            if s and s['wifi']['connected'] and end - clock() >= 15:
                try:
                    p = board.api('/api/diag/ap-forward', b'', timeout=min(15, end - clock()))
                    ok = all(p.get(k, {}).get('ok') for k in ['udp_dns', 'tcp_syn'])
                    result['probe_pairs'] += 1
                    result['probe_pairs_ok'] += bool(ok)
                    record('measurements', {'kind': 'ap-forward', 'complete': bool(ok), 'result': p})
                    if not ok:
                        record('events', {'event': 'probe_failure', 'result': p})
                        snapshot('failure-before-any-reset')
                except Exception as e:
                    record('events', {'event': 'probe_error', 'error': str(e)})
                # Failed STA flows back off: keep observing, do not hammer a stuck link.
                cases = [('sta', 'up'), ('sta', 'down')] if failures < 2 else [('sta', 'up')]
                if cycle % 5 == 0:
                    cases += [('usb', 'up'), ('usb', 'down')]
                for kind, direction in cases:
                    if end - clock() < 6 or stopped:
                        break
                    snapshot('before-' + kind + '-' + direction)
                    row = board.transfer(s['wifi']['ip'] if kind == 'sta' else a.admin_ip, direction, min(end, clock() + 35))
                    row['kind'] = kind
                    record('measurements', row)
                    result['transfers'] += 1
                    result['complete'] += bool(row['complete'])
                    if kind == 'sta':
                        failures = 0 if row['complete'] else failures + 1
                    snapshot('after-' + kind + '-' + direction)
                    if not row['complete']:
                        try:
                            logs = board.opener.open(urllib.request.Request('http://' + board.address + '/api/logs',
                                headers={'Authorization': 'Bearer ' + board.token}), timeout=5).read()
                            with os.fdopen(os.open(root / ('failure-' + str(result['transfers']) + '.log'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as f:
                                f.write(logs)
                        except Exception:
                            pass
                cycle += 1
            private_json(root / 'result.json', result)
            print(json.dumps({'elapsed_min': round((clock() - start) / 60, 2), **{k: result[k] for k in ['transfers', 'complete', 'probe_pairs_ok', 'probe_pairs', 'api_errors', 'boot_changes']}}), flush=True)
            until = min(end, clock() + (max(a.cycle_gap, 60) if failures >= 2 else a.cycle_gap))
            while clock() < until and not stopped:
                wait(min(5, until - clock()))
                if not stopped:
                    snapshot('recovery-idle')
        warnings = []
        if result['complete'] != result['transfers']:
            warnings.append('incomplete_transfers')
        if result['probe_pairs_ok'] != result['probe_pairs']:
            warnings.append('failed_ap_forward_probes')
        if result['api_errors'] or result['boot_changes'] or result['offline_samples']:
            warnings.append('api_or_link_events')
        result['warnings'] = warnings
        result['status'] = 'interrupted' if stopped else 'completed-with-warnings' if warnings else 'completed'
    except Exception as e:
        result['status'] = 'failed'
        result['error'] = str(e)
    finally:
        if last:
            private_json(root / 'after.json', clean(last))
        result['elapsed_s'] = clock() - start
        result['ended'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        private_json(root / 'result.json', result)
        for f in fds.values():
            f.close()
        for s, handler in previous.items():
            signal.signal(s, handler)
    return result, root


if __name__ == '__main__':
    result, _ = run(options())
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result['status'] == 'completed' else 2 if result['status'] == 'completed-with-warnings' else 1)
