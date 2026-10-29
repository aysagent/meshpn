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
    p.add_argument('--admin-ip')
    p.add_argument('--board', default=os.environ.get('BOARD', 'waveshare'))
    p.add_argument('--out', type=Path, default=Path(__file__).resolve().parents[1] / 'perf-results')
    p.add_argument('--cycle-gap', type=float, default=20)
    p.add_argument('--sta-tcp-trace', action='store_true',
                   help='save bounded STA TCP header snapshots via USB after each STA transfer')
    a = p.parse_args(argv)
    catalog = json.loads((Path(__file__).resolve().parents[1] / 'boards/development.json').read_text())
    selected = [(name, v) for name, v in catalog.items() if a.board == name or a.board in v['aliases']]
    if len(selected) != 1:
        p.error('unknown board; use waveshare or stamp')
    a.board, profile = selected[0]
    a.admin_ip = a.admin_ip or profile['usb']
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
                                   'radio', 'tx', 'tx_failures', 'hosted'] if k in w}
    v = s.get('vpn', {})
    out['vpn'] = {k: v[k] for k in ['enabled', 'connected', 'state', 'transport'] if k in v}
    return out


def private_json(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as f:
        json.dump(data, f, indent=2)


def clean_sta_trace(trace):
    """Retain header metadata only, even if a future API adds other fields."""
    if not isinstance(trace, dict):
        raise ValueError('invalid_STA_trace_response')
    def numbers(value, fields):
        if not isinstance(value, dict):
            return {}
        return {k: value[k] for k in fields if type(value.get(k)) is int and 0 <= value[k] < 2**64}
    out = numbers(trace, ['peer_port', 'age_ms', 'total_events', 'omitted_events'])
    for key in ['peer', 'local']:
        try:
            out[key] = str(ipaddress.IPv4Address(trace.get(key)))
        except (ValueError, TypeError):
            pass
    for key in ['rx', 'tx']:
        out[key] = numbers(trace.get(key), ['packets', 'data_bytes_including_repeats',
                                          'checksum_checked', 'bad_ip', 'bad_tcp'])
    events = trace.get('events')
    out['events'] = [numbers(e, ['elapsed_ms', 'seq', 'ack', 'flags', 'tx', 'payload', 'window',
                                'sack_blocks', 'sack_left', 'sack_right', 'checksum_checked',
                                'bad_ip', 'bad_tcp']) for e in events[-64:]] if isinstance(events, list) else []
    return out


def upload_blocks(body, deadline):
    """Keep sendall's operation timeout local to a bounded block, not 1 MB."""
    view = memoryview(body)
    for offset in range(0, len(view), 16384):
        if time.monotonic() >= deadline:
            raise TimeoutError('transfer_deadline')
        yield view[offset:offset + 16384]


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
        for attempt in range(2):
            try:
                self.token = self.api('/api/login', {'password': os.environ.get('MESHPN_ADMIN_PASSWORD', 'admin')}, retry=False)['token']
                return
            except urllib.error.HTTPError as e:
                # Firmware also limits successful logins to one per second.
                # One bounded retry handles a preceding operator/preflight login;
                # a wrong password is never retried or used to bypass lockout.
                if e.code != 429 or attempt:
                    raise
                time.sleep(1.1)

    def transfer(self, address, direction, deadline, source=None, iface=None, nodelay=True):
        """Count only consumed response bytes; upload requires board receipt JSON."""
        row = {'address': address, 'direction': direction, 'complete': False, 'bytes': 0}
        if direction == 'down': row['server_tcp_nodelay'] = bool(nodelay)
        started = time.monotonic()
        duration = min(35, deadline - started)
        if duration <= 0:
            return {**row, 'error': 'run_deadline', 'seconds': 0}
        route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn = None
        try:
            route.connect((address, 80))
            source = source or route.getsockname()[0]
            row['source'] = source
            conn = http.client.HTTPConnection(address, 80, timeout=min(5, duration), source_address=(source, 0))
            if iface:
                # macOS IP_BOUND_IF forces the test through the selected USB NIC.
                conn.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.sock.settimeout(min(5, duration))
                conn.sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(iface))
                conn.sock.bind((source, 0))
                conn.sock.connect((address, 80))
            else:
                conn.connect()
            row['connect_s'] = time.monotonic() - started
            row['source_port'] = conn.sock.getsockname()[1]
            conn.sock.settimeout(min(3, duration))
            body = bytes(1000000) if direction == 'up' else b''
            # socket.sendall times out across its whole argument even while
            # making progress. One 1 MB argument falsely aborts a healthy slow
            # upload after 3 s. Stream bounded pieces under the total budget;
            # explicit length keeps the firmware request unchunked.
            payload = upload_blocks(body, min(started + duration, deadline)) if direction == 'up' else body
            endpoint = '/api/diag/link-upload' if direction == 'up' else '/api/diag/link-download?nodelay=' + str(int(bool(nodelay)))
            conn.request('POST', endpoint,
                         body=payload, headers={'Authorization': 'Bearer ' + self.token,
                                                'Connection': 'close', 'Content-Length': str(len(body))})
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
    result.update(sta_tcp_traces=0, sta_tcp_trace_errors=0)
    trace_enabled = getattr(a, 'sta_tcp_trace', False)
    result['sta_tcp_trace_requested'] = trace_enabled
    fds = {n: os.fdopen(os.open(root / (n + '.ndjson'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w', buffering=1)
           for n in ['status', 'measurements', 'events']}
    first = None
    last = None
    failures = 0
    def capture_sta_trace(row):
        nonlocal trace_enabled
        if not trace_enabled or row['kind'] != 'sta' or end - clock() < .5:
            return
        try:
            trace = clean_sta_trace(board.api('/api/diag/sta-tcp', timeout=min(5, end-clock())))
            expected = {'peer': row.get('source'), 'peer_port': row.get('source_port'), 'local': row.get('address')}
            matches = all(trace.get(k) == v for k, v in expected.items()) if all(v is not None for v in expected.values()) else None
            private_json(root / ('sta-tcp-%06d.json' % result['transfers']),
                         {'transfer_index': result['transfers'], 'direction': row['direction'],
                          'tuple_matches': matches, 'trace': trace})
            result['sta_tcp_traces'] += 1
            if matches is False:
                result['sta_tcp_trace_errors'] += 1
                record('events', {'event': 'sta_tcp_trace_tuple_mismatch', 'transfer_index': result['transfers']})
        except Exception as e:
            result['sta_tcp_trace_errors'] += 1
            record('events', {'event': 'sta_tcp_trace_error', 'transfer_index': result['transfers'], 'error': str(e)})
            if isinstance(e, urllib.error.HTTPError) and e.code in [401, 403, 404, 501]:
                trace_enabled = False  # Missing capability/auth is explicit; never hammer it.
            if isinstance(e, urllib.error.HTTPError):
                e.close()
    def record(name, row):
        fds[name].write(json.dumps({'elapsed_s': clock() - start, **row}) + '\n')
    def snapshot(phase):
        nonlocal first, last
        t = clock()
        try:
            s = board.api('/api/status')
            if s.get('board') != getattr(a, 'board', 'waveshare_esp32_p4_wifi6'):
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
                    row['transfer_index'] = result['transfers'] + 1
                    record('measurements', row)
                    result['transfers'] += 1
                    result['complete'] += bool(row['complete'])
                    capture_sta_trace(row)  # Before any later STA SYN can replace this flow.
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
        if result['sta_tcp_trace_errors']:
            warnings.append('sta_tcp_trace_issues')
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
