#!/usr/bin/env python3
"""Bounded local throughput peer for /api/diag/net-bench; no routes/Wi-Fi changes.

TCP/UDP share one port on an explicitly supplied local address. Only explicitly
listed source IPs may start work. UDP sessions cannot redirect/amplify to a third
party. Receiver bytes, not sender bytes, are used for throughput comparisons.
"""
import argparse
import collections
import json
import socket
import struct
import threading
import time

HELLO = struct.Struct('!4s7I')
DATA = struct.Struct('!4sII')


def hello(data):
    if len(data) != HELLO.size:
        raise ValueError('hello length')
    magic, nonce, down, seconds, rate, size, r1, r2 = HELLO.unpack(data)
    if (magic != b'MNB1' or not nonce or down not in (0, 1) or
            not 1 <= seconds <= 60 or not 64 <= rate <= 32000 or
            size not in (1200, 8192) or r1 or r2):
        raise ValueError('hello fields')
    return nonce, down, seconds, rate, size


class Peer:
    def __init__(self, host, allowed, port=0):
        self.allowed = set(allowed)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.rows = collections.OrderedDict()
        self.connections = set()
        self.tcp = socket.socket()
        self.tcp.bind((host, port)); self.tcp.listen(4); self.tcp.settimeout(.2)
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((host, self.port)); self.udp.settimeout(.2)
        self.threads = []
        self.spawn(self.accept)
        self.spawn(self.datagrams)

    def spawn(self, target, *args):
        # Finished handles are pruned; long soaks must not retain every test.
        self.threads = [t for t in self.threads if t.is_alive()]
        t = threading.Thread(target=target, args=args, daemon=True)
        self.threads.append(t); t.start()

    def begin(self, header, source, protocol):
        nonce, down, seconds, rate, size = hello(header)
        if source[0] not in self.allowed or size != (1200 if protocol == 'udp' else 8192):
            raise ValueError('unauthorized source or payload')
        with self.lock:
            if any(not row['done'] for row in self.rows.values()):
                raise ValueError('peer busy')
            if nonce in self.rows:
                raise ValueError('reused nonce')
            row = dict(nonce=nonce, source=source, protocol=protocol, down=bool(down),
                       seconds=seconds, target_kbps=rate, bytes=0, packets=0,
                       duplicates=0, invalid=0, started=time.monotonic(), elapsed=0,
                       sequence_span=0, reordered=0,
                       done=False, error=None)
            self.rows[nonce] = row
            while len(self.rows) > 256:
                self.rows.popitem(last=False)
        return row

    def finish(self, row):
        row['elapsed'] = time.monotonic() - row['started']; row['done'] = True

    def snapshot(self, nonce):
        with self.lock:
            row = dict(self.rows.get(nonce, {}))
            if row:
                row['udp_sequence_available'] = row['protocol'] == 'udp' and not row['down']
                row['sequence_missing'] = row['sequence_span'] - row['packets'] if row['udp_sequence_available'] else None
            return row

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, source = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if source[0] not in self.allowed or len(self.connections) >= 2:
                    conn.close(); continue
                self.connections.add(conn)
            self.spawn(self.stream, conn, source)

    def stream(self, conn, source):
        row = None
        try:
            conn.settimeout(.2); conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            header = b''; deadline = time.monotonic() + 3
            while len(header) < 32 and time.monotonic() < deadline and not self.stop.is_set():
                try:
                    b = conn.recv(32-len(header))
                    if not b: return
                    header += b
                except socket.timeout:
                    pass
            row = self.begin(header, source, 'tcp'); conn.sendall(header)
            row['started'] = time.monotonic()
            deadline = row['started'] + row['seconds'] + (0 if row['down'] else 1)
            payload = b'Z' * 8192
            while time.monotonic() < deadline and not self.stop.is_set():
                try:
                    if row['down']:
                        n = conn.send(payload)
                    else:
                        n = len(conn.recv(65536))
                    if not n: break
                    row['bytes'] += n; row['packets'] += 1
                except socket.timeout:
                    continue
        except (OSError, ValueError) as e:
            if row: row['error'] = str(e)
        finally:
            if row: self.finish(row)
            with self.lock: self.connections.discard(conn)
            conn.close()

    def datagrams(self):
        current = None; seen = set()
        while not self.stop.is_set():
            if current and time.monotonic() > current['started'] + current['seconds'] + .5:
                self.finish(current); current = None; seen.clear()
            try:
                data, source = self.udp.recvfrom(16384)
            except socket.timeout:
                continue
            except OSError:
                break
            if source[0] not in self.allowed: continue
            if data.startswith(b'MNB1'):
                try:
                    row = self.begin(data, source, 'udp')
                except ValueError:
                    continue
                self.udp.sendto(data, source)
                row['started'] = time.monotonic()
                if row['down']:
                    self.spawn(self.send_udp, row, source)
                else:
                    current = row; seen.clear()
            elif current and source == current['source']:
                if len(data) != 1200 or data[:4] != b'MND1':
                    current['invalid'] += 1; continue
                _, nonce, seq = DATA.unpack(data[:12])
                if nonce != current['nonce'] or seq >= 250000:
                    current['invalid'] += 1; continue
                if seq in seen:
                    current['duplicates'] += 1; continue
                if seq < current['sequence_span']: current['reordered'] += 1
                else: current['sequence_span'] = seq + 1
                seen.add(seq); current['bytes'] += len(data); current['packets'] += 1
                # Duration from acknowledged start, without the final drain wait.
                current['receive_elapsed'] = time.monotonic() - current['started']
        if current: self.finish(current)

    def send_udp(self, row, source):
        try:
            while not self.stop.is_set() and time.monotonic() < row['started'] + row['seconds']:
                due = row['started'] + row['bytes'] * 8 / (row['target_kbps'] * 1000)
                if due > time.monotonic():
                    self.stop.wait(min(.1, due-time.monotonic())); continue
                data = DATA.pack(b'MND1', row['nonce'], row['packets']) + b'Z' * 1188
                n = self.udp.sendto(data, source)
                row['bytes'] += n; row['packets'] += 1
        except OSError as e:
            row['error'] = str(e)
        finally:
            self.finish(row)

    def close(self):
        self.stop.set()
        self.tcp.close(); self.udp.close()
        with self.lock:
            for conn in self.connections:
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        for t in list(self.threads): t.join(2)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True); p.add_argument('--allow', action='append', required=True)
    a = p.parse_args(); peer = Peer(a.host, a.allow)
    print(json.dumps({'host': a.host, 'port': peer.port}), flush=True)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        peer.close()
        print(json.dumps(list(peer.rows.values()), indent=2))
