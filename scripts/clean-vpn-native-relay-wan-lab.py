#!/usr/bin/env python3
"""Bounded relay WAN fixture. Host sockets only; all routing is in a fresh netns.

Not a deployment tool or throughput benchmark. Byte bridges alter TCP timing.
Credentials must already be provisioned in a new private directory.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time

STOP = threading.Event()
BODY = b'clean-vpn-relay-wan\n' * 8192
ORIGIN = '11.22.33.44'
INNER_EXIT = '127.0.0.2'
INNER_PORT = 33443
RELAY_PORT = 10443
LIMIT = threading.BoundedSemaphore(8)


def emit(**record):
    print(json.dumps(record, sort_keys=True), flush=True)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout


def private(path, expected_size=None):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
        raise RuntimeError('private_regular_file_required')
    if expected_size is not None and s.st_size != expected_size:
        raise RuntimeError('credential_size')


def bridge(left, right, lifetime=30):
    """Two bounded queues with backpressure, half-close and absolute lifetime."""
    streams = (left, right)
    queues = [bytearray(), bytearray()]
    ended = [False, False]
    shut = [False, False]
    until = time.monotonic() + lifetime
    for s in streams:
        s.setblocking(False)
    while not STOP.is_set() and time.monotonic() < until:
        readers = [s for i, s in enumerate(streams) if not ended[i] and len(queues[1-i]) < 65536]
        writers = [s for i, s in enumerate(streams) if queues[i]]
        for i in (0, 1):
            if ended[1-i] and not queues[i] and not shut[i]:
                streams[i].shutdown(socket.SHUT_WR)
                shut[i] = True
        if all(shut):
            return
        readable, writable, _ = select.select(readers, writers, [], 0.1)
        for i, s in enumerate(streams):
            if s in writable:
                try:
                    n = s.send(queues[i])
                    del queues[i][:n]
                except BlockingIOError:
                    pass
            if s in readable:
                try:
                    data = s.recv(min(16384, 65536-len(queues[1-i])))
                    if data:
                        queues[1-i].extend(data)
                    else:
                        ended[i] = True
                except BlockingIOError:
                    pass
    raise RuntimeError('bridge_deadline_or_stop')


class Listener:
    def __init__(self, family, address, handler):
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        if family == socket.AF_UNIX:
            os.chmod(address, 0o600)
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.handler = handler
        self.threads = []
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()

    def accept(self):
        while not STOP.is_set():
            try:
                conn, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not LIMIT.acquire(blocking=False):
                conn.close()
                continue
            def task(sock):
                try:
                    with sock:
                        sock.settimeout(5)
                        self.handler(sock)
                except (OSError, RuntimeError, ssl.SSLError):
                    pass
                finally:
                    LIMIT.release()
            t = threading.Thread(target=task, args=(conn,), daemon=True)
            self.threads = [x for x in self.threads if x.is_alive()]
            self.threads.append(t)
            t.start()

    def close(self):
        self.socket.close()
        self.worker.join(1)
        for t in self.threads:
            t.join(0.2)


def forward(family, address, lifetime=30):
    def connected(incoming):
        with socket.socket(family, socket.SOCK_STREAM) as outgoing:
            outgoing.settimeout(5)
            outgoing.connect(address)
            bridge(incoming, outgoing, lifetime)
    return connected


def wait_for(test, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until and not STOP.is_set():
        try:
            if test():
                return
        except (OSError, RuntimeError):
            pass
        time.sleep(0.05)
    raise RuntimeError('readiness_deadline')


def terminate(child):
    if child and child.poll() is None:
        child.terminate()
        try:
            child.wait(5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(5)


def inside(args):
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        raise RuntimeError('host_namespace_refused')
    links = json.loads(run('ip', '-j', 'link', 'show'))
    if len(links) != 1 or links[0]['ifname'] != 'lo':
        raise RuntimeError('fresh_empty_namespace_required')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'addr', 'add', ORIGIN+'/32', 'dev', 'lo')
    directory = Path(args.directory)
    engine = capture = None
    listeners = []
    until = time.monotonic() + args.seconds
    try:
        if args.role == 'exit':
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory/'cert.pem', directory/'key.pem')
            def origin(raw):
                with context.wrap_socket(raw, server_side=True) as tls:
                    header = bytearray()
                    while b'\r\n\r\n' not in header:
                        data = tls.recv(1024)
                        if not data or len(header)+len(data) > 8192:
                            raise RuntimeError('request_header')
                        header.extend(data)
                    tls.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\n\r\n'+BODY)
            listeners.append(Listener(socket.AF_INET, (ORIGIN, 443), origin))
        else:
            listeners.append(Listener(socket.AF_INET, (INNER_EXIT, INNER_PORT), forward(socket.AF_UNIX, str(directory/'bridge.sock'))))
            # Only this fresh namespace: intercept this one synthetic origin.
            run('iptables', '-t', 'nat', '-A', 'OUTPUT', '-d', ORIGIN, '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-ports', str(RELAY_PORT))
        log = open(directory/'engine.log', 'xb', buffering=0)
        engine = subprocess.Popen([args.engine, '--config', str(directory/'engine.json'), '--service'], stdout=log, stderr=log)
        def ready():
            if engine.poll() is not None:
                raise RuntimeError('engine_early_exit')
            return b'"state":"listening"' in (directory/'engine.log').read_bytes()
        wait_for(ready)
        if args.role == 'exit':
            listeners.append(Listener(socket.AF_UNIX, str(directory/'bridge.sock'), forward(socket.AF_INET, (INNER_EXIT, INNER_PORT))))
            emit(stage='namespace-exit-ready')
            while not STOP.is_set() and time.monotonic() < until:
                if engine.poll() is not None:
                    raise RuntimeError('engine_early_exit')
                time.sleep(0.1)
        else:
            capture_log = open(directory/'client-capture.log', 'xb', buffering=0)
            capture = subprocess.Popen(['tcpdump', '-Z', 'root', '--immediate-mode', '-i', 'lo', '-p', '-n', '-U', '-s', '4096', '-c', '12000', '-w', str(directory/'client.pcap'), 'tcp port '+str(RELAY_PORT)], stdout=subprocess.DEVNULL, stderr=capture_log)
            wait_for(lambda: b'listening on' in (directory/'client-capture.log').read_bytes())
            results = []
            for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]*4:
                if STOP.is_set() or time.monotonic() >= until:
                    raise RuntimeError('client_deadline')
                context = ssl.create_default_context(cafile=str(directory/'ca.pem'))
                context.minimum_version = context.maximum_version = version
                context.set_alpn_protocols(['http/1.1'])
                with socket.create_connection((ORIGIN, 443), timeout=8) as raw:
                    with context.wrap_socket(raw, server_hostname='wan-relay.test') as tls:
                        negotiated_version=tls.version()
                        tls.sendall(b'GET / HTTP/1.1\r\nHost: wan-relay.test\r\nConnection: close\r\n\r\n')
                        data = bytearray()
                        while True:
                            part = tls.recv(16384)
                            if not part:
                                break
                            data.extend(part)
                            if len(data) > len(BODY)+8192:
                                raise RuntimeError('response_limit')
                        header, body = bytes(data).split(b'\r\n\r\n', 1)
                        if not header.startswith(b'HTTP/1.1 200 OK') or body != BODY:
                            raise RuntimeError('response_mismatch')
                        results.append({'tls':negotiated_version,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
            emit(kind='native-relay-wan-client', status='passed', requests=results, scope='real-native-transparent-relay-over-host-TCP-Unix-fixture-bridges')
    finally:
        STOP.set()
        terminate(capture)
        terminate(engine)
        for item in listeners:
            item.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['client','exit'], required=True)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--exit-address', required=True)
    parser.add_argument('--port', type=int, default=3443)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent-netns', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not 15 <= args.seconds <= 300 or not 1024 <= args.port <= 65535:
        raise RuntimeError('root_linux_bounded_trial_required')
    ipaddress.IPv4Address(args.exit_address)
    directory = Path(args.directory)
    if not directory.is_absolute() or directory.resolve() != directory or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise RuntimeError('private_directory_required')
    private(directory/'psk', 32)
    for name in (['cert.pem','key.pem'] if args.role == 'exit' else ['ca.pem']):
        private(directory/name)
    if args.inside:
        inside(args)
        return
    if any((directory/name).exists() for name in ['engine.json','bridge.sock','replay','engine.log']):
        raise RuntimeError('fresh_trial_directory_required')
    config = {'version':1,'transport':'transparent-tls','role':args.role,'public_name':'relay.example','secret_path':str(directory/'psk'),
              'listen':{'ipv4':INNER_EXIT if args.role=='exit' else '127.0.0.1','port':INNER_PORT if args.role=='exit' else RELAY_PORT},
              'destinations':[{'ipv4':ORIGIN,'port':443}]}
    if args.role == 'exit':
        (directory/'replay').mkdir(mode=0o700)
        config['replay_directory'] = str(directory/'replay')
    else:
        config['exit'] = {'ipv4':INNER_EXIT,'port':INNER_PORT}
    fd=os.open(directory/'engine.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(config,f)
    run(args.engine,'--check-config',str(directory/'engine.json'))
    if args.role=='exit':
        run(args.engine,'--init-transparent-replay',str(directory/'engine.json'))
    child = listener = None
    try:
        if args.role=='client':
            listener=Listener(socket.AF_UNIX,str(directory/'bridge.sock'),forward(socket.AF_INET,(args.exit_address,args.port)))
        child=subprocess.Popen(['unshare','--net','--mount','--propagation','private',sys.executable,str(Path(__file__).resolve()),
                                *sys.argv[1:],'--inside','--parent-netns',os.readlink('/proc/self/ns/net')],start_new_session=True)
        if args.role=='exit':
            wait_for(lambda:(directory/'bridge.sock').exists())
            listener=Listener(socket.AF_INET,(args.exit_address,args.port),forward(socket.AF_UNIX,str(directory/'bridge.sock')))
            emit(stage='wan-exit-ready',port=args.port)
        deadline=time.monotonic()+args.seconds+15
        while child.poll() is None and not STOP.is_set() and time.monotonic()<deadline:
            time.sleep(0.1)
        if child.poll() is None and not STOP.is_set():
            raise RuntimeError('trial_deadline')
        if child.poll() not in (None,0):
            raise RuntimeError('namespace_worker_failed')
    finally:
        STOP.set()
        if listener:
            listener.close()
        if child and child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL)
                child.wait(5)
        (directory/'bridge.sock').unlink(missing_ok=True)


if __name__=='__main__':
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,lambda *_:STOP.set())
    try:
        main()
    except Exception as error:
        emit(status='failed',error=type(error).__name__,reason=str(error)[:400])
        sys.exit(1)
