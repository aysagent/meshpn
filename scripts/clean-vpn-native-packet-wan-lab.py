#!/usr/bin/env python3
"""Bounded native packet/DNS WAN fixture; every TUN/route lives in a new netns.

Only host action is a bounded TCP byte bridge (exit listen/client connect).
Not an installer, benchmark, or host networking recovery tool.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HELPER = Path(__file__).with_name('clean-vpn-native-relay-wan-lab.py')
spec = importlib.util.spec_from_file_location('relay_fixture', HELPER)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
STOP = relay.STOP
INNER = '127.0.0.2'
PORT = 33443
TUN = 'cvpw0'
ORIGIN = '11.22.33.44'
BODY = b'clean-vpn-native-packet-wan\n' * 128


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)


def recv_all(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count-len(result))
        if not part:
            raise RuntimeError('fixture_early_eof')
        result.extend(part)
    return bytes(result)


def dns_probe(address, name, tcp):
    labels = name.rstrip('.').split('.')
    if not name.endswith('.mpn') or len(name) > 253 or any(not x or len(x) > 63 or not all(c.isascii() and (c.isalnum() or c == '-') for c in x) for x in labels):
        raise RuntimeError('private_probe_name_required')
    ident = os.urandom(2)
    question = b''.join(bytes([len(x)])+x.encode('ascii') for x in labels)+b'\0\0\1\0\1'
    query = ident+b'\x01\x00\x00\x01'+b'\0'*6+question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect((address, 1053))
        sock.sendall((struct.pack('!H', len(query)) if tcp else b'')+query)
        if tcp:
            size = struct.unpack('!H', recv_all(sock, 2))[0]
            if not 12 <= size <= 4096:
                raise RuntimeError('dns_response_limit')
            answer = recv_all(sock, size)
        else:
            answer = sock.recv(4097)
    if not 12 <= len(answer) <= 4096 or answer[:2] != ident or not answer[2] & 0x80 or answer[3] & 15 or answer[4:6] != b'\0\1' or answer[12:12+len(question)] != question:
        raise RuntimeError('dns_response_mismatch '+json.dumps({'transport':'tcp' if tcp else 'udp','length':len(answer),'idMatch':answer[:2]==ident,'flags':answer[2:4].hex(),'rcode':answer[3]&15 if len(answer)>=4 else None,'qd':int.from_bytes(answer[4:6],'big') if len(answer)>=6 else None,'questionMatch':answer[12:12+len(question)]==question},separators=(',',':')))
    at = 12+len(question)
    addresses = []
    for _ in range(struct.unpack('!H', answer[6:8])[0]):
        while True:
            if at >= len(answer):
                raise RuntimeError('dns_answer_short')
            n = answer[at]
            at += 1
            if n & 0xc0 == 0xc0:
                at += 1
                break
            if n == 0:
                break
            if n > 63:
                raise RuntimeError('dns_answer_name')
            at += n
        if at+10 > len(answer):
            raise RuntimeError('dns_answer_short')
        kind, cls, _, length = struct.unpack('!HHIH', answer[at:at+10])
        at += 10
        if at+length > len(answer):
            raise RuntimeError('dns_answer_short')
        if kind == 1 and cls == 1 and length == 4:
            addresses.append(socket.inet_ntoa(answer[at:at+length]))
        at += length
    if address not in addresses:
        raise RuntimeError('dns_expected_assignment_missing')
    return {'transport': 'tcp' if tcp else 'udp', 'name': name, 'addresses': addresses}


def relay_config(path):
    relay.private(Path(path))
    config = json.loads(Path(path).read_text())
    if config.get('transport') != 'combo-tls':
        raise RuntimeError('relay_probe_combo_required')
    transparent = config['transparent']
    if transparent.get('destinations') != [{'ipv4': ORIGIN, 'port': 443}] or 'destination_policy' in transparent:
        raise RuntimeError('relay_probe_scoped_origin_required')
    return config


def https_probe(config):
    packet = config['boring']
    if packet.get('role') != 'client':
        raise RuntimeError('relay_probe_client_required')
    relay.private(Path(packet['ca']))
    name = packet['server_name']
    if not name or len(name) > 253 or not all(c.isascii() and (c.isalnum() or c in '.-') for c in name):
        raise RuntimeError('relay_probe_name_required')
    requests = []
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context = ssl.create_default_context(cafile=packet['ca'])
        context.minimum_version = context.maximum_version = version
        context.set_alpn_protocols(['http/1.1'])
        with socket.create_connection((ORIGIN, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=name) as tls:
                negotiated = tls.version()
                tls.sendall(('GET / HTTP/1.1\r\nHost: '+name+'\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = bytearray()
                while True:
                    part = tls.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                    if len(response) > 8192+len(BODY):
                        raise RuntimeError('relay_response_limit')
                header, body = bytes(response).split(b'\r\n\r\n', 1)
                if not header.startswith(b'HTTP/1.1 200 OK\r\n') or body != BODY:
                    raise RuntimeError('relay_response_mismatch')
                requests.append({'tls': negotiated, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'certificateVerified': True})
    return requests


def probe(address, name, config_path=None):
    value = ipaddress.IPv4Address(address)
    if value not in ipaddress.IPv4Network('10.99.0.0/24') or not 2 <= (int(value) & 255) <= 254:
        raise RuntimeError('assigned_address_required')
    dns = [dns_probe(address, name, tcp) for tcp in (False, True)]
    with socket.create_connection((ORIGIN, 18080), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(BODY)
        response = recv_all(sock, len(BODY))
        if response != BODY:
            raise RuntimeError('echo_mismatch')
    requests = https_probe(relay_config(config_path)) if config_path else None
    return {'event': 'packet_wan_probe', 'status': 'passed', 'ipv4': address,
            'dns': dns, 'echoBytes': len(BODY), 'echoSha256': hashlib.sha256(response).hexdigest(),
            'realTun': True, 'nativeDns': True, **({'relayHttps': requests} if requests is not None else {})}


def inside(args):
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        raise RuntimeError('host_namespace_refused')
    links = json.loads(relay.run('ip', '-j', 'link'))
    if [link['ifname'] for link in links] != ['lo']:
        raise RuntimeError('fresh_empty_namespace_required')
    relay.run('ip', 'link', 'set', 'lo', 'up')
    directory = Path(args.directory)
    write_private(directory/'namespace.pid', str(os.getpid())+'\n')
    write_private(directory/'namespace.id', os.readlink('/proc/self/ns/net')+'\n')
    listeners, engine, resolver = [], None, None
    until = time.monotonic()+args.seconds
    try:
        if args.role == 'client':
            listeners.append(relay.Listener(socket.AF_INET, (INNER, PORT), relay.forward(socket.AF_UNIX, str(directory/'bridge.sock'), args.seconds+10)))
            result = json.loads(relay.run(args.engine, '--discover-address', str(directory/'engine.json')))
            if set(result) != {'version','event','status','assignment','ipv4'} or result['version'] != 1 or result['event'] != 'address_discovery' or result['status'] != 'verified' or result['assignment'] != 'v1':
                raise RuntimeError('unverified_discovery')
            address = str(ipaddress.IPv4Address(result['ipv4']))
            if not address.startswith('10.99.0.') or not 2 <= int(address.split('.')[-1]) <= 254:
                raise RuntimeError('assigned_address_range')
            config = json.loads((directory/'engine.json').read_text())
            packet = config.get('boring', config)
            packet['peer_ipv4'] = address
            write_private(directory/'engine-effective.json', json.dumps(config)+'\n')
            write_private(directory/'assignment.json', json.dumps(result)+'\n')
            config_path = directory/'engine-effective.json'
            relay.emit(**result)
        else:
            address = '10.99.0.1'
            config_path = directory/'engine.json'
        relay.run('ip', 'tuntap', 'add', 'dev', TUN, 'mode', 'tun')
        relay.run('ip', 'addr', 'add', address+('/32' if args.role == 'client' else '/24'), 'dev', TUN)
        relay.run('ip', 'link', 'set', TUN, 'mtu', '1400', 'up')
        if args.role == 'client':
            relay.run('ip', 'route', 'add', 'default', 'dev', TUN)
            if args.relay_probe:
                relay_port = config['transparent']['listen']['port']
                relay.run('iptables', '-t', 'nat', '-A', 'OUTPUT', '-d', ORIGIN, '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-ports', str(relay_port))
        else:
            relay.run('ip', 'addr', 'add', ORIGIN+'/32', 'dev', 'lo')
            def echo(sock):
                data = recv_all(sock, len(BODY))
                if data != BODY:
                    raise RuntimeError('echo_request')
                sock.sendall(data)
            listeners.append(relay.Listener(socket.AF_INET, (ORIGIN, 18080), echo))
            if args.relay_probe:
                packet = relay_config(config_path)['boring']
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(packet['cert'], packet['key'])
                context.set_alpn_protocols(['http/1.1'])
                def origin(raw):
                    # Only a local relay dial may reach this synthetic origin;
                    # packet-tunnel clients have 10.99.0.x source addresses.
                    if raw.getpeername()[0] != ORIGIN:
                        raise RuntimeError('relay_origin_requires_local_dial')
                    with context.wrap_socket(raw, server_side=True) as tls:
                        header = bytearray()
                        while b'\r\n\r\n' not in header:
                            data = tls.recv(1024)
                            if not data or len(header)+len(data) > 8192:
                                raise RuntimeError('relay_request_header')
                            header.extend(data)
                        tls.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(BODY)).encode()+b'\r\n\r\n'+BODY)
                listeners.append(relay.Listener(socket.AF_INET, (ORIGIN, 443), origin))
            with open(directory/'resolver.log', 'xb') as log:
                os.chmod(directory/'resolver.log', 0o600)
                resolver = subprocess.Popen([args.node, args.registry_script, 'run', '--registry='+args.registry_file], stdout=log, stderr=log)
            write_private(directory/'resolver.pid', str(resolver.pid)+'\n')
        with open(directory/'native.log', 'xb') as log:
            os.chmod(directory/'native.log', 0o600)
            engine = subprocess.Popen([args.engine, '--config', str(config_path), '--service'], stdout=log, stderr=log)
        write_private(directory/'engine.pid', str(engine.pid)+'\n')
        def started():
            if engine.poll() is not None or resolver and resolver.poll() is not None:
                raise RuntimeError('native_or_resolver_exited')
            records = [json.loads(line) for line in (directory/'native.log').read_text().splitlines() if line.startswith('{')]
            return any(r.get('state') == ('ready' if args.role == 'client' else 'listening') for r in records)
        relay.wait_for(started, 12)
        if args.role == 'exit':
            listeners.append(relay.Listener(socket.AF_UNIX, str(directory/'bridge.sock'), relay.forward(socket.AF_INET, (INNER, PORT), args.seconds+10)))
        relay.emit(event='packet_wan_ready', role=args.role, ipv4=address, namespacePid=os.getpid(), enginePid=engine.pid)
        sequence = 0
        while not STOP.is_set() and time.monotonic() < until:
            if engine.poll() is not None or resolver and resolver.poll() is not None:
                raise RuntimeError('native_or_resolver_exited')
            if args.role == 'client':
                sequence += 1
                try:
                    relay.emit(sequence=sequence, **probe(address, args.peer_name, str(config_path) if args.relay_probe else None))
                except (OSError, RuntimeError) as error:
                    relay.emit(event='packet_wan_probe', status='failed', sequence=sequence, reason=str(error)[:200])
            STOP.wait(1)
    finally:
        STOP.set()
        relay.terminate(engine)
        relay.terminate(resolver)
        for listener in listeners:
            listener.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'probe':
        parser = argparse.ArgumentParser()
        parser.add_argument('--address', required=True)
        parser.add_argument('--name', required=True)
        parser.add_argument('--config', help='Private combo client config enables CA-verified relay HTTPS probe')
        args = parser.parse_args(sys.argv[2:])
        relay.emit(**probe(args.address, args.name, args.config))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['client','exit'], required=True)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--exit-address', required=True)
    parser.add_argument('--port', type=int, default=3443)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--peer-name', default='laptop.mpn')
    parser.add_argument('--relay-probe', action='store_true')
    parser.add_argument('--node')
    parser.add_argument('--registry-script')
    parser.add_argument('--registry-file')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent-netns', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not 15 <= args.seconds <= 300 or not 1024 <= args.port <= 65535:
        raise RuntimeError('root_linux_bounded_trial_required')
    ipaddress.IPv4Address(args.exit_address)
    directory = Path(args.directory)
    if not directory.is_absolute() or directory.resolve() != directory or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise RuntimeError('private_directory_required')
    relay.private(directory/'engine.json')
    config = json.loads((directory/'engine.json').read_text())
    if args.relay_probe:
        relay_config(directory/'engine.json')
    packet = config.get('boring', config)
    if packet.get('role') != args.role or packet.get('address') != INNER or packet.get('port') != PORT or packet.get('tun') != TUN:
        raise RuntimeError('fixed_namespace_endpoint_required')
    if args.role == 'client' and (packet.get('address_assignment') != 'v1' or 'peer_ipv4' in packet or packet.get('dns') is not True):
        raise RuntimeError('discovery_dns_source_required')
    if args.role == 'exit':
        if packet.get('private_peer_dns') is not True or not all((args.node,args.registry_script,args.registry_file)):
            raise RuntimeError('private_registry_required')
        relay.private(Path(args.registry_file))
    if args.inside:
        inside(args)
        return
    for name in ['bridge.sock','engine-effective.json','assignment.json','namespace.pid','namespace.id','engine.pid','resolver.pid','native.log','resolver.log']:
        if (directory/name).exists() or (directory/name).is_symlink():
            raise RuntimeError('fresh_trial_directory_required')
    relay.run(args.engine, '--check-config', str(directory/'engine.json'))
    child = listener = None
    try:
        if args.role == 'client':
            listener = relay.Listener(socket.AF_UNIX, str(directory/'bridge.sock'), relay.forward(socket.AF_INET, (args.exit_address,args.port), args.seconds+10))
        child = subprocess.Popen(['unshare','--net','--mount','--propagation','private',sys.executable,str(Path(__file__).resolve()),*sys.argv[1:],'--inside','--parent-netns',os.readlink('/proc/self/ns/net')], start_new_session=True)
        if args.role == 'exit':
            relay.wait_for(lambda:(directory/'bridge.sock').exists(), 15)
            listener = relay.Listener(socket.AF_INET, (args.exit_address,args.port), relay.forward(socket.AF_UNIX, str(directory/'bridge.sock'), args.seconds+10))
            relay.emit(event='packet_wan_exit_listening', address=args.exit_address, port=args.port)
        deadline = time.monotonic()+args.seconds+20
        while child.poll() is None and not STOP.is_set() and time.monotonic() < deadline:
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
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(5)
        (directory/'bridge.sock').unlink(missing_ok=True)


if __name__ == '__main__':
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    try:
        main()
    except Exception as error:
        relay.emit(status='failed', error=type(error).__name__, reason=str(error)[:300])
        sys.exit(1)
