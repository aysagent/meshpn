#!/usr/bin/env python3
"""Private, bounded DNS capture for the disposable packet WAN lab only.

AF_PACKET/SOCK_DGRAM strips link headers on both loopback and TUN; output uses
DLT_RAW (101), one pcap per interface. No promiscuous mode or network changes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import time


def dns_ipv4(packet):
    """Accept complete, unfragmented IPv4 TCP/UDP packets involving port 1055."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 15) * 4
    total = int.from_bytes(packet[2:4], 'big')
    if ihl < 20 or total < ihl or total > len(packet):
        return None
    # A fragment lacks independently verifiable port/length semantics.
    if int.from_bytes(packet[6:8], 'big') & 0x3fff:
        return None
    protocol = packet[9]
    minimum = 8 if protocol == 17 else 20 if protocol == 6 else 0
    if not minimum or total < ihl + minimum:
        return None
    source, destination = struct.unpack('!HH', packet[ihl:ihl+4])
    if 1055 not in (source, destination):
        return None
    if protocol == 17:
        length = int.from_bytes(packet[ihl+4:ihl+6], 'big')
        if length < 8 or ihl + length != total:
            return None
    elif not 20 <= (packet[ihl+12] >> 4) * 4 <= total - ihl:
        return None
    return packet[:total]


def check_namespace(parent):
    if not re.fullmatch(r'net:\[[0-9]+\]', parent):
        raise RuntimeError('parent_netns_required')
    current = os.readlink('/proc/self/ns/net')
    if current in (parent, os.readlink('/proc/1/ns/net')):
        raise RuntimeError('host_namespace_refused')
    if {name for _, name in socket.if_nameindex()} != {'lo', 'cvpw0'}:
        raise RuntimeError('disposable_interfaces_required')
    return current


def private_directory(value):
    directory = Path(value)
    if not directory.is_absolute() or str(directory) != os.path.normpath(value):
        raise RuntimeError('absolute_private_directory_required')
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise RuntimeError('untrusted_directory')
        if parent == directory:
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise RuntimeError('private_directory_mode_required')
        elif info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise RuntimeError('writable_parent_refused')
    return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def capture(args):
    namespace = check_namespace(args.parent_netns)
    if not 1 <= args.seconds <= 300 or not 1 <= args.max_packets <= 100000 or not 1024 <= args.max_bytes <= 64*1024*1024:
        raise RuntimeError('capture_limits')
    directory_fd = private_directory(args.directory)
    sockets, outputs = [], {}
    packets = dropped = 0
    written = 48  # two pcap headers, included in aggregate byte budget
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for interface in ('lo', 'cvpw0'):
            fd = os.open(interface+'.pcap', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            output = os.fdopen(fd, 'wb', buffering=0)
            outputs[interface] = output
            output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
            sockets.append(sock)
            sock.bind((interface, 0))
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256*1024)
        print(json.dumps({'event': 'dns_capture_ready', 'namespace': namespace, 'interfaces': ['lo', 'cvpw0'], 'dlt': 101}), flush=True)
        end = time.monotonic() + args.seconds
        reason = 'deadline'
        while not stopped and time.monotonic() < end:
            ready, _, _ = select.select(sockets, [], [], min(.2, max(0, end-time.monotonic())))
            for sock in ready:
                try:
                    raw, source = sock.recvfrom(65535)
                except BlockingIOError:
                    continue
                packet = dns_ipv4(raw)
                if packet is None:
                    continue
                size = 16 + len(packet)
                if packets >= args.max_packets or written + size > args.max_bytes:
                    stopped = True
                    reason = 'limit'
                    break
                now = time.time_ns()
                outputs[source[0]].write(struct.pack('<IIII', now//1000000000, now//1000 % 1000000, len(packet), len(packet))+packet)
                packets += 1
                written += size
        if stopped and reason != 'limit':
            reason = 'signal'
        # PACKET_STATISTICS resets the kernel counters; read once at the end.
        for sock in sockets:
            try:
                _, lost = struct.unpack('II', sock.getsockopt(263, 6, 8))
                dropped += lost
            except OSError:
                dropped = None
                break
        print(json.dumps({'event': 'dns_capture_complete', 'packets': packets, 'bytes': written, 'kernelDropped': dropped, 'reason': reason}), flush=True)
    finally:
        for sock in sockets:
            sock.close()
        for output in outputs.values():
            output.close()
        os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-netns', required=True)
    parser.add_argument('--directory', required=True, help='Existing private 0700 directory; files must not exist')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--max-packets', type=int, default=20000)
    parser.add_argument('--max-bytes', type=int, default=16*1024*1024)
    capture(parser.parse_args())


if __name__ == '__main__':
    main()
