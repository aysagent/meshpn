#!/usr/bin/env python3
"""Offline bounded Ethernet/IPv4 TCP header analysis; never changes networking.

Contains endpoint tuples and a truncated hash of a first-record ClientHello random.
No raw payload, SNI, keys or tickets are printed. Hash correlation needs matching
known test traffic; it is not authentication or a full ClientHello parser.
"""
import hashlib
import json
import socket
import struct
import sys

MAX_FILE = 96 * 1024 * 1024

def require(value, code):
    if not value:
        raise ValueError(code)

def analyze(path):
    with open(path, 'rb') as source:
        data = source.read(MAX_FILE + 1)
    require(24 <= len(data) <= MAX_FILE, 'pcap_size')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    require(data[:4] in [bytes.fromhex('d4c3b2a1'), bytes.fromhex('a1b2c3d4')], 'classic_microsecond_pcap_required')
    require(struct.unpack_from(endian + 'HH', data, 4) == (2, 4) and struct.unpack_from(endian + 'I', data, 20)[0] == 1, 'ethernet_pcap_v24_required')
    flows = []
    current = {}
    offset = 24
    packets = 0
    while offset < len(data):
        require(offset + 16 <= len(data) and packets < 600000, 'packet_limit_or_truncated_header')
        sec, usec, size, orig = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        require(usec < 1000000 and size <= orig and (offset + size <= len(data)), 'invalid_packet_header')
        b = data[offset:offset + size]
        offset += size
        packets += 1
        t = sec + usec / 1000000.0
        if len(b) < 54 or b[12:14] != b'\x08\x00':
            continue
        ip = 14
        ihl = (b[ip] & 15) * 4
        require(b[ip] >> 4 == 4 and ihl >= 20, 'invalid_ipv4_header')
        if b[ip + 9] != 6 or struct.unpack_from('!H', b, ip + 6)[0] & 16383:
            continue
        tcp = ip + ihl
        if len(b) < tcp + 20:
            continue
        src = socket.inet_ntoa(b[ip + 12:ip + 16])
        dst = socket.inet_ntoa(b[ip + 16:ip + 20])
        sp, dp, seq, ack = struct.unpack_from('!HHII', b, tcp)
        if 443 not in [sp, dp]:
            continue
        outbound = dp == 443
        key = (src, sp, dst, dp) if outbound else (dst, dp, src, sp)
        th = (b[tcp + 12] >> 4) * 4
        flags = b[tcp + 13]
        win = struct.unpack_from('!H', b, tcp + 14)[0]
        length = struct.unpack_from('!H', b, ip + 2)[0] - ihl - th
        require(th >= 20 and length >= 0 and (ip + ihl + th + length <= orig), 'invalid_tcp_length')
        if len(b) < tcp + th:
            continue
        f = current.get(key)
        if f is None or (outbound and flags & 2 and (not flags & 16) and (f.get('syn') != seq)):
            require(len(flows) < 4096, 'flow_limit')
            f = {'tuple': key, 'start': t, 'end': t, 'helloId': None, 'directions': [[], []], 'syn': seq if outbound and flags & 2 else None}
            current[key] = f
            flows.append(f)
        f['end'] = t
        payload = b[tcp + th:tcp + th + length]
        if (outbound and f['syn'] is not None
                and seq == ((f['syn'] + 1) & 0xffffffff)
                and len(payload) >= 43 and payload[0] == 22
                and payload[1] == 3 and payload[5] == 1
                and payload[9:11] == b'\x03\x03'):
            f['helloId'] = hashlib.sha256(payload[11:43]).hexdigest()[:24]
        f['directions'][0 if outbound else 1].append({'t': t, 'seq': seq, 'ack': ack, 'n': length, 'flags': flags, 'win': win})
    out = []
    for f in flows:
        row = {k: v for k, v in f.items() if k != 'directions'}
        row['directions'] = []
        for i, pk in enumerate(f['directions']):
            syn = next((p['seq'] for p in pk if p['flags'] & 2), None)
            base = syn + 1 & 4294967295 if syn is not None else pk[0]['seq'] if pk else 0
            ranges = []
            wire = 0
            high = 0
            timeline = []
            for p in pk:
                if p['n']:
                    s = p['seq'] + (1 if p['flags'] & 2 else 0) - base & 4294967295
                    e = s + p['n']
                    if s >= 2 ** 31:
                        continue
                    wire += p['n']
                    high = max(high, e)
                    ranges.append((s, e))
                    timeline.append([round(p['t'] - f['start'], 6), s, e])
            merged = []
            for a, b in sorted(ranges):
                if merged and a <= merged[-1][1]:
                    merged[-1][1] = max(b, merged[-1][1])
                else:
                    merged.append([a, b])
            acks = [p['ack'] - base & 4294967295 for p in f['directions'][1 - i] if p['flags'] & 16]
            acks = [n for n in acks if n < 2 ** 31]
            unique = sum(b - a for a, b in merged)
            row['directions'].append({
                'synCaptured': syn is not None, 'packets': len(pk),
                'wirePayloadBytes': wire, 'uniquePayloadBytes': unique,
                'highestEnd': high, 'highestPeerAck': max(acks, default=0),
                'overlapBytes': wire - unique, 'gaps': max(0, len(merged) - 1),
                'zeroWindowPackets': sum(p['win'] == 0 for p in pk),
                'fin': sum(bool(p['flags'] & 1) for p in pk),
                'rst': sum(bool(p['flags'] & 4) for p in pk),
                'firstData': timeline[:2], 'lastData': timeline[-4:]
            })
        out.append(row)
    return {
        'schema': 1, 'kind': 'clean-vpn-tcp-header-analysis',
        'limitations': [
            'ethernet-ipv4-443-only-no-VLAN-or-fragments',
            'header-sequence-coverage-not-payload-integrity',
            'overlap-is-not-proof-of-wire-retransmission',
            'requires-captured-SYN-for-reliable-relative-counts',
            'tuple-reuse-separated-by-client-SYN-sequence',
            'late-packets-after-tuple-reuse-may-be-ambiguous',
            'per-direction-sequence-span-must-be-below-2GiB',
            'hello-prefix-hash-only-no-reassembly',
            'no-capture-drop-proof', 'no-leak-or-browser-verdict'
        ],
        'file': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
        'packets': packets, 'flows': out
    }

if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'usage_pcap_path')
        print(json.dumps(analyze(sys.argv[1]), indent=2))
    except (ValueError, OSError, struct.error) as error:
        code = str(error) if isinstance(error, ValueError) else 'capture_read_failed'
        print(json.dumps({'status': 'failed', 'code': code}), file=sys.stderr)
        sys.exit(1)
