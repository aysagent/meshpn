import importlib.util
import pathlib
import socket
import struct
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('capture', pathlib.Path(__file__).with_name('clean-vpn-tcp-capture.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)

def packet(seq, payload=b'', flags=16, reverse=False, ack=0, window=4096, snap=None):
    ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
    struct.pack_into('!H', ip, 2, 40 + len(payload))
    ip[12:16] = socket.inet_aton('192.0.2.2' if reverse else '192.0.2.1')
    ip[16:20] = socket.inet_aton('192.0.2.1' if reverse else '192.0.2.2')
    tcp = bytearray(20)
    struct.pack_into('!HHII', tcp, 0, 443 if reverse else 50000, 50000 if reverse else 443, seq, ack)
    tcp[12] = 0x50; tcp[13] = flags; struct.pack_into('!H', tcp, 14, window)
    b = bytes(12) + b'\x08\x00' + ip + tcp + payload
    return (bytes(b[:snap] if snap else b), len(b))

def pcap(packets):
    b = bytes.fromhex('d4c3b2a1') + struct.pack('<HHIIII', 2, 4, 0, 0, 128, 1)
    for n, (body, original) in enumerate(packets):
        b += struct.pack('<IIII', 1700000000, n * 1000, len(body), original) + body
    return b

class CaptureTests(unittest.TestCase):
    def read(self, data):
        with tempfile.NamedTemporaryFile() as f:
            f.write(data); f.flush(); return capture.analyze(f.name)

    def test_reorder_overlap_and_ack_with_header_only_capture(self):
        r = self.read(pcap([packet(100, flags=2), packet(900, flags=18, reverse=True, ack=101),
            packet(111, b'x'*10, snap=54), packet(101, b'x'*15, snap=54),
            packet(901, reverse=True, ack=121, window=0)]))
        d = r['flows'][0]['directions']
        self.assertEqual(d[0]['uniquePayloadBytes'], 20)
        self.assertEqual(d[0]['overlapBytes'], 5)
        self.assertEqual(d[0]['highestPeerAck'], 20)
        self.assertEqual(d[1]['zeroWindowPackets'], 1)
        self.assertEqual(d[1]['gaps'], 0)

    def test_nat_tuple_reuse_separates_sessions_but_syn_retry_does_not(self):
        r = self.read(pcap([packet(100, flags=2), packet(100, flags=2), packet(101, b'a'*10),
            packet(2000, flags=2), packet(2001, b'b'*30)]))
        self.assertEqual(len(r['flows']), 2)
        self.assertEqual([f['directions'][0]['uniquePayloadBytes'] for f in r['flows']], [10, 30])

    def test_sequence_wrap_and_missing_syn_are_explicit(self):
        r = self.read(pcap([packet(0xfffffff0, flags=2), packet(0xfffffff1, b'x'*32), packet(17, b'y'*8)]))
        self.assertEqual(r['flows'][0]['directions'][0]['uniquePayloadBytes'], 40)
        r = self.read(pcap([packet(100, b'x')]))
        self.assertFalse(r['flows'][0]['directions'][0]['synCaptured'])

    def test_only_hashes_hello_random_and_rejects_truncated_files(self):
        body = b'\x16\x03\x01\x00\x26\x01\x00\x00\x22\x03\x03' + b'PRIVATE-CLIENT-RANDOM-012345678901'
        r = self.read(pcap([packet(100, flags=2), packet(101, body)]))
        self.assertEqual(len(r['flows'][0]['helloId']), 24)
        self.assertNotIn('PRIVATE', str(r))
        for raw in [b'', pcap([]) + b'\x00', pcap([packet(100, b'x')])[:-1]]:
            with self.assertRaises(ValueError): self.read(raw)

if __name__ == '__main__':
    unittest.main()
