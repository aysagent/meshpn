#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('clean-vpn-native-dns-capture.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def packet(protocol=17, source=12345, destination=1055):
    transport = struct.pack('!HHHH', source, destination, 12, 0)+b'test' if protocol == 17 else struct.pack('!HH', source, destination)+bytes(8)+b'\x50'+bytes(7)
    return bytearray(b'\x45\0'+struct.pack('!H', 20+len(transport))+bytes(4)+bytes([64, protocol])+bytes(10)+transport)


class Capture(unittest.TestCase):
    def test_protocols_both_directions_and_padding(self):
        for protocol in (6, 17):
            for source, destination in ((1055, 12345), (12345, 1055)):
                p = bytes(packet(protocol, source, destination))
                self.assertEqual(capture.dns_ipv4(p+b'padding'), p)

    def test_other_traffic_and_truncation(self):
        self.assertIsNone(capture.dns_ipv4(packet(destination=53)))
        p = packet(); p[9] = 1
        self.assertIsNone(capture.dns_ipv4(p))
        p = packet()
        for length in range(len(p)):
            self.assertIsNone(capture.dns_ipv4(p[:length]))

    def test_invalid_lengths_fragmentation_and_version(self):
        for offset, value in ((0, 0x65), (0, 0x44), (6, 0x20), (7, 1), (24, 255)):
            p = packet(); p[offset] = value
            self.assertIsNone(capture.dns_ipv4(p))
        p = packet(6); p[32] = 0x40
        self.assertIsNone(capture.dns_ipv4(p))

    def test_namespace_guards(self):
        with patch.object(capture.os, 'readlink', side_effect=['net:[9]', 'net:[1]']), patch.object(capture.socket, 'if_nameindex', return_value=[(1, 'lo'), (2, 'cvpw0')]):
            self.assertEqual(capture.check_namespace('net:[1]'), 'net:[9]')
        for current, parent in [('net:[1]', 'net:[1]'), ('net:[1]', 'net:[9]')]:
            with patch.object(capture.os, 'readlink', side_effect=[current, 'net:[1]']):
                with self.assertRaisesRegex(RuntimeError, 'host_namespace'):
                    capture.check_namespace(parent)
        with patch.object(capture.os, 'readlink', side_effect=['net:[9]', 'net:[1]']), patch.object(capture.socket, 'if_nameindex', return_value=[(1, 'lo'), (2, 'cvpw0'), (3, 'eth0')]):
            with self.assertRaisesRegex(RuntimeError, 'disposable_interfaces'):
                capture.check_namespace('net:[1]')


if __name__ == '__main__':
    unittest.main()
