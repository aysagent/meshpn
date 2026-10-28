import importlib.util
from pathlib import Path
import socket
import struct
import time
import unittest

spec=importlib.util.spec_from_file_location('peer',Path(__file__).resolve().parents[1]/'scripts/p4-net-peer.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class PeerTests(unittest.TestCase):
    def setUp(self):self.peer=p.Peer('127.0.0.1',['127.0.0.1'])
    def tearDown(self):self.peer.close()
    def header(self,nonce,down=0,seconds=1,rate=1000,size=8192):
        return p.HELLO.pack(b'MNB1',nonce,down,seconds,rate,size,0,0)
    def test_bounded_parser(self):
        for kw in [dict(nonce=0),dict(nonce=1,seconds=0),dict(nonce=1,seconds=61),
                   dict(nonce=1,down=2),dict(nonce=1,rate=64000),dict(nonce=1,size=65000)]:
            with self.assertRaises(ValueError):p.hello(self.header(**kw))
        with self.assertRaises(ValueError):p.hello(self.header(1)+b'x')
    def test_fragmented_tcp_and_receiver_count(self):
        s=socket.create_connection(('127.0.0.1',self.peer.port));s.settimeout(2)
        h=self.header(10)
        for b in h:s.sendall(bytes([b]))
        got=b''
        while len(got)<32:got+=s.recv(32-len(got))
        self.assertEqual(got,h)
        s.sendall(b'a'*12345);s.shutdown(socket.SHUT_WR)
        self.assertEqual(s.recv(1),b'');s.close()
        self.assertEqual(self.peer.snapshot(10)['bytes'],12345)
    def test_udp_counts_unique_and_rejects_wrong_nonce(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
        s.connect(('127.0.0.1',self.peer.port));h=self.header(11,size=1200)
        s.send(h);self.assertEqual(s.recv(32),h)
        for nonce,seq in [(11,0),(11,0),(11,1),(12,2)]:
            s.send(p.DATA.pack(b'MND1',nonce,seq)+b'x'*1188)
        time.sleep(.1);r=self.peer.snapshot(11)
        self.assertEqual(r['bytes'],2400);self.assertEqual(r['duplicates'],1);self.assertEqual(r['invalid'],1)
        s.close()
    def test_udp_download_has_requested_nonce_and_bound(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
        s.connect(('127.0.0.1',self.peer.port));h=self.header(12,down=1,rate=64,size=1200)
        s.send(h);self.assertEqual(s.recv(32),h)
        data=s.recv(1500);self.assertEqual(len(data),1200);self.assertEqual(p.DATA.unpack(data[:12]),(b'MND1',12,0))
        time.sleep(1.1);self.assertTrue(self.peer.snapshot(12)['done'])
        self.assertLessEqual(self.peer.snapshot(12)['bytes'],9600);s.close()
    def test_stop_terminates_active_stream(self):
        s=socket.create_connection(('127.0.0.1',self.peer.port));s.settimeout(2)
        s.sendall(self.header(13,seconds=60));s.recv(32)
        self.peer.close();self.assertEqual(s.recv(1),b'');s.close()

if __name__=='__main__':unittest.main()
