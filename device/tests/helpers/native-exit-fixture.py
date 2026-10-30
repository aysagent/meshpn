"""Test-only AF_UNIX TUN substitute. Native engine owns TLS/H2/auth/framing.
No /dev/net/tun, routes, firewall, DNS, external sockets, or packet contents in logs.
"""
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
from pathlib import Path


def relay():
    # Encrypted stream bridge for an isolated --network=none container. The
    # test driver listens on Mac loopback; this connects only container loopback.
    with socket.create_connection(("127.0.0.1", 8765), timeout=5) as peer:
        peer.settimeout(None)
        sel = selectors.DefaultSelector()
        sel.register(sys.stdin.buffer, selectors.EVENT_READ)
        sel.register(peer, selectors.EVENT_READ)
        while True:
            for key, _ in sel.select(20):
                if key.fileobj is peer:
                    data = peer.recv(65536)
                    if not data:
                        return
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if not data:
                        peer.shutdown(socket.SHUT_WR)
                        sel.unregister(sys.stdin.buffer)
                    else:
                        peer.sendall(data)


def serve(executable, directory):
    out = Path(directory)
    engine = None
    running = True
    counts = {"packets": 0, "bytes": 0}

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        with open(out / "engine.log", "wb") as log:
            prefix = [os.environ["MESHPN_FIXTURE_QEMU"]] if os.environ.get("MESHPN_FIXTURE_QEMU") else []
            engine = subprocess.Popen(prefix + [executable, "--config", str(out / "config.json"),
                                       "--test-packet-fd", str(right.fileno())],
                                      pass_fds=(right.fileno(),), stdin=subprocess.PIPE,
                                      stdout=log, stderr=log)
            right.close()
            left.settimeout(0.1)
            while running:
                if engine.poll() is not None:
                    raise RuntimeError("Native exit stopped unexpectedly")
                try:
                    p = bytearray(left.recv(2048))
                except socket.timeout:
                    continue
                assert len(p) >= 28 and p[0] == 0x45 and p[9] == 17
                assert p[12:16] == bytes([10, 99, 0, 2])
                assert p[16:20] == bytes([1, 1, 1, 1])
                counts["packets"] += 1
                counts["bytes"] += len(p)
                # A return IP packet must target the authenticated peer. Swapping
                # addresses leaves IPv4 + UDP pseudo-header sums unchanged.
                p[12:16], p[16:20] = p[16:20], p[12:16]
                assert left.send(p) == len(p)
    finally:
        if engine is not None:
            engine.terminate()
            try:
                engine.wait(timeout=3)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.wait()
        left.close()
        right.close()
        (out / "counts.json").write_text(json.dumps(counts) + "\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["relay"]:
        relay()
    else:
        assert len(sys.argv) == 3
        serve(sys.argv[1], sys.argv[2])
