import importlib.util
import contextlib
import io
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import threading
import tty
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "usb-diag.py"
SPEC = importlib.util.spec_from_file_location("usb_diag", SCRIPT)
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)


class USBTests(unittest.TestCase):
    def test_frames(self):
        packet = DIAG.BEGIN + b"build=test\n" + DIAG.END
        self.assertIsNone(DIAG.frame(packet[:-1]))
        self.assertEqual(DIAG.frame(b"old bytes" + packet), packet.decode())
        with self.assertRaisesRegex(RuntimeError, "Oversized"):
            DIAG.frame(b"x" * (DIAG.LIMIT + 1))

    def test_port_selection(self):
        self.assertEqual(DIAG.find_port("/dev/test"), "/dev/test")

    def test_read_only_exchange(self):
        master, slave = pty.openpty()
        process = subprocess.Popen([sys.executable, str(SCRIPT), "--port", os.ttyname(slave), "--no-http"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([master], [], [], 5)[0])
            self.assertEqual(os.read(master, 64), b"?")
            os.write(master, DIAG.BEGIN + b"build=test web.stage=ready\n" + DIAG.END)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("build=test web.stage=ready", stdout)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            os.close(master)
            os.close(slave)

    def test_disconnected_or_wrong_port(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--port", "/nonexistent-meshpn-port"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("USB diagnostics:", result.stderr)

    def test_timeout(self):
        master, slave = pty.openpty()
        try:
            tty.setraw(slave)
            with self.assertRaisesRegex(RuntimeError, "device:flash:diag"):
                DIAG.snapshot(slave, timeout=0.03)
            self.assertEqual(os.read(master, 64), b"?")
        finally:
            os.close(master)
            os.close(slave)

    def test_two_snapshots_around_http(self):
        master, slave = pty.openpty()
        received = []

        def board():
            for index in range(2):
                if not select.select([master], [], [], 5)[0]:
                    return
                received.append(os.read(master, 64))
                os.write(master, DIAG.BEGIN + ("snapshot=%d\n" % index).encode() + DIAG.END)

        thread = threading.Thread(target=board, daemon=True)
        thread.start()
        output = io.StringIO()
        try:
            with patch.object(DIAG.subprocess, "run", return_value=subprocess.CompletedProcess([], 28, "", "HTTP timeout")) as probe:
                with contextlib.redirect_stdout(output):
                    self.assertEqual(DIAG.main(["--port", os.ttyname(slave)]), 0)
                args = probe.call_args.args[0]
                self.assertIn("http://192.168.7.1/login", args)
                self.assertIn("--noproxy", args)
                self.assertNotIn("-L", args)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(received, [b"?", b"?"])
            self.assertIn("snapshot=0", output.getvalue())
            self.assertIn("snapshot=1", output.getvalue())
        finally:
            os.close(master)
            os.close(slave)


if __name__ == "__main__":
    unittest.main()
