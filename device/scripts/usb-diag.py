#!/usr/bin/env python3
"""Read-only USB CDC snapshots; stdlib only, no serial reset/flash commands."""
import argparse
import errno
import fcntl
import glob
import ipaddress
import os
import select
import struct
import subprocess
import sys
import termios
import time
import tty

BEGIN = b"MESHPN_DIAG_BEGIN\n"
END = b"\nMESHPN_DIAG_END\n"
LIMIT = 32768


def frame(data):
    if len(data) > LIMIT:
        raise RuntimeError("Oversized diagnostic response")
    start = data.find(BEGIN)
    end = data.find(END, start) if start >= 0 else -1
    if end >= 0:
        return data[start:end + len(END)].decode("utf-8", errors="replace")
    return None


def snapshot(fd, timeout=12):
    # Clear leftovers, not board state. This does not toggle RTS/DTR or reset.
    termios.tcflush(fd, termios.TCIFLUSH)
    os.write(fd, b"?")
    deadline = time.monotonic() + timeout
    data = b""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue
        if not chunk:
            raise RuntimeError("USB serial disconnected")
        data += chunk
        complete = frame(data)
        if complete is not None:
            return complete
    tail = data.decode("utf-8", errors="replace")[-2000:]
    raise RuntimeError("No complete USB diagnostic snapshot. Flash with npm run device:flash:diag, "
                       "release BOOT, and close monitor/other serial readers. Partial response:\n" + tail)


def find_port(explicit):
    if explicit:
        return explicit
    ports = sorted(glob.glob("/dev/cu.usbmodem*") if sys.platform == "darwin" else glob.glob("/dev/ttyACM*"))
    if len(ports) != 1:
        raise RuntimeError("Expected one USB CDC port; pass --port /dev/cu.usbmodem... . Found: " + ", ".join(ports))
    return ports[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", help="USB CDC port; autodetects when exactly one is present")
    parser.add_argument("--host", default="192.168.7.1", help="Board gateway IPv4 for the HTTP probe")
    parser.add_argument("--no-http", action="store_true", help="Only one USB snapshot, no network requests")
    args = parser.parse_args(argv)
    ipaddress.IPv4Address(args.host)
    port = find_port(args.port)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    original = None
    try:
        original = termios.tcgetattr(fd)
        # Avoid competing with a monitor/flasher. Native CDC has no UART reset wiring.
        fcntl.ioctl(fd, termios.TIOCEXCL)
        tty.setraw(fd, termios.TCSANOW)
        attrs = termios.tcgetattr(fd)
        attrs[4] = attrs[5] = termios.B115200
        attrs[2] |= termios.CLOCAL | termios.CREAD
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        try:
            fcntl.ioctl(fd, termios.TIOCMBIS, struct.pack("i", termios.TIOCM_DTR))
        except OSError as e:
            if e.errno not in (errno.ENOTTY, errno.EINVAL):
                raise
        time.sleep(0.2)
        print("USB port:", port, flush=True)
        print("--- before HTTP ---", flush=True)
        print(snapshot(fd), flush=True)
        if not args.no_http:
            print("--- HTTP probe (no credentials, no redirects) ---", flush=True)
            try:
                r = subprocess.run(["curl", "-q", "--noproxy", "*", "-v", "--connect-timeout", "3",
                                    "--max-time", "8", "http://" + args.host + "/login", "-o", os.devnull],
                                   capture_output=True, text=True, timeout=10)
                print(r.stdout + r.stderr, flush=True)
                print("curl exit:", r.returncode, flush=True)
            except (OSError, subprocess.TimeoutExpired) as e:
                print("HTTP probe unavailable:", str(e), flush=True)
            time.sleep(1.1)  # Firmware snapshot rate limit.
            print("--- after HTTP ---", flush=True)
            print(snapshot(fd), flush=True)
    finally:
        if original is not None:
            try:
                termios.tcsetattr(fd, termios.TCSANOW, original)
            except OSError:
                pass
        os.close(fd)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, RuntimeError) as error:
        print("USB diagnostics:", error, file=sys.stderr)
        sys.exit(1)
