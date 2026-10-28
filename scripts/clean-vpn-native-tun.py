#!/usr/bin/env python3
"""Create an owned TUN; it is ephemeral until its recovery alias is installed."""
import fcntl
import os
import re
import struct
import subprocess
import sys


def create(name, owner):
    if name != 'tun0' or not re.fullmatch(r'cvpn-native-host-[a-f0-9]{24}', owner):
        raise ValueError('invalid TUN ownership')
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
    try:
        # IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL: never attach an existing device.
        fcntl.ioctl(fd, 0x400454CA, struct.pack('16sH', name.encode(), 0x9001))
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'alias', owner], check=True, timeout=10)
        subprocess.run(['ip', 'address', 'add', '10.99.0.2/32', 'dev', name], check=True, timeout=10)
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'mtu', '1400', 'up'], check=True, timeout=10)
        # A crash before this ioctl deletes the ephemeral device. After it,
        # the durable parent intent + unique alias authorize bounded recovery.
        fcntl.ioctl(fd, 0x400454CB, 1)
    finally:
        os.close(fd)


if __name__ == '__main__':
    if len(sys.argv) != 3 or os.geteuid() != 0:
        raise SystemExit('usage: clean-vpn-native-tun.py tun0 OWNER (root)')
    create(*sys.argv[1:])
