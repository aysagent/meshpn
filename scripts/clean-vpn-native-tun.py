#!/usr/bin/env python3
"""Create an owned TUN; it is ephemeral until its recovery alias is installed."""
import fcntl
import ipaddress
import os
import re
import struct
import subprocess
import sys


def create(name, owner, peer=None):
    client = name == 'tun0' and re.fullmatch(r'cvpn-native-host-[a-f0-9]{24}', owner)
    exit_node = re.fullmatch(r'cvexit[a-z0-9]{0,8}', name) and re.fullmatch(r'cvpn-native-exit-host-[a-f0-9]{24}', owner)
    if not (client or exit_node):
        raise ValueError('invalid TUN ownership')
    if peer is not None:
        ip = ipaddress.IPv4Address(peer)
        if not client or ip not in ipaddress.IPv4Network('10.99.0.0/24') or not 2 <= int(ip) % 256 <= 254:
            raise ValueError('invalid client peer address')
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
    try:
        # IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL: never attach an existing device.
        fcntl.ioctl(fd, 0x400454CA, struct.pack('16sH', name.encode(), 0x9001))
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'alias', owner], check=True, timeout=10)
        address = (peer or '10.99.0.2') + '/32' if client else '10.99.0.1/24'
        subprocess.run(['ip', 'address', 'add', address, 'dev', name], check=True, timeout=10)
        subprocess.run(['ip', 'link', 'set', 'dev', name, 'mtu', '1400', 'up'], check=True, timeout=10)
        # A crash before this ioctl deletes the ephemeral device. After it,
        # the durable parent intent + unique alias authorize bounded recovery.
        fcntl.ioctl(fd, 0x400454CB, 1)
    finally:
        os.close(fd)


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4) or os.geteuid() != 0:
        raise SystemExit('usage: clean-vpn-native-tun.py tun0|cvexit[SUFFIX] OWNER [CLIENT_IPV4] (root)')
    create(*sys.argv[1:])
