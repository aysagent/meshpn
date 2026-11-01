#!/usr/bin/env python3
"""Fixed Radxa startup ordering. No service restart or live USB change."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path('/usr/local/bin/usb-gadget-start.sh')
DROPIN = Path('/etc/systemd/system/usb-gadget.service.d/40-meshpn-dhcp.conf')
BACKUP = Path('/var/lib/meshpn-usb-boot-order')
EXPECTED = 'a6846d0ac08b3af378cede7aefc797a43dd79b3a720f0bf12d398a55dbf33cbf'


def write(path, data, mode):
    fd, temp = tempfile.mkstemp(prefix='.meshpn-usb-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode); f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def main():
    if os.geteuid() or sys.argv[1:] not in [[], ['--apply']]: raise ValueError('root required: [--apply]')
    for p in [SCRIPT, SCRIPT.parent, DROPIN.parent.parent, BACKUP.parent]:
        for q in [p, *p.parents]:
            s = q.lstat()
            if q.is_symlink() or s.st_uid or s.st_mode & 0o022: raise ValueError('unsafe_path')
    for p in [DROPIN, BACKUP]:
        if p.exists() or p.is_symlink(): raise ValueError('already_installed')
    if DROPIN.parent.exists():
        s = DROPIN.parent.lstat()
        if DROPIN.parent.is_symlink() or s.st_uid or s.st_mode & 0o022: raise ValueError('unsafe_dropin_directory')
    old = SCRIPT.read_bytes()
    if hashlib.sha256(old).hexdigest() != EXPECTED: raise ValueError('unknown_gadget_script')
    target = b'ip addr flush dev usb0\nip addr add 192.168.7.1/24 dev usb0'
    if old.count(target) != 1: raise ValueError('unknown_address_setup')
    new = old.replace(target, b'ip address replace 192.168.7.1/24 dev usb0')
    subprocess.run(['/bin/bash', '-n'], input=new, check=True)
    if sys.argv[1:]:
        BACKUP.mkdir(mode=0o700)
        write(BACKUP / 'usb-gadget-start.sh.original', old, 0o600)
        DROPIN.parent.mkdir(mode=0o755, exist_ok=True)
        write(DROPIN, (Path(__file__).parent / 'usb/dhcp-before-gadget.conf').read_bytes(), 0o644)
        subprocess.run(['/usr/bin/systemd-analyze', 'verify', '--man=no', 'usb-gadget.service'], check=True)
        if SCRIPT.read_bytes() != old: raise ValueError('script_changed')
        write(SCRIPT, new, SCRIPT.stat().st_mode & 0o777)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
    print(json.dumps({'mode': 'applied-for-next-boot' if sys.argv[1:] else 'plan',
                      'servicesRestarted': False, 'usbRebound': False,
                      'oldSha256': EXPECTED, 'newSha256': hashlib.sha256(new).hexdigest()}))


if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'status': 'failed', 'error': str(e)}), file=sys.stderr); sys.exit(1)
