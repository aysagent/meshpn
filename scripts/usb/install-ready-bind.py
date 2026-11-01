#!/usr/bin/env python3
"""Fixed Radxa boot-only repair. --apply never restarts or unbinds USB."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
SCRIPT = pathlib.Path('/usr/local/bin/usb-gadget-start.sh')
STATE = pathlib.Path('/var/lib/meshpn-usb-ready-bind')
HELPER = pathlib.Path('/usr/local/lib/meshpn-usb-ready-bind.py')
UNIT = pathlib.Path('/etc/systemd/system/meshpn-usb-ready-bind.service')
OLD = '''# Привязка
echo "" > /sys/kernel/config/usb_gadget/g1/UDC 2>/dev/null || true
sleep 1
UDC_DEV=$(ls /sys/class/udc | head -n 1)
echo "$UDC_DEV" > UDC

# Сеть для usb0
ip addr flush dev usb0
ip addr add 192.168.7.1/24 dev usb0
ip link set usb0 up
'''
NEW = '''# Address first. meshpn-usb-ready-bind.service exposes g1 after DHCP startup.
# No address flush: preserve an address already supplied by USB rescue.
ip address replace 192.168.7.1/24 dev usb0
ip link set usb0 up
'''


def trusted(path):
    for p in [path, *path.parents]:
        s = p.lstat()
        if p.is_symlink() or s.st_uid != 0 or s.st_mode & 0o022:
            raise RuntimeError('untrusted_path: ' + str(p))


def atomic(path, data, mode):
    fd, name = tempfile.mkstemp(prefix='.meshpn-usb-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        d = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(name): os.unlink(name)


def main():
    if os.geteuid() or sys.argv[1:] not in [[], ['--apply']]:
        raise RuntimeError('run as root: [--apply]')
    for p in [SCRIPT, HELPER.parent, UNIT.parent, STATE.parent]: trusted(p)
    for p in [STATE, HELPER, UNIT]:
        if p.exists() or p.is_symlink(): raise RuntimeError('already_exists: ' + str(p))
    old = SCRIPT.read_bytes()
    text = old.decode()
    if text.count(OLD) != 1 or not text.endswith(OLD):
        raise RuntimeError('unexpected_gadget_script_tail')
    if 'G=/sys/kernel/config/usb_gadget/g1\n' not in text:
        raise RuntimeError('unexpected_gadget')
    new = text.replace(OLD, NEW).encode()
    # Verify the actual current board before publishing boot changes.
    subprocess.run(['/usr/bin/python3', str(ROOT / 'ready-bind.py'), '--check'], check=True)
    subprocess.run(['/bin/bash', '-n'], input=new, check=True)
    result = {'mode': 'apply' if sys.argv[1:] else 'plan', 'oldSha256': hashlib.sha256(old).hexdigest(),
              'newSha256': hashlib.sha256(new).hexdigest(), 'takesEffect': 'next boot',
              'servicesRestarted': False, 'usbRebound': False}
    if not sys.argv[1:]:
        print(json.dumps(result)); return
    STATE.mkdir(mode=0o700)
    atomic(STATE / 'usb-gadget-start.sh.original', old, 0o600)
    atomic(STATE / 'manifest.json', json.dumps(result).encode(), 0o600)
    atomic(HELPER, (ROOT / 'ready-bind.py').read_bytes(), 0o644)
    atomic(UNIT, (ROOT / UNIT.name).read_bytes(), 0o644)
    subprocess.run(['/usr/bin/systemd-analyze', 'verify', '--man=no', str(UNIT)], check=True)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
    # Enable before changing setup: a publication failure must not leave an
    # unbound gadget with no boot consumer. The current live gadget is untouched.
    subprocess.run(['/usr/bin/systemctl', 'enable', UNIT.name], check=True)
    if SCRIPT.read_bytes() != old: raise RuntimeError('gadget_changed_during_install')
    atomic(SCRIPT, new, SCRIPT.stat().st_mode & 0o777)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)
