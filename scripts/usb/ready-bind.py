#!/usr/bin/env python3
"""Radxa g1: expose the prepared USB gadget after address/DHCP readiness.
Never unbind, recreate functions, change addresses or restart services.
"""
import json
import pathlib
import subprocess
import sys
import time

GADGET = pathlib.Path('/sys/kernel/config/usb_gadget/g1')
CONTROLLERS = pathlib.Path('/sys/class/udc')


def run(*args):
    return subprocess.check_output(args, text=True, timeout=2).strip()


def prepared():
    links = json.loads(run('/usr/sbin/ip', '-j', 'address', 'show', 'dev', 'usb0'))
    if len(links) != 1:
        raise RuntimeError('usb_interface_missing')
    link = links[0]
    addresses = [(x['local'], x['prefixlen']) for x in link['addr_info'] if x['family'] == 'inet']
    if (link.get('address') != '02:00:00:00:00:02' or 'UP' not in link['flags']
            or addresses != [('192.168.7.1', 24)]):
        raise RuntimeError('usb_address_not_ready')
    if (GADGET / 'functions/ecm.usb0/ifname').read_text().strip() != 'usb0':
        raise RuntimeError('usb_function_mismatch')
    controllers = sorted(p.name for p in CONTROLLERS.iterdir())
    if len(controllers) != 1:
        raise RuntimeError('usb_controller_ambiguous')
    return controllers[0]


def dhcp_ready():
    try:
        if run('/usr/bin/systemctl', 'is-active', 'dnsmasq.service') != 'active':
            return False
        pid = int(run('/usr/bin/systemctl', 'show', 'dnsmasq.service', '-p', 'MainPID', '--value'))
        if pid <= 0:
            return False
        sockets = {p.readlink().as_posix() for p in pathlib.Path(f'/proc/{pid}/fd').iterdir()}
        for line in pathlib.Path(f'/proc/{pid}/net/udp').read_text().splitlines()[1:]:
            fields = line.split()
            if fields[1].endswith(':0043') and f'socket:[{fields[9]}]' in sockets:
                return True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return False


def apply(*, check=False):
    controller = prepared()
    udc = GADGET / 'UDC'
    bound = udc.read_text().strip()
    if bound and bound != controller:
        raise RuntimeError('usb_controller_changed')
    ready = dhcp_ready()
    if check or bound:
        return {'status': 'already-bound' if bound else 'prepared', 'dhcpReady': ready,
                'changed': False, 'checkOnly': check}
    deadline = time.monotonic() + 8
    while not ready and time.monotonic() < deadline:
        time.sleep(.25)
        ready = dhcp_ready()
    # A failed DHCP service must not hide static USB rescue from the host.
    # This degraded outcome is explicit, and does not trigger USB resets.
    if prepared() != controller or udc.read_text().strip():
        raise RuntimeError('usb_state_changed')
    udc.write_text(controller + '\n')
    return {'status': 'bound' if ready else 'bound-rescue-dhcp-unavailable',
            'dhcpReady': ready, 'changed': True, 'checkOnly': False}


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in [['--check'], ['--bind']]:
            raise RuntimeError('usage: --check | --bind')
        print(json.dumps(apply(check=sys.argv[1] == '--check')), flush=True)
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)
