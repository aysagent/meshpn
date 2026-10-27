#!/usr/bin/env python3
"""Authenticated cold-clock control plane. No TLS bypass and no VPN packet IO.

Server is an SSH forced command, with restrict/no forwarding. Client accepts
only an explicitly pinned raw Ed25519 SSH host key and a fresh nonce response.
Probe never writes. Apply requires a specific native failure, is Linux/root
only, and refuses a running consumer. It is NOT an unconditional boot hook.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

MIN_EPOCH = 1767225600  # 2026-01-01; not derived from the possibly broken clock.
MAX_EPOCH = 4102444800  # 2100-01-01; explicit protocol bound.
MAX_RTT = 5.0
COMMAND = 'clean-vpn-clock-v1'
ELIGIBLE_FAILURES = frozenset(('tls_verify_expired', 'tls_verify_not_yet_valid', 'auth_clock_skew'))
EXIT_FAILURES = {'75': 'tls_verify_not_yet_valid', '76': 'tls_verify_expired', '77': 'auth_clock_skew'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def require_failure(failure):
    require(failure in ELIGIBLE_FAILURES, 'clock_failure_required')


def trusted_path(value):
    require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and os.path.normpath(value) == value and value != '/', 'unsafe_path')
    p = Path(value)
    for parent in reversed(p.parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.geteuid()), 'unsafe_ancestor')
        require(not s.st_mode & 0o022 or s.st_mode & stat.S_ISVTX, 'writable_ancestor')
    return p


def read_private(value, limit=4096, private=True):
    p = trusted_path(value)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                and s.st_uid == os.geteuid() and not s.st_mode & (0o077 if private else 0o022)
                and 0 < s.st_size <= limit, 'unsafe_file')
        data = os.read(fd, limit + 1)
        require(len(data) == s.st_size, 'changed_file')
        return data
    finally:
        os.close(fd)


def validate_config(c):
    require(type(c) is dict and set(c) == {'version', 'host', 'port', 'user', 'identity',
                                          'known_hosts', 'state_dir', 'consumer_unit'}, 'invalid_config_fields')
    require(c['version'] == 1 and type(c['version']) is int, 'invalid_version')
    address = ipaddress.IPv4Address(c['host'])
    require(not address.is_unspecified and not address.is_multicast, 'invalid_host')
    require(type(c['port']) is int and 1 <= c['port'] <= 65535, 'invalid_port')
    require(re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', c['user']) is not None, 'invalid_user')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}\.service', c['consumer_unit']) is not None, 'invalid_consumer')
    for name in ('identity', 'known_hosts', 'state_dir'):
        trusted_path(c[name])
    return c


def host_pin(data):
    parts = data.decode('ascii').strip().split()
    require(len(parts) == 3 and parts[:2] == ['clean-vpn-clock', 'ssh-ed25519'], 'single_pinned_host_required')
    raw = base64.b64decode(parts[2], validate=True)
    require(len(raw) == 51 and raw[:19] == b'\0\0\0\x0bssh-ed25519\0\0\0\x20', 'invalid_ed25519_pin')
    return hashlib.sha256(raw).hexdigest()


def ssh_args(c):
    # -F /dev/null and disabled multiplex prevent inheriting an already
    # authenticated socket, proxy, agent or a user/system SSH configuration.
    return ['/usr/bin/ssh', '-F', '/dev/null', '-4', '-T', '-p', str(c['port']),
            '-i', c['identity'], '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'HostKeyAlias=clean-vpn-clock',
            '-o', 'UserKnownHostsFile=' + c['known_hosts'], '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'KnownHostsCommand=none', '-o', 'UpdateHostKeys=no', '-o', 'VerifyHostKeyDNS=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyCommand=none',
            '-o', 'ProxyJump=none', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'ConnectTimeout=3', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=1', '-o', 'ServerAliveCountMax=2',
            c['user'] + '@' + c['host'], COMMAND]


def validate_response(data, nonce, elapsed, wall_before, wall_after, floor=0):
    require(0 <= elapsed <= MAX_RTT, 'clock_round_trip_exceeded')
    require(abs((wall_after - wall_before) - elapsed) <= 1.5, 'local_clock_changed_during_probe')
    require(len(data) <= 512, 'clock_response_too_large')
    r = strict_json(data)
    require(type(r) is dict and set(r) == {'version', 'nonce', 'unix_seconds', 'synchronized'}, 'invalid_clock_response')
    require(type(r['version']) is int and r['version'] == 1 and r['nonce'] == nonce
            and re.fullmatch(r'[0-9a-f]{64}', nonce) is not None, 'clock_nonce_or_version_mismatch')
    require(r['synchronized'] is True, 'exit_clock_not_synchronized')
    seconds = r['unix_seconds']
    require(type(seconds) is int and MIN_EPOCH <= seconds < MAX_EPOCH, 'invalid_remote_epoch')
    require(seconds + 5 >= floor, 'remote_time_older_than_trusted_floor')
    # The response is generated after the request arrives. Do not pretend the
    # entire SSH handshake RTT is a symmetric propagation delay.
    return {'remoteUnixSeconds': seconds, 'roundTripMs': round(elapsed * 1000),
            'uncertaintySeconds': elapsed + 1, 'offsetSeconds': round(seconds - wall_after, 3),
            'needsCorrection': abs(seconds - wall_after) > elapsed + 2}


def serve():
    require(os.environ.get('SSH_ORIGINAL_COMMAND') == COMMAND, 'forced_command_required')
    # A missing newline or a slow sender is bounded by the outer forced-command
    # timeout. Never interpret input as a command or filesystem path.
    raw = sys.stdin.buffer.readline(128)
    require(re.fullmatch(rb'[0-9a-f]{64}\n', raw) is not None, 'invalid_nonce')
    result = subprocess.run(['/usr/bin/timedatectl', 'show', '-p', 'NTPSynchronized', '--value'],
                            capture_output=True, timeout=2, check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.stdout.strip() == b'yes', 'exit_clock_not_synchronized')
    now = int(time.time())
    require(MIN_EPOCH <= now < MAX_EPOCH, 'invalid_exit_epoch')
    print(json.dumps({'version': 1, 'nonce': raw.decode().strip(), 'unix_seconds': now, 'synchronized': True}))


def floor_read(c):
    p = trusted_path(c['state_dir'])
    if not p.exists():
        require(not p.is_symlink(), 'unsafe_state_directory')
        return 0
    s = p.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'unsafe_state_directory')
    try:
        value = strict_json(read_private(str(p / 'last-good.json')))
    except FileNotFoundError:
        return 0
    require(type(value) is dict and set(value) == {'version', 'unix_seconds'}
            and type(value['version']) is int and value['version'] == 1
            and type(value['unix_seconds']) is int and MIN_EPOCH <= value['unix_seconds'] < MAX_EPOCH, 'invalid_clock_floor')
    return value['unix_seconds']


def save_state(c, name, value):
    p = trusted_path(c['state_dir'])
    p.mkdir(mode=0o700, exist_ok=True)
    floor_read(c)  # Recheck object/owner/mode before publication.
    temp = p / ('floor-' + secrets.token_hex(12) + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = (json.dumps(value) + '\n').encode()
        require(os.write(fd, data) == len(data), 'incomplete_state_write')
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, p / name)
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_floor(c, seconds):
    save_state(c, 'last-good.json', {'version': 1, 'unix_seconds': seconds})


def claim_attempt(c, failure, boot_id):
    """Called under the state lock, before any network or clock operation.

    A service restart or failed SSH query must not reset the budget. The
    caller obtains failure from the owned engine, never from remote text.
    """
    require_failure(failure)
    require(re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id) is not None, 'invalid_boot_id')
    try:
        previous = strict_json(read_private(str(Path(c['state_dir']) / 'attempt.json')))
    except FileNotFoundError:
        previous = None
    if previous is not None:
        require(type(previous) is dict and set(previous) == {'version', 'boot_id', 'failure'}
                and type(previous['version']) is int and previous['version'] == 1
                and isinstance(previous['boot_id'], str)
                and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', previous['boot_id']) is not None
                and previous['failure'] in ELIGIBLE_FAILURES, 'invalid_attempt_state')
        require(previous['boot_id'] != boot_id, 'clock_attempt_already_consumed')
    save_state(c, 'attempt.json', {'version': 1, 'boot_id': boot_id, 'failure': failure})


def probe(c):
    read_private(c['identity'], 16384)
    require(not Path(c['identity'] + '-cert.pub').exists(), 'ssh_certificate_not_allowed')
    pin = host_pin(read_private(c['known_hosts'], private=False))
    floor = floor_read(c)
    nonce = secrets.token_hex(32)
    before, start = time.time(), time.monotonic()
    # Bound stdout with a selector; never retain arbitrary SSH stderr in reports.
    import selectors
    child = subprocess.Popen(ssh_args(c), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    data = b''
    try:
        child.stdin.write((nonce + '\n').encode()); child.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = MAX_RTT - (time.monotonic() - start)
                require(remaining > 0, 'clock_round_trip_exceeded')
                events = selector.select(remaining)
                require(events, 'clock_round_trip_exceeded')
                chunk = os.read(child.stdout.fileno(), 513)
                if not chunk:
                    break
                data += chunk
                require(len(data) <= 512, 'clock_response_too_large')
        code = child.wait(timeout=max(.01, MAX_RTT - (time.monotonic() - start)))
        require(code == 0, 'authenticated_clock_query_failed')
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()
    report = validate_response(data, nonce, time.monotonic() - start, before, time.time(), floor)
    return {**report, 'hostPinSha256': pin, 'trustedFloor': floor}


def unit_state(c, extra=()):
    names = ('MainPID', 'ActiveState', 'SubState', 'Job') + tuple(extra)
    output = subprocess.check_output(['/usr/bin/systemctl', 'show', c['consumer_unit']]
                                     + [arg for name in names for arg in ('-p', name)], timeout=3)
    fields = {}
    for line in output.decode('ascii').splitlines():
        key, value = line.split('=', 1)
        require(key not in fields, 'invalid_consumer_state')
        fields[key] = value
    require(set(fields) == set(names), 'invalid_consumer_state')
    return fields


def consumer_stopped(c):
    fields = unit_state(c)
    require(fields['MainPID'] == '0' and fields['ActiveState'] in ('inactive', 'failed')
            and fields['SubState'] in ('dead', 'failed') and fields['Job'] == '', 'consumer_still_running')


def failed_invocation(c):
    fields = unit_state(c, ('Result', 'ExecMainCode', 'ExecMainStatus', 'InvocationID'))
    if (fields['MainPID'] != '0' or fields['ActiveState'] != 'failed' or fields['SubState'] != 'failed'
            or fields['Job'] != '' or fields['Result'] != 'exit-code' or fields['ExecMainCode'] != '1'
            or fields['ExecMainStatus'] not in EXIT_FAILURES):
        return None
    require(re.fullmatch(r'[0-9a-f]{32}', fields['InvocationID']) is not None, 'invalid_invocation_id')
    return (EXIT_FAILURES[fields['ExecMainStatus']], fields['InvocationID'])


def apply_locked(c, failure, boot_id, check_failure=None):
    require_failure(failure)
    consumer_stopped(c)
    if check_failure:
        check_failure()
    claim_attempt(c, failure, boot_id)
    r = probe(c)
    received = time.monotonic()
    wall = time.time()
    consumer_stopped(c)
    if check_failure:
        check_failure()
    delay = time.monotonic() - received
    require(0 <= delay <= 4, 'clock_response_stale')
    require(abs(time.time() - wall - delay) <= 1.5, 'local_clock_changed_before_apply')
    if r['needsCorrection']:
        # Correct only toward authenticated current time, never certificate dates.
        target = r['remoteUnixSeconds'] + int(delay)
        subprocess.run(['/usr/bin/date', '--utc', '--set=@' + str(target)],
                       check=True, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    save_floor(c, max(r['trustedFloor'], r['remoteUnixSeconds']))
    return {**r, 'failure': failure, 'systemClockChanged': r['needsCorrection']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['serve', 'probe', 'apply', 'recover'])
    parser.add_argument('--config')
    parser.add_argument('--failure')
    args = parser.parse_args()
    if args.mode == 'serve':
        require(args.config is None and args.failure is None, 'server_has_no_config')
        serve(); return
    require(args.config is not None, 'config_required')
    if args.mode == 'apply':
        require_failure(args.failure)  # Fail before reading config or sending SSH.
    else:
        require(args.failure is None, 'unexpected_failure_argument')
    c = validate_config(strict_json(read_private(args.config)))
    if args.mode in ('apply', 'recover'):
        require(sys.platform == 'linux' and os.geteuid() == 0, 'linux_root_required')
        require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'systemd_required')
        invocation = failed_invocation(c) if args.mode == 'recover' else None
        if args.mode == 'recover' and invocation is None:
            print(json.dumps({'kind': 'clean-vpn-authenticated-clock', 'status': 'skipped',
                              'mode': 'recover', 'code': 'not_a_native_time_failure', 'systemClockChanged': False}))
            return
        def check_failure():
            require(failed_invocation(c) == invocation, 'consumer_failure_changed')
        # Lock held across the probe/set/save sequence, inherited config is not
        # enough to authorize changing time beneath a running VPN consumer.
        import fcntl
        state = trusted_path(c['state_dir']); state.mkdir(mode=0o700, exist_ok=True); floor_read(c)
        fd = os.open(state / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            s = os.fstat(lock.fileno())
            require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600, 'unsafe_lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            r = apply_locked(c, invocation[0] if invocation else args.failure, boot_id,
                             check_failure if invocation else None)
            if invocation:
                check_failure()
                r['restartQueued'] = False
                if r['systemClockChanged']:
                    # Before=consumer in the recovery unit defers this start
                    # until we finish. Do not block waiting on our own job.
                    subprocess.run(['/usr/bin/systemctl', '--no-block', 'start', c['consumer_unit']],
                                   check=True, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    r['restartQueued'] = True
    else:
        r = {**probe(c), 'systemClockChanged': False}
    print(json.dumps({'kind': 'clean-vpn-authenticated-clock', 'status': 'passed', 'mode': args.mode, **r}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r'[a-z_]{1,100}', str(error)) else 'clock_operation_failed'
        print(json.dumps({'kind': 'clean-vpn-authenticated-clock', 'status': 'refused', 'code': code}), file=sys.stderr)
        sys.exit(1)
