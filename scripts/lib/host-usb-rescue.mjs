/** Additive, fixed Radxa USB rescue. Never rebuilds a gadget or changes firewall. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

export const rescueName = 'clean-vpn-usb-rescue';
export const rescueHelper = `#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# Refuse a different interface; never flush addresses or rebuild the gadget.
test "$(cat /sys/class/net/usb0/address)" = 02:00:00:00:00:02
test "$(cat /sys/class/net/usb0/type)" = 1
addresses=$(ip -4 -o address show dev usb0 | awk '{print $4}')
if [ -n "$addresses" ] && [ "$addresses" != 192.168.7.1/24 ]; then
  echo 'USB rescue: unexpected IPv4 address; no changes' >&2
  exit 1
fi
if [ -z "$addresses" ]; then
  ip address add 192.168.7.1/24 dev usb0
fi
flags=$(cat /sys/class/net/usb0/flags)
if (( (flags & 1) == 0 )); then
  ip link set dev usb0 up
fi
`;

export const rescueUnits = {
  [`${rescueName}-address.service`]: `[Unit]
Description=Local USB rescue address (no gadget or uplink changes)
BindsTo=sys-subsystem-net-devices-usb0.device
After=sys-subsystem-net-devices-usb0.device

[Service]
Type=oneshot
ExecStart=/usr/local/bin/${rescueName}-address.sh
RemainAfterExit=yes
TimeoutStartSec=15
`,
  [`${rescueName}.socket`]: `[Unit]
Description=USB-only rescue SSH on 192.168.7.1:2222
# Avoid the sockets.target -> basic.target -> address.service ordering cycle.
DefaultDependencies=no
Requires=${rescueName}-address.service
After=${rescueName}-address.service
Conflicts=shutdown.target
Before=shutdown.target

[Socket]
ListenStream=192.168.7.1:2222
BindToDevice=usb0
FreeBind=yes
Accept=yes
MaxConnections=4

[Install]
WantedBy=multi-user.target sys-subsystem-net-devices-usb0.device
`,
  [`${rescueName}@.service`]: `[Unit]
Description=USB rescue SSH connection

[Service]
# Use existing authentication policy and host keys; do not create credentials.
ExecStart=/usr/sbin/sshd -i -e -o DisableForwarding=yes -o PermitTunnel=no -o UseDNS=no
StandardInput=socket
StandardOutput=socket
StandardError=journal
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
`,
};

export const rescueFiles = {
  [`/usr/local/bin/${rescueName}-address.sh`]: rescueHelper,
  ...Object.fromEntries(Object.entries(rescueUnits).map(([n, text]) => [`/etc/systemd/system/${n}`, text])),
};
export const rescueProbeUnit = unit => unit.replace('@.service', '@inspection.service');

export function validateUsbAddress(links) {
  assert.equal(links.length, 1, 'exactly one USB interface required');
  const link = links[0];
  assert.equal(link.ifname, 'usb0');
  assert.equal(link.address, '02:00:00:00:00:02', 'unexpected USB MAC');
  assert.ok(link.flags.includes('UP'), 'USB must already be up at installation');
  assert.deepEqual(link.addr_info.filter(a => a.family === 'inet').map(a => [a.local, a.prefixlen]),
    [['192.168.7.1', 24]], 'known USB address required at installation');
}

function trustedDirectory(path) {
  for (let p = path; ; p = dirname(p)) {
    const s = fs.lstatSync(p);
    assert.ok(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0 && !(s.mode & 0o022), `unsafe directory: ${p}`);
    if (p === '/') break;
  }
}

export function installUsbRescue({ apply = false, run = (file, args) => execFileSync(file, args,
  { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 }), log = console.log } = {}) {
  assert.equal(process.getuid(), 0, 'run as root');
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.equal(fs.readlinkSync('/proc/self/ns/net'), fs.readlinkSync('/proc/1/ns/net'), 'host network namespace required');
  validateUsbAddress(JSON.parse(run('ip', ['-j', 'address', 'show', 'dev', 'usb0'])));
  assert.equal(run('systemctl', ['show', 'sys-subsystem-net-devices-usb0.device', '--property=ActiveState', '--value']).trim(),
    'active', 'USB device must be registered with systemd/udev');
  for (const unit of Object.keys(rescueUnits)) {
    const probe = rescueProbeUnit(unit); // systemctl show requires a concrete instance
    assert.equal(run('systemctl', ['show', probe, '--property=LoadState', '--value']).trim(), 'not-found', `existing unit: ${unit}`);
    assert.equal(run('systemctl', ['show', probe, '--property=DropInPaths', '--value']).trim(), '', `existing drop-ins: ${unit}`);
  }
  for (const path of Object.keys(rescueFiles)) {
    trustedDirectory(dirname(path));
    assert.throws(() => fs.lstatSync(path), { code: 'ENOENT' }, `existing file: ${path}`);
  }
  assert.equal(run('ss', ['-H', '-ltn', 'sport = :2222']).trim(), '', 'port 2222 already in use');
  run('/usr/sbin/sshd', ['-t', '-o', 'DisableForwarding=yes', '-o', 'PermitTunnel=no', '-o', 'UseDNS=no']);
  log(JSON.stringify({ status: apply ? 'publishing' : 'plan', files: Object.keys(rescueFiles),
    endpoint: '192.168.7.1:2222', interface: 'usb0', authentication: 'existing-sshd-config',
    changes: 'new rescue files/units only; add missing USB address, bring USB link up',
    untouched: ['existing SSH', 'gadget', 'VPN', 'networkd', 'firewall', 'default routes'],
    limitations: ['requires-working-usb0-gadget', 'not-a-UART-replacement', 'no-reboot-or-power-failure-proof',
      'existing-firewall-and-authentication-must-permit-USB-login', 'no-concurrent-administrators'] }));
  if (!apply) return;
  // Publish complete files exclusively. Never overwrite an existing installation.
  for (const [path, text] of Object.entries(rescueFiles)) {
    const stage = fs.mkdtempSync(join(dirname(path), '.usb-rescue-'));
    const staged = join(stage, 'new');
    try {
      const fd = fs.openSync(staged, 'wx', path.endsWith('.sh') ? 0o755 : 0o644);
      try { fs.writeFileSync(fd, text); fs.fchmodSync(fd, path.endsWith('.sh') ? 0o755 : 0o644); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      fs.linkSync(staged, path);
      const dir = fs.openSync(dirname(path), 'r');
      try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
    } finally {
      if (fs.existsSync(staged)) fs.unlinkSync(staged);
      fs.rmdirSync(stage);
    }
  }
  // Failure retains published files for inspection. No broad/automatic rollback.
  run('systemd-analyze', ['verify', '--man=no', ...Object.keys(rescueUnits).map(n => `/etc/systemd/system/${n}`)]);
  run('systemctl', ['daemon-reload']);
  run('systemctl', ['enable', `${rescueName}.socket`]);
  run('systemctl', ['start', `${rescueName}.socket`]);
  assert.equal(run('systemctl', ['show', `${rescueName}.socket`, '--property=ActiveState', '--value']).trim(), 'active');
  log(JSON.stringify({ status: 'listening-not-login-verified', next: 'Keep port 22 session open; test ssh -p 2222 root@192.168.7.1 from USB peer. Do not reboot yet.' }));
}
