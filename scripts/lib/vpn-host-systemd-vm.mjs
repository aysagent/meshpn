/** NIC-less QEMU only. No environment variable alone authorizes host mutations. */
import assert from 'node:assert/strict';
import { readFileSync, readlinkSync, readdirSync } from 'node:fs';

export const HOST_SYSTEMD_CHECKS = [
  'baseline direct IPv6', 'PID1 is real systemd', 'systemd lab DNS baseline positive control',
  'installed service KillMode', 'installed service stop budget', 'installed guard active',
  'installed service IPv4 HTTPS', 'installed service IPv6 HTTPS', 'installed service DNS', 'installed service DNS peer is exit',
  ...['KILLSWITCH=0 refused', 'KILLSWITCH=1 refused', 'preserves files', 'preserves main PID', 'retains guard'].map(n => `active update ${n}`),
  ...['IPv4 HTTPS', 'IPv6 HTTPS', 'DNS'].map(n => `refused active update ${n}`),
  ...['prepared','renamed'].flatMap(p => ['SIGKILL injected','complete wrapper','retains units','leaves service stopped','retains guard',
    'blocks IPv4','blocks IPv6','blocks DNS'].map(n => `updater ${p} ${n}`)),
  ...['publishes stopped release','retains previous wrapper','selects new release','preserves units'].map(n => `updater CLI ${n}`),
  ...['IPv4 HTTPS','IPv6 HTTPS','DNS'].map(n => `updated release ${n}`),
  'systemctl restart replaces main PID', 'systemctl restart IPv4 HTTPS', 'systemctl stop releases original IPv4 network',
  ...['clean-vpn-dns-recover.mjs', 'clean-vpn-ipv6-recover.mjs', 'clean-vpn-host-recover.mjs'].map(n => `systemctl stop ${n} released`),
  ...['IPv4', 'IPv6', 'DNS'].map(n => `persist guard survives systemctl stop ${n}`),
  'SIGKILL restart refuses stale ownership', ...['IPv4', 'IPv6', 'DNS'].map(n => `SIGKILL persists ${n} guard`),
  ...['KILLSWITCH=0 refused', 'KILLSWITCH=1 refused', 'preserves files', 'preserves main PID', 'retains guard'].map(n => `crashed update ${n}`),
  ...['IPv4', 'IPv6', 'DNS'].map(n => `refused crashed update blocks ${n}`),
  'updater CLI refuses unfinished journal','refused updater CLI retains files','refused updater CLI retains guard',
  ...['IPv4','IPv6','DNS'].map(n=>`refused updater CLI blocks ${n}`),
  'uninstall after SIGKILL refuses unfinished journals', 'refused uninstall retains installed files',
  'refused uninstall retains active guard unit', ...['IPv4', 'IPv6', 'DNS'].map(n => `refused uninstall blocks ${n}`),
  'explicit recovery restores original routes under systemd', 'explicit recovery leaves persist guard',
  'systemd starts after explicit recovery', 'clean uninstall removes installed main unit', 'clean uninstall removes installed wrapper',
  ...['IPv4', 'IPv6', 'DNS'].map(n => `clean uninstall restores baseline ${n}`),
];

export const HOST_STOP_FAULT_CHECKS = [
  ...HOST_SYSTEMD_CHECKS.slice(0,10),
  ...['error','timeout'].flatMap(phase => [
    'fault reached DNS cleanup','systemd result','main exit status','detached helper gone','guard active',
    'DNS journal retained','IPv6 journal retained','host journal retained',
    'blocks IPv4','blocks IPv6','blocks DNS','restart refuses unfinished journals',
    'updater refuses unfinished journals','uninstall refuses unfinished journals','installed files unchanged',
    'recovery restores routes','recovery retains guard','restart after recovery',
  ].map(n=>`${phase} stop ${n}`)),
  'fault fixture restored production timeout',
  ...['IPv4','IPv6','DNS'].map(n=>`fault lab clean uninstall restores ${n}`),
];

export function assertHostSystemdEvidence(evidence, { stopFaults = false } = {}) {
  assert.equal(evidence?.status, 'passed');
  assert.equal(evidence.actualTransportTested, 'tls-ipv6');
  assert.equal(evidence.hostNetworkChanged, false);
  assert.deepEqual(evidence.checks, stopFaults ? HOST_STOP_FAULT_CHECKS : HOST_SYSTEMD_CHECKS);
  assert.equal(evidence.hostSystemd?.stopFaults === true, stopFaults);
  if (stopFaults) assert.equal(evidence.hostSystemd.acceleratedStopTimeoutSec, 5);
  assert.equal(evidence.hostSystemd?.systemdPid1, true);
  assert.equal(evidence.hostSystemd?.actualInstaller, true);
  assert.equal(evidence.hostSystemd?.acceptance, 'not-ready-for-deployment');
  for (const limitation of ['fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart'])
    assert.ok(evidence.hostSystemd.limitations.includes(limitation));
}

export function assertHostSystemdVm() {
  assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-systemd=1(?:\s|$)/);
  assert.match(readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.equal(process.getuid(), 0);
  for (const ns of ['net', 'mnt', 'pid']) assert.equal(readlinkSync(`/proc/self/ns/${ns}`), readlinkSync(`/proc/1/ns/${ns}`));
  assert.ok(readdirSync('/sys/class/net').every(n => ['lo', 'client0', 'exit0'].includes(n)), 'unexpected NIC');
}

export function hostSystemdVmUnits() {
  return {
    'default.target': '[Unit]\nDefaultDependencies=no\nWants=host-vm-driver.service\n',
    'network.target': '[Unit]\nDefaultDependencies=no\n',
    'network-pre.target': '[Unit]\nDefaultDependencies=no\n',
    'multi-user.target': '[Unit]\nDefaultDependencies=no\n',
    'sysinit.target': '[Unit]\nDefaultDependencies=no\n',
    'basic.target': '[Unit]\nDefaultDependencies=no\n',
    'dbus.socket': '[Unit]\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\nSocketMode=0666\n',
    'dbus.service': '[Unit]\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=notify\nExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --systemd-activation --config-file=/etc/dbus-vm.conf\n',
    'host-vm-driver.service': '[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nWorkingDirectory=/project\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=20min\nExecStart=/usr/bin/node /project/scripts/lib/vpn-host-systemd-driver.mjs\n',
  };
}
