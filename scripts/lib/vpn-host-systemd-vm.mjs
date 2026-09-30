/** NIC-less QEMU only. No environment variable alone authorizes host mutations. */
import assert from 'node:assert/strict';
import { readFileSync, readlinkSync, readdirSync } from 'node:fs';

export const HOST_SYSTEMD_CHECKS = [
  'baseline direct IPv6', 'PID1 is real systemd', 'systemd lab DNS baseline positive control',
  'installed service KillMode', 'installed service stop budget', 'installed guard active',
  'installed service IPv4 HTTPS', 'installed service IPv6 HTTPS', 'installed service DNS', 'installed service DNS peer is exit',
  'systemctl restart replaces main PID', 'systemctl restart IPv4 HTTPS', 'systemctl stop releases original IPv4 network',
  ...['clean-vpn-dns-recover.mjs', 'clean-vpn-ipv6-recover.mjs', 'clean-vpn-host-recover.mjs'].map(n => `systemctl stop ${n} released`),
  ...['IPv4', 'IPv6', 'DNS'].map(n => `persist guard survives systemctl stop ${n}`),
  'SIGKILL restart refuses stale ownership', ...['IPv4', 'IPv6', 'DNS'].map(n => `SIGKILL persists ${n} guard`),
  'explicit recovery restores original routes under systemd', 'explicit recovery leaves persist guard',
  'systemd starts after explicit recovery', 'clean uninstall removes installed main unit', 'clean uninstall removes installed wrapper',
  ...['IPv4', 'IPv6', 'DNS'].map(n => `clean uninstall restores baseline ${n}`),
];

export function assertHostSystemdEvidence(evidence) {
  assert.equal(evidence?.status, 'passed');
  assert.equal(evidence.actualTransportTested, 'tls-ipv6');
  assert.equal(evidence.hostNetworkChanged, false);
  assert.deepEqual(evidence.checks, HOST_SYSTEMD_CHECKS);
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
