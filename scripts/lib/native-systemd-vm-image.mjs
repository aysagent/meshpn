import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { nativeServiceUnit } from './native-service-unit.mjs';

// Files for a disposable NIC-less guest only; no host units or network writes.
export const nativeSystemdChecks = ['DIRECT_CONTROL', 'GUARD_REFUSAL', 'NOTIFY_WAIT', 'TWO_PEERS',
  'CLIENT_STOP_ISOLATED', 'CLIENT_RESTART', 'CLIENT_CRASH_RESTART', 'EXIT_CRASH_RESTART',
  'UPLINK_RECOVERY', 'GUARD_STOP_BINDS', 'STOP_FAIL_CLOSED', 'CLEANUP'];
export function addNativeSystemdImage(put) {
  const shared = { version: 1, address: '154.62.226.216', port: 443, tun: 'tun0' };
  const peers = [2, 3].map(last => {
    const secret_path = `/native/key-${last}`;
    put(secret_path, randomBytes(32), 0o600);
    put(`/native/c${last}.json`, JSON.stringify({ ...shared, role: 'client', peer_ipv4: `10.99.0.${last}`,
      secret_path, dns: true, ca: '/native/cert.pem', server_name: 'localhost' }), 0o600);
    return { ipv4: `10.99.0.${last}`, secret_path };
  });
  put('/native/exit.json', JSON.stringify({ ...shared, role: 'exit', peers, cert: '/native/cert.pem', key: '/native/key.pem' }), 0o600);
  put('/native/systemd-lab.sh', fs.readFileSync('scripts/lib/native-systemd-vm.sh'), 0o755);
  const units = {
    'default.target': '[Unit]\nDefaultDependencies=no\nWants=native-lab-driver.service\n',
    'native-lab-network.service': '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /native/systemd-lab.sh network\n',
    'native-lab-guard.service': '[Unit]\nDefaultDependencies=no\nRequires=native-lab-network.service\nAfter=native-lab-network.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /native/systemd-lab.sh guard\n',
    'native-lab-driver.service': '[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=/bin/sh /native/systemd-lab.sh driver\nTimeoutStartSec=10min\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n',
  };
  for (const [name, ns, config] of [['c2', 'nc2', 'c2'], ['c3', 'nc3', 'c3'], ['exit', 'nexit', 'exit']]) {
    units[`native-${name}.service`] = nativeServiceUnit({ binary: '/native/clean-vpn-engine', config: `/native/${config}.json`,
      networkUnit: 'native-lab-network.service', guardUnit: 'native-lab-guard.service' });
    // Only the fixture's namespace and dependency cycle accommodation differ.
    put(`/etc/systemd/system/native-${name}.service.d/lab.conf`,
      `[Unit]\nDefaultDependencies=no\n[Service]\nNetworkNamespacePath=/run/netns/${ns}\n`);
  }
  for (const [name, unit] of Object.entries(units)) put('/etc/systemd/system/' + name, unit);
}
