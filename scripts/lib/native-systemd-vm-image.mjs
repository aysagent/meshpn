import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { nativeServiceUnit } from './native-service-unit.mjs';
import { nativeRouteServiceUnit } from './native-route-unit.mjs';

// Files for a disposable NIC-less guest only; no host units or network writes.
export const nativeSystemdChecks = ['DIRECT_CONTROL', 'GUARD_REFUSAL', 'NOTIFY_WAIT', 'TWO_PEERS',
  'CLIENT_STOP_ISOLATED', 'CLIENT_RESTART', 'CLIENT_CRASH_RESTART', 'EXIT_CRASH_RESTART',
  'UPLINK_RECOVERY', 'GUARD_STOP_BINDS', 'STOP_FAIL_CLOSED', 'CLEANUP'];
export const nativeRouteChecks = ['INITIAL_DHCP', 'TWO_NATIVE_PEERS', 'DHCP_ADDRESS_CHANGE', 'DHCP_GATEWAY_CHANGE',
  'DEFAULT_LOSS_BLOCKED', 'DEFAULT_RECOVERY', 'OWNED_ROUTE_REPAIR', 'FOREIGN_ROUTE_REFUSED',
  'FOREIGN_REMOVED_RECOVERY', 'COORDINATOR_CRASH_BLOCKED', 'COORDINATOR_RESTART', 'GUARD_STOP_BLOCKED', 'CLEANUP'];
export function addNativeSystemdImage(put, { boot = false, routes = false } = {}) {
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
  if (boot) {
    units['default.target'] = '[Unit]\nDefaultDependencies=no\nWants=multi-user.target native-lab-driver.service\n';
    units['native-lab-uplink.service'] = '[Unit]\nDefaultDependencies=no\nRequires=native-lab-network.service native-lab-guard.service\nAfter=native-lab-network.service native-lab-guard.service\nBindsTo=native-lab-guard.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /native/systemd-lab.sh uplink\nExecStop=/bin/sh /native/systemd-lab.sh uplink-down\n';
    units['native-lab-driver.service'] = units['native-lab-driver.service']
      .replace('ExecStart=/bin/sh /native/systemd-lab.sh driver', 'ExecStart=/usr/bin/node /project/scripts/lib/native-boot-vm.mjs run');
  }
  if (routes) {
    const profile = { version: 1, tun: 'tun0', uplink: 'wlan0', exit_ip: shared.address,
      engine_unit: 'native-c2.service', guard_unit: 'native-lab-guard.service', route_unit: 'native-routes-c2.service' };
    put('/native/routes-c2.json', JSON.stringify(profile), 0o600);
    units[profile.route_unit] = nativeRouteServiceUnit({ config: '/native/routes-c2.json',
      script: '/project/scripts/clean-vpn-native-routes.mjs', profile, provisionUnit: 'native-lab-network.service' });
    put('/etc/systemd/system/native-routes-c2.service.d/lab.conf', '[Unit]\nDefaultDependencies=no\n[Service]\nNetworkNamespacePath=/run/netns/nc2\nStandardOutput=append:/run/native-route-control.log\nStandardError=append:/run/native-route-control.log\n');
    put('/native/routes-lab.sh', fs.readFileSync('scripts/lib/native-route-vm.sh'), 0o755);
    put('/native/dhcp-hook.sh', fs.readFileSync('scripts/lib/native-route-dhcp-vm.sh'), 0o755);
    for (const [i, ip, router] of [[1, '192.0.2.2', '192.0.2.1'], [2, '192.0.2.99', '192.0.2.1'], [3, '192.0.2.100', '192.0.2.254']]) {
      put(`/native/dhcp${i}.conf`, `start ${ip}\nend ${ip}\ninterface from2\noption subnet 255.255.255.0\noption router ${router}\noption lease 3600\nlease_file /run/dhcp${i}.leases\npidfile /run/dhcp${i}.pid\n`);
    }
    units['native-lab-driver.service'] = units['native-lab-driver.service']
      .replace('/native/systemd-lab.sh driver', '/native/routes-lab.sh');
  }
  for (const [name, ns, config] of [['c2', 'nc2', 'c2'], ['c3', 'nc3', 'c3'], ['exit', 'nexit', 'exit']]) {
    if (!boot) units[`native-${name}.service`] = nativeServiceUnit({ binary: '/native/clean-vpn-engine', config: `/native/${config}.json`,
      networkUnit: routes && name === 'c2' ? 'native-routes-c2.service' : 'native-lab-network.service', guardUnit: 'native-lab-guard.service' });
    // Only the fixture's namespace and dependency cycle accommodation differ.
    if (!boot) put(`/etc/systemd/system/native-${name}.service.d/lab.conf`,
      `[Unit]\nDefaultDependencies=no\n[Service]\nNetworkNamespacePath=/run/netns/${ns}\n`);
  }
  for (const [name, unit] of Object.entries(units)) put('/etc/systemd/system/' + name, unit);
}
