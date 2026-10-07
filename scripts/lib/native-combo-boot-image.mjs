import { randomBytes } from 'node:crypto';
export const comboBootChecks = [
  ['INSTALLED_DISABLED', 'GUARD_BEFORE_LINK', 'DIRECT_CPP_NOTIFY', 'TLS', 'TUN_DNS', 'ROUTE_COORDINATOR', 'UNSUPPORTED_BLOCKED',
    'CLIENT_AUTORESTART', 'CLIENT_CRASH_BLOCKED', 'EXIT_AUTORESTART', 'EXIT_CRASH_BLOCKED', 'TARGET_STOP_BLOCKED', 'REPLAY_PERSISTED'],
  ['REBOOT_REPLAY_BYTES', 'REBOOT_AUTOSTART_ORDER', 'REBOOT_TLS', 'REBOOT_TUN_DNS', 'ROUTE_COORDINATOR', 'UNSUPPORTED_BLOCKED',
    'MISSING_REPLAY_REFUSED', 'CORRUPT_REPLAY_REFUSED', 'REPLAY_RESTORED_TLS', 'TARGET_STOP_BLOCKED'],
];
export function addComboBootImage(put) {
  const driver = '/usr/bin/node /project/scripts/lib/native-combo-boot-vm.mjs';
  const units = {
    'default.target': '[Unit]\nDefaultDependencies=no\nWants=multi-user.target native-co-driver.service\n',
    'native-co-links.service': `[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${driver} network\nTimeoutStartSec=90\nStandardOutput=append:/run/combo-network.log\nStandardError=append:/run/combo-network.log\n`,
    'native-co-driver.service': `[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=${driver} run\nTimeoutStartSec=15min\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n`,
  };
  put('/native/combo-relay.psk', randomBytes(32), 0o600);
  for (const [name, role] of [['coclient', 'client'], ['coexit', 'exit']]) {
    units[`native-${name}-defaults.service`] = `[Unit]\nDefaultDependencies=no\nRequires=native-${name}-uplink.service\nAfter=native-${name}-uplink.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${driver} defaults ${name}\nStandardOutput=append:/run/combo-network.log\nStandardError=append:/run/combo-network.log\n`;
    const profile = { version: 1, transport: 'combo-tls', role, tun: 'tun0', tun_address: role === 'client' ? '10.99.0.2/32' : '10.99.0.1/24', mtu: 1400,
      uplink: 'wan0', endpoint: '198.18.0.3', port: 33001, listen_port: role === 'client' ? 33002 : 33001,
      lan: role === 'client' ? { interface: 'lan0', subnet: '192.168.7.0/24' } : null, deny_ipv4: ['8.8.8.0/24'] };
    const transparent = { version: 1, transport: 'transparent-tls', role, public_name: 'relay.example', secret_path: '/native/combo-relay.psk',
      destination_policy: { mode: 'public-https', deny_ipv4: profile.deny_ipv4 },
      listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: profile.listen_port },
      ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: profile.port } } : { replay_directory: '/native/unused-combo-replay' }) };
    const boring = { version: 1, role, tun: 'tun0', address: profile.endpoint, port: profile.port,
      ...(role === 'client' ? { secret_path: '/native/psk', ca: '/native/cert.pem', server_name: 'localhost', sni: 'relay.example', dns: true } :
        { cert: '/native/cert.pem', key: '/native/key.pem', peers: [{ ipv4: '10.99.0.2', secret_path: '/native/psk' }] }) };
    put(`/native/${name}.json`, JSON.stringify({ version: 1, transport: 'combo-tls', role, boring, transparent }), 0o600);
    put(`/native/${name}-site.json`, JSON.stringify({ link_unit: 'native-co-links.service', profile }), 0o600);
  }
  for (const [name, unit] of Object.entries(units)) put('/etc/systemd/system/' + name, unit);
}
