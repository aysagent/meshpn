export const transparentBootChecks = [
  ['INSTALLED_DISABLED', 'GUARD_BEFORE_LINK', 'DIRECT_CPP_NOTIFY', 'TLS', 'UNSUPPORTED_BLOCKED',
    'CLIENT_AUTORESTART', 'CLIENT_CRASH_BLOCKED', 'EXIT_AUTORESTART', 'EXIT_CRASH_BLOCKED', 'TARGET_STOP_BLOCKED', 'REPLAY_PERSISTED'],
  ['REBOOT_REPLAY_BYTES', 'REBOOT_AUTOSTART_ORDER', 'REBOOT_TLS', 'UNSUPPORTED_BLOCKED',
    'MISSING_REPLAY_REFUSED', 'CORRUPT_REPLAY_REFUSED', 'REPLAY_RESTORED_TLS', 'TARGET_STOP_BLOCKED'],
];
export function addTransparentBootImage(put) {
  const driver = '/usr/bin/node /project/scripts/lib/native-transparent-boot-vm.mjs';
  const units = {
    'default.target': '[Unit]\nDefaultDependencies=no\nWants=multi-user.target native-tr-driver.service\n',
    'native-tr-links.service': `[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${driver} network\nTimeoutStartSec=90\nStandardOutput=append:/run/transparent-network.log\nStandardError=append:/run/transparent-network.log\n`,
    'native-tr-defaults.service': `[Unit]\nDefaultDependencies=no\nRequires=native-trclient-uplink.service native-trexit-uplink.service\nAfter=native-trclient-uplink.service native-trexit-uplink.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${driver} defaults\nStandardOutput=append:/run/transparent-network.log\nStandardError=append:/run/transparent-network.log\n`,
    'native-tr-driver.service': `[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=${driver} run\nTimeoutStartSec=15min\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n`,
  };
  for (const [name, unit] of Object.entries(units)) put('/etc/systemd/system/' + name, unit);
  for (const [name, role] of [['trclient', 'client'], ['trexit', 'exit']]) {
    const profile = { version: 1, transport: 'transparent-tls', role, uplink: 'wan0', endpoint: '198.18.0.3', port: 33001,
      listen_port: role === 'client' ? 33002 : 33001, lan: role === 'client' ? { interface: 'lan0', subnet: '192.168.7.0/24' } : null,
      deny_ipv4: ['8.8.8.0/24'] };
    const config = { version: 1, transport: 'transparent-tls', role, public_name: 'relay.example', secret_path: '/native/psk',
      destination_policy: { mode: 'public-https', deny_ipv4: profile.deny_ipv4 },
      listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: profile.listen_port },
      ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: profile.port } } : { replay_directory: '/native/unused-replay' }) };
    put(`/native/${name}.json`, JSON.stringify(config), 0o600);
    put(`/native/${name}-site.json`, JSON.stringify({ link_unit: 'native-tr-links.service', profile }), 0o600);
  }
}
