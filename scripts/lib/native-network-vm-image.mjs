import fs from 'node:fs';
export const nativeNetworkChecks = ['INSTALLED_DISABLED', 'PROFILES_BEFORE_UPLINK', 'NATIVE_LAN_DATA', 'NATIVE_DNS_INTERCEPTION', 'DOUBLE_NAT',
  'RESTART_AUDIT', 'CLIENT_CRASH_BLOCKED', 'CLIENT_RESTART', 'EXIT_CRASH_BLOCKED', 'EXIT_RESTART', 'FOREIGN_GUARD_REFUSED', 'GUARD_STOP_BLOCKED', 'CLEANUP'];
export function addNativeNetworkImage(put) {
  put('/native/network-lab.sh', fs.readFileSync('scripts/lib/native-network-vm.sh'), 0o755);
  const common = { version: 1, tun: 'tun0', mtu: 1400, uplink: 'wan0', endpoint: '154.62.226.216', port: 443 };
  for (const [name, ns, role, address, lan] of [['c2', 'nc2', 'client', '10.99.0.2/32', { interface: 'lan0', subnet: '192.168.7.0/24' }], ['exit', 'nexit', 'exit', '10.99.0.1/24', null]]) {
    put(`/native/site-${name}.json`, JSON.stringify({ link_unit: 'native-lab-network.service', profile: { ...common, role, tun_address: address, lan } }), 0o600);
  }
  put('/etc/systemd/system/native-lab-network.service', '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /native/network-lab.sh network\n');
  put('/etc/systemd/system/native-lab-defaults.service', '[Unit]\nDefaultDependencies=no\nRequires=native-c2-uplink.service native-exit-uplink.service\nAfter=native-c2-uplink.service native-exit-uplink.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /native/network-lab.sh defaults\n');
  put('/etc/systemd/system/native-lab-driver.service', '[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=/bin/sh /native/network-lab.sh driver\nTimeoutStartSec=10min\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n');
}
