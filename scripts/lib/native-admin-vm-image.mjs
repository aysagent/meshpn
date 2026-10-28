import fs from 'node:fs';
export const nativeAdminChecks = ['AUTH', 'REAL_NATIVE_DATA', 'SETTINGS_APPLY', 'TLS_FAILURE_ROLLBACK',
  'STOPPED_STAYS_STOPPED', 'BROKER_CRASH_ROLLBACK', 'GUARD_REMAINS', 'CLEANUP'];

export function addNativeAdminImage(put) {
  const copy = dir => {
    for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      const file = dir + '/' + entry.name;
      if (entry.isDirectory()) copy(file);
      else put('/project/' + file, fs.readFileSync(file));
    }
  };
  copy('admin');
  put('/native/profile.json', fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json'), 0o600);
  put('/etc/systemd/system/native-lab-driver.service', `[Unit]
DefaultDependencies=no
Requires=dbus.service
After=dbus.service
[Service]
Type=oneshot
ExecStart=/usr/bin/node /project/scripts/lib/native-admin-vm.mjs
TimeoutStartSec=10min
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
`);
  // Only in the disposable guest. Production broker uses its installed guard
  // auditor; this adapter audits the fixture's actual namespace firewall.
  put('/native/admin-guard.sh', `#!/bin/sh
set -eu
test "$1" = status
/usr/bin/systemctl is-active --quiet native-lab-guard.service
/usr/bin/ip netns exec nc2 iptables -S OUTPUT | grep -q '^-P OUTPUT DROP$'
/usr/bin/ip netns exec nc2 ip6tables -S OUTPUT | grep -q '^-P OUTPUT DROP$'
echo 'IPv4: cvks fixture default DROP'
echo 'IPv6: cvks fixture default DROP'
`, 0o755);
  put('/etc/systemd/system/native-c2.service.d/timeout.conf', '[Service]\nTimeoutStartSec=8\nRestart=no\n');
  put('/etc/systemd/system/meshpn-admin-broker.service', `[Unit]
DefaultDependencies=no
After=dbus.service
[Service]
User=root
Group=65534
RuntimeDirectory=meshpn-admin
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/node /project/admin/broker.mjs /native/admin-broker.json
Restart=on-failure
RestartSec=1
StandardOutput=append:/run/admin-broker.log
StandardError=append:/run/admin-broker.log
`);
  put('/etc/systemd/system/meshpn-admin-web.service', `[Unit]
DefaultDependencies=no
Requires=meshpn-admin-broker.service
After=meshpn-admin-broker.service
[Service]
User=65534
Group=65534
ExecStart=/usr/bin/node /project/admin/server.mjs /native/admin-web.json
Restart=on-failure
RestartSec=1
StandardOutput=append:/run/admin-web.log
StandardError=append:/run/admin-web.log
`);
}
