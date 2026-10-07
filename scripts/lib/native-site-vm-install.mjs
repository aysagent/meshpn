// Disposable VM acceptance only: actual installer, with namespace-only dropins.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { installNative } from './native-install.mjs';
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-network=1\b/);
assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
fs.mkdirSync('/opt', { recursive: true });
for (const [name, ns] of [['c2', 'nc2'], ['exit', 'nexit']]) {
  const result = installNative({ name, binary: '/native/clean-vpn-engine', config: `/native/${name}.json`, siteProfile: `/native/site-${name}.json`, apply: true });
  assert.equal(result.status, 'installed-disabled');
  const manifest = JSON.parse(fs.readFileSync(`/opt/clean-vpn-native/${name}/installed.json`));
  for (const unit of manifest.units) {
    assert.ok(!fs.existsSync('/etc/systemd/system/multi-user.target.wants/' + unit));
    fs.mkdirSync(`/etc/systemd/system/${unit}.d`);
    const log = unit === `native-${name}-network.service` || unit === `native-${name}-uplink.service` ? `/run/native-profile-${name}.log` : '/run/native-route-control.log';
    fs.writeFileSync(`/etc/systemd/system/${unit}.d/lab.conf`, '[Unit]\nDefaultDependencies=no\n' + (unit.endsWith('.service') ? `[Service]\nNetworkNamespacePath=/run/netns/${ns}\nRestart=no\nStandardOutput=append:${log}\nStandardError=append:${log}\n` : ''));
  }
}
console.log('NATIVE_NETWORK_INSTALLED_DISABLED_PASS');
