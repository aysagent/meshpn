/** Reuse synthetic dnsmasq services, replace only coordinator and driver. */
import { dnsmasqVmUnits } from './dnsmasq-vm-units.mjs';
import { dnsSystemdVmUnits } from './dns-systemd-vm-units.mjs';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';
export function radxaVmUnits() {
  const units = dnsmasqVmUnits();
  const shared = dnsSystemdVmUnits({ cliAdapter: true });
  for (const name of ['dns-vm-guard.service', 'network-pre.target', 'dns-vm-adapter.service']) units[name] = shared[name];
  units['dns-vm-adapter.service'] = units['dns-vm-adapter.service'].replace('systemd-ready.test', 'vm-ready.test')
    // Synthetic /etc is a 0700 journal directory after bind. Keep that storage
    // protection; the fixture uses explicit TLS settings/custom CA credentials.
    // All other VM Node workers already avoid the guest OpenSSL config too.
    .replace('ExecStart=/usr/bin/node ', 'ExecStart=/usr/bin/node --openssl-config=/dev/null ');
  units['dns-vm-fixture.service'] = shared['dns-vm-fixture.service'].replace('dns-systemd-vm-worker.mjs cli-fixture', 'dnsmasq-vm-worker.mjs cli-fixture');
  units['dns-vm-controller.service'] = units['dns-vm-controller.service']
    .replace('/state/controller.lock', DNS_BOOT_LOCK).replace('dnsmasq-vm-worker.mjs activate', 'dns-radxa-vm-worker.mjs activate');
  units['dns-vm-driver.service'] = units['dns-vm-driver.service'].replace('dnsmasq-vm-driver.mjs', 'dns-radxa-vm-driver.mjs');
  return units;
}
