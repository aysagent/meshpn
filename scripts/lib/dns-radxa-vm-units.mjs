/** Reuse synthetic dnsmasq services, replace only coordinator and driver. */
import { dnsmasqVmUnits } from './dnsmasq-vm-units.mjs';
export function radxaVmUnits() {
  const units = dnsmasqVmUnits();
  units['dns-vm-controller.service'] = units['dns-vm-controller.service'].replace('dnsmasq-vm-worker.mjs activate', 'dns-radxa-vm-worker.mjs activate');
  units['dns-vm-driver.service'] = units['dns-vm-driver.service'].replace('dnsmasq-vm-driver.mjs', 'dns-radxa-vm-driver.mjs');
  return units;
}
