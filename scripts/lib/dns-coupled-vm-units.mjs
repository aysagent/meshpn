/** Offline NIC-less VM fixture only; not live-client service units. */
import { dnsSystemdVmUnits } from './dns-systemd-vm-units.mjs';
export function dnsCoupledVmUnits() {
  const units = dnsSystemdVmUnits();
  units['dns-vm-controller.service'] = units['dns-vm-controller.service']
    .replace('flock -n ', 'flock -n -F ')
    .replace('dns-systemd-vm-worker.mjs activate', 'dns-coupled-vm-worker.mjs activate');
  units['dns-vm-driver.service'] = units['dns-vm-driver.service']
    .replace('dns-systemd-vm-driver.mjs', 'dns-coupled-vm-driver.mjs')
    .replace('Type=oneshot', 'Type=oneshot\nSuccessExitStatus=SIGTERM');
  return units;
}
