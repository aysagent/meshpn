/** Offline NIC-less VM fixture only; not live-client service units. */
import { dnsSystemdVmUnits } from './dns-systemd-vm-units.mjs';
export function dnsCoupledVmUnits() {
  const units = dnsSystemdVmUnits({ cliAdapter: true });
  units['dns-vm-controller.service'] = units['dns-vm-controller.service']
    .replace('dns-systemd-vm-worker.mjs activate', 'dns-coupled-vm-worker.mjs activate');
  units['dns-vm-driver.service'] = units['dns-vm-driver.service']
    .replace('dns-systemd-vm-driver.mjs', 'dns-coupled-vm-driver.mjs')
    .replace('Type=oneshot', 'Type=oneshot\nSuccessExitStatus=SIGTERM');
  units['systemd-networkd.service'] = `[Unit]
Description=Read-only installed inspection networkd fixture
DefaultDependencies=no
Requires=dbus.service
After=dbus.service
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=notify
ExecStart=/usr/lib/systemd/systemd-networkd
Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin SYSTEMD_LOG_TARGET=console
TimeoutStartSec=30
TimeoutStopSec=15
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
`;
  return units;
}
