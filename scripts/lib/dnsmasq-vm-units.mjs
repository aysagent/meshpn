/** Synthetic guest services. No [Install], no host deployment authority. */
const worker = '/usr/bin/node --max-old-space-size=192 /project/scripts/lib/dnsmasq-vm-worker.mjs';
const common = 'DefaultDependencies=no\nConflicts=shutdown.target\nBefore=shutdown.target\n';
const service = 'Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null MESHPN_DNSMASQ_VM=1\nUMask=0077\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=180\nTimeoutStopSec=15\nKillMode=control-group\n';
const unit = (description, deps, body) => `[Unit]\nDescription=${description}\n${common}${deps}\n[Service]\n${service}${body}\n`;
export function dnsmasqVmUnits() {
  return {
    'default.target': '[Unit]\nDescription=Isolated dnsmasq VM\nDefaultDependencies=no\nWants=dns-vm-driver.service\n',
    'dns-vm-guard.service': unit('Persistent guard; stop never releases', '', `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} guard`),
    'dns-vm-network.service': unit('NIC-less guest baseline', 'Requires=dns-vm-guard.service\nAfter=dns-vm-guard.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} network`),
    'dns-vm-sentinel.service': unit('Direct DNS observer', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=notify\nNotifyAccess=all\nExecStart=${worker} sentinel`),
    'dns-vm-adapter.service': unit('Protected adapter and exit fixture', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=notify\nNotifyAccess=all\nExecStart=${worker} adapter`),
    // Deliberately independent of adapter/controller: DHCP survives their loss.
    'dns-vm-dnsmasq.service': unit('Owned USB DHCP and DNS daemon', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=exec\nExecStartPre=${worker} daemon-check\nExecStart=/usr/sbin/dnsmasq --no-daemon --conf-file=/state/dnsmasq/dnsmasq.conf --bind-interfaces --no-hosts --cache-size=0 --pid-file= --log-facility=- --dhcp-leasefile=/state/dnsmasq-leases`),
    'dns-vm-controller.service': unit('Persistent dnsmasq transaction',
      'BindsTo=dns-vm-guard.service dns-vm-adapter.service\nAfter=dns-vm-guard.service dns-vm-adapter.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/flock -n -F /state/controller.lock ${worker} activate`),
    'dns-vm-consumer.service': unit('Protected DNS consumer',
      'BindsTo=dns-vm-controller.service\nAfter=dns-vm-controller.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} consumer`),
    'dns-vm-driver.service': unit('Bounded dnsmasq acceptance', '',
      // PID1 may stop the still-activating oneshot during its requested reboot.
      // The host still requires all evidence and completed kernel shutdown.
      'Type=oneshot\nSuccessExitStatus=SIGTERM\nTimeoutStartSec=15min\nExecStart=/usr/bin/node --max-old-space-size=192 /project/scripts/lib/dnsmasq-vm-driver.mjs'),
  };
}
