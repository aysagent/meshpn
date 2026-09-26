/** Synthetic guest units only: never install these on a host. */
import { compileDnsAdapterServicePlan } from './dns-adapter-service-plan.mjs';
import { dnsBootGuardUnit } from './dns-boot-guard.mjs';
const worker = '/usr/bin/node --max-old-space-size=192 /project/scripts/lib/dns-systemd-vm-worker.mjs';
const common = 'DefaultDependencies=no\nConflicts=shutdown.target\nBefore=shutdown.target\n';
const service = 'Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin OPENSSL_CONF=/dev/null\nUMask=0077\nStandardInput=null\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=180\nTimeoutStopSec=15\nKillMode=control-group\n';
const unit = (description, deps, body) => `[Unit]\nDescription=${description}\n${common}${deps}\n[Service]\n${service}${body}\n`;
export function dnsSystemdVmUnits({ cliAdapter = false } = {}) {
  const units = {
    'default.target': '[Unit]\nDescription=Isolated DNS VM\nDefaultDependencies=no\nWants=dns-vm-driver.service\n',
    'dbus.service': unit('Private guest D-Bus', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      'Type=notify\nUMask=0022\nExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --systemd-activation --config-file=/etc/dbus-vm.conf'),
    'systemd-resolved.service': unit('Guest resolved', 'Requires=dbus.service\nAfter=dbus.service',
      'Type=notify\nExecStart=/usr/lib/systemd/systemd-resolved\nEnvironment=SYSTEMD_LOG_TARGET=console'),
    'dns-vm-guard.service': unit('DNS guard; stop never releases it', '', `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} guard`),
    'dns-vm-network.service': unit('Controlled guest network', 'Requires=dns-vm-guard.service\nAfter=dns-vm-guard.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} network`),
    'dns-vm-baseline.service': unit('Explicit synthetic link baseline', 'Requires=systemd-resolved.service\nAfter=systemd-resolved.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} baseline`),
    'dns-vm-sentinel.service': unit('Independent baseline DNS observer', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=notify\nNotifyAccess=all\nExecStart=${worker} sentinel`),
    'dns-vm-adapter.service': unit('Protected DNS path fixture', 'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=notify\nNotifyAccess=all\nExecStart=${worker} adapter`),
    'dns-vm-controller.service': unit('Journalled owned-link DNS',
      'Requires=dns-vm-baseline.service\nBindsTo=dns-vm-guard.service dns-vm-adapter.service systemd-resolved.service\nAfter=dns-vm-baseline.service dns-vm-guard.service dns-vm-adapter.service systemd-resolved.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/flock -n /state/controller.lock ${worker} activate`),
    'dns-vm-consumer.service': unit('Readiness-gated DNS consumer',
      'BindsTo=dns-vm-controller.service\nAfter=dns-vm-controller.service',
      `Type=oneshot\nRemainAfterExit=yes\nExecStart=${worker} consumer`),
    'dns-vm-driver.service': unit('Bounded systemd lifecycle acceptance', '',
      `Type=oneshot\nTimeoutStartSec=15min\nExecStart=/usr/bin/node --max-old-space-size=192 /project/scripts/lib/dns-systemd-vm-driver.mjs`),
  };
  if (cliAdapter) {
    units['network-pre.target'] = '[Unit]\nDescription=Guest passive network-pre target\nDefaultDependencies=no\n';
    units['dns-vm-guard.service'] = dnsBootGuardUnit('legacy')
      .replace('[Service]\n', "[Service]\nExecStartPre=/bin/busybox test ! -e /run/meshpn/deny-start\n")
      .replace('StandardOutput=journal\nStandardError=journal', 'StandardOutput=append:/run/meshpn/boot-guard.log\nStandardError=append:/run/meshpn/boot-guard.log');
    units['dns-vm-fixture.service'] = unit('Separate synthetic exit and DoH origin',
      'Requires=dns-vm-network.service\nAfter=dns-vm-network.service',
      `Type=notify\nNotifyAccess=all\nExecStart=${worker} cli-fixture`);
    const plan = compileDnsAdapterServicePlan({ schema: 1, exitIp: '93.184.216.36', exitPort: 44443,
      publicName: 'relay.test', listenPort: 2053, readyName: 'systemd-ready.test',
      upstream: { schema: 1, transport: 'doh', hostname: 'resolver.test', port: 443, path: '/dns-query',
        bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } },
      domainPolicy: { schema: 1, denySuffixes: ['blocked.test'] } });
    // Only boot graph/log sink differ in the synthetic guest. Keep the rendered
    // CLI, credentials, dynamic UID, capabilities and sandbox directives intact.
    units['dns-vm-adapter.service'] = plan.files[0].contents
      .replace('ExecStart=/usr/bin/node ', 'ExecStart=/usr/bin/node --import=/opt/clean-vpn/scripts/lib/dns-vm-adapter-observe.mjs ')
      .replace('[Unit]\n', `[Unit]\n${common}`)
      .replace('Wants=network-online.target\n', '')
      .replace('BindsTo=clean-vpn-dns-guard.service', 'BindsTo=dns-vm-guard.service dns-vm-fixture.service')
      .replace('After=network-online.target clean-vpn-dns-guard.service', 'After=dns-vm-guard.service dns-vm-fixture.service')
      // PrivateDevices intentionally hides console; guest has no journald.
      // The driver measures unit state, MainPID, DNS counters and /proc instead.
      .replace('StandardOutput=journal\nStandardError=journal', 'StandardOutput=null\nStandardError=null');
  }
  return units;
}
