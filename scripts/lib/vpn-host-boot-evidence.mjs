import assert from 'node:assert/strict';
export const hostBootChecks = phase => [
  'systemd PID1', 'udev active', 'networkd socket gated', 'no container marker',
  ...(phase === 0 ? ['direct baseline IPv4', 'legacy audit eligible', 'legacy audit preserves files', 'legacy retired', 'legacy backup exact', 'legacy files removed', 'legacy retirement keeps networkd PID', 'legacy retirement keeps direct IPv4'] : phase === 2 ? ['failed guard', 'failed guard prevents networkd', 'failed guard prevents VPN', 'failed guard link down', 'failed guard no addresses', ...['IPv4', 'IPv6', 'DNS'].map(n => 'failed guard blocks ' + n)] : []),
  'client active', 'active guard audit passes', 'active guard audit read-only', 'active guard up refused', 'active guard down refused', 'active guard mutations unchanged',
  'DHCP IPv4 address', 'DHCP lease recorded', 'IPv4 through exit', 'IPv6 through exit', 'DNS through exit', 'DNS peer exit',
  ...(phase ? ['guard precedes networkd', 'boot differs', ...(phase === 1 ? ['late DHCP retried'] : [])] : []),
  'client stopped', ...['IPv4', 'IPv6', 'DNS'].map(n => 'stopped VPN blocks ' + n),
  ...(phase === 2 ? ['manual guard stop inactive', 'manual guard stop stops networkd', 'manual guard stop stops socket', 'manual guard stop retains rules',
    ...['IPv4', 'IPv6', 'DNS'].map(n => 'manual guard stop blocks ' + n),
    'manual guard stop not reactivated',
    'update leaves client stopped', 'update preserves gate files', 'update preserves active guard', 'update changes wrapper release',
    'updated IPv4 through exit', 'updated IPv6 through exit', 'updated DNS through exit',
    'uninstall complete', 'uninstall removes owned gate and files', 'uninstall keeps networkd active', 'uninstall keeps socket active',
    'uninstall direct IPv4 restored', 'uninstall direct IPv6 restored', 'uninstall direct DNS restored'] : []),
];
export function assertHostBootEvidence(report) {
  assert.equal(report.nic, 'none'); assert.equal(report.hostSharedFilesystem, false); assert.equal(report.acceptance, 'lab-ready-for-host-review');
  assert.equal(report.boots.length, 3); const ids = [];
  for (const [phase, boot] of report.boots.entries()) {
    assert.equal(boot.phase, phase); assert.equal(boot.exitCode, 0); assert.equal(boot.kernelRestart, phase < 2); assert.equal(boot.powerDown, phase === 2); assert.equal(boot.synced, true); assert.equal(boot.unmounted, true);
    assert.equal(boot.events.filter(e => e.event === 'prepared' && e.phase === phase && e.linkInitiallyDown).length, 1);
    assert.equal(boot.events.some(e => e.event === 'failed'), false);
    assert.deepEqual(boot.events.filter(e => e.event === 'check').map(e => e.name), hostBootChecks(phase));
    const ends = boot.events.filter(e => ['reboot-ready', 'passed'].includes(e.event)); assert.equal(ends.length, 1); const end = ends[0];
    assert.equal(end.event, phase < 2 ? 'reboot-ready' : 'passed'); assert.equal(end.phase, phase); assert.deepEqual(end.checks, hostBootChecks(phase));
    assert.match(end.bootId, /^[0-9a-f-]{36}$/); ids.push(end.bootId); assert.equal(end.acceptance, phase < 2 ? 'matrix-pending' : 'lab-ready-for-host-review'); assert.equal(end.actualNetworkdInstaller, true);
    for (const limit of ['virtual-ethernet-not-wifi', 'no-initramfs-network', 'no-power-cut', 'host-preflight-and-console-review-required']) assert.ok(end.limitations.includes(limit));
  }
  assert.equal(new Set(ids).size, 3);
}
