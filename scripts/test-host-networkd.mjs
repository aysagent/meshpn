import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { hostNetworkdUnit, hostNetworkdConfig, runHostNetworkdChecks } from './lib/vpn-host-networkd-lab.mjs';
import { HOST_NETWORKD_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';

test('networkd scenario refuses mutations on development host', async () => {
  await assert.rejects(runHostNetworkdChecks({}), /meshpn\.host-systemd/);
});
test('host networkd image includes daemon plus its required user and group', () => {
  const source = readFileSync(new URL('./lib/dns-vm-image.mjs', import.meta.url), 'utf8');
  assert.match(source, /if \(coupled \|\| hostNetworkd\) await elf\('\/usr\/lib\/systemd\/systemd-networkd'\)/);
  assert.match(source, /coupled \|\| hostNetworkd \? 'systemd-network:x:192:192:/);
  assert.match(source, /coupled \|\| hostNetworkd \? 'systemd-network:x:192:/);
});
test('networkd fixture uses actual daemon, mandatory ordering and explicit link teardown', () => {
  assert.match(hostNetworkdUnit, /^Requires=.*clean-vpn-killswitch.service$/m);
  assert.match(hostNetworkdUnit, /^After=.*clean-vpn-killswitch.service$/m);
  assert.match(hostNetworkdUnit, /^ExecStart=\/usr\/lib\/systemd\/systemd-networkd$/m);
  assert.match(hostNetworkdUnit, /^ExecStopPost=\/usr\/bin\/ip link set eth0 down$/m);
  assert.match(hostNetworkdUnit, /^NetworkNamespacePath=\/run\/netns\/client$/m);
  assert.doesNotMatch(hostNetworkdUnit, /ExecStartPre=.*ip/);
  assert.match(hostNetworkdConfig, /^Name=eth0$/m);
  assert.match(hostNetworkdConfig, /^DHCP=no$/m);
  assert.doesNotMatch(hostNetworkdConfig, /ConfigureWithoutCarrier=yes/);
});
test('networkd evidence requires all checks and cannot claim cold boot or deployment', () => {
  const report = { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false, checks: [...HOST_NETWORKD_CHECKS],
    hostSystemd: { networkd: true, actualNetworkd: true, systemdPid1: true, actualInstaller: true, acceptance: 'not-ready-for-deployment',
      limitations: ['fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
        'minimal-root-networkd-unit-not-vendor-sandbox', 'container-marker-no-udev', 'static-addresses-late-carrier-not-DHCP'] } };
  assertHostSystemdEvidence(report, { networkd: true });
  assert.throws(() => assertHostSystemdEvidence(report));
  assert.throws(() => assertHostSystemdEvidence(report, { networkd: true, networkGate: true }));
  for (let i = 0; i < report.checks.length; i++) assert.throws(() => assertHostSystemdEvidence({ ...report, checks: report.checks.filter((_, j) => i !== j) }, { networkd: true }));
  for (const change of [{ actualNetworkd: false }, { limitations: [] }, { acceptance: 'ready' }])
    assert.throws(() => assertHostSystemdEvidence({ ...report, hostSystemd: { ...report.hostSystemd, ...change } }, { networkd: true }));
});
test('networkd CLI rejects mixed scopes before image construction', () => {
  for (const flags of [[], ...['--host-stop-faults', '--host-boot-order', '--host-network-gate'].map(f => ['--host-systemd', '--ipv6', '--dns-conntrack=/unused', f])]) {
    const p = spawnSync(process.execPath, ['scripts/ingress-vm-lab.mjs', '--tools=/unused', '--kernel=/unused', '--resolved=/unused', '--host-networkd', ...flags], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.match(p.stderr, /--host-networkd requires/); assert.doesNotMatch(p.stderr, /Ingress VM artifacts/);
  }
});
