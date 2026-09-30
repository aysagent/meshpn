import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { gatedNetworkUnit, runHostNetworkGateChecks } from './lib/vpn-host-network-gate-lab.mjs';
import { HOST_NETWORK_GATE_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';

test('network gate mutation refuses the development host', async () => {
  await assert.rejects(runHostNetworkGateChecks({}), /meshpn\.host-systemd/);
});
test('candidate gates interface activation on successful guard and lowers link on stop', () => {
  const unit = gatedNetworkUnit('/tmp/host-systemd-abc');
  assert.match(unit, /^Requires=clean-vpn-killswitch.service$/m);
  assert.match(unit, /^After=network-pre.target clean-vpn-killswitch.service$/m);
  assert.match(unit, /^ExecStartPre=\/usr\/bin\/ip link set eth0 up$/m);
  assert.match(unit, /^ExecStartPre=\/usr\/bin\/ip -4 route replace default via 192.0.2.1 dev eth0$/m);
  assert.match(unit, /^ExecStop=\/usr\/bin\/ip link set eth0 down$/m);
  assert.match(unit, /^NetworkNamespacePath=\/run\/netns\/client$/m);
  assert.throws(() => gatedNetworkUnit('/tmp/host-systemd-a\nExecStart=bad'));
  const installer = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  assert.doesNotMatch(installer, /host-network-gate|host-vm-network-observer/);
});
test('network gate evidence cannot become deployment acceptance or replace historical defect', () => {
  const evidence = { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false,
    checks: [...HOST_NETWORK_GATE_CHECKS], hostSystemd: { systemdPid1: true, actualInstaller: true,
      networkGate: true, managedLinkFailClosed: true, acceptance: 'not-ready-for-deployment', limitations: [
        'fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart',
        'synthetic-network-manager-not-networkd', 'managed-link-initially-down-only', 'failed-guard-also-prevents-SSH'] } };
  assertHostSystemdEvidence(evidence, { networkGate: true });
  assert.throws(() => assertHostSystemdEvidence(evidence));
  assert.throws(() => assertHostSystemdEvidence(evidence, { networkGate: true, bootOrder: true }));
  for (let i = 0; i < evidence.checks.length; i++) assert.throws(() => assertHostSystemdEvidence({ ...evidence,
    checks: evidence.checks.filter((_, j) => i !== j) }, { networkGate: true }));
  for (const change of [{ managedLinkFailClosed: false }, { acceptance: 'ready' }, { limitations: [] }])
    assert.throws(() => assertHostSystemdEvidence({ ...evidence, hostSystemd: { ...evidence.hostSystemd, ...change } }, { networkGate: true }));
});
test('network gate CLI rejects missing or mixed scopes before image creation', () => {
  for (const flags of [[], ['--host-systemd', '--ipv6', '--dns-conntrack=/unused', '--host-boot-order'],
    ['--host-systemd', '--ipv6', '--dns-conntrack=/unused', '--host-stop-faults']]) {
    const p = spawnSync(process.execPath, ['scripts/ingress-vm-lab.mjs', '--tools=/unused', '--kernel=/unused',
      '--resolved=/unused', '--host-network-gate', ...flags], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.match(p.stderr, /--host-network-gate requires/);
    assert.doesNotMatch(p.stderr, /Ingress VM artifacts/);
  }
});
