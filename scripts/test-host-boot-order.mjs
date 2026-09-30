import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { bootObserverUnit, runHostBootOrderChecks } from './lib/vpn-host-boot-order-lab.mjs';
import { HOST_BOOT_ORDER_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';

test('boot ordering driver refuses development host before systemd or filesystem mutations', async () => {
  await assert.rejects(runHostBootOrderChecks({}), /meshpn\.host-systemd/);
  const p = spawnSync(process.execPath, ['scripts/lib/vpn-host-boot-observer.mjs', '/tmp/host-systemd-test'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(p.status, 1); assert.match(p.stderr, /meshpn\.host-boot-order/);
});
test('synthetic network consumer orders after network-pre, before network, without requiring guard', () => {
  const unit = bootObserverUnit('/tmp/host-systemd-aB12');
  assert.match(unit, /^After=network-pre.target$/m); assert.match(unit, /^Before=network.target$/m);
  assert.match(unit, /^Wants=network-pre.target network.target$/m);
  assert.match(unit, /^NetworkNamespacePath=\/run\/netns\/client$/m);
  assert.doesNotMatch(unit, /Requires=|clean-vpn-killswitch/);
  for (const dir of ['/tmp/other', '/tmp/host-systemd-a\nExecStart=bad', '/']) assert.throws(() => bootObserverUnit(dir));
});
test('reproduced boot defect requires complete evidence and cannot be accepted as a successful lifecycle', () => {
  const evidence = { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false, checks: [...HOST_BOOT_ORDER_CHECKS],
    hostSystemd: { systemdPid1: true, actualInstaller: true, bootOrder: true, failClosed: false,
      finding: 'network-consumer-ran-after-guard-failure', acceptance: 'not-ready-for-deployment',
      limitations: ['fixture-network-namespace-dropins', 'no-early-boot-or-reboot', 'explicit-recovery-not-auto-restart'] } };
  assertHostSystemdEvidence(evidence, { bootOrder: true });
  assert.throws(() => assertHostSystemdEvidence(evidence));
  assert.throws(() => assertHostSystemdEvidence(evidence, { bootOrder: true, stopFaults: true }));
  for (let i = 0; i < evidence.checks.length; i++) assert.throws(() => assertHostSystemdEvidence({ ...evidence,
    checks: evidence.checks.filter((_, j) => j !== i) }, { bootOrder: true }));
  for (const change of [{ failClosed: true }, { finding: undefined }, { acceptance: 'ready' }])
    assert.throws(() => assertHostSystemdEvidence({ ...evidence, hostSystemd: { ...evidence.hostSystemd, ...change } }, { bootOrder: true }));
});
test('boot ordering CLI refuses incompatible modes before building image', () => {
  for (const flags of [[], ['--host-systemd', '--ipv6', '--dns-conntrack=/not-used', '--host-stop-faults']]) {
    const p = spawnSync(process.execPath, ['scripts/ingress-vm-lab.mjs', '--tools=/not-used', '--kernel=/not-used',
      '--resolved=/not-used', '--host-boot-order', ...flags], { encoding: 'utf8', timeout: 5000 });
    assert.equal(p.status, 1); assert.match(p.stderr, /--host-boot-order requires/);
    assert.doesNotMatch(p.stderr, /Ingress VM artifacts/);
  }
});
test('runner publishes a nonzero reproduced-defect result, never deployment success', () => {
  const runner = readFileSync(new URL('./ingress-vm-lab.mjs', import.meta.url), 'utf8');
  assert.match(runner, /report.status = 'reproduced-defect'/);
  assert.match(runner, /process.exitCode = 2/);
  assert.match(runner, /DEPLOYMENT BLOCKER/);
  const source = readFileSync(new URL('./lib/vpn-host-boot-order-lab.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /ctl\('reset-failed', main/);
  assert.match(source, /ctl\('reset-failed', guard\)/);
});
