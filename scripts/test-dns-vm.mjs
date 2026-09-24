import assert from 'node:assert/strict';
import test from 'node:test';
import { VM_CUT_POINTS, VM_FAULTS, VM_SYSTEMD_CHECKS, vmCases, vmBootOptions, qemuDnsArgs, assertVmJournalCheckpoint, assertVmFaultEvidence, assertVmSystemdEvidence, vmSerialEvent } from './lib/dns-vm-protocol.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { dnsSystemdVmUnits } from './lib/dns-systemd-vm-units.mjs';

const input = { root: '/private/tools', kernel: '/private/kernel', initrd: '/private/initrd', disk: '/private/state.raw', phase: 'cycle', point: 'none' };
test('shared console framing tolerates a PID1 prefix, never malformed JSON', () => {
  assert.equal(vmSerialEvent('ordinary kernel log'), null);
  for (const prefix of ['', 'service: Deactivated successfully.']) {
    assert.deepEqual(vmSerialEvent(`${prefix}DNS_VM_EVENT {"event":"passed"}`), { event: 'passed' });
  }
  assert.throws(() => vmSerialEvent('DNS_VM_EVENT {"event":"passed"'));
});
test('VM launcher explicitly disables network, display, monitor and default devices', () => {
  const args = qemuDnsArgs(input);
  for (const [flag, value] of [['-nic', 'none'], ['-monitor', 'none'], ['-display', 'none'], ['-accel', 'tcg'], ['-m', '1024'], ['-smp', '1']]) {
    assert.equal(args[args.indexOf(flag) + 1], value);
  }
  for (const flag of ['-nodefaults', '-no-user-config']) assert.ok(args.includes(flag));
  for (const flag of ['-net', '-netdev', '-virtfs', '-fsdev', '-enable-kvm', '-snapshot', '-qmp']) assert.ok(!args.includes(flag));
  assert.ok(args.includes('-no-reboot'));
  assert.equal(args[args.indexOf('-drive') + 1], 'file=/private/state.raw,format=raw,if=virtio,cache=writeback');
  assert.deepEqual(vmBootOptions(args[args.indexOf('-append') + 1]), { phase: 'cycle', point: 'none' });
});
for (const point of VM_CUT_POINTS) test(`VM cut/inspect protocol permits only known checkpoint ${point}`, () => {
  for (const phase of ['cut', 'inspect']) {
    const args = qemuDnsArgs({ ...input, phase, point });
    assert.ok(args.includes('-no-reboot'));
    assert.deepEqual(vmBootOptions(args[args.indexOf('-append') + 1]), { phase, point });
  }
});
test('fault group is bounded and cannot silently extend the original reboot matrix', () => {
  assert.equal(vmCases().length, 9); assert.deepEqual(vmCases('faults'), VM_FAULTS);
  assert.deepEqual(vmCases('cycle'), ['none']);
  for (const value of ['unknown', 'none', '', '__proto__']) assert.throws(() => vmCases(value));
});
test('systemd lifecycle selection remains separate and uses the same NIC-less QEMU isolation', () => {
  assert.deepEqual(vmCases('systemd'), ['lifecycle']);
  const args = qemuDnsArgs({ ...input, phase: 'systemd', point: 'lifecycle' });
  assert.deepEqual(vmBootOptions(args[args.indexOf('-append') + 1]), { phase: 'systemd', point: 'lifecycle' });
  assert.ok(args.includes('-no-reboot')); assert.ok(args.includes('none'));
  assert.throws(() => qemuDnsArgs({ ...input, phase: 'systemd', point: 'none' }));
});
test('VM units gate consumers on readiness and stop does not implicitly disable DNS protection', () => {
  const units = dnsSystemdVmUnits();
  assert.match(units['dns-vm-consumer.service'], /BindsTo=dns-vm-controller.service\nAfter=dns-vm-controller.service/);
  assert.match(units['dns-vm-controller.service'], /BindsTo=dns-vm-guard.service dns-vm-adapter.service systemd-resolved.service/);
  assert.match(units['dns-vm-controller.service'], /flock -n \/state\/controller.lock/);
  assert.match(units['dns-vm-adapter.service'], /Type=notify/);
  assert.match(units['dns-vm-network.service'], /Requires=dns-vm-guard.service\nAfter=dns-vm-guard.service/);
  for (const unit of Object.values(units)) { assert.ok(!unit.includes('ExecStop=')); assert.ok(!unit.includes('[Install]')); }
});
test('systemd evidence needs both boots and all lifecycle gates, not just a passed marker', () => {
  const evidence = { phase: 'systemd', point: 'lifecycle', systemdPid1: true, automaticStaleAdoption: false,
    baselineQueriesDuringProtection: 0, baselinePositiveControl: true, explicitDisablePassed: true, resolvConfUnchanged: true,
    checks: [...VM_SYSTEMD_CHECKS, 'real-service-readiness-before-consumer', 'explicit-disable-restores-owned-baseline'] };
  assertVmSystemdEvidence(evidence);
  for (const key of Object.keys(evidence).filter((k) => k !== 'checks')) {
    assert.throws(() => assertVmSystemdEvidence({ ...evidence, [key]: typeof evidence[key] === 'boolean' ? !evidence[key] : 'wrong' }));
  }
  for (let n = 0; n < evidence.checks.length; n++) {
    assert.throws(() => assertVmSystemdEvidence({ ...evidence, checks: evidence.checks.filter((_, i) => i !== n) }));
  }
  assert.throws(() => assertVmSystemdEvidence({ ...evidence, checks: [...evidence.checks, evidence.checks[0]] }));
});
for (const point of VM_FAULTS) test(`VM fault ${point} has strict selection and evidence`, () => {
  const args = qemuDnsArgs({ ...input, phase: 'fault', point });
  assert.deepEqual(vmBootOptions(args[args.indexOf('-append') + 1]), { phase: 'fault', point });
  assert.deepEqual(vmCases(point), [point]);
  assert.throws(() => vmBootOptions(`meshpn_dns_vm=isolated-v1 meshpn_phase=cut meshpn_point=${point}`));
  const e = { point, status: 'passed', dnsUnchangedOnFailure: true, noSettersOnFailure: true,
    blockedAfterFailure: true, explicitRecoveryPassed: true,
    failure: ({ 'guard-unavailable': 'permission-denied', 'storage-readonly': 'EROFS',
      'corrupt-journal': 'SyntaxError', 'adapter-unready': 'readiness-failed' })[point],
    ...(point === 'guard-unavailable' ? { guardClaimedInstalledOnFailure: false, loopbackStayedDown: true, consumersStartedOnFailure: false } : { guardRetained: true }),
    ...(point === 'corrupt-journal' ? { corruptBytesPreserved: true } : {}),
    ...(point === 'adapter-unready' ? { sameTransactionRecovered: true } : {}) };
  assertVmFaultEvidence(point, e);
  for (const key of Object.keys(e)) {
    assert.throws(() => assertVmFaultEvidence(point, { ...e, [key]: typeof e[key] === 'boolean' ? !e[key] : 'incorrect' }), key);
  }
});
test('VM parameter parser refuses ordinary host cmdline, duplicates and extra options', () => {
  const base = 'meshpn_dns_vm=isolated-v1 meshpn_phase=cycle meshpn_point=none';
  for (const cmd of ['', 'root=/dev/vda', `${base} meshpn_phase=cut`, `${base} meshpn_extra=1`, base.replace('cycle', 'host'), base.replace('none', 'active')]) {
    assert.throws(() => vmBootOptions(cmd));
  }
});
test('drive paths cannot inject QEMU suboptions', () => {
  for (const key of ['root', 'kernel', 'initrd', 'disk']) for (const value of ['relative', '/tmp/disk,cache=unsafe', '/tmp/disk\n', '/tmp/disk\0']) {
    assert.throws(() => qemuDnsArgs({ ...input, [key]: value }));
  }
});
test('checkpoint evidence cannot mistake pending setters for durable acknowledgements', () => {
  const pending = { direction: 'apply', cursor: 0, pending: true, stage: 'running' };
  assertVmJournalCheckpoint(pending, 'apply:DNSEx:set');
  for (const key of ['cursor', 'pending', 'direction', 'stage']) {
    assert.throws(() => assertVmJournalCheckpoint({ ...pending, [key]: 'invalid' }, 'apply:DNSEx:set'));
  }
  assert.throws(() => assertVmJournalCheckpoint(pending, 'prepared:file-synced'));
  assert.throws(() => assertVmJournalCheckpoint(pending, 'none'));
});
for (const args of [[], ['--apply'], ['--tools=relative'], ['--case=host'], ['--case=cycle', '--case=all']]) {
  test(`VM CLI rejects invalid/missing opt-in arguments: ${args.join(' ')}`, async () => {
    const r = await runCommand(process.execPath, ['scripts/dns-vm-lab.mjs', ...args]);
    assert.equal(r.code, 1); assert.equal(r.stdout, ''); assert.ok(!r.stderr.includes('VM artifacts:'));
  });
}
test('guest entrypoint refuses host execution before fixture mutations', async () => {
  const r = await runCommand(process.execPath, ['scripts/lib/dns-vm-guest.mjs']);
  assert.equal(r.code, 1); assert.match(r.stdout, /DNS_VM_EVENT.*failed/); assert.ok(!r.stdout.includes('boot-guard'));
});
for (const entry of ['worker', 'driver']) test(`systemd VM ${entry} refuses the host before any mutation`, async () => {
  const r = await runCommand(process.execPath, [`scripts/lib/dns-systemd-vm-${entry}.mjs`, 'guard']);
  assert.equal(r.code, 1); assert.ok(!r.stdout.includes('boot-guard'));
});
