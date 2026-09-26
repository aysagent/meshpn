import assert from 'node:assert/strict';
import test from 'node:test';
import { VM_CUT_POINTS, VM_FAULTS, VM_SYSTEMD_CHECKS, VM_DNSMASQ_CHECKS, vmCases, vmBootOptions, qemuDnsArgs, assertVmJournalCheckpoint, assertVmFaultEvidence, assertVmSystemdEvidence, assertVmDnsmasqEvidence, vmSerialEvent } from './lib/dns-vm-protocol.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { dnsSystemdVmUnits } from './lib/dns-systemd-vm-units.mjs';
import { dnsmasqVmUnits } from './lib/dnsmasq-vm-units.mjs';
import { dnsCoupledVmUnits } from './lib/dns-coupled-vm-units.mjs';
import { VM_COUPLED_CUTS, VM_COUPLED_CHECKS, assertVmCoupledEvidence } from './lib/dns-vm-protocol.mjs';
import { createVmCoupledBackend } from './lib/dns-coupled-backend.mjs';
import { createVmOwnedLinkBackend } from './lib/dns-owned-link-backend.mjs';

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
test('dnsmasq VM is separately selected and preserves DHCP independence from adapter', () => {
  assert.deepEqual(vmCases('dnsmasq'), ['lifecycle']); assert.equal(vmCases().length, 9);
  assert.deepEqual(vmBootOptions(qemuDnsArgs({ ...input, phase: 'dnsmasq', point: 'lifecycle' }).find((arg) => arg.startsWith('console='))),
    { phase: 'dnsmasq', point: 'lifecycle' });
  const units = dnsmasqVmUnits();
  assert.doesNotMatch(units['dns-vm-dnsmasq.service'], /BindsTo=.*(?:adapter|controller)/);
  assert.match(units['dns-vm-dnsmasq.service'], /ExecStartPre=.*daemon-check/);
  assert.match(units['dns-vm-controller.service'], /BindsTo=dns-vm-guard.service dns-vm-adapter.service/);
  assert.match(units['dns-vm-controller.service'], /flock -n -F \/state\/controller.lock/);
  assert.match(units['dns-vm-consumer.service'], /After=dns-vm-controller.service/);
  assert.match(units['dns-vm-driver.service'], /SuccessExitStatus=SIGTERM/);
  for (const [name, unit] of Object.entries(units)) if (name !== 'dns-vm-driver.service') assert.doesNotMatch(unit, /SuccessExitStatus=/);
  for (const unit of Object.values(units)) assert.doesNotMatch(unit, /ExecStop=|\[Install\]/);
});
test('dnsmasq VM evidence requires both boots, DHCP preservation and exact lifecycle criteria', () => {
  const evidence = { phase: 'dnsmasq', point: 'lifecycle', systemdPid1: true, automaticStaleAdoption: false,
    baselineQueriesDuringProtection: 0, baselinePositiveControl: true, explicitDisablePassed: true, resolvConfUnchanged: true,
    dhcpPreservedOnAdapterFailure: true,
    checks: [...VM_DNSMASQ_CHECKS, 'service-readiness-and-usb-dhcp', 'explicit-disable-restores-baseline'] };
  assertVmDnsmasqEvidence(evidence);
  for (const key of Object.keys(evidence).filter((k) => k !== 'checks')) assert.throws(() =>
    assertVmDnsmasqEvidence({ ...evidence, [key]: typeof evidence[key] === 'boolean' ? !evidence[key] : 'bad' }));
  for (let i = 0; i < evidence.checks.length; i++) assert.throws(() =>
    assertVmDnsmasqEvidence({ ...evidence, checks: evidence.checks.filter((_, n) => n !== i) }));
});
for (const entry of ['worker', 'driver']) test(`dnsmasq VM ${entry} refuses ordinary host execution`, async () => {
  const r = await runCommand(process.execPath, [`scripts/lib/dnsmasq-vm-${entry}.mjs`, 'guard']);
  assert.equal(r.code, 1); assert.ok(!r.stdout.includes('boot-guard'));
});
test('VM flag alone cannot authorize peer work on host', async () => {
  const r = await runCommand(process.execPath, ['scripts/lib/dnsmasq-usb-peer-worker.mjs'],
    { env: { ...process.env, MESHPN_DNSMASQ_VM: '1' } });
  assert.equal(r.code, 1); assert.equal(r.stdout, ''); assert.match(r.stderr, /USB_PEER_FAILED/);
});

test('coupled VM has independent bounded selection and lock, without changing old fixture units', () => {
  assert.deepEqual(vmCases('coupled'), ['lifecycle']); assert.deepEqual(vmCases('coupled-cuts'), VM_COUPLED_CUTS);
  for (const point of VM_COUPLED_CUTS) assert.deepEqual(vmCases(`coupled-cut:${point}`), [point]);
  for (const point of ['', 'none', 'lifecycle', 'guard-removed']) assert.throws(() => vmCases(`coupled-cut:${point}`));
  assert.equal(vmCases().length, 9);
  const old = dnsSystemdVmUnits(), units = dnsCoupledVmUnits();
  assert.match(units['dns-vm-controller.service'], /flock -n -F \/state\/controller.lock.*dns-coupled-vm-worker.mjs activate/);
  assert.match(units['dns-vm-controller.service'], /BindsTo=dns-vm-guard.service dns-vm-adapter.service systemd-resolved.service/);
  assert.match(units['dns-vm-driver.service'], /dns-coupled-vm-driver.mjs/);
  assert.deepEqual(dnsSystemdVmUnits(), old);
  for (const [name, unit] of Object.entries(units)) {
    assert.doesNotMatch(unit, /ExecStop=|\[Install\]/);
    if (!['dns-vm-controller.service', 'dns-vm-driver.service'].includes(name)) assert.equal(unit, old[name]);
  }
  for (const phase of ['coupled-cut', 'coupled-inspect']) for (const point of VM_COUPLED_CUTS) {
    assert.deepEqual(vmBootOptions(qemuDnsArgs({ ...input, phase, point }).find((v) => v.startsWith('console='))), { phase, point });
  }
  for (const [phase, point] of [['coupled', 'apply:DNSEx:set'], ['coupled-cut', 'lifecycle'], ['coupled-inspect', 'guard-removed'], ['cut', 'link-released']]) {
    assert.throws(() => qemuDnsArgs({ ...input, phase, point }));
  }
});
const coupledEvidence = () => ({ phase: 'coupled', point: 'lifecycle', systemdPid1: true, automaticStaleAdoption: false,
  baselineQueriesDuringProtection: 0, baselinePositiveControl: true, explicitDisablePassed: true, resolvConfUnchanged: true,
  ownedLinkRemoved: true, bothJournalsPreservedOnRefusal: true,
  checks: [...VM_COUPLED_CHECKS, 'readiness-owned-link-and-protected-dns', 'disable-removes-owned-link-before-baseline-release'] });
test('coupled lifecycle evidence requires exactly both boots and all checks', () => {
  const e = coupledEvidence(); assertVmCoupledEvidence(e);
  for (const key of Object.keys(e).filter((k) => k !== 'checks')) assert.throws(() => assertVmCoupledEvidence({ ...e,
    [key]: typeof e[key] === 'boolean' ? !e[key] : 'bad' }));
  for (let i = 0; i < e.checks.length; i++) assert.throws(() => assertVmCoupledEvidence({ ...e, checks: e.checks.filter((_, n) => n !== i) }));
  assert.throws(() => assertVmCoupledEvidence({ ...e, checks: [...e.checks, e.checks[0]] }));
});
for (const point of VM_COUPLED_CUTS) test(`whole-guest cut evidence compares both on-disk journals to checkpoint: ${point}`, () => {
  const [phase, direction, level, pending, stage] = ({
    'apply:DNSEx:set': ['settings', 'apply', 4, true, 'created'],
    'restore:DNSEx:set': ['settings', 'restore', 5, true, 'created'],
    'link-released': ['unlink', 'restore', 0, false, 'released'],
  })[point];
  const context = { bootId: 'previous' }, root = { id: 'same', context, phase, direction, level, pending }, child = { id: 'same', context, stage };
  const cut = { event: 'cut-ready', point, root, child };
  const e = { ...coupledEvidence(), phase: 'coupled-inspect', point, previousBootId: 'previous', inspected: { root, child },
    checks: ['stale-journals-preserved-start-refused', 'readiness-owned-link-and-protected-dns', 'disable-removes-owned-link-before-baseline-release'] };
  assertVmCoupledEvidence(e, cut);
  for (const key of ['root', 'child']) {
    const bad = structuredClone(e); bad.inspected[key].id = 'changed';
    assert.throws(() => assertVmCoupledEvidence(bad, cut));
  }
  for (const key of ['phase', 'direction', 'level', 'pending']) {
    const bad = structuredClone(e), badCut = structuredClone(cut);
    bad.inspected.root[key] = badCut.root[key] = 'bad'; assert.throws(() => assertVmCoupledEvidence(bad, badCut));
  }
  assert.throws(() => assertVmCoupledEvidence(e));
});
for (const entry of ['worker', 'driver']) test(`coupled VM ${entry} refuses host execution`, async () => {
  const r = await runCommand(process.execPath, [`scripts/lib/dns-coupled-vm-${entry}.mjs`, 'activate']);
  assert.equal(r.code, 1); assert.ok(!r.stdout.includes('boot-guard')); assert.ok(!r.stdout.includes('DNS_COUPLED_TRANSACTION'));
});
test('VM backend factories refuse the host before contacting injected bus or guard', async () => {
  let calls = 0; const action = () => { calls++; throw new Error('must not be called'); };
  for (const factory of [createVmCoupledBackend, createVmOwnedLinkBackend]) {
    await assert.rejects(factory({ bus: { id: action, owner: action }, ensureGuard: action, releaseGuard: action, probe: action, port: 2053 }));
  }
  assert.equal(calls, 0);
});
