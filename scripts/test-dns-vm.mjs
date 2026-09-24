import assert from 'node:assert/strict';
import test from 'node:test';
import { VM_CUT_POINTS, vmBootOptions, qemuDnsArgs, assertVmJournalCheckpoint } from './lib/dns-vm-protocol.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

const input = { root: '/private/tools', kernel: '/private/kernel', initrd: '/private/initrd', disk: '/private/state.raw', phase: 'cycle', point: 'none' };
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
    assert.ok(!args.includes('-no-reboot'));
    assert.deepEqual(vmBootOptions(args[args.indexOf('-append') + 1]), { phase, point });
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
