import assert from 'node:assert/strict';

export const VM_CUT_POINTS = Object.freeze([
  'prepared:file-synced', 'prepared:renamed', 'apply:DNSEx:intent:dir-synced',
  'apply:DNSEx:set', 'apply:Domains:ack:dir-synced', 'restore:DNSEx:set',
  'restore:DefaultRoute:ack:dir-synced', 'guard-removed',
]);
export function assertVmJournalCheckpoint(record, point) {
  const states = {
    none: ['apply', 3, false, 'complete'],
    'prepared:renamed': ['apply', 0, false, 'running'],
    'apply:DNSEx:intent:dir-synced': ['apply', 0, true, 'running'],
    'apply:DNSEx:set': ['apply', 0, true, 'running'],
    'apply:Domains:ack:dir-synced': ['apply', 2, false, 'running'],
    'restore:DNSEx:set': ['restore', 0, true, 'running'],
    'restore:DefaultRoute:ack:dir-synced': ['restore', 3, false, 'complete'],
    'guard-removed': ['restore', 3, false, 'complete'],
  };
  assert.ok(Object.hasOwn(states, point), 'unexpected committed journal');
  assert.deepEqual([record.direction, record.cursor, record.pending, record.stage], states[point]);
}
export function vmBootOptions(cmdline) {
  const fields = cmdline.trim().split(/\s+/).filter((v) => v.startsWith('meshpn_'));
  assert.equal(fields.length, 3, 'VM fixture parameters required');
  const get = (name) => {
    const entries = fields.filter((v) => v.startsWith(`${name}=`)); assert.equal(entries.length, 1);
    return entries[0].slice(name.length + 1);
  };
  assert.equal(get('meshpn_dns_vm'), 'isolated-v1');
  const phase = get('meshpn_phase'), point = get('meshpn_point');
  assert.ok(['cycle', 'cut', 'inspect'].includes(phase));
  assert.ok(phase === 'cycle' ? point === 'none' : VM_CUT_POINTS.includes(point));
  return { phase, point };
}
export function qemuDnsArgs({ root, kernel, initrd, disk, phase, point }) {
  vmBootOptions(`meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`);
  for (const path of [root, kernel, initrd, disk]) assert.ok(path.startsWith('/') && !/[,\n\r\0]/.test(path));
  return ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none',
    // Exit on the guest's reboot request; the parent cold-launches the same private disk.
    ...(phase === 'cycle' ? ['-no-reboot'] : []),
    '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1',
    '-machine', 'pc,dump-guest-core=off', '-bios', `${root}/usr/share/seabios/bios-256k.bin`,
    '-L', `${root}/usr/share/qemu`, '-kernel', kernel, '-initrd', initrd,
    '-append', `console=ttyS0 quiet panic=-1 reboot=t random.trust_cpu=on meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`,
    '-drive', `file=${disk},format=raw,if=virtio,cache=writeback`];
}
