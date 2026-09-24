import assert from 'node:assert/strict';

export function vmSerialEvent(line) {
  // PID1 can write a non-newline-terminated status message before a service's
  // complete JSON line. Do not silently lose that result on a shared console.
  const at = line.indexOf('DNS_VM_EVENT ');
  return at < 0 ? null : JSON.parse(line.slice(at + 13));
}

export const VM_CUT_POINTS = Object.freeze([
  'prepared:file-synced', 'prepared:renamed', 'apply:DNSEx:intent:dir-synced',
  'apply:DNSEx:set', 'apply:Domains:ack:dir-synced', 'restore:DNSEx:set',
  'restore:DefaultRoute:ack:dir-synced', 'guard-removed',
]);
export const VM_FAULTS = Object.freeze(['guard-unavailable', 'storage-readonly', 'corrupt-journal', 'adapter-unready']);
export const VM_SYSTEMD_CHECKS = Object.freeze([
  'failed-guard-prevents-network-and-consumer', 'real-service-readiness-before-consumer',
  'controller-stop-retains-guard-and-restart-recovers', 'exit-outage-no-baseline-fallback',
  'adapter-sigkill-stops-dependents-restart-recovers', 'foreign-policy-not-overwritten',
  'explicit-disable-restores-owned-baseline', 'reboot-stale-journal-refused-with-guard',
  'released-journal-restart-refused-under-guard',
]);
export function assertVmSystemdEvidence(evidence) {
  assert.equal(evidence.phase, 'systemd'); assert.equal(evidence.point, 'lifecycle');
  assert.equal(evidence.systemdPid1, true); assert.equal(evidence.automaticStaleAdoption, false);
  assert.equal(evidence.baselineQueriesDuringProtection, 0); assert.equal(evidence.baselinePositiveControl, true);
  assert.equal(evidence.explicitDisablePassed, true); assert.equal(evidence.resolvConfUnchanged, true);
  assert.deepEqual([...new Set(evidence.checks)].sort(), [...VM_SYSTEMD_CHECKS].sort());
  for (const label of VM_SYSTEMD_CHECKS) assert.equal(evidence.checks.filter((v) => v === label).length,
    ['real-service-readiness-before-consumer', 'explicit-disable-restores-owned-baseline'].includes(label) ? 2 : 1, label);
}
export function vmCases(selected = 'all') {
  if (selected === 'all') return ['none', ...VM_CUT_POINTS];
  if (selected === 'faults') return [...VM_FAULTS];
  if (selected === 'cycle') return ['none'];
  if (selected === 'systemd') return ['lifecycle'];
  assert.ok([...VM_CUT_POINTS, ...VM_FAULTS].includes(selected), 'unknown VM case');
  return [selected];
}
export function assertVmFaultEvidence(point, evidence) {
  assert.ok(VM_FAULTS.includes(point));
  assert.equal(evidence.point, point); assert.equal(evidence.status, 'passed');
  for (const key of ['dnsUnchangedOnFailure', 'noSettersOnFailure', 'blockedAfterFailure', 'explicitRecoveryPassed']) assert.equal(evidence[key], true, key);
  assert.equal(evidence.failure, ({ 'guard-unavailable': 'permission-denied', 'storage-readonly': 'EROFS',
    'corrupt-journal': 'SyntaxError', 'adapter-unready': 'readiness-failed' })[point]);
  if (point === 'guard-unavailable') {
    assert.equal(evidence.guardClaimedInstalledOnFailure, false); assert.equal(evidence.loopbackStayedDown, true);
    assert.equal(evidence.consumersStartedOnFailure, false);
  } else assert.equal(evidence.guardRetained, true);
  if (point === 'corrupt-journal') assert.equal(evidence.corruptBytesPreserved, true);
  if (point === 'adapter-unready') assert.equal(evidence.sameTransactionRecovered, true);
}
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
  assert.ok(['cycle', 'cut', 'inspect', 'fault', 'systemd'].includes(phase));
  assert.ok(phase === 'cycle' ? point === 'none' : phase === 'fault' ? VM_FAULTS.includes(point)
    : phase === 'systemd' ? point === 'lifecycle' : VM_CUT_POINTS.includes(point));
  return { phase, point };
}
export function qemuDnsArgs({ root, kernel, initrd, disk, phase, point }) {
  vmBootOptions(`meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`);
  for (const path of [root, kernel, initrd, disk]) assert.ok(path.startsWith('/') && !/[,\n\r\0]/.test(path));
  return ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none',
    // Only the parent may launch another boot; unexpected reboot/panic cannot hide a failed attempt.
    '-no-reboot',
    '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1',
    '-machine', 'pc,dump-guest-core=off', '-bios', `${root}/usr/share/seabios/bios-256k.bin`,
    '-L', `${root}/usr/share/qemu`, '-kernel', kernel, '-initrd', initrd,
    '-append', `console=ttyS0 quiet panic=-1 reboot=t random.trust_cpu=on meshpn_dns_vm=isolated-v1 meshpn_phase=${phase} meshpn_point=${point}`,
    '-drive', `file=${disk},format=raw,if=virtio,cache=writeback`];
}
