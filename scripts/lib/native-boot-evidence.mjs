import assert from 'node:assert/strict';
const peers = ['c2', 'c3', 'exit'];
const working = [...peers.flatMap(n => ['active-' + n, 'native-mainpid-' + n]),
  ...[2, 3].flatMap(n => ['tun-data-' + n, 'native-dns-' + n]), 'guard-active', 'guard-before-uplink'];
export const nativeBootChecks = [
  [...peers.map(n => 'installed-disabled-' + n), ...peers.map(n => 'not-started-by-installer-' + n), ...working],
  [...working, 'installed-bytes-survived-reboot'],
  ['guard-failed', 'uplink-not-active', ...peers.map(n => 'engine-not-started-' + n),
    ...[2, 3].flatMap(n => ['uplink-stays-down-' + n, 'no-default-' + n]), 'installed-bytes-preserved-on-failure'],
];
export function assertNativeBootEvidence(report) {
  assert.equal(report.nic, 'none'); assert.equal(report.hostSharedFilesystem, false);
  assert.equal(report.nativeOnly, true); assert.equal(report.boots?.length, 3);
  const ids = new Set();
  for (let phase = 0; phase < 3; phase++) {
    const boot = report.boots[phase]; assert.equal(boot.boot, phase); assert.equal(boot.code, 0);
    assert.ok(boot.events.every(e => e.phase === phase && ['prepared', 'check', 'reboot-ready', 'passed'].includes(e.event)));
    const prepared = boot.events.filter(e => e.event === 'prepared'); assert.equal(prepared.length, 1);
    assert.match(prepared[0].bootId, /^[a-f0-9-]{36}$/); ids.add(prepared[0].bootId);
    assert.deepEqual(boot.events.filter(e => e.event === 'check').map(e => e.name), nativeBootChecks[phase]);
    assert.equal(boot.events.at(-1).event, phase < 2 ? 'reboot-ready' : 'passed');
    assert.equal(boot.restarted, phase < 2); assert.equal(boot.poweredDown, phase === 2);
  }
  assert.equal(ids.size, 3);
}
