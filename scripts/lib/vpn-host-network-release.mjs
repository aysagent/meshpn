/** Pure VM candidate predicate: no network mutation or implicit repair. */
import assert from 'node:assert/strict';

export function assertManagedNetworkStopped(expected, rows, manager) {
  assert.deepEqual(Object.keys(expected).sort(), ['address', 'ifindex', 'ifname']);
  assert.match(expected.ifname, /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/);
  assert.notEqual(expected.ifname, 'lo');
  assert.ok(Number.isSafeInteger(expected.ifindex) && expected.ifindex > 0);
  assert.match(expected.address, /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/);
  assert.ok(['inactive', 'failed'].includes(manager.state), 'network manager has not stopped');
  assert.equal(manager.pid, '0', 'network manager PID remains');
  assert.ok(Array.isArray(rows) && rows.length > 0 && rows.length <= 64);
  assert.equal(new Set(rows.map(r => r.ifname)).size, rows.length);
  const row = rows.find(r => r.ifname === expected.ifname);
  assert.ok(row, 'managed link missing: identity needs review');
  for (const key of ['ifname', 'ifindex', 'address']) assert.equal(row[key], expected[key], 'managed link identity changed');
  for (const link of rows) {
    assert.ok(Array.isArray(link.flags) && link.flags.every(f => typeof f === 'string'));
    if (link.ifname !== 'lo') assert.ok(!link.flags.includes('UP'), 'network link still UP; guard retained');
  }
}
