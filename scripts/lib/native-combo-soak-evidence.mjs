import assert from 'node:assert/strict';
// All payload/counter/resource evidence comes from the C++ fixture, not Node.
export function assertComboSoakEvidence(r, seconds) {
  assert.ok(Number.isInteger(seconds) && seconds >= 10 && seconds <= 600);
  assert.equal(r.requested_seconds, seconds);
  assert.ok(Number.isFinite(r.seconds) && r.seconds >= seconds && r.seconds < seconds + 30);
  assert.equal(r.payload_verified, true); assert.equal(r.unexpected_packet_reconnects, 0);
  assert.ok(Number.isInteger(r.packets) && r.packets > 200 && r.packets % 2 === 0);
  assert.equal(r.packet_bytes, r.packets * 1400);
  for (const k of ['tls12_sessions', 'tls13_hrr_sessions']) assert.ok(Number.isInteger(r[k]) && r[k] > 0);
  assert.equal(r.tls_echo_bytes_one_way, (r.tls12_sessions + r.tls13_hrr_sessions) * 1048576);
  assert.ok(Number.isInteger(r.resource_samples) && r.resource_samples >= Math.floor(seconds / 2));
  assert.deepEqual(Object.keys(r.roles).sort(), ['client', 'exit']);
  for (const role of Object.values(r.roles)) {
    assert.equal(role.tx_packets, r.packets / 2 + 1); assert.equal(role.rx_packets, role.tx_packets);
    assert.equal(role.dropped_packets, 0);
    for (const kind of ['fds', 'threads']) {
      assert.ok(Number.isInteger(role['baseline_' + kind]) && role['baseline_' + kind] > 0);
      assert.equal(role['idle_' + kind], role['baseline_' + kind]);
    }
    for (const [key, limit] of [['peak_rss_kib', 256 * 1024], ['peak_fds', 97], ['peak_threads', 49]])
      assert.ok(Number.isInteger(role[key]) && role[key] > 0 && role[key] < limit, key);
    assert.ok(Number.isInteger(role.warm_rss_growth_kib) && role.warm_rss_growth_kib >= 0 && role.warm_rss_growth_kib < 64 * 1024);
    assert.ok(Number.isFinite(role.cpu_seconds) && role.cpu_seconds >= 0);
  }
}
