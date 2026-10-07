import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assertComboSoakEvidence } from './lib/native-combo-soak-evidence.mjs';
test('combo soak evidence refuses incomplete, lossy, reconnected or unbounded runs', () => {
  const recorded = JSON.parse(readFileSync(new URL('./fixtures/clean-vpn-native-combo-soak-report.json', import.meta.url)));
  assertComboSoakEvidence(recorded.normal, 180);
  assertComboSoakEvidence(recorded.asanUbsan, 30);
  const role = { tx_packets: 201, rx_packets: 201, dropped_packets: 0, peak_rss_kib: 8192,
    baseline_fds: 7, idle_fds: 7, baseline_threads: 2, idle_threads: 2,
    peak_fds: 12, peak_threads: 4, warm_rss_growth_kib: 256, cpu_seconds: 1.5 };
  const good = { seconds: 10.5, requested_seconds: 10, packets: 400, packet_bytes: 560000,
    tls12_sessions: 2, tls13_hrr_sessions: 2, tls_echo_bytes_one_way: 4 * 1048576,
    payload_verified: true, unexpected_packet_reconnects: 0, resource_samples: 10,
    roles: { client: role, exit: { ...role } } };
  assertComboSoakEvidence(good, 10);
  for (const mutate of [r => { r.seconds = 9; }, r => { r.payload_verified = false; },
    r => { r.unexpected_packet_reconnects = 1; }, r => { r.roles.exit.dropped_packets = 1; },
    r => { r.roles.client.rx_packets--; }, r => { r.roles.exit.peak_fds = 97; },
    r => { r.roles.exit.peak_threads = 49; }, r => { r.roles.exit.peak_rss_kib = 262144; },
    r => { r.roles.exit.warm_rss_growth_kib = 65536; }, r => { r.resource_samples = 4; },
    r => { r.tls13_hrr_sessions = 0; }, r => { r.packet_bytes++; },
    r => { r.roles.client.cpu_seconds = NaN; }, r => { delete r.roles.exit; }]) {
    const bad = structuredClone(good); mutate(bad); assert.throws(() => assertComboSoakEvidence(bad, 10));
  }
  for (const key of ['idle_fds', 'idle_threads']) {
    const bad = structuredClone(good); bad.roles.exit[key]++; assert.throws(() => assertComboSoakEvidence(bad, 10));
  }
});
