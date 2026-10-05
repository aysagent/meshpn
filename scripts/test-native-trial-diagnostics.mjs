import test from 'node:test';
import assert from 'node:assert/strict';
import { trialDiagnostics } from './lib/native-trial-diagnostics.mjs';

const event = state => ({ version: 1, event: 'state', state, generation: 1, tx_packets: 2, rx_packets: 3, dropped_packets: 4 });
test('session failure/closure reasons remain fixed metadata, not unknown', () => {
  const d = trialDiagnostics();
  for (const code of `h2_callback_failure h2_send_callback_failure h2_goaway_no_error h2_goaway_error
    h2_reset_no_error h2_reset_error h2_peer_end_stream h2_invalid_frame h2_stream_closed h2_stream_error
    tls_peer_closed h2_flooded h2_no_memory h2_bad_client_magic h2_local_goaway_error h2_local_reset_error
    invalid_frame_length invalid_ipv4 peer_address`.split(/\s+/)) assert.equal(d.state(event(code)), code);
});
test('TLS verification reasons survive diagnostic sanitization as fixed codes', () => {
  const d = trialDiagnostics();
  for (const code of ['tls_verify_name', 'tls_verify_expired', 'tls_verify_not_yet_valid', 'tls_verify_untrusted', 'tls_verify_failed']) {
    assert.equal(d.state(event(code)), code);
  }
  assert.equal(d.snapshot().events.length, 5);
});
test('only fixed vocabulary, counters and monotonic offsets enter diagnostics', () => {
  let now = 100; const d = trialDiagnostics(() => now); now = 125;
  assert.equal(d.state(event('handshake')), 'handshake');
  d.stderrLine('native-control: DNS guard/routes ready'); d.stderrLine('SECRET token=abcdef');
  d.stderrLine('SECRET native-control: DNS active');
  assert.equal(d.state(event('private_secret_text')), 'unknown');
  const s = d.snapshot();
  assert.equal(s.events[0].atMs, 25); assert.equal(s.lastState, 'unknown'); assert.equal(s.readySeen, false);
  assert.deepEqual(s.stages, [{ atMs: 25, stage: 'dns_guard_ready' }]);
  assert.doesNotMatch(JSON.stringify(s), /SECRET|abcdef|private_secret_text/);
});
test('state history is capped, snapshot immutable, readiness retained across stopped state', () => {
  const d = trialDiagnostics(); d.state(event('ready'));
  for (let i = 0; i < 100; i++) { d.state(event('connect_deadline')); d.stderrLine('native-control: DNS active'); }
  const before = d.snapshot(); d.state(event('stopped'));
  assert.equal(before.events.length, 48); assert.equal(before.omittedEvents, 53);
  assert.equal(before.lastState, 'connect_deadline'); assert.equal(before.readySeen, true);
  assert.equal(before.stages.length, 1); before.events[0].state = 'mutated';
  assert.equal(d.snapshot().lastState, 'stopped'); assert.ok(!JSON.stringify(d.snapshot()).includes('mutated'));
});
test('malformed status and unrecognized payload fields are rejected without echo', () => {
  for (const value of [null, [], {}, { ...event('ready'), secret: 'PRIVATE' }, { ...event('ready'), tx_packets: 'PRIVATE' },
    { ...event('ready'), rx_packets: -1 }, { ...event('ready'), generation: Infinity }, event('PRIVATE=key')]) {
    assert.throws(() => trialDiagnostics().state(value), /^Error: invalid_native_status$/);
  }
});
