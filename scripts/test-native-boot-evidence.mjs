import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeBootChecks, assertNativeBootEvidence } from './lib/native-boot-evidence.mjs';
const fixture = () => ({ nic: 'none', hostSharedFilesystem: false, nativeOnly: true,
  boots: nativeBootChecks.map((checks, phase) => ({ boot: phase, code: 0, restarted: phase < 2, poweredDown: phase === 2,
    events: [{ phase, event: 'prepared', bootId: `${phase}1111111-1111-4111-8111-111111111111` },
      ...checks.map(name => ({ phase, event: 'check', name })), { phase, event: phase < 2 ? 'reboot-ready' : 'passed' }] })) });
test('native cold-boot evidence requires all gates and distinct actual boots', () => {
  assertNativeBootEvidence(fixture());
  for (const mutate of [r => r.boots.pop(), r => r.boots[0].events.splice(2, 1),
    r => r.boots[2].events[1].name = 'other', r => r.boots[1].events[0].bootId = r.boots[0].events[0].bootId,
    r => r.boots[2].poweredDown = false, r => r.nic = 'user', r => r.hostSharedFilesystem = true,
    r => r.boots[0].events.push({ phase: 0, event: 'failed' })]) {
    const report = fixture(); mutate(report); assert.throws(() => assertNativeBootEvidence(report));
  }
});
