import assert from 'node:assert/strict';
import { transparentBootChecks } from './native-transparent-vm-image.mjs';
export function assertTransparentBootEvidence(report) {
  assert.equal(report.nic, 'none'); assert.equal(report.hostSharedFilesystem, false);
  assert.equal(report.transparentBoot, true); assert.equal(report.transport, 'transparent-tls');
  assert.equal(report.systemdPid1, true); assert.equal(report.nativeDirectServices, true);
  assert.equal(report.realTun, false); assert.equal(report.code, 0);
  assert.equal(report.boots.length, 2);
  assert.equal(new Set(report.boots.map(b => b.bootId)).size, 2);
  for (const [i, boot] of report.boots.entries()) {
    assert.equal(boot.phase, i); assert.match(boot.bootId, /^[0-9a-f-]{36}$/);
    const required = transparentBootChecks[i].map(s => 'NATIVE_TRANSPARENT_' + s + '_PASS');
    assert.deepEqual(Object.keys(boot.checks).sort(), [...required].sort());
    for (const key of required) assert.equal(boot.checks[key], true, key);
  }
}
