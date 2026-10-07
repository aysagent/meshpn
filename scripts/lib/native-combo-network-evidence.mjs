import assert from 'node:assert/strict';
export const comboNetworkChecks = Object.freeze(['DIRECT_POSITIVE_CONTROL', 'GUARDS_REAL_TUN', 'HTTPS_TRANSPARENT_NOT_TUN',
  'CONCURRENT_TLS_TCP_UDP', 'NATIVE_DNS_HOST_LAN', 'DOUBLE_NAT', 'POLICY_NO_DOWNGRADE',
  'CLIENT_CRASH_DIRECT_ROUTE_BLOCKED', 'CLIENT_RESTART', 'EXIT_CRASH_BLOCKED', 'EXIT_RESTART', 'SELECTED_ORIGIN_NO_DIRECT_PACKETS']);
export function assertComboNetworkEvidence(evidence) {
  assert.equal(evidence?.status, 'passed');
  assert.deepEqual(evidence.checks, comboNetworkChecks);
  assert.equal(evidence.realTun, true); assert.equal(evidence.packetOwner, 'C++');
  assert.deepEqual(evidence.roles, ['client', 'exit']); assert.equal(evidence.namespaces, 5);
  assert.ok(Number.isInteger(evidence.positiveCapturePackets) && evidence.positiveCapturePackets > 0);
  assert.equal(evidence.directPacketsAfterGuard, 0);
  assert.equal(evidence.captureKernelDropped, 0);
  assert.equal(evidence.scope, 'runtime-static-routes-selected-IPv4-origin-not-installer-systemd-reboot-all-egress-or-benchmark');
}
