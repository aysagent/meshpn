import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { comboNetworkChecks, assertComboNetworkEvidence } from './lib/native-combo-network-evidence.mjs';
test('combo real-TUN VM driver refuses development host before network writes', () => {
  for (const args of [[], ['--load'], ['--benchmark'], ['--unexpected']]) {
    const r = spawnSync(process.execPath, ['scripts/lib/native-combo-network-vm.mjs', ...args], { encoding: 'utf8', timeout: 5000 });
    assert.notEqual(r.status, 0); assert.match(r.stderr, /QEMU|meshpn.native-combo-network|ENOENT/);
  }
});
test('combo acceptance needs every gate and a nonzero direct capture control', () => {
  assertComboNetworkEvidence(JSON.parse(fs.readFileSync(new URL('./fixtures/clean-vpn-native-combo-network-report.json', import.meta.url))).evidence);
  const good = { status: 'passed', checks: [...comboNetworkChecks], realTun: true, packetOwner: 'C++', roles: ['client', 'exit'], namespaces: 5,
    positiveCapturePackets: 20, directPacketsAfterGuard: 0, captureKernelDropped: 0, scope: 'runtime-static-routes-selected-IPv4-origin-not-installer-systemd-reboot-all-egress-or-benchmark' };
  assertComboNetworkEvidence(good);
  for (const patch of [{ checks: good.checks.slice(1) }, { checks: [...good.checks.slice(1), good.checks[1]] },
    { realTun: false }, { roles: ['client'] }, { positiveCapturePackets: 0 }, { directPacketsAfterGuard: 1 }, { captureKernelDropped: 1 }, { scope: 'all-egress' }])
    assert.throws(() => assertComboNetworkEvidence({ ...good, ...patch }));
});
