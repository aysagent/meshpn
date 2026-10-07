import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { addComboBootImage, comboBootChecks } from './lib/native-combo-boot-image.mjs';
import { assertComboBootEvidence } from './lib/native-combo-boot-evidence.mjs';
test('combo boot driver refuses development host before any action', () => {
  for (const mode of ['prepare', 'network', 'defaults', 'run']) {
    const r = spawnSync(process.execPath, ['scripts/lib/native-combo-boot-vm.mjs', mode], { encoding: 'utf8', timeout: 3000 });
    assert.notEqual(r.status, 0); assert.ok(!r.error);
  }
});
test('combo boot fixtures bind nested engines, isolate default-route owners and preserve observer lifetime', () => {
  const files = new Map(); addComboBootImage((name, body, mode) => files.set(name, { body, mode }));
  for (const name of ['coclient', 'coexit']) {
    const c = JSON.parse(files.get(`/native/${name}.json`).body), site = JSON.parse(files.get(`/native/${name}-site.json`).body);
    assert.equal(c.transport, 'combo-tls'); assert.equal(site.profile.transport, 'combo-tls');
    assert.equal(c.boring.port, c.transparent.exit?.port ?? c.transparent.listen.port);
    assert.notEqual(c.boring.secret_path ?? c.boring.peers[0].secret_path, c.transparent.secret_path);
    const defaults = files.get(`/etc/systemd/system/native-${name}-defaults.service`).body;
    assert.match(defaults, new RegExp(`After=native-${name}-uplink.service`));
    assert.ok(!defaults.includes(name === 'coclient' ? 'native-coexit' : 'native-coclient'));
  }
  assert.ok(!files.get('/etc/systemd/system/native-co-driver.service').body.includes('Requires=native-coclient'));
});
test('combo boot evidence requires real TUN, two distinct boots and all gates', () => {
  assertComboBootEvidence(JSON.parse(readFileSync(new URL('./fixtures/clean-vpn-native-combo-boot-report.json', import.meta.url))));
  const good = () => ({ nic: 'none', hostSharedFilesystem: false, comboBoot: true, transport: 'combo-tls',
    systemdPid1: true, nativeDirectServices: true, realTun: true, code: 0,
    boots: comboBootChecks.map((checks, phase) => ({ phase, bootId: `00000000-0000-0000-0000-00000000000${phase}`,
      checks: Object.fromEntries(checks.map(k => ['NATIVE_COMBO_' + k + '_PASS', true])) })) });
  assertComboBootEvidence(good());
  for (const alter of [r => { r.boots.pop(); }, r => { r.boots[1].bootId = r.boots[0].bootId; }, r => { r.realTun = false; },
    r => { r.nic = 'user'; }, r => { r.code = 1; }, r => { delete r.boots[1].checks.NATIVE_COMBO_REBOOT_TUN_DNS_PASS; },
    r => { r.boots[1].checks.NATIVE_COMBO_MISSING_REPLAY_REFUSED_PASS = false; }]) {
    const r = good(); alter(r); assert.throws(() => assertComboBootEvidence(r));
  }
});
