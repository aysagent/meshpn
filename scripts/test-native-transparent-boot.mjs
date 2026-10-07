import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { copyVmTree } from './lib/native-vm-copy-tree.mjs';
import { addTransparentBootImage, transparentBootChecks } from './lib/native-transparent-vm-image.mjs';
import { assertTransparentBootEvidence } from './lib/native-transparent-boot-evidence.mjs';
test('transparent VM driver refuses all actions outside dedicated QEMU before writes', () => {
  for (const mode of ['prepare', 'network', 'defaults', 'run']) {
    const r = spawnSync(process.execPath, ['scripts/lib/native-transparent-boot-vm.mjs', mode], { encoding: 'utf8', timeout: 3000 });
    assert.notEqual(r.status, 0); assert.ok(!r.error);
  }
});
test('transparent VM fixtures separate DOWN link provisioning and protected route setup', () => {
  const files = new Map(); addTransparentBootImage((name, body, mode) => files.set(name, { body, mode }));
  assert.match(files.get('/etc/systemd/system/native-tr-defaults.service').body, /After=native-trclient-uplink.service native-trexit-uplink.service/);
  assert.match(files.get('/etc/systemd/system/default.target').body, /multi-user.target native-tr-driver.service/);
  assert.ok(!files.get('/etc/systemd/system/native-tr-driver.service').body.includes('Requires=native-trclient'));
  for (const name of ['trclient', 'trexit']) {
    const c = JSON.parse(files.get('/native/' + name + '.json').body);
    assert.equal(c.transport, 'transparent-tls'); assert.equal(files.get('/native/' + name + '.json').mode, 0o600);
  }
});
const good = () => ({ nic: 'none', hostSharedFilesystem: false, transparentBoot: true, transport: 'transparent-tls',
  systemdPid1: true, nativeDirectServices: true, realTun: false, code: 0,
  boots: transparentBootChecks.map((checks, phase) => ({ phase, bootId: `00000000-0000-0000-0000-00000000000${phase}`,
    checks: Object.fromEntries(checks.map(k => ['NATIVE_TRANSPARENT_' + k + '_PASS', true])) })) });
test('VM persistence preserves private replay directories across both copies, without following symlinks', t => {
  const base = fs.mkdtempSync('/tmp/transparent-vm-copy-');
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  fs.mkdirSync(base + '/source/replay', { recursive: true, mode: 0o700 });
  fs.writeFileSync(base + '/source/replay/state', 'fixture', { mode: 0o600 });
  fs.symlinkSync('/not-a-real-path', base + '/source/unit-link');
  copyVmTree(base + '/source', base + '/disk'); copyVmTree(base + '/disk', base + '/restored');
  for (const name of ['disk', 'restored']) {
    assert.equal(fs.statSync(base + '/' + name + '/replay').mode & 0o7777, 0o700);
    assert.equal(fs.statSync(base + '/' + name + '/replay/state').mode & 0o7777, 0o600);
    assert.equal(fs.readlinkSync(base + '/' + name + '/unit-link'), '/not-a-real-path');
    assert.equal(fs.readFileSync(base + '/' + name + '/replay/state', 'utf8'), 'fixture');
  }
});
test('transparent evidence requires both boots, distinct IDs, exact gates and no host NIC', () => {
  assertTransparentBootEvidence(good());
  assertTransparentBootEvidence(JSON.parse(fs.readFileSync(new URL('./fixtures/clean-vpn-native-transparent-boot-report.json', import.meta.url))));
  for (const alter of [r => { r.boots.pop(); }, r => { r.boots[1].bootId = r.boots[0].bootId; },
    r => { r.nic = 'user'; }, r => { r.systemdPid1 = false; }, r => { r.code = 1; },
    r => { r.boots[1].checks.NATIVE_TRANSPARENT_REBOOT_REPLAY_BYTES_PASS = false; },
    r => { delete r.boots[1].checks.NATIVE_TRANSPARENT_MISSING_REPLAY_REFUSED_PASS; }]) {
    const r = good(); alter(r); assert.throws(() => assertTransparentBootEvidence(r));
  }
});
