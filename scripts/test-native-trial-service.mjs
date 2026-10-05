import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { stableExecStart, trialServiceFingerprint } from './lib/native-trial-service.mjs';
import { runTrial } from './lib/native-radxa-trial.mjs';

const running = () => ({ type: 'a(sasbttttuii)', data: [
  ['/usr/local/bin/clean-vpn-run.sh', ['/usr/local/bin/clean-vpn-run.sh'], false, 1791234000000000, 1000000, 0, 0, 1178, 0, 0],
] });
function fixture() {
  const data = { exec: running(), wrapper: 'original wrapper', source: 'original source', unit: '# unit\nExecStart=/usr/local/bin/clean-vpn-run.sh',
    effective: 'FragmentPath=/etc/systemd/system/clean-vpn.service\nEnvironment=SECRET=not-printed', reload: 'no' };
  const calls = [];
  const io = { root: '/repo', readFile: file => file.endsWith('clean-vpn.js') ? data.source : data.wrapper,
    async run(file, args) {
      calls.push([file, args]);
      if (file === 'busctl') return JSON.stringify(args.includes('GetUnit')
        ? { type: 'o', data: ['/org/freedesktop/systemd1/unit/clean_2dvpn_2eservice'] } : data.exec);
      if (args[0] === 'cat') return data.unit;
      return args.includes('--property=NeedDaemonReload') ? data.reload : data.effective;
    } };
  return { data, calls, io };
}
const exited = f => { Object.assign(f.data.exec.data[0], { 5: 1791234010000000, 6: 11000000, 7: 0, 8: 1, 9: 0 }); };

test('normal systemd exit timestamps, PID and result do not change configuration fingerprint', async () => {
  const f = fixture(), before = await trialServiceFingerprint(f.io);
  exited(f);
  assert.equal(await trialServiceFingerprint(f.io), before);
  assert.match(before, /^[a-f0-9]{64}$/); assert.ok(!before.includes('SECRET'));
  assert.ok(!f.calls.some(([file, args]) => file === 'systemctl' && args.some(a => a.includes('ExecStart'))));
});
for (const [name, change] of Object.entries({
  executable: f => { f.data.exec.data[0][0] = '/different'; },
  arguments: f => { f.data.exec.data[0][1].push(' ; stop_time=ignored ; PRIVATE'); },
  ignoreFailure: f => { f.data.exec.data[0][2] = true; },
  wrapper: f => { f.data.wrapper += 'changed'; },
  source: f => { f.data.source += 'changed'; },
  unit: f => { f.data.unit += '\nRestart=no'; },
  dropin: f => { f.data.unit += '\n# drop-in\n[Service]\nEnvironment=CHANGED=1'; },
  effectiveEnvironment: f => { f.data.effective += '\nEnvironment=CHANGED=1'; },
})) test(`fingerprint still detects changed ${name}`, async () => {
  const f = fixture(), before = await trialServiceFingerprint(f.io); change(f);
  assert.notEqual(await trialServiceFingerprint(f.io), before);
});
test('unit pending daemon-reload is refused, never automatically reloaded', async () => {
  const f = fixture(); f.data.reload = 'yes';
  await assert.rejects(trialServiceFingerprint(f.io), /legacy_unit_needs_daemon_reload/);
  assert.ok(!f.calls.some(([, args]) => args.includes('daemon-reload')));
});
test('missing bus/invalid schema refuses preflight without dumping arguments', async () => {
  for (const value of [null, {}, { type: 's', data: [] }, { ...running(), data: [] },
    { ...running(), data: [['/bin/PRIVATE', ['PRIVATE'], false]] }]) {
    assert.throws(() => stableExecStart(value), /^Error: invalid_service_configuration_snapshot$/);
  }
  const f = fixture(); f.io.run = async () => { throw Error('command_busctl_failed'); };
  await assert.rejects(trialServiceFingerprint(f.io), /command_busctl_failed/);
});
test('native-ready timeout returns to old after ordinary stop; real unit edits still block rollback', async () => {
  for (const changed of [false, true]) {
    const f = fixture(), initial = await trialServiceFingerprint(f.io); let started = false;
    const noOp = async () => {};
    const io = Object.fromEntries(['preflight', 'beforeStop', 'auditReleased', 'auditIpv6Released', 'requireNoTun',
      'requireOldInactive', 'configureTun', 'removeTun', 'waitOld', 'verifyGuard'].map(k => [k, noOp]));
    Object.assign(io, { probe: async () => ({ status: 'ipv4-smoke-passed' }), createTun: async () => 2,
      stopOld: async () => { exited(f); if (changed) f.data.unit += '\nChanged'; },
      launch: async () => ({ ready() { throw Error('native_ready_timeout'); }, stop: noOp }),
      startOld: async () => {
        if (await trialServiceFingerprint(f.io) !== initial) throw Error('legacy_source_or_unit_changed');
        started = true;
      } });
    const result = await runTrial(io);
    assert.equal(result.failure.code, 'native_ready_timeout'); assert.equal(started, !changed);
    assert.equal(result.rollback, changed ? 'manual-review-required' : 'verified');
  }
});
test('real systemd ExecStart D-Bus JSON is accepted (read-only, no services changed)', t => {
  const r = spawnSync('busctl', ['--system', '--json=short', 'get-property', 'org.freedesktop.systemd1',
    '/org/freedesktop/systemd1/unit/dbus_2eservice', 'org.freedesktop.systemd1.Service', 'ExecStart'], { encoding: 'utf8', timeout: 5000 });
  if (r.status !== 0) return t.skip('system bus/dbus.service unavailable');
  const stable = stableExecStart(JSON.parse(r.stdout));
  assert.ok(stable.length > 0); assert.deepEqual(Object.keys(stable[0]), ['path', 'argv', 'ignoreFailure']);
});
