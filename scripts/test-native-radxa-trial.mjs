import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { deriveTrialConfig, summarizeTrialProbe, runTrial } from './lib/native-radxa-trial.mjs';
import { launchTrialNative } from './clean-vpn-native-trial.mjs';

const root = '/root/dev/meshpn';
const base = ['/usr/bin/node', root + '/scripts/clean-vpn.js', '--role=client', '--type=tls',
  '--server=154.62.226.216:443', '--split-default', '--dns-usb=1'];
const derive = (args = [], files = ['ca.pem', 'clean-vpn-hmac.key']) => deriveTrialConfig([...base, ...args], {
  cwd: root, root, exists: p => files.some(f => p === root + '/certs/' + f) });

test('derive effective default CA/key/names from running argv, default tunnel DNS', () => {
  assert.deepEqual(derive(), { version: 1, role: 'client', address: '154.62.226.216', port: 443,
    tun: 'tun0', ca: root + '/certs/ca.pem', secret_path: root + '/certs/clean-vpn-hmac.key',
    server_name: 'clean-vpn', sni: 'www.google.com', dns: true });
  assert.equal(derive(['--tls-client-sni=www.trustpilot.com']).sni, 'www.trustpilot.com');
  assert.equal(derive(['--tls-server-name=www.google.com']).server_name, 'clean-vpn');
});
test('fullchain, public name, explicit name, legacy key and relative paths match old precedence', () => {
  assert.equal(derive(['--tls-public-name=vpn.example,backup.example'], ['fullchain.pem', 'clean-vpn-hmac.key']).server_name, 'vpn.example');
  assert.equal(derive(['--tls-public-name=vpn.example']).server_name, 'clean-vpn');
  assert.equal(derive([], ['ca.pem', 'quic-ext-hmac.key']).secret_path, root + '/certs/quic-ext-hmac.key');
  assert.equal(derive(['--shared-hmac-key=certs/custom'], ['ca.pem', 'custom']).secret_path, root + '/certs/custom');
  assert.equal(derive(['--tls-server-name=other.example', '--tls-client-sni=decoy.example']).server_name, 'other.example');
});
for (const args of [['--dns-mode=off'], ['--dns-state-dir=/run/custom'], ['--dns-server=8.8.8.8'],
  ['--http-vers=1.1'], ['--ipv6=auto'], ['--from-tun=wg0'], ['--role=exit'], ['--type=combo-tls'],
  ['--tls-server-name=bad name'], ['--server=other:443'], ['--dns-usb=0']]) {
  test(`unsupported/duplicate configuration refused: ${args[0].split('=')[0]}`, () => assert.throws(() => derive(args)));
}
test('missing key is not generated and shell-looking values are never executed', () => {
  assert.throws(() => derive([], ['ca.pem']), /existing_credentials_missing/);
  assert.throws(() => derive(['--tls-client-sni=$(id)']), /invalid_tls_name/);
});
test('compact report excludes tool output and arbitrary response bodies', () => {
  const r = summarizeTrialProbe({ status: 'ipv4-smoke-passed', commands: { stdout: 'PRIVATE' },
    probes: { nss: { status: 'passed' }, egress: { status: 'passed', observedExitIp: '154.62.226.216', seconds: 0.5, body: 'PRIVATE' },
      dns: [{ status: 'passed' }] } }, 0);
  assert.equal(r.dnsPassed, 1); assert.equal(r.httpsPassed, 1); assert.ok(!JSON.stringify(r).includes('PRIVATE'));
});

function fixture({ fail, baseline = 'ipv4-smoke-passed', native = 'ipv4-smoke-passed', restored = 'ipv4-smoke-passed' } = {}) {
  const events = []; let probe = 0, audit = 0;
  const event = async name => { events.push(name); if (fail === name) throw Error('injected_failure'); };
  const io = Object.fromEntries(['preflight', 'beforeStop', 'stopOld', 'requireNoTun', 'configureTun', 'requireOldInactive',
    'startOld', 'waitOld', 'verifyGuard'].map(name => [name, () => event(name)]));
  io.auditReleased = () => event(`audit${++audit}`);
  io.createTun = async () => { await event('createTun'); return 17; };
  io.removeTun = async index => { assert.equal(index, 17); await event('removeTun'); };
  io.probe = async () => { await event(`probe${++probe}`); return { status: [baseline, native, restored][probe - 1] }; };
  io.launch = async () => { await event('launch'); return { ready: () => event('ready'), stop: () => event('stop-native') }; };
  io.hold = () => event('hold');
  return { events, io };
}
test('success: old/native/restored probes; stop native and audit before removing TUN and starting old', async () => {
  const f = fixture(); const r = await runTrial(f.io);
  assert.equal(r.status, 'passed'); assert.equal(r.rollback, 'verified');
  assert.deepEqual(f.events, ['preflight', 'probe1', 'beforeStop', 'stopOld', 'audit1', 'requireNoTun', 'createTun',
    'configureTun', 'launch', 'ready', 'probe2', 'hold', 'stop-native', 'requireOldInactive', 'audit2', 'removeTun',
    'requireNoTun', 'startOld', 'waitOld', 'probe3', 'verifyGuard']);
});
for (const fail of ['preflight', 'probe1', 'beforeStop']) {
  test(`${fail} failure never stops the working service`, async () => {
    const f = fixture({ fail }), r = await runTrial(f.io);
    assert.equal(r.status, 'failed'); assert.equal(r.rollback, 'not-needed');
    assert.ok(!f.events.includes('stopOld')); assert.ok(!f.events.includes('startOld'));
  });
}
test('bad baseline aborts before disruption', async () => {
  const f = fixture({ baseline: 'incomplete-or-failed' }), r = await runTrial(f.io);
  assert.equal(r.failure.code, 'baseline_failed'); assert.ok(!f.events.includes('stopOld'));
});
for (const fail of ['ready', 'probe2', 'hold']) {
  test(`${fail} failure still attempts ordered rollback`, async () => {
    const f = fixture({ fail }), r = await runTrial(f.io);
    assert.equal(r.status, 'failed'); assert.ok(f.events.includes('stop-native'));
    assert.ok(f.events.indexOf('stop-native') < f.events.indexOf('startOld'));
  });
}
test('configuration failure removes unused owned TUN before auditing old journal identities', async () => {
  const f = fixture({ fail: 'configureTun' }), r = await runTrial(f.io);
  assert.ok(f.events.indexOf('removeTun') < f.events.indexOf('audit2'));
  assert.ok(f.events.includes('startOld')); assert.equal(r.status, 'failed');
});
for (const fail of ['stop-native', 'requireOldInactive', 'audit2', 'removeTun']) {
  test(`${fail} failure refuses blind legacy restart, retains guard`, async () => {
    const f = fixture({ fail }), r = await runTrial(f.io);
    assert.equal(r.rollback, 'manual-review-required');
    assert.ok(!f.events.includes('startOld')); assert.equal(f.events.at(-1), 'verifyGuard');
  });
}
test('signal during native check cancels test but does not cancel rollback', async () => {
  const f = fixture(); let cancel = false;
  const r = await runTrial(f.io, { cancelled: () => cancel, progress: stage => { if (stage === 'native-client-check') cancel = true; } });
  assert.equal(r.failure.code, 'cancelled'); assert.ok(f.events.includes('startOld'));
});
test('restored service with failing smoke is not reported as verified rollback', async () => {
  const f = fixture({ restored: 'incomplete-or-failed' }), r = await runTrial(f.io);
  assert.equal(r.status, 'failed'); assert.equal(r.rollback, 'service-restored');
  assert.equal(r.rollbackFailure.code, 'restored_smoke_failed');
});
test('arbitrary exception text and credentials do not escape into report', async () => {
  const f = fixture(); f.io.preflight = () => { throw Error('secret=NEVER_PRINT_THIS'); };
  const r = await runTrial(f.io); assert.ok(!JSON.stringify(r).includes('NEVER_PRINT_THIS'));
});

test('real child pipe stays open, detached from terminal; stop is JSON, never group SIGINT', async () => {
  let child;
  const session = launchTrialNative('/private/config.json', { spawnChild(file, args, options) {
    assert.equal(options.detached, true); assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
    child = spawn(process.execPath, ['-e', `
      process.stdout.write('{"state":"ready"}\\n');
      process.stderr.write('native-control: DNS active\\n');
      process.stdin.on('data', b => { if (b.toString() === '{"op":"stop"}\\n') process.exit(0); else process.exit(2); });
    `], options);
    return child;
  }, readyMs: 5000, stopMs: 5000 });
  try { await session.ready(() => false); assert.equal(session.healthy(), true); assert.equal((await session.stop()).code, 0); }
  finally { child.kill('SIGKILL'); }
});
test('native exit before readiness fails promptly instead of reporting success', async () => {
  const s = launchTrialNative('/private/config.json', { spawnChild: (file, args, options) => spawn(process.execPath, ['-e', 'process.exit(1)'], options), readyMs: 5000 });
  await assert.rejects(s.ready(() => false), /native_start_failed/); await s.stop();
});

test('build failure stops chain; legacy dependency directory and services never touched', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-native-build-test-'));
  try {
    fs.mkdirSync(path.join(dir, 'scripts')); fs.mkdirSync(path.join(dir, 'bin'));
    fs.copyFileSync(new URL('./build-clean-vpn-native.sh', import.meta.url), path.join(dir, 'scripts/build.sh'));
    fs.writeFileSync(path.join(dir, 'bin/cmake'), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CV_CALLS"\nexit 23\n', { mode: 0o755 });
    const r = spawnSync('bash', [path.join(dir, 'scripts/build.sh')], {
      env: { ...process.env, PATH: path.join(dir, 'bin') + ':' + process.env.PATH, CV_CALLS: path.join(dir, 'calls') }, encoding: 'utf8' });
    assert.equal(r.status, 1); assert.match(r.stderr, /NATIVE_BUILD=failed/);
    const calls = fs.readFileSync(path.join(dir, 'calls'), 'utf8').trim().split('\n');
    assert.equal(calls.length, 1); assert.match(calls[0], /-B native\/clean_vpn\/build-deps-helper/);
    assert.ok(!fs.existsSync(path.join(dir, 'native/boring_tls/build')));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('transient unit contracts: bounded, SSH-independent, no enable/reboot/flush/mask', () => {
  const code = fs.readFileSync(new URL('./clean-vpn-native-trial.mjs', import.meta.url), 'utf8');
  assert.match(code, /--property=KillMode=mixed/); assert.match(code, /--property=RuntimeMaxSec=1500/);
  assert.match(code, /worker_requires_transient_unit/); assert.match(code, /usb_rescue_connection_not_found/);
  assert.doesNotMatch(code, /\['(?:enable|disable|mask|reboot)'/);
  assert.doesNotMatch(code, /iptables.*(?:-F|--flush)/);
});
