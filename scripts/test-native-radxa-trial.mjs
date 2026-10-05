import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { deriveTrialConfig, summarizeTrialProbe, hasUsbRescueConnection, runTrial } from './lib/native-radxa-trial.mjs';
import { launchTrialNative } from './clean-vpn-native-trial.mjs';

const root = '/root/dev/meshpn';
const base = ['/usr/bin/node', root + '/scripts/clean-vpn.js', '--role=client', '--type=tls',
  '--server=154.62.226.216:443', '--split-default', '--dns-usb=1'];
const derive = (args = [], files = ['ca.pem', 'clean-vpn-hmac.key']) => deriveTrialConfig([...base, ...args], {
  cwd: root, root, exists: p => files.some(f => p === root + '/certs/' + f) });

const ssh = ['192.168.7.19', '63208', '192.168.7.1', '2222'];
test('rescue matcher accepts ss device scope, plain endpoints, and optional ESTAB column', () => {
  for (const local of ['192.168.7.1:2222', '192.168.7.1%usb0:2222']) {
    for (const prefix of ['', 'ESTAB ']) {
      assert.equal(hasUsbRescueConnection(`${prefix}0 0 ${local} 192.168.7.19:63208\n`, ssh), true);
    }
  }
});
test('rescue matcher requires exact same-row endpoint tuple and rejects foreign scopes/states', () => {
  const valid = '0 0 192.168.7.1%usb0:2222 192.168.7.19:63208';
  for (const row of ['', valid.replace('%usb0', '%wlan0'), valid.replace('%usb0', '%usb00'),
    valid.replace(':2222', ':22220'), valid.replace(':63208', ':63209'), valid.replace(':63208', ':632080'),
    valid.replace('192.168.7.19:', '192.168.7.119:'), valid.replace('192.168.7.1%', '192.168.7.11%'),
    'LISTEN ' + valid, 'CLOSE-WAIT ' + valid, valid + ' extra',
    valid.replace('192.168.7.19', '192.168.7.119') + '\n' + valid.replace(':2222', ':22'),
    '0 0 192.168.7.19:63208 192.168.7.1%usb0:2222']) {
    assert.equal(hasUsbRescueConnection(row, ssh), false, row);
  }
  assert.equal(hasUsbRescueConnection(valid, ['192.168.7.19', '63208', '192.168.7.1', '22']), false);
  assert.equal(hasUsbRescueConnection(valid, ['192.168.7.999', '63208', '192.168.7.1', '2222']), false);
});
test('real bound-device TCP socket produces %usb0 and matches rescue tuple in isolated netns', t => {
  if (process.platform !== 'linux') return t.skip('Linux network namespace required');
  const available = spawnSync('unshare', ['--user', '--map-root-user', '--net', 'true'], { timeout: 5000 });
  if (available.status !== 0) return t.skip('unprivileged network namespaces unavailable');
  for (const file of ['ip', 'ss', 'python3']) {
    if (spawnSync(file, [file === 'ip' ? '-Version' : '--version'], { timeout: 5000 }).status !== 0)
      return t.skip(`${file} unavailable`);
  }
  const r = spawnSync('unshare', ['--user', '--map-root-user', '--net', 'python3', '-c', `
import json, socket, subprocess
for args in [['link', 'set', 'lo', 'name', 'usb0'], ['link', 'set', 'usb0', 'up'],
             ['addr', 'add', '192.168.7.1/24', 'dev', 'usb0'], ['addr', 'add', '192.168.7.19/24', 'dev', 'usb0']]:
    subprocess.run(['ip'] + args, check=True)
listener = socket.socket()
listener.settimeout(3)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'usb0\\0')
listener.bind(('192.168.7.1', 2222))
listener.listen()
client = socket.socket()
client.settimeout(3)
client.bind(('192.168.7.19', 0))
client.connect(('192.168.7.1', 2222))
accepted, peer = listener.accept()
rows = subprocess.run(['ss', '-4Htn', 'state', 'established', '( sport = :2222 )'],
                      check=True, text=True, capture_output=True).stdout
print(json.dumps({'rows': rows, 'ssh': [peer[0], str(peer[1]), '192.168.7.1', '2222']}))
`], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 0, r.stderr);
  const actual = JSON.parse(r.stdout);
  assert.match(actual.rows, /192\.168\.7\.1%usb0:2222/);
  assert.equal(actual.rows.includes('192.168.7.1:2222'), false, 'old substring check fails');
  assert.equal(hasUsbRescueConnection(actual.rows, actual.ssh), true);
});

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
  const events = []; let probe = 0, audit = 0, ipv6Audit = 0;
  const event = async name => { events.push(name); if (fail === name) throw Error('injected_failure'); };
  const io = Object.fromEntries(['preflight', 'beforeStop', 'stopOld', 'requireNoTun', 'configureTun', 'requireOldInactive',
    'startOld', 'waitOld', 'verifyGuard'].map(name => [name, () => event(name)]));
  io.auditReleased = () => event(`audit${++audit}`);
  io.auditIpv6Released = () => event(`ipv6Audit${++ipv6Audit}`);
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
  assert.deepEqual(f.events, ['preflight', 'probe1', 'beforeStop', 'stopOld', 'audit1', 'requireNoTun', 'ipv6Audit1', 'createTun',
    'configureTun', 'launch', 'ready', 'probe2', 'hold', 'stop-native', 'requireOldInactive', 'audit2', 'removeTun',
    'requireNoTun', 'ipv6Audit2', 'startOld', 'waitOld', 'probe3', 'verifyGuard']);
});
test('started legacy service is not called verified when readiness times out', async () => {
  const f = fixture({ fail: 'waitOld' }), r = await runTrial(f.io);
  assert.equal(r.status, 'failed'); assert.equal(r.rollback, 'service-restored');
  assert.equal(r.rollbackFailure.stage, 'old-ready'); assert.ok(!f.events.includes('probe3'));
});
test('successful readiness metadata is retained before the independent restored smoke', async () => {
  const f = fixture();
  f.io.waitOld = async () => ({ status: 'ready', attempts: 4, consecutive: 2, seconds: 3 });
  const r = await runTrial(f.io);
  assert.equal(r.restorationReadiness.attempts, 4); assert.equal(r.rollback, 'verified');
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
for (const fail of ['stop-native', 'requireOldInactive', 'audit2', 'removeTun', 'ipv6Audit2']) {
  test(`${fail} failure refuses blind legacy restart, retains guard`, async () => {
    const f = fixture({ fail }), r = await runTrial(f.io);
    assert.equal(r.rollback, 'manual-review-required');
    assert.ok(!f.events.includes('startOld')); assert.equal(f.events.at(-1), 'verifyGuard');
  });
}
test('unreleased IPv6 aborts before creating native TUN; persistent conflict refuses restart', async () => {
  const f = fixture(); f.io.auditIpv6Released = async () => { throw Error('ipv6_journal_not_released'); };
  const r = await runTrial(f.io);
  assert.equal(r.failure.stage, 'old-ipv6-cleanup-audit');
  assert.equal(r.rollback, 'manual-review-required');
  assert.ok(!f.events.includes('createTun')); assert.ok(!f.events.includes('startOld'));
});
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
      process.stdout.write('{"version":1,"event":"state","state":"ready","generation":0,"tx_packets":0,"rx_packets":0,"dropped_packets":0}\\n');
      process.stderr.write('native-control: DNS active\\n');
      process.stdin.on('data', b => { if (b.toString() === '{"op":"stop"}\\n') process.exit(0); else process.exit(2); });
    `], options);
    return child;
  }, readyMs: 5000, stopMs: 5000 });
  try {
    await session.ready(() => false); assert.equal(session.healthy(), true);
    assert.equal(session.diagnostics().lastState, 'ready'); assert.equal(session.diagnostics().dnsReady, true);
    assert.equal((await session.stop()).code, 0); assert.equal(session.diagnostics().ended, true);
  }
  finally { child.kill('SIGKILL'); }
});
test('native exit before readiness fails promptly instead of reporting success', async () => {
  const s = launchTrialNative('/private/config.json', { spawnChild: (file, args, options) => spawn(process.execPath, ['-e', 'process.exit(1)'], options), readyMs: 5000 });
  await assert.rejects(s.ready(() => false), /native_start_failed/); await s.stop();
});

test('native timeout retains safe states before graceful stop, even when rollback also fails', async () => {
  let child;
  const f = fixture({ fail: 'startOld' });
  f.io.launch = async () => launchTrialNative('/private/config.json', { readyMs: 600, stopMs: 3000,
    spawnChild(file, args, options) {
      child = spawn(process.execPath, ['-e', `
        const event = state => process.stdout.write(JSON.stringify({version:1,event:'state',state,
          generation:0,tx_packets:0,rx_packets:0,dropped_packets:0})+'\\n');
        process.stderr.write('secret=DO_NOT_REPORT\\nnative-control: DNS guard/');
        setTimeout(() => {process.stderr.write('routes ready\\n');event('handshake');event('tls_handshake');}, 20);
        process.stdin.on('data', b => {if(b.toString()==='{"op":"stop"}\\n'){event('stopped');process.exit(0);}});
      `], options); return child;
    } });
  try {
    const r = await runTrial(f.io);
    assert.equal(r.failure.code, 'native_ready_timeout'); assert.equal(r.rollbackFailure.stage, 'start-old');
    assert.equal(r.nativeDiagnostics.beforeStop.lastState, 'tls_handshake');
    assert.equal(r.nativeDiagnostics.beforeStop.dnsReady, false);
    assert.equal(r.nativeDiagnostics.beforeStop.stages[0].stage, 'dns_guard_ready');
    assert.equal(r.nativeDiagnostics.afterStop.lastState, 'stopped');
    assert.equal(r.nativeDiagnostics.afterStop.exitCode, 0);
    assert.ok(!JSON.stringify(r).includes('DO_NOT_REPORT'));
  } finally { child?.kill('SIGKILL'); }
});
test('diagnostic snapshot errors cannot prevent successful cleanup and restore', async () => {
  const f = fixture(), launch = f.io.launch;
  f.io.launch = async () => ({ ...await launch(), diagnostics() { throw Error('PRIVATE'); } });
  const r = await runTrial(f.io);
  assert.equal(r.rollback, 'verified'); assert.equal(r.status, 'passed');
  assert.deepEqual(r.nativeDiagnostics.beforeStop, { unavailable: true });
  assert.ok(!JSON.stringify(r).includes('PRIVATE'));
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
