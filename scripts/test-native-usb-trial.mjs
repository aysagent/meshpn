import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createPeerChannel, peerStatus, submitPeerResult, validatePeerResult, exerciseNativePeer } from './lib/native-usb-trial-peer.mjs';
import { runFault, faultUnitArgs } from './clean-vpn-native-usb-uplink.mjs';
import { probePeer, dnsAddresses, execute, quote } from './clean-vpn-native-usb-check.mjs';
import { uplinkFault } from './clean-vpn-native-trial.mjs';

const ip = '192.168.7.19';
const request = { token: '12345678-1234-1234-1234-123456789abc', phase: 'native' };
const good = p => ({ ...p, dnsPassed: 4, httpsPassed: 3, downloadBytes: 1048576,
  exitIp: '154.62.226.216', blockedAttempts: 0, recoveryMs: 0, elapsedMs: 100 });
const temp = t => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-peer-test-'));
  t.after(() => fs.rmSync(d, { recursive: true })); return d; };
test('strict peer result rejects foreign fields, nonce, counters and false pass', () => {
  assert.equal(validatePeerResult(good(request), request).status, 'passed');
  for (const patch of [{ token: 'old' }, { phase: 'blocked' }, { dnsPassed: 5 }, { elapsedMs: -1 },
    { extra: 'secret' }, { exitIp: '192.168.1.1' }, { recoveryMs: 60001 }])
    assert.throws(() => validatePeerResult({ ...good(request), ...patch }, request));
  assert.equal(validatePeerResult({ ...good(request), httpsPassed: 2 }, request).status, 'failed');
});
test('peer channel binds source, nonce, deadline; prevents duplicate and late result', async t => {
  const dir = temp(t); let clock = 100;
  const channel = createPeerChannel(dir, ip, { now: () => clock, sleep: async () => {
    const p = peerStatus(dir, ip, () => clock);
    assert.equal(p.status, 'probe');
    assert.throws(() => peerStatus(dir, '192.168.7.20', () => clock), /address_changed/);
    const v = good({ token: p.token, phase: p.phase });
    assert.throws(() => submitPeerResult(dir, '192.168.7.20', v, () => clock), /closed/);
    submitPeerResult(dir, ip, v, () => clock);
    assert.throws(() => submitPeerResult(dir, ip, v, () => clock), /EEXIST/);
    clock += 250;
  } });
  const results = {}; await channel.phase('native', results);
  assert.equal(results.native.status, 'passed');
  assert.equal(peerStatus(dir, ip, () => clock).status, 'waiting');
  const p = JSON.parse(fs.readFileSync(path.join(dir, 'peer-phase.json')));
  assert.throws(() => submitPeerResult(dir, ip, good({ phase: p.phase, token: p.token }), () => clock), /closed/);
});
test('missing Mac, cancelled trial and dead engine close the active phase', async t => {
  for (const fault of ['timeout', 'cancelled', 'dead']) {
    const dir = temp(t); let clock = 0;
    const c = createPeerChannel(dir, ip, { now: () => clock, sleep: async () => { clock += 120001; }, cancelled: () => fault === 'cancelled' });
    await assert.rejects(c.phase('native', {}, () => fault !== 'dead'));
    assert.equal(peerStatus(dir, ip, () => clock).status, 'waiting');
  }
});
for (const fail of [null, 'start', 'down', 'blocked']) test(`real-fault controller always restores (${fail})`, async () => {
  const calls = [], report = { phases: {} };
  const event = async name => { calls.push(name); if (name === fail) throw Error('injected'); };
  const peer = { phase: p => event(p) };
  const session = { healthy: () => true, diagnostics: () => ({ stateCounts: {} }) };
  const fault = { start: () => event('start'), requireDown: () => event('down'), restore: () => event('restore') };
  if (fail) await assert.rejects(exerciseNativePeer(peer, session, report, fault));
  else await exerciseNativePeer(peer, session, report, fault);
  assert.ok(calls.includes('restore'));
  if (!fail) assert.deepEqual(calls, ['native', 'start', 'down', 'blocked', 'down', 'restore', 'recovered']);
  else assert.ok(!calls.includes('recovered'));
});
for (const fail of [null, 'down', 'hold']) test(`fault owner up in finally (${fail})`, async () => {
  const calls = [];
  const promise = runFault('/unused', {
    run: async (file, args) => { assert.equal(file, '/usr/bin/networkctl'); assert.equal(args[1], 'wlan0'); calls.push(args[0]); if (args[0] === fail) throw Error('injected'); },
    hold: async ms => { assert.equal(ms, 20000); if (fail === 'hold') throw Error('injected'); }, mark: () => {},
  });
  if (fail) await assert.rejects(promise); else await promise;
  assert.deepEqual(calls, ['down', 'up']);
});
test('systemd safety is independent, bounded and has an unconditional post-stop up', () => {
  const args = faultUnitArgs('/var/lib/clean-vpn-native-trial/run-abc', '/usr/bin/node', '/script.mjs');
  assert.ok(args.includes('--property=ExecStopPost=/usr/bin/networkctl up wlan0'));
  assert.ok(args.includes('--property=RuntimeMaxSec=30'));
  assert.ok(args.includes('--property=KillMode=control-group'));
  assert.ok(!args.some(s => /PartOf|BindsTo|clean-vpn-native-trial.service/.test(s)));
});
for (const fail of [null, 'guard', 'foreign-default', 'still-up', 'restore']) {
  test(`uplink adapter verifies actual link/default state (${fail})`, async () => {
    let up = true, time = 0, spawned = false, stopped = false;
    const f = uplinkFault('/var/lib/clean-vpn-native-trial/run-test', {
      guard: async () => { if (fail === 'guard') throw Error('guard_failed'); },
      getLinks: async () => [{ ifname: 'wlan0', flags: up ? ['UP'] : [] }],
      clock: () => time, wait: async ms => { time += ms; },
      exec: async (file, args) => {
        if (file === 'systemctl') return 'active';
        if (file === 'ip') return JSON.stringify(up ? [{ dev: fail === 'foreign-default' ? 'end1' : 'wlan0' }] : []);
        assert.equal(file, 'systemd-run'); assert.ok(args.includes('--property=ExecStopPost=/usr/bin/networkctl up wlan0'));
        spawned = true; up = fail === 'still-up'; return '';
      },
      commandResult: async (file, args) => {
        assert.equal(file, 'systemctl'); assert.equal(args[0], 'stop');
        stopped = true; up = fail !== 'restore'; return { code: 0, reason: null };
      },
    });
    if (['guard', 'foreign-default', 'still-up'].includes(fail)) await assert.rejects(f.start());
    else { await f.start(); await f.requireDown(); assert.equal(up, false); }
    if (fail === 'restore') await assert.rejects(f.restore(), /restore_not_up/);
    else await f.restore();
    assert.equal(spawned, !['guard', 'foreign-default'].includes(fail));
    assert.equal(stopped, spawned);
  });
}
const response = (out, code = 0) => ({ code, out, reason: null });
function probes({ traceCode = 0, download = '200 1048576 0' } = {}) {
  const calls = [];
  return { calls, run: async (file, args) => {
    calls.push({ file, args });
    if (file === 'dig') {
      const type = args[5];
      return response(`;; status: NOERROR,\nexample.com. 60 IN ${type} ${type === 'A' ? '1.1.1.1' : '2606:4700::1111'}\n`);
    }
    if (args.includes('--resolve')) return response(download);
    return response('ip=154.62.226.216\n', traceCode);
  } };
}
test('Mac positive probes pin USB, direct gateway DNS, resolved download and TLS verification', async () => {
  const f = probes(), v = await probePeer(request, { iface: 'en9', address: ip, run: f.run });
  assert.equal(validatePeerResult(v, request).status, 'passed');
  for (const { file, args } of f.calls) {
    if (file === 'dig') { assert.ok(args.includes(ip)); assert.ok(args.includes('@192.168.7.1')); }
    else { assert.equal(args[0], '-q'); assert.ok(args.includes('en9')); assert.ok(args.includes('--noproxy')); assert.ok(!args.includes('-k')); }
  }
  assert.equal(f.calls.filter(c => c.file === 'dig' && c.args.includes('+tcp')).length, 2);
  assert.ok(f.calls.find(c => c.args.includes('--resolve')));
});
test('blocking requires two connect failures/timeouts, not missing curl or bad interface/TLS', async () => {
  for (const code of [0, 7, 28, 45, 60, 127]) {
    const p = { ...request, phase: 'blocked' }, f = probes({ traceCode: code });
    const v = await probePeer(p, { iface: 'en9', address: ip, run: f.run });
    assert.equal(validatePeerResult(v, p).status, [7, 28].includes(code) ? 'passed' : 'failed');
    assert.equal(f.calls.length, 2);
  }
});
test('truncated download and invalid DNS are not accepted', async () => {
  const f = probes({ download: '200 500 0' });
  const v = await probePeer(request, { iface: 'en9', address: ip, run: f.run });
  assert.equal(validatePeerResult(v, request).status, 'failed');
  assert.deepEqual(dnsAddresses(response(';; status: SERVFAIL,\nx 60 IN A 1.1.1.1'), 'A'), []);
  assert.deepEqual(dnsAddresses(response(';; status: NOERROR,\nx 60 IN A injected;command'), 'A'), []);
});
test('recovery retries are bounded; no ready result without working HTTPS', async () => {
  let clock = 0;
  const p = { ...request, phase: 'recovered' };
  const v = await probePeer(p, { iface: 'en9', address: ip, now: () => clock,
    sleep: async ms => { clock += ms; }, run: async () => { clock += 5000; return response('', 28); } });
  assert.equal(validatePeerResult(v, p).status, 'failed'); assert.ok(clock <= 60000);
});
test('bounded command runner reports spawn and timeout failures without raw stderr', async () => {
  assert.equal((await execute('/does-not-exist', [])).reason, 'spawn_failed');
  const r = await execute(process.execPath, ['-e', 'console.error("PRIVATE"); setTimeout(()=>{}, 10000)'], { timeout: 100 });
  assert.equal(r.reason, 'timeout'); assert.ok(!JSON.stringify(r).includes('PRIVATE'));
  assert.equal(quote("a'b"), "'a'\\''b'");
});
