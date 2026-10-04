import test from 'node:test';
import assert from 'node:assert/strict';
import { recoverUsbClient, usbRecoveryProfile } from './lib/usb-client-recovery.mjs';
import { watchVpnUplink, subscribeUplinkEvents } from './lib/vpn-uplink-watch.mjs';
import { EventEmitter } from 'node:events';

const scope = { fromTun: null, lanSubnet: '192.168.7.0/24', lanInterface: 'usb0' };
function fixture() {
  const calls = [];
  const journal = (name, state) => ({ state: { stage: 'active', ...state }, lockDescriptors: [3],
    audit() { calls.push(name + ':audit'); },
    restore(options) { if (options?.apply === false) { this.audit(); return; }
      calls.push(name + ':restore'); this.state.stage = 'released'; } });
  const args = { host: journal('host', { tun: 'tun0' }),
    ipv6: journal('ipv6', { config: { role: 'client', tun: 'tun0' } }),
    dns: journal('dns', { config: { tun: 'tun0', ...scope } }), scope,
    verifyGuard() { calls.push('guard'); }, links: () => [], log() {} };
  return { args, calls };
}
test('all owners audited before writes; DNS then IPv6 then host; repeat no-op', () => {
  const { args, calls } = fixture(); assert.equal(recoverUsbClient(args), true);
  assert.deepEqual(calls.slice(0, 4), ['guard', 'host:audit', 'ipv6:audit', 'dns:audit']);
  assert.deepEqual(calls.filter(x => x.endsWith(':restore')), ['dns:restore', 'ipv6:restore', 'host:restore']);
  assert.equal(recoverUsbClient(args), false);
});
for (const fault of ['guard', 'tun', 'host', 'ipv6', 'dns', 'scope', 'role']) test('refuse before mutations: ' + fault, () => {
  const { args, calls } = fixture();
  if (fault === 'guard') args.verifyGuard = () => { throw Error('guard'); };
  else if (fault === 'tun') args.links = () => [{ ifname: 'tun0' }];
  else if (fault === 'scope') args.dns.state.config.lanSubnet = '10.0.0.0/8';
  else if (fault === 'role') args.ipv6.state.config.role = 'exit';
  else args[fault].audit = () => { throw Error('foreign ownership'); };
  assert.throws(() => recoverUsbClient(args)); assert.ok(!calls.some(x => x.endsWith(':restore')));
});
test('partial failure retains remaining journals; retry completes', () => {
  const { args, calls } = fixture(), restore = args.ipv6.restore;
  args.ipv6.restore = () => { throw Error('interrupted'); };
  assert.throws(() => recoverUsbClient(args)); assert.equal(args.host.state.stage, 'active');
  assert.deepEqual(calls.filter(x => x.endsWith(':restore')), ['dns:restore']);
  args.ipv6.restore = restore; assert.equal(recoverUsbClient(args), true);
});
test('only explicit reviewed profile permits automatic recovery', () => {
  const o = { dnsUsb: true, role: 'client', type: 'tls', splitDefault: true, ipv6: 'auto', dnsMode: 'tunnel', server: '154.62.226.216:443' };
  assert.equal(usbRecoveryProfile(o), true);
  for (const [k, v] of Object.entries({ dnsUsb: false, role: 'exit', type: 'udp', splitDefault: false, ipv6: 'off', dnsMode: 'off', server: '1.1.1.1:443', fromTun: 'tun9', clientLanSubnet: '10.0.0.0/8', dnsStateDir: '/tmp/state' })) assert.equal(usbRecoveryProfile({ ...o, [k]: v }), false);
});
test('watch closes stale transport, repairs without restart, stops before cleanup', () => {
  let tick, mode = 0; const calls = [];
  const w = watchVpnUplink({ repair() { calls.push('audit'); if (mode < 0) throw Error('no default'); return mode; },
    disconnect: () => calls.push('disconnect'), reconnect: () => calls.push('connect'), log() {},
    schedule: fn => { tick = fn; }, cancel: () => calls.push('cancel'), subscribe: () => () => {} });
  tick(); assert.deepEqual(calls, ['audit']);
  assert.equal(w.available, true);
  mode = -1; tick(); tick(); assert.equal(w.generation, 1); assert.equal(calls.filter(x => x === 'disconnect').length, 1);
  assert.equal(w.available, false);
  mode = 4; tick(); assert.equal(w.generation, 2); assert.deepEqual(calls.slice(-3), ['audit', 'disconnect', 'connect']);
  assert.equal(w.available, true);
  w.stop(); const before = calls.length; tick(); assert.equal(calls.length, before);
  assert.equal(w.available, false);
});
test('netlink wakes audit immediately; failure switches to bounded polling; stop detaches', () => {
  let changed, failed, audits = 0, detached = 0;
  const periods = [];
  const w = watchVpnUplink({ repair: () => { audits++; return 0; }, disconnect() {}, reconnect() {}, log() {},
    schedule: (fn, ms) => { periods.push(ms); return {}; }, cancel() {},
    subscribe: (a, b) => { changed = a; failed = b; return () => detached++; } });
  assert.deepEqual(periods, [10000]); changed(); assert.equal(audits, 1);
  failed(); assert.deepEqual(periods, [10000, 1000]); assert.equal(audits, 2);
  w.stop(); changed(); failed(); assert.equal(audits, 2); assert.equal(detached, 1);
});
test('netlink subscriber coalesces events, falls back once, and reaps its own child', () => {
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
  const signals = [], timers = []; let changes = 0, failures = 0;
  child.kill = signal => signals.push(signal);
  const stop = subscribeUplinkEvents(() => changes++, () => failures++, {
    spawnChild: (file, args) => { assert.equal(file, 'ip'); assert.deepEqual(args, ['-o', 'monitor', 'link', 'route', 'address']); return child; },
    schedule: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; }, cancel: t => { if (t) t.cancelled = true; },
  });
  child.stdout.emit('data', Buffer.from('route')); child.stdout.emit('data', Buffer.from('link'));
  assert.equal(timers.length, 1); assert.equal(timers[0].ms, 50); timers[0].fn(); assert.equal(changes, 1);
  child.emit('error', Error('lost')); child.stderr.emit('data', Buffer.from('failure')); assert.equal(failures, 1);
  child.stdout.emit('data', Buffer.from('address')); stop(); timers[1].fn(); assert.equal(changes, 1);
  assert.deepEqual(signals, ['SIGTERM']); child.signalCode = 'SIGTERM'; child.emit('close');
  assert.equal(timers.at(-1).cancelled, true); assert.equal(failures, 1); stop();
});
test('netlink spawn failure falls back without retaining a child', () => {
  let failures = 0;
  const stop = subscribeUplinkEvents(() => assert.fail('no event source'), () => failures++, {
    spawnChild: () => { throw Error('missing ip'); },
  });
  assert.equal(failures, 1); stop(); stop();
});
