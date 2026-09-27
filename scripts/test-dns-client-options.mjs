import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { cleanVpnDnsOptions, tunnelDnsLanInterface } from './lib/dns-client-options.mjs';
import { recoverTunnelDns } from './clean-vpn-dns-recover.mjs';
import { tunnelDnsFixtureAnswer } from './lib/dns-tunnel-cli-lab.mjs';
import { makeDnsQuery, validateDnsResponse } from './lib/lab-dns-wire.mjs';

const source = readFileSync(new URL('./clean-vpn.js', import.meta.url), 'utf8');
const slice = (start, end) => {
  const a = source.indexOf(start), b = source.indexOf(end, a);
  assert.ok(a >= 0 && b > a); return source.slice(a, b);
};
const parseArgs = runInNewContext(`${slice('function parseArgs(argv)', '\nfunction parseHostPort')}\nparseArgs`, { cleanVpnDnsOptions });
const base = ['--role=client', '--type=tls', '--server=192.0.2.1:443'];

test('actual CLI lab fixture emits valid A and 16-byte AAAA records for every endpoint', () => {
  for (const type of [1, 28]) for (const suffix of [10, 20, 30]) {
    const q = makeDnsQuery('origin.test', type), r = tunnelDnsFixtureAnswer(q, suffix);
    const rr = validateDnsResponse(r, q).records[0];
    assert.equal(rr.length, type === 28 ? 16 : 4); assert.equal(r[rr.offset + rr.length - 1], suffix);
  }
});

test('actual CLI defaults to tunnel DNS; override and explicit off are separate', () => {
  assert.equal(parseArgs(base).dnsMode, 'tunnel');
  assert.equal(parseArgs([...base, '--dns-server=9.9.9.9']).dnsServer, '9.9.9.9');
  assert.equal(parseArgs([...base, '--dns-state-dir=/run/my-dns']).dnsStateDir, '/run/my-dns');
  assert.equal(parseArgs(['--role=exit', '--type=tls']).dnsMode, 'off');
  assert.equal(parseArgs([...base, '--dns-mode=off']).dnsMode, 'off');
  assert.equal(parseArgs(['--role=client', '--server=exit.test:443', '--dns-mode=off']).dnsMode, 'off');
});

test('actual CLI rejects ambiguous, unsupported and bootstrap-recursive DNS options', () => {
  for (const flags of [
    ['--dns-mode=managed'], ['--dns-mode=bad'], ['--dns-mode=off', '--dns-server=1.1.1.1'],
    ['--dns-mode=off', '--dns-state-dir=/run/dns'], ['--dns-server=127.0.0.1'],
    ['--dns-server=::1'], ['--dns-server=dns.test'], ['--dns-state-dir=relative'],
    ['--dns-state-dir=/run/../tmp/dns'], ['--dns-server=1.1.1.1', '--dns-server=8.8.8.8'],
    ['--dns-mode=tunnel', '--dns-mode=off'], ['--dns-sever=1.1.1.1'],
  ]) assert.throws(() => parseArgs([...base, ...flags]), undefined, flags.join(' '));
  assert.throws(() => parseArgs(['--role=exit', '--dns-mode=off']), /client DNS/);
  assert.throws(() => parseArgs(['--role=client', '--server=exit.test:443']), /bootstrap/);
});

test('LAN DNS scope requires a unique matching interface', () => {
  const link = (ifname, local) => ({ ifname, addr_info: [{ family: 'inet', local }] });
  const links = [link('lo', '127.0.0.1'), link('usb0', '192.168.7.1'), link('wlan0', '192.168.1.8')];
  assert.equal(tunnelDnsLanInterface('192.168.7.0/24', links), 'usb0');
  assert.equal(tunnelDnsLanInterface(null, links), null);
  assert.throws(() => tunnelDnsLanInterface('10.0.0.0/24', links));
  assert.throws(() => tunnelDnsLanInterface('192.168.7.0/24', [...links, link('dup0', '192.168.7.2')]));
});

function clientFixture({ off = false, failure = null, stopping = false } = {}) {
  const events = [], ctx = { ifname: 'tun0' };
  const journal = { prepareRestart() { events.push('park'); }, release() { events.push('release'); } };
  const runtime = { activate() { events.push('dns-activate'); if (failure === 'activate') throw Error('activate'); },
    async close({ restore }) { events.push(`close:${restore}`); } };
  const runClient = runInNewContext(`${slice('async function runClient(options)', '\nasync function runClientImpl(')}\nrunClient`, {
    console: { log() {} }, openTunnelDnsJournal: () => journal,
    async runClientImpl(options) {
      events.push('transport'); options.dnsNetworkPrepared(ctx);
      options.ingressPrepared({ activate() { events.push('ingress-activate'); } });
      ctx.stopping = stopping;
    },
    async startTunnelDnsRuntime({ config }) {
      assert.equal(config.tun, 'tun0'); events.push('dns-start');
      if (failure === 'start') throw Error('start'); return runtime;
    },
  });
  return { events, run: () => runClient({ dnsMode: off ? 'off' : 'tunnel', fromTun: 'wg0' }) };
}

test('actual client opens ingress only after transport handlers and DNS activation', async () => {
  const f = clientFixture(); await f.run();
  assert.deepEqual(f.events, ['park', 'transport', 'dns-start', 'dns-activate', 'ingress-activate']);
});
test('explicit off does not touch DNS ownership or runtime', async () => {
  const f = clientFixture({ off: true }); await f.run();
  assert.deepEqual(f.events, ['transport', 'ingress-activate']);
});
test('failed DNS activation leaves ingress closed and retains guards', async () => {
  for (const failure of ['start', 'activate']) {
    const f = clientFixture({ failure }); await assert.rejects(f.run(), new RegExp(failure));
    assert.ok(!f.events.includes('ingress-activate')); assert.equal(f.events.at(-1), 'release');
    if (failure === 'activate') assert.ok(f.events.includes('close:false'));
  }
});
test('stop during transport setup prevents subsequent DNS/ingress activation', async () => {
  const f = clientFixture({ stopping: true }); await f.run();
  assert.deepEqual(f.events, ['park', 'transport']);
});

test('actual shutdown waits for DNS startup and parks safe ingress before DNS release', async () => {
  for (const exitCode of [0, 1]) for (const fromTunRestartSafe of [false, true]) {
    const events = []; let finishStartup;
    const routeCtx = { dnsStartup: new Promise(resolve => { finishStartup = resolve; }),
      ingressRouting: { close() { events.push('ingress-hold'); } } };
    const finish = runInNewContext(`${slice('  let finishNetworkPromise;', '\n  registerCleanVpnEmergencyShutdown(')}\nfinishNetwork`, {
      routeCtx, fromTunRestartSafe, console: { log() {}, error() {} },
      teardownClientRoutes(_ctx, { retainIngress }) { events.push(`routes:${retainIngress}`); },
      safe: fn => fn(), tun: { close() { events.push('tun'); } }, clearCleanVpnEmergencyShutdown() {},
      process: { exit(code) { events.push(`exit:${code}`); } },
    });
    const done = finish(exitCode, 'test');
    assert.equal(routeCtx.stopping, true); assert.deepEqual(events, []);
    assert.equal(finish(exitCode, 'again'), done);
    finishStartup({ async close({ restore }) { events.push(`dns:${restore}`); } });
    await done;
    assert.deepEqual(events, [...(exitCode === 0 && fromTunRestartSafe ? ['ingress-hold'] : []),
      `dns:${exitCode === 0 && !fromTunRestartSafe}`, `routes:${exitCode !== 0}`, 'tun', `exit:${exitCode}`]);
  }
});

test('DNS recovery is audit-only by default, validates flags before opening, and always releases lock', () => {
  for (const apply of [false, true]) {
    const calls = [];
    const result = recoverTunnelDns(apply ? ['--state-dir=/run/test', '--apply'] : [], directory => ({
      state: { stage: 'active' }, restore(options) { calls.push([directory, options.apply]); return { mode: options.apply ? 'restored' : 'dry-run' }; },
      release() { calls.push('release'); },
    }));
    assert.deepEqual(calls, [[apply ? '/run/test' : undefined, apply], 'release']);
    assert.equal(result.mode, apply ? 'restored' : 'dry-run');
  }
  for (const flags of [['--apply', '--apply'], ['--state-dir=relative'], ['--force']])
    assert.throws(() => recoverTunnelDns(flags, () => { assert.fail('must not open'); }));
  let released = false;
  assert.throws(() => recoverTunnelDns([], () => ({ state: null, release() { released = true; } })), /no tunnel DNS journal/);
  assert.equal(released, true);
});

test('failed safe-stop gate never releases DNS protection or restores direct ingress', async () => {
  const events = [], routeCtx = {
    ingressRouting: { close() { throw Error('hold failed'); } },
    dnsRuntime: { close() { assert.fail('must retain DNS guard'); } },
  };
  const finish = runInNewContext(`${slice('  let finishNetworkPromise;', '\n  registerCleanVpnEmergencyShutdown(')}\nfinishNetwork`, {
    routeCtx, fromTunRestartSafe: true, console: { log() {}, error() {} },
    teardownClientRoutes(_ctx, { retainIngress }) { events.push(retainIngress); },
    safe: fn => fn(), tun: { close() { events.push('tun'); } }, clearCleanVpnEmergencyShutdown() {},
    process: { exit(code) { events.push(code); } },
  });
  await finish(0, 'test'); assert.deepEqual(events, [true, 'tun', 1]);
});
