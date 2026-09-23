/** Public addresses are connector doubles here; real connections have a private namespace suite. */
import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ExitDestinationPolicy, EXIT_DNS_MAX_PENDING } from './lib/transparent-tls-destination.mjs';
import { compileDnsUpstream, compileLabDnsUpstream, dnsUpstreamExitPolicy } from './lib/dns-upstream-config.mjs';
import { loadExitDnsUpstreamPolicy } from './lib/dns-upstream-exit.mjs';
import { wireTransparentTlsEncSniSession, classifyComboTlsExitPrefix } from './lib/transparent-tls-runtime.mjs';
import { encodeRelayHostname } from './lib/transparent-tls-enc-sni.mjs';
import { EncSniReplayGuard } from './lib/transparent-tls-replay.mjs';

const HOST = 'resolver.example', PUBLIC = 'relay.test', PSK = randomBytes(32);
const config = () => ({ schema: 1, transport: 'doh', hostname: HOST, port: 443, path: '/dns-query',
  bootstrap: { addresses: ['93.184.216.34', '2606:4700::1111'] }, trust: { mode: 'bundled' } });
const pin = () => ({ hostname: HOST, port: 443, addresses: [{ address: '93.184.216.34', family: 4, port: 443 }] });
const forbidden = () => assert.fail('DNS must not be called');
const policy = () => dnsUpstreamExitPolicy(compileDnsUpstream(config()), { lookup: forbidden });

test('configured name is case-insensitive and exact, IP snapshot is immutable and isolated', async () => {
  const route = pin(); route.addresses.push({ ...route.addresses[0] });
  const p = new ExitDestinationPolicy({ pinnedRoute: route, lookup: forbidden });
  route.hostname = 'other.example'; route.addresses[0].address = '127.0.0.1';
  const a = await p.resolve(HOST.toUpperCase(), 443);
  assert.deepEqual(a, pin().addresses); assert.ok(Object.isFrozen(a) && Object.isFrozen(a[0]));
  assert.equal(await p.resolve(HOST, 443), a);
});
test('same name wrong port and invalid/local aliases fail without lookup', async () => {
  const p = policy();
  for (const [host, port] of [[HOST, 8443], [HOST, '443'], [HOST, 0], [`${HOST}.`, 443], ['localhost', 443],
    ['127.0.0.1', 443], ['a.local', 443], ['resolver..example', 443]]) {
    await assert.rejects(p.resolve(host, port), { code: 'TLS_RELAY_DESTINATION' });
  }
});
test('other domains and public literals retain normal destination policy', async () => {
  const calls = [], p = dnsUpstreamExitPolicy(compileDnsUpstream(config()), { lookup: async (...args) => {
    calls.push(args); return [{ address: '8.8.8.8', family: 4 }];
  } });
  for (const name of ['other.example', `sub.${HOST}`, `${HOST}.other`]) {
    assert.deepEqual(await p.resolve(name, 8443), [{ address: '8.8.8.8', family: 4, port: 8443 }]);
    assert.deepEqual(calls.at(-1), [`${name}.`, { all: true, verbatim: true }]);
  }
  assert.deepEqual(await p.resolve('1.1.1.1', 443), [{ address: '1.1.1.1', family: 4, port: 443 }]);
  assert.equal(calls.length, 3);
});
test('ordinary DNS mixed-private answer is still denied with a pin installed', async () => {
  const p = dnsUpstreamExitPolicy(compileDnsUpstream(config()), { lookup: async () => [
    { address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 },
  ] });
  await assert.rejects(p.resolve('other.example', 443), { code: 'TLS_RELAY_DESTINATION' });
});
for (const [name, mutate] of [
  ['private', (r) => { r.addresses[0].address = '10.0.0.1'; }],
  ['loopback', (r) => { r.addresses[0].address = '127.0.0.1'; }],
  ['mapped IPv6', (r) => { r.addresses[0] = { address: '::ffff:8.8.8.8', family: 6, port: 443 }; }],
  ['family mismatch', (r) => { r.addresses[0].family = 6; }],
  ['port mismatch', (r) => { r.addresses[0].port = 8443; }],
  ['hostname literal', (r) => { r.hostname = '8.8.8.8'; }],
  ['local hostname', (r) => { r.hostname = 'a.local'; }],
  ['trailing dot', (r) => { r.hostname += '.'; }],
  ['empty addresses', (r) => { r.addresses = []; }],
  ['oversized addresses', (r) => { r.addresses = Array(9).fill(r.addresses[0]); }],
  ['sparse addresses', (r) => { r.addresses = Array(2); }],
]) test(`operator pin rejects ${name} before any socket`, () => {
  const r = pin(); mutate(r);
  assert.throws(() => new ExitDestinationPolicy({ pinnedRoute: r }), { code: 'TLS_RELAY_CONFIG' });
});
test('loopback exception cannot be combined with production pin; forged/lab profiles refused', () => {
  assert.throws(() => new ExitDestinationPolicy({ loopback: { hostname: HOST, port: 443 }, pinnedRoute: pin() }));
  assert.throws(() => dnsUpstreamExitPolicy({ ...compileDnsUpstream(config()) }));
  const c = config(); c.bootstrap.addresses = ['127.0.0.1'];
  assert.throws(() => dnsUpstreamExitPolicy(compileLabDnsUpstream(c)));
});
test('DNS pending limit neither blocks nor gets spent by pinned routes', async () => {
  let release, lookups = 0; const wait = new Promise((resolve) => { release = resolve; });
  const p = dnsUpstreamExitPolicy(compileDnsUpstream(config()), { lookup: async () => { lookups++; await wait; return [{ address: '8.8.8.8', family: 4 }]; } });
  const pending = Array.from({ length: EXIT_DNS_MAX_PENDING }, () => p.resolve('other.example', 443));
  try {
    await assert.rejects(p.resolve('other.example', 443), { code: 'TLS_RELAY_DNS_BUSY' });
    for (let i = 0; i < 100; i++) assert.equal((await p.resolve(HOST, 443)).length, 2);
    assert.equal(lookups, EXIT_DNS_MAX_PENDING);
  } finally { release(); await Promise.all(pending); }
});

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
function hello(secret = PSK, port = 443) {
  const name = Buffer.from(encodeRelayHostname(secret, { hostname: HOST, port }, PUBLIC));
  const sni = Buffer.concat([u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const ext = Buffer.concat([u16(0), u16(sni.length), sni]);
  const body = Buffer.concat([Buffer.from([3, 3]), randomBytes(32), Buffer.from([0, 0, 2, 0x13, 1, 1, 0]), u16(ext.length), ext]);
  const hs = Buffer.alloc(4); hs[0] = 1; hs.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(body.length + 4), hs, body]);
}
class Socket extends Duplex {
  constructor(address, port = 443, connecting = false) {
    super(); this.remoteAddress = address; this.remotePort = port; this.connecting = connecting; this.writes = [];
  }
  _read() {}
  _write(bytes, encoding, done) { this.writes.push(Buffer.from(bytes)); done(); }
}
const refused = () => { throw Object.assign(new Error('private detail'), { code: 'ECONNREFUSED' }); };
function endpoint(t, { connector, prefix = hello(), replayGuard = new EncSniReplayGuard(), ...options } = {}) {
  const inbound = new Socket('127.0.0.1'), calls = [], sockets = [];
  const session = wireTransparentTlsEncSniSession(inbound, { vpnSecretBuf: PSK, publicName: PUBLIC,
    destinationPolicy: policy(), initialBuf: prefix, replayGuard, ...options,
    connectOrigin: (address, port, family) => {
      calls.push({ address, port, family });
      const socket = connector ? connector(address, port, family) : new Socket(address, port);
      sockets.push(socket); return socket;
    } });
  t.after(async () => { inbound.destroy(); for (const s of sockets) s.destroy(); await session.closed; assert.equal(session.timers.size, 0); });
  return { session, inbound, calls, sockets };
}
for (const modeTag of ['transparent-tls', 'combo-tls']) test(`${modeTag} uses static IPv4/IPv6 TCP failover with no DNS`, { timeout: 3000 }, async (t) => {
  const prefix = hello(); assert.equal(classifyComboTlsExitPrefix(prefix, PUBLIC, PSK).status, 'relay');
  const e = endpoint(t, { prefix, modeTag, connector: (address, port) => address.includes(':') ? new Socket(address, port) : refused() });
  await e.session.ready; assert.equal(e.calls.length, 2); assert.equal(e.calls[1].family, 6);
  assert.equal(e.sockets[0].writes.length, 1);
});
test('exhaustion closes without OS DNS or mux fallback', { timeout: 3000 }, async (t) => {
  const e = endpoint(t, { connector: refused, modeTag: 'combo-tls' });
  assert.equal((await e.session.closed).code, 'TLS_RELAY_CONNECT_EXHAUSTED'); assert.equal(e.calls.length, 2);
});
test('hanging first IP times out and only selected socket gets ClientHello', { timeout: 3000 }, async (t) => {
  let first;
  const e = endpoint(t, { connector: (address, port) => address.includes(':') ? new Socket(address, port) : (first = new Socket(address, port, true)) });
  await e.session.ready; assert.equal(e.calls.length, 2); assert.equal(first.destroyed, true); assert.equal(first.writes.length, 0);
  assert.equal(e.sockets[1].writes.length, 1);
});
test('overall deadline stops pin traversal, preserving the existing connection budget', { timeout: 3000 }, async (t) => {
  const e = endpoint(t, { limits: { connectTimeoutMs: 50 }, connector: (a, p) => new Socket(a, p, true) });
  assert.equal((await e.session.closed).code, 'TLS_RELAY_CONNECT_TIMEOUT'); assert.equal(e.calls.length, 1);
});
test('peer abort during the first pinned TCP attempt cancels the remaining candidates', { timeout: 3000 }, async (t) => {
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const e = endpoint(t, { connector: (a, p) => { started(); return new Socket(a, p, true); } });
  await ready; e.inbound.destroy(); await e.session.closed;
  assert.equal(e.calls.length, 1); assert.equal(e.sockets[0].destroyed, true);
});
test('default runtime connector gets only the pinned numeric IP, family and port', { timeout: 3000 }, async (t) => {
  const calls = [], sockets = [], inbound = new Socket('127.0.0.1');
  t.mock.method(net, 'connect', (options) => {
    calls.push(options);
    assert.deepEqual(options, { host: config().bootstrap.addresses[calls.length - 1], port: 443,
      family: calls.length === 1 ? 4 : 6, autoSelectFamily: false });
    if (calls.length === 1) return refused();
    const socket = new Socket(options.host, options.port); sockets.push(socket); return socket;
  });
  const session = wireTransparentTlsEncSniSession(inbound, { vpnSecretBuf: PSK, publicName: PUBLIC,
    initialBuf: hello(), replayGuard: new EncSniReplayGuard(), destinationPolicy: policy() });
  t.after(async () => { inbound.destroy(); for (const s of sockets) s.destroy(); await session.closed; });
  await session.ready; assert.equal(calls.length, 2); assert.equal(sockets[0].writes.length, 1);
});
test('peer mismatch and reset after selected TCP never try another address', { timeout: 3000 }, async (t) => {
  const bad = endpoint(t, { connector: () => new Socket('1.1.1.1') });
  assert.equal((await bad.session.closed).code, 'TLS_RELAY_DESTINATION_PEER'); assert.equal(bad.calls.length, 1);
  const e = endpoint(t); await e.session.ready;
  e.sockets[0].destroy(Object.assign(new Error('reset'), { code: 'ECONNRESET' })); await e.session.closed;
  assert.equal(e.calls.length, 1);
});
test('bad authentication, wrong pinned port and replay cannot create extra outbound attempts', { timeout: 3000 }, async (t) => {
  for (const prefix of [hello(randomBytes(32)), hello(PSK, 8443)]) {
    const e = endpoint(t, { prefix }); await e.session.closed; assert.equal(e.calls.length, 0);
  }
  const prefix = hello(), replayGuard = new EncSniReplayGuard();
  const first = endpoint(t, { prefix, replayGuard, connector: refused }); await first.session.closed;
  const repeated = endpoint(t, { prefix, replayGuard });
  assert.equal((await repeated.session.closed).code, 'TLS_RELAY_REPLAY'); assert.equal(repeated.calls.length, 0);
});
test('exit-only startup opt-in validates context, reads once and retains snapshot', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-route-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'config.json'); await writeFile(path, JSON.stringify(config()));
  assert.equal(await loadExitDnsUpstreamPolicy({ role: 'client', type: 'tcp' }, []), undefined);
  for (const type of ['transparent-tls', 'combo-tls']) {
    const p = await loadExitDnsUpstreamPolicy({ role: 'exit', type }, [`--tls-dns-upstream-config=${path}`]);
    assert.ok(p instanceof ExitDestinationPolicy); assert.equal((await p.resolve(HOST, 443)).length, 2);
  }
  const p = await loadExitDnsUpstreamPolicy({ role: 'exit', type: 'transparent-tls' }, [`--tls-dns-upstream-config=${path}`]);
  await writeFile(path, 'invalid replacement'); assert.equal((await p.resolve(HOST, 443)).length, 2);
  for (const [ctx, argv] of [
    [{ role: 'client', type: 'transparent-tls' }, [`--tls-dns-upstream-config=${path}`]],
    [{ role: 'exit', type: 'tls' }, [`--tls-dns-upstream-config=${path}`]],
    [{ role: 'exit', type: 'transparent-tls' }, ['--tls-dns-upstream-config']],
    [{ role: 'exit', type: 'transparent-tls' }, ['--tls-dns-upstream-config=']],
    [{ role: 'exit', type: 'transparent-tls' }, ['--tls-dns-upstream-config-typo=anything']],
    [{ role: 'exit', type: 'transparent-tls' }, [`--tls-dns-upstream-config=${path}`, `--tls-dns-upstream-config=${path}`]],
    [{ role: 'exit', type: 'transparent-tls' }, [`--tls-dns-upstream-config=${path}`]],
  ]) await assert.rejects(loadExitDnsUpstreamPolicy(ctx, argv), { code: 'DNS_UPSTREAM_CONFIG', message: 'DNS_UPSTREAM_CONFIG' });
});
test('clean-vpn preflight precedes runExit/runClient and both enc-SNI branches receive the policy', async () => {
  const source = await readFile(new URL('./clean-vpn.js', import.meta.url), 'utf8');
  assert.match(source, /args\.dnsUpstreamDestinationPolicy = await loadExitDnsUpstreamPolicy\(args, process\.argv\.slice\(2\)\);\s+if \(args\.role === 'exit'\) \{\s+await runExit\(args\)/);
  for (const type of ['transparent-tls', 'combo-tls']) assert.ok(source.includes(`modeTag: '${type}',\n      ${type === 'combo-tls' ? '  ' : ''}destinationPolicy,`));
  assert.equal((source.match(/\s+dnsUpstreamDestinationPolicy,\n/g) ?? []).length, 3);
});
