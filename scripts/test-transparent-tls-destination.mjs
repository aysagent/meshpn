/** No public network: controlled DNS/connector doubles + real loopback rejection. */
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import net from 'node:net';
import { once } from 'node:events';
import { Duplex } from 'node:stream';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { ExitDestinationPolicy, isPublicRelayAddress, EXIT_DNS_MAX_PENDING } from './lib/transparent-tls-destination.mjs';
import { wireTransparentTlsEncSniSession, classifyComboTlsExitPrefix } from './lib/transparent-tls-runtime.mjs';
import { encodeRelayHostname } from './lib/transparent-tls-enc-sni.mjs';
import { EncSniReplayGuard } from './lib/transparent-tls-replay.mjs';

const PSK = randomBytes(32), PUBLIC = 'relay.test', HOST = 'origin.test';
const v4 = (address = '8.8.8.8') => ({ address, family: 4 });
const v6 = (address = '2606:4700:4700::1111') => ({ address, family: 6 });
const policyWith = (answers) => new ExitDestinationPolicy({ lookup: async () => answers });
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
function hello(hostname = HOST, port = 443) {
  const name = Buffer.from(encodeRelayHostname(PSK, { hostname, port }, PUBLIC));
  const sni = Buffer.concat([u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const ext = Buffer.concat([u16(0), u16(sni.length), sni]);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 7), Buffer.from([0, 0, 2, 0x13, 1, 1, 0]), u16(ext.length), ext]);
  const hs = Buffer.alloc(4); hs[0] = 1; hs.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(body.length + 4), hs, body]);
}
class Socket extends Duplex {
  constructor(address = '8.8.8.8', port = 443) {
    super(); this.remoteAddress = address; this.remotePort = port; this.connecting = false; this.writes = [];
  }
  _read() {}
  _write(bytes, encoding, callback) { this.writes.push(Buffer.from(bytes)); callback(); }
}
async function within(promise, ms = 2000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test deadline')), ms); })]); }
  finally { clearTimeout(timer); }
}
function endpoint(t, { policy, prefix = hello(), connector, ...options } = {}) {
  const inbound = new Socket(), outbound = new Socket();
  const calls = [];
  const session = wireTransparentTlsEncSniSession(inbound, {
    vpnSecretBuf: PSK, publicName: PUBLIC, initialBuf: prefix, replayGuard: new EncSniReplayGuard(),
    ...(policy === undefined ? {} : { destinationPolicy: policy }),
    connectOrigin: (...args) => { calls.push(args); return connector ? connector(...args) : outbound; },
    ...options,
  });
  t.after(async () => { inbound.destroy(); outbound.destroy(); await session?.closed; });
  return { inbound, outbound, session, calls };
}

test('public-unicast positive samples and CIDR boundaries', () => {
  for (const address of ['1.1.1.1', '8.8.8.8', '100.63.255.255', '100.128.0.0',
    '172.15.255.255', '172.32.0.0', '192.0.1.1', '198.17.255.255', '198.20.0.0',
    '223.255.255.255', '2001:4860:4860::8888', '2606:4700:4700::1111', '2001:200::1', '3ffe::1']) {
    assert.equal(isPublicRelayAddress(address), true, address);
  }
});
for (const [name, addresses] of [
  ['unspecified and this-network', ['0.0.0.0', '0.255.255.255', '::']],
  ['RFC1918', ['10.0.0.0', '10.255.255.255', '172.16.0.0', '172.31.255.255', '192.168.0.0', '192.168.255.255']],
  ['loopback', ['127.0.0.1', '127.255.255.255', '::1']],
  ['link-local and metadata', ['169.254.0.0', '169.254.169.254', '169.254.255.255', 'fe80::1', 'febf:ffff::1']],
  ['CGNAT', ['100.64.0.0', '100.100.100.200', '100.127.255.255']],
  ['special-use, documentation, benchmark', ['192.0.0.8', '192.0.0.9', '192.0.0.170', '192.0.2.1', '192.88.99.1', '198.18.0.0', '198.19.255.255', '198.51.100.1', '203.0.113.1', '2001:db8::1', '3fff:fff:ffff::1']],
  ['multicast and reserved', ['224.0.0.0', '239.255.255.255', '240.0.0.0', '255.255.255.255', 'ff02::1', '4000::1']],
  ['IPv4 encodings and translation', ['::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:8.8.8.8', '::127.0.0.1', '64:ff9b::7f00:1', '64:ff9b:1::1', '2002:7f00:1::1', '2001::1']],
  ['IPv6 local/special', ['fc00::1', 'fdff:ffff::1', 'fec0::1', '100::1', '100:0:0:1::1', '2001:2::1', '2001:20::1', '5f00::1']],
  ['invalid and scoped addresses', ['', null, 4, {}, '127.1', '2130706433', '0x7f000001', '0177.0.0.1', '[::1]', 'fe80::1%eth0', '2606:4700::1%lo', '8.8.8.8 ', '1.2.3.999']],
]) test(`denies ${name}`, async () => {
  for (const address of addresses) {
    assert.equal(isPublicRelayAddress(address), false, String(address));
    await assert.rejects(policyWith([{ address, family: typeof address === 'string' ? net.isIP(address) : 0 }]).resolve(HOST, 443), { code: 'TLS_RELAY_DESTINATION' });
  }
});

test('invalid/local/legacy-numeric routes never invoke DNS', async () => {
  const policy = new ExitDestinationPolicy({ lookup: () => assert.fail('must not query DNS') });
  for (const hostname of ['', 'localhost', 'LOCALHOST', 'a.localhost', 'a.local', 'a.internal', 'a.home.arpa',
    '127.1', '2130706433', '0x7f000001', '0x7f.0.0.1', '0177.0.0.1', '127.0.0.1', 'origin.test.', 'a..test',
    '-a.test', 'a-.test', 'a_b.test', 'https://origin.test', 'a\0.test', 'é.test', `${'a'.repeat(64)}.test`]) {
    await assert.rejects(policy.resolve(hostname, 443), { code: 'TLS_RELAY_DESTINATION' }, hostname);
  }
  for (const port of [0, -1, 65536, NaN, 1.5, '443']) await assert.rejects(policy.resolve(HOST, port), { code: 'TLS_RELAY_DESTINATION' });
});
test('public IP literal skips DNS and preserves a valid non-443 port', async () => {
  const policy = new ExitDestinationPolicy({ lookup: () => assert.fail('must not query DNS') });
  assert.deepEqual(await policy.resolve('8.8.8.8', 8443), { address: '8.8.8.8', family: 4, port: 8443 });
});
test('DNS is absolute, all families inspected, target copied and immutable', async () => {
  const answers = [v6(), v4()];
  const policy = new ExitDestinationPolicy({ lookup: async (host, options) => {
    assert.equal(host, `${HOST}.`); assert.deepEqual(options, { all: true, verbatim: true }); return answers;
  } });
  const target = await policy.resolve(HOST, 443);
  answers[0].address = '::1';
  assert.equal(target.address, '2606:4700:4700::1111'); assert.equal(target.family, 6); assert.ok(Object.isFrozen(target));
});
test('mixed answers rejected in either order and across families', async () => {
  for (const forbidden of [v4('127.0.0.1'), v4('10.0.0.1'), v6('::1'), v6('::ffff:127.0.0.1'), v6('fd00::1')]) {
    for (const answers of [[v4(), forbidden], [forbidden, v6()]]) {
      await assert.rejects(policyWith(answers).resolve(HOST, 443), { code: 'TLS_RELAY_DESTINATION' });
    }
  }
});
test('malformed, empty, oversized and family-mismatched DNS answers fail closed', async () => {
  for (const answers of [null, {}, [], Array.from({ length: 65 }, () => v4())]) {
    await assert.rejects(policyWith(answers).resolve(HOST, 443), { code: 'TLS_RELAY_DNS' });
  }
  for (const answers of [[null], [{}], [{ address: '8.8.8.8', family: 6 }], [{ address: '8.8.8.8', family: '4' }]]) {
    await assert.rejects(policyWith(answers).resolve(HOST, 443), { code: 'TLS_RELAY_DESTINATION' });
  }
});
test('resolver failures expose no raw hostname or resolver error text', async () => {
  const policy = new ExitDestinationPolicy({ lookup: async () => { throw new Error('SECRET internal resolver name'); } });
  await assert.rejects(policy.resolve(HOST, 443), (error) => error.code === 'TLS_RELAY_DNS' && !String(error).includes('SECRET') && !error.cause);
});
test('loopback exception is exact hostname/port pin, immutable and never invokes DNS', async () => {
  const pin = { hostname: HOST, port: 8443 };
  const policy = new ExitDestinationPolicy({ loopback: pin, lookup: () => assert.fail('must not query DNS') });
  pin.hostname = 'other.test'; pin.port = 22;
  assert.deepEqual(await policy.resolve(HOST, 8443), { address: '127.0.0.1', family: 4, port: 8443 });
  for (const [host, port] of [[HOST, 443], ['other.test', 8443], ['127.0.0.1', 8443], ['sub.origin.test', 8443]]) {
    await assert.rejects(policy.resolve(host, port), { code: 'TLS_RELAY_DESTINATION' });
  }
});
test('bad policy configuration cannot silently permit destinations', () => {
  for (const options of [{ lookup: null }, { loopback: null }, { loopback: {} }, { loopback: { hostname: HOST, port: 0 } }]) {
    assert.throws(() => new ExitDestinationPolicy(options), { code: 'TLS_RELAY_CONFIG' });
  }
});
test('resolver budget is bounded without an unbounded queue and releases after settlement', async () => {
  const releases = []; let calls = 0;
  const policy = new ExitDestinationPolicy({ lookup: () => { calls++; return new Promise((resolve) => releases.push(resolve)); } });
  const pending = Array.from({ length: EXIT_DNS_MAX_PENDING }, () => policy.resolve(HOST, 443));
  await assert.rejects(policy.resolve(HOST, 443), { code: 'TLS_RELAY_DNS_BUSY' }); assert.equal(calls, 64);
  releases.shift()([v4()]); await pending[0];
  pending.push(policy.resolve(HOST, 443)); assert.equal(calls, 65);
  for (const resolve of releases) resolve([v4()]);
  await Promise.all(pending);
});

test('default production policy pins one numeric target, second lookup cannot rebind it', async (t) => {
  let calls = 0;
  t.mock.method(dns, 'lookup', async () => ++calls === 1 ? [v4()] : [v4('127.0.0.1')]);
  const a = endpoint(t); await within(a.session.ready);
  assert.equal(a.session.state, 'streaming'); assert.deepEqual(a.calls, [['8.8.8.8', 443, 4]]); assert.equal(calls, 1);
  const b = endpoint(t); await within(b.session.ready);
  assert.equal((await within(b.session.closed)).code, 'TLS_RELAY_DESTINATION');
  assert.equal(b.calls.length, 0); assert.equal(calls, 2);
});
test('default net connector receives an IP, explicit family and no DNS callback', async (t) => {
  t.mock.method(dns, 'lookup', async () => [v4()]);
  const socket = new Socket(); t.after(() => socket.destroy());
  const calls = [];
  t.mock.method(net, 'connect', (options) => { calls.push(options); return socket; });
  const a = endpoint(t, { connectOrigin: undefined }); await within(a.session.ready);
  assert.equal(a.session.state, 'streaming');
  assert.deepEqual(calls, [{ host: '8.8.8.8', port: 443, family: 4, autoSelectFamily: false }]);
  assert.equal(socket.writes.length, 1);
});
test('IPv6 pin accepts equivalent peer notation without DNS re-resolution', async (t) => {
  const socket = new Socket('2606:4700:4700:0:0:0:0:1111'); t.after(() => socket.destroy());
  const a = endpoint(t, { policy: policyWith([v6()]), connector: () => socket }); await within(a.session.ready);
  assert.equal(a.session.state, 'streaming'); assert.deepEqual(a.calls, [['2606:4700:4700::1111', 443, 6]]);
});
for (const [address, port] of [['127.0.0.1', 443], ['1.1.1.1', 443], ['8.8.8.8', 22], [undefined, 443]]) {
  test(`wrong connected peer ${address}:${port} receives no ClientHello`, async (t) => {
    const socket = new Socket(); socket.remoteAddress = address; socket.remotePort = port; t.after(() => socket.destroy());
    const a = endpoint(t, { policy: policyWith([v4()]), connector: () => {
      queueMicrotask(() => socket.emit('connect')); return socket;
    } });
    assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_DESTINATION_PEER');
    assert.equal(socket.writes.length, 0); assert.ok(socket.destroyed); assert.equal(a.session.timers.size, 0);
  });
}
test('mixed private answer blocks combo relay before connector, with no mux fallback', async (t) => {
  const prefix = hello(); assert.equal(classifyComboTlsExitPrefix(prefix, PUBLIC, PSK).status, 'relay');
  const a = endpoint(t, { prefix, policy: policyWith([v4(), v6('::1')]), modeTag: 'combo-tls' });
  assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_DESTINATION'); assert.equal(a.calls.length, 0);
});
test('failed authentication does not invoke resolver', async (t) => {
  const policy = new ExitDestinationPolicy({ lookup: () => assert.fail('must authenticate first') });
  const a = endpoint(t, { policy, vpnSecretBuf: randomBytes(32) });
  assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_DECODE'); assert.equal(a.calls.length, 0);
});
test('denied route spends replay token, preventing repeated DNS with that token', async (t) => {
  let calls = 0;
  const policy = new ExitDestinationPolicy({ lookup: async () => { calls++; return [v4('127.0.0.1')]; } });
  const replayGuard = new EncSniReplayGuard(), prefix = hello();
  const a = endpoint(t, { policy, replayGuard, prefix }); assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_DESTINATION');
  const b = endpoint(t, { policy, replayGuard, prefix }); assert.equal((await within(b.session.closed)).code, 'TLS_RELAY_REPLAY');
  assert.equal(calls, 1); assert.equal(a.calls.length + b.calls.length, 0);
});
for (const earlyClose of [false, true]) test(`pending DNS ${earlyClose ? 'peer close' : 'deadline'} never connects after late success`, async (t) => {
  let resolve, started;
  const began = new Promise((done) => { started = done; });
  const policy = new ExitDestinationPolicy({ lookup: () => { started(); return new Promise((done) => { resolve = done; }); } });
  const a = endpoint(t, { policy, limits: { connectTimeoutMs: 40 } }); await within(began);
  assert.ok(a.inbound.isPaused()); if (earlyClose) a.inbound.destroy();
  const error = await within(a.session.closed); await within(a.session.ready);
  assert.equal(error.code, earlyClose ? 'TLS_RELAY_CLOSED' : 'TLS_RELAY_CONNECT_TIMEOUT');
  assert.equal(a.session.timers.size, 0); resolve([v4()]); await delay(10); assert.equal(a.calls.length, 0);
});
test('DNS and TCP share one absolute connect deadline', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const socket = new Socket(); socket.connecting = true; t.after(() => socket.destroy());
  let resolve, started;
  const began = new Promise((done) => { started = done; });
  const policy = new ExitDestinationPolicy({ lookup: () => { started(); return new Promise((done) => { resolve = done; }); } });
  const a = endpoint(t, { policy, limits: { connectTimeoutMs: 100 }, connector: () => socket });
  await began; t.mock.timers.tick(70); resolve([v4()]);
  await new Promise((done) => setImmediate(done));
  assert.equal(a.calls.length, 1);
  t.mock.timers.tick(29); assert.equal(a.session.signal.aborted, false);
  t.mock.timers.tick(1);
  assert.equal((await a.session.closed).code, 'TLS_RELAY_CONNECT_TIMEOUT');
  assert.equal(a.calls.length, 1); assert.equal(a.session.timers.size, 0); assert.ok(socket.destroyed);
});
test('late resolver rejection after timeout is handled and releases its DNS slot', async (t) => {
  let reject;
  const policy = new ExitDestinationPolicy({ lookup: () => new Promise((_, fail) => { reject = fail; }) });
  const a = endpoint(t, { policy, limits: { connectTimeoutMs: 30 } });
  assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_CONNECT_TIMEOUT');
  await within(a.session.ready); reject(new Error('late secret hostname')); await delay(10);
  assert.equal(a.calls.length, 0); assert.equal(a.session.timers.size, 0);
});
test('timed-out lookup retains its bounded slot until actual DNS settlement', async (t) => {
  const releases = [];
  const policy = new ExitDestinationPolicy({ lookup: () => new Promise((resolve) => releases.push(resolve)) });
  const a = endpoint(t, { policy, limits: { connectTimeoutMs: 30 } });
  assert.equal((await within(a.session.closed)).code, 'TLS_RELAY_CONNECT_TIMEOUT');
  const pending = Array.from({ length: 63 }, () => policy.resolve(HOST, 443));
  await assert.rejects(policy.resolve(HOST, 443), { code: 'TLS_RELAY_DNS_BUSY' });
  assert.equal(releases.length, 64); for (const release of releases) release([v4()]); await Promise.all(pending);
  await delay(5); assert.equal(a.calls.length, 0);
});
test('explicit null/false/plain object cannot disable destination policy', (t) => {
  for (const destinationPolicy of [null, false, {}]) {
    let reason;
    const a = endpoint(t, { destinationPolicy, onSessionError: (error) => { reason = error.code; } });
    assert.equal(a.session, null); assert.equal(reason, 'TLS_RELAY_CONFIG'); assert.ok(a.inbound.destroyed);
  }
});
test('real loopback origin receives zero connections from default exit policy', async (t) => {
  let connections = 0;
  const origin = net.createServer((socket) => { connections++; socket.destroy(); });
  origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
  t.after(() => new Promise((resolve) => origin.close(resolve)));
  const sessions = [];
  const exit = net.createServer((socket) => sessions.push(wireTransparentTlsEncSniSession(socket, { vpnSecretBuf: PSK, publicName: PUBLIC })));
  exit.listen(0, '127.0.0.1'); await once(exit, 'listening');
  t.after(() => new Promise((resolve) => exit.close(resolve)));
  const client = net.connect(exit.address().port, '127.0.0.1'); t.after(() => client.destroy());
  const closed = once(client, 'close'); await once(client, 'connect');
  client.write(hello('127.0.0.1', origin.address().port)); await within(closed);
  assert.equal((await sessions[0].closed).code, 'TLS_RELAY_DESTINATION'); assert.equal(connections, 0);
  assert.equal(sessions[0].timers.size, 0);
});
