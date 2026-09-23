/** Replay admission, not application exactly-once or TLS 0-RTT replay policy. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import net from 'node:net';
import { Duplex } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { EncSniReplayGuard, ENC_SNI_REPLAY_RETENTION_MS } from './lib/transparent-tls-replay.mjs';
import { ExitDestinationPolicy } from './lib/transparent-tls-destination.mjs';
import { encodeRelayHostname, decodeRelayFromHostname, parseRelayEncLabels } from './lib/transparent-tls-enc-sni.mjs';
import { wireTransparentTlsEncSniSession, classifyComboTlsExitPrefix } from './lib/transparent-tls-runtime.mjs';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';
import { replaceFirstSniInTcpBuffer } from './lib/transparent-tls-ch-rebuild.mjs';
import { HELLO_RETRY_RANDOM_HEX } from './lib/transparent-tls-retry.mjs';

const PUBLIC = 'relay.test', PSK = randomBytes(32), ORIGIN = 'origin.test';
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
function hello(name, random = 7, tls13 = false) {
  const h = Buffer.from(name), sni = Buffer.concat([u16(h.length + 3), Buffer.from([0]), u16(h.length), h]);
  const exts = Buffer.concat([u16(0), u16(sni.length), sni, ...(tls13 ? [Buffer.from([0, 43, 0, 3, 2, 3, 4])] : [])]);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, random), Buffer.from([0, 0, 2, 0x13, 1, 1, 0]), u16(exts.length), exts]);
  const hs = Buffer.alloc(4); hs[0] = 1; hs.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(body.length + 4), hs, body]);
}
const token = () => encodeRelayHostname(PSK, { hostname: ORIGIN, port: 443 }, PUBLIC);
const metadata = (key, issuedAtSeconds) => ({ replayId: createHash('sha256').update(String(key)).digest('hex'), issuedAtSeconds });
function clockGuard(maxEntries = 2) {
  let now = 1_700_000_000_000;
  const guard = new EncSniReplayGuard({ maxEntries, now: () => now });
  return { guard, get now() { return now; }, set now(value) { now = value; }, meta: (id, offset = 0) => metadata(id, Math.floor(now / 1000) + offset) };
}

test('default replay budget is bounded and has no per-entry timer', () => {
  const before = process.getActiveResourcesInfo().filter((x) => x === 'Timeout').length;
  const guard = new EncSniReplayGuard();
  guard.consume(metadata('test', Math.floor(Date.now() / 1000)));
  assert.deepEqual(guard.stats(), { entries: 1, maxEntries: 65536, retentionMs: 601000 });
  assert.equal(process.getActiveResourcesInfo().filter((x) => x === 'Timeout').length, before);
  assert.deepEqual(Object.keys(guard), [], 'cache material is private');
});
for (const maxEntries of [0, -1, 65537, 1.5, Infinity, NaN, '4']) {
  test(`replay guard rejects invalid capacity ${maxEntries}`, () => assert.throws(() => new EncSniReplayGuard({ maxEntries }), { code: 'TLS_RELAY_CONFIG' }));
}
test('same authenticated token is consumed once, with no live-entry eviction at capacity', () => {
  const c = clockGuard(1), a = c.meta('a'); c.guard.consume(a);
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY' });
  assert.throws(() => c.guard.consume(c.meta('b')), { code: 'TLS_RELAY_REPLAY_FULL' });
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY' });
  assert.equal(c.guard.stats().entries, 1);
});
test('future-skew token remains reserved through inclusive second boundary', () => {
  const c = clockGuard(1), a = c.meta('future', 300); c.guard.consume(a);
  c.now += 600999;
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY' });
  assert.throws(() => c.guard.consume(c.meta('b')), { code: 'TLS_RELAY_REPLAY_FULL' });
  c.now++;
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY_STALE' });
  c.guard.consume(c.meta('b')); assert.equal(c.guard.stats().entries, 1);
});
test('fixed retention keeps insertion-ordered pruning valid for differently skewed timestamps', () => {
  const c = clockGuard(), a = c.meta('a', 300); c.guard.consume(a);
  c.now += 1000; c.guard.consume(c.meta('b', -300));
  c.now += ENC_SNI_REPLAY_RETENTION_MS - 1000;
  c.guard.consume(c.meta('c')); assert.equal(c.guard.stats().entries, 2);
  assert.throws(() => c.guard.consume(c.meta('d')), { code: 'TLS_RELAY_REPLAY_FULL' });
  c.now += 1000; c.guard.consume(c.meta('d')); assert.equal(c.guard.stats().entries, 2);
});
test('backward clock cannot resurrect a token after its old cache record was purged', () => {
  const c = clockGuard(1), start = c.now, a = c.meta('a'); c.guard.consume(a);
  c.now += ENC_SNI_REPLAY_RETENTION_MS; c.guard.consume(c.meta('b'));
  const high = c.now; c.now = start;
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY_CLOCK' });
  c.now = high;
  assert.throws(() => c.guard.consume(a), { code: 'TLS_RELAY_REPLAY_STALE' });
  c.now += ENC_SNI_REPLAY_RETENTION_MS; c.guard.consume(c.meta('c'));
});
for (const invalid of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
  test(`invalid replay clock fails closed: ${invalid}`, () => {
    const guard = new EncSniReplayGuard({ now: () => invalid });
    assert.throws(() => guard.consume(metadata('a', 1)), { code: 'TLS_RELAY_REPLAY_CLOCK' });
    assert.equal(guard.stats().entries, 0);
  });
}
test('expired/future or malformed admission metadata does not fill the cache', () => {
  const c = clockGuard();
  for (const offset of [-301, 301]) assert.throws(() => c.guard.consume(c.meta('a', offset)), { code: 'TLS_RELAY_REPLAY_STALE' });
  for (const value of [{}, { replayId: 'raw token', issuedAtSeconds: 1 }, { ...c.meta('a'), issuedAtSeconds: -1 }]) {
    assert.throws(() => c.guard.consume(value), { code: 'TLS_RELAY_CONFIG' });
  }
  assert.equal(c.guard.stats().entries, 0);
});
test('authenticated replay identity survives alternative DNS label cuts and public suffix case', () => {
  const original = token(), blob = parseRelayEncLabels(original, PUBLIC).join('');
  const alias = `${blob.match(/.{1,17}/g).join('.')}..RELAY.TEST`;
  const a = decodeRelayFromHostname(original, PUBLIC, PSK), b = decodeRelayFromHostname(alias, PUBLIC, PSK);
  assert.equal(a.ok, true); assert.equal(b.ok, true); assert.equal(a.replayId, b.replayId);
  const guard = new EncSniReplayGuard(); guard.consume(a);
  assert.throws(() => guard.consume(b), { code: 'TLS_RELAY_REPLAY' });
  const next = decodeRelayFromHostname(token(), PUBLIC, PSK);
  assert.notEqual(next.replayId, a.replayId); guard.consume(next);
});
test('real authenticated future timestamp stays protected for its entire inclusive decode window', (t) => {
  let now = 1_700_000_300_000;
  t.mock.method(Date, 'now', () => now);
  const name = token(); now -= 300000;
  const guard = new EncSniReplayGuard({ maxEntries: 1, now: () => now });
  const first = decodeRelayFromHostname(name, PUBLIC, PSK); assert.equal(first.ok, true); guard.consume(first);
  now += 600999;
  const last = decodeRelayFromHostname(name, PUBLIC, PSK); assert.equal(last.ok, true);
  assert.throws(() => guard.consume(last), { code: 'TLS_RELAY_REPLAY' });
  now++;
  assert.equal(decodeRelayFromHostname(name, PUBLIC, PSK).ok, false);
  guard.consume(decodeRelayFromHostname(token(), PUBLIC, PSK)); assert.equal(guard.stats().entries, 1);
});
test('full default capacity is bounded and old entries prune before admitting fresh traffic', () => {
  const c = clockGuard(65536);
  for (let i = 0; i < 65536; i++) c.guard.consume(c.meta(i));
  assert.equal(c.guard.stats().entries, 65536);
  assert.throws(() => c.guard.consume(c.meta('overflow')), { code: 'TLS_RELAY_REPLAY_FULL' });
  assert.throws(() => c.guard.consume(c.meta(0)), { code: 'TLS_RELAY_REPLAY' });
  c.now += ENC_SNI_REPLAY_RETENTION_MS;
  c.guard.consume(c.meta('fresh')); assert.equal(c.guard.stats().entries, 1);
});
test('local cache scope does not claim durable or multi-process replay prevention', () => {
  const dec = decodeRelayFromHostname(token(), PUBLIC, PSK);
  new EncSniReplayGuard().consume(dec);
  assert.doesNotThrow(() => new EncSniReplayGuard().consume(dec));
});

class Socket extends Duplex {
  constructor() { super(); this.connecting = false; this.remoteAddress = '127.0.0.1'; this.remotePort = 443; this.writes = []; }
  _read() {}
  _write(bytes, encoding, callback) { this.writes.push(Buffer.from(bytes)); callback(); }
}
async function within(promise, ms = 2000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test deadline')), ms); })]); }
  finally { clearTimeout(timer); }
}
function endpoint(t, prefix, { guard, failConnect = false, modeTag, psk = PSK } = {}) {
  const inbound = new Socket(), outbound = new Socket();
  let calls = 0;
  const session = wireTransparentTlsEncSniSession(inbound, { vpnSecretBuf: psk, publicName: PUBLIC,
    initialBuf: prefix, ...(guard ? { replayGuard: guard } : {}), modeTag,
    destinationPolicy: new ExitDestinationPolicy({ loopback: { hostname: ORIGIN, port: 443 } }),
    connectOrigin: () => { calls++; if (failConnect) throw new Error('test connector failure'); return outbound; } });
  t.after(async () => { inbound.destroy(); outbound.destroy(); await session?.closed; });
  return { inbound, outbound, session, get calls() { return calls; } };
}
test('process default rejects concurrent admissions across transparent/combo callers before connect', async (t) => {
  const prefix = hello(token());
  const a = endpoint(t, prefix), b = endpoint(t, prefix, { modeTag: 'combo-tls' });
  await within(Promise.all([a.session.ready, b.session.ready]));
  assert.equal(a.calls + b.calls, 1);
  assert.equal((await within(b.session.closed)).code, 'TLS_RELAY_REPLAY');
  assert.equal(a.outbound.writes.length, 1); assert.equal(b.outbound.writes.length, 0);
});
test('token stays spent after connector failure and changed ClientHello random', async (t) => {
  const name = token(), guard = new EncSniReplayGuard();
  const a = endpoint(t, hello(name), { guard, failConnect: true }); await within(a.session.closed);
  assert.equal(a.calls, 1);
  const b = endpoint(t, hello(name, 8), { guard });
  assert.equal((await within(b.session.closed)).code, 'TLS_RELAY_REPLAY'); assert.equal(b.calls, 0);
});
test('unauthenticated ciphertext/wrong PSK cannot consume a replay slot', async (t) => {
  const guard = new EncSniReplayGuard({ maxEntries: 1 }), name = token();
  const bad = endpoint(t, hello(name), { guard, psk: randomBytes(32) });
  assert.equal((await within(bad.session.closed)).code, 'TLS_RELAY_DECODE'); assert.equal(guard.stats().entries, 0);
  const good = endpoint(t, hello(name), { guard }); await within(good.session.ready);
  assert.equal(good.calls, 1); assert.equal(guard.stats().entries, 1);
});
test('combo classification is stateless and never downgrades a seen valid token to TLS mux', async (t) => {
  const prefix = hello(token()), guard = new EncSniReplayGuard();
  for (let i = 0; i < 3; i++) assert.equal(classifyComboTlsExitPrefix(prefix, PUBLIC, PSK).status, 'relay');
  assert.equal(guard.stats().entries, 0);
  const first = endpoint(t, prefix, { guard }); await within(first.session.ready);
  assert.equal(classifyComboTlsExitPrefix(prefix, PUBLIC, PSK).status, 'relay');
  const second = endpoint(t, prefix, { guard, modeTag: 'combo-tls' });
  assert.equal((await within(second.session.closed)).code, 'TLS_RELAY_REPLAY'); assert.equal(second.calls, 0);
});
test('valid HRR/CH2 stays in its existing admission; separate CH2 connection does not', async (t) => {
  const guard = new EncSniReplayGuard({ maxEntries: 1 }), name = token(), original = hello(name, 7, true);
  const e = endpoint(t, original, { guard }); await within(e.session.ready);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex'),
    Buffer.from([0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4])]);
  e.outbound.push(Buffer.concat([Buffer.from([0x16, 3, 3, 0, body.length + 4, 2, 0, 0, body.length]), body]));
  await delay(0); e.inbound.push(original); await delay(0);
  assert.equal(e.outbound.writes.length, 2); assert.equal(e.calls, 1); assert.equal(guard.stats().entries, 1);
  const newConnection = endpoint(t, original, { guard });
  assert.equal((await within(newConnection.session.closed)).code, 'TLS_RELAY_REPLAY'); assert.equal(newConnection.calls, 0);
});
test('changing the token in CH2 fails the existing identity guard without a second admission', async (t) => {
  const guard = new EncSniReplayGuard(), name = token(), e = endpoint(t, hello(name, 7, true), { guard });
  await within(e.session.ready);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex'),
    Buffer.from([0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4])]);
  e.outbound.push(Buffer.concat([Buffer.from([0x16, 3, 3, 0, body.length + 4, 2, 0, 0, body.length]), body]));
  await delay(0); e.inbound.push(hello(token(), 7, true));
  assert.equal((await within(e.session.closed)).code, 'TLS_RELAY_RETRY_IDENTITY');
  assert.equal(e.calls, 1); assert.equal(e.outbound.writes.length, 1); assert.equal(guard.stats().entries, 1);
});
test('closing an admitted connection never releases its token reservation', async (t) => {
  const guard = new EncSniReplayGuard(), name = token(), first = endpoint(t, hello(name), { guard });
  await within(first.session.ready); first.inbound.destroy(); await within(first.session.closed);
  const second = endpoint(t, hello(name), { guard });
  assert.equal((await within(second.session.closed)).code, 'TLS_RELAY_REPLAY'); assert.equal(second.calls, 0);
});
test('default replay errors/logs contain neither token nor replay hash nor plaintext destination', async (t) => {
  const messages = [];
  t.mock.method(console, 'log', (...args) => messages.push(args.join(' ')));
  t.mock.method(console, 'error', (...args) => messages.push(args.join(' ')));
  const name = token(), dec = decodeRelayFromHostname(name, PUBLIC, PSK), guard = new EncSniReplayGuard();
  const first = endpoint(t, hello(name), { guard }); await within(first.session.ready);
  const second = endpoint(t, hello(name), { guard }); await within(second.session.closed);
  const log = messages.join('\n'); assert.ok(log.includes('TLS_RELAY_REPLAY'));
  for (const secret of [name, dec.replayId, ORIGIN, PSK.toString('hex')]) assert.equal(log.includes(secret), false);
});
test('full replay cache rejects fresh tokens before outgoing connect', async (t) => {
  const guard = new EncSniReplayGuard({ maxEntries: 1 });
  const a = endpoint(t, hello(token()), { guard }); await within(a.session.ready);
  const b = endpoint(t, hello(token()), { guard });
  assert.equal((await within(b.session.closed)).code, 'TLS_RELAY_REPLAY_FULL'); assert.equal(b.calls, 0);
});
test('invalid explicit guard cannot disable default replay checking', async () => {
  for (const replayGuard of [null, false, {}]) {
    const socket = new Socket(); let reason;
    assert.equal(wireTransparentTlsEncSniSession(socket, { replayGuard, onSessionError: (e) => { reason = e.code; } }), null);
    assert.equal(socket.destroyed, true); assert.equal(reason, 'TLS_RELAY_CONFIG');
  }
});

async function replay(lab, prefix) {
  const socket = net.connect(lab.exitPort, lab.host); socket.on('error', () => {}); socket.resume();
  try {
    const closed = new Promise((resolve) => socket.once('close', resolve));
    await once(socket, 'connect'); socket.write(prefix); await within(closed);
  } finally { socket.destroy(); }
}
for (const hrr of [false, true]) test(`real TLS${hrr ? ' HRR' : ''}: captured wire token cannot create another origin connection`, { timeout: 8000 }, async (t) => {
  const lab = await startTransparentTlsLab({ originTls: hrr ? { ecdhCurve: 'P-256' } : {} });
  t.after(() => lab.close());
  await requestThroughLab(lab, { httpVersion: '2' });
  const wire = lab.captures.filter((c) => c.stage === 'exit');
  assert.equal(wire.length, hrr ? 2 : 1); assert.equal(lab.stats().replay.entries, 1);
  for (const capture of wire) assertRelayTrace(lab, capture.id, capture.flight);
  const before = lab.stats().originConnections;
  const blob = parseRelayEncLabels(wire[0].sni, lab.publicName).join('');
  const alias = `${blob.match(/.{1,19}/g).join('.')}.${lab.publicName.toUpperCase()}`;
  const rewritten = replaceFirstSniInTcpBuffer(wire[0].prefix, alias); assert.equal(rewritten.ok, true);
  await Promise.all([replay(lab, wire[0].prefix), replay(lab, rewritten.prefixBuf), ...(hrr ? [replay(lab, wire[1].prefix)] : [])]);
  assert.equal(lab.stats().originConnections, before);
  assert.equal(lab.runtimeErrors.filter((e) => e.role === 'exit' && e.code === 'TLS_RELAY_REPLAY').length, hrr ? 3 : 2);
  await requestThroughLab(lab, { httpVersion: '2' });
  assert.equal(lab.stats().originConnections, before + 1); assert.equal(lab.stats().replay.entries, 2);
});
