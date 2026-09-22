/** State-machine tests complement the real forced-HRR integration tests. */
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createHelloRetryGuard, HELLO_RETRY_RANDOM_HEX } from './lib/transparent-tls-retry.mjs';
import { RelaySession, relayError } from './lib/transparent-tls-io.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';
import { replaceFirstSniInTcpBuffer, restoreFirstSniInTcpBuffer } from './lib/transparent-tls-ch-rebuild.mjs';

const HOST = 'origin.example';
const RELAY = 'opaque-route.relay.example';
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const extension = (type, bytes) => Buffer.concat([u16(type), u16(bytes.length), bytes]);
const CCS = Buffer.from([0x14, 3, 3, 0, 1, 1]);
const ENCRYPTED = Buffer.from([0x17, 3, 3, 0, 3, 1, 2, 3]);

function records(type, body, cuts = []) {
  const hs = Buffer.alloc(4);
  hs[0] = type;
  hs.writeUIntBE(body.length, 1, 3);
  const payload = Buffer.concat([hs, body]);
  const boundaries = [0, ...cuts, payload.length];
  return Buffer.concat(boundaries.slice(1).map((end, i) => {
    const part = payload.subarray(boundaries[i], end);
    return Buffer.concat([Buffer.from([0x16, 3, i % 2 ? 3 : 1]), u16(part.length), part]);
  }));
}

function clientHello({ hostname = HOST, random = 0xab, sid = Buffer.from([7]), cookie = false, cuts = [] } = {}) {
  const host = Buffer.from(hostname);
  const name = Buffer.concat([Buffer.from([0]), u16(host.length), host]);
  const ext = Buffer.concat([
    extension(0, Buffer.concat([u16(name.length), name])),
    extension(43, Buffer.from([2, 3, 4])),
    ...(cookie ? [extension(44, Buffer.from([0, 3, 8, 9, 10]))] : []),
  ]);
  return records(1, Buffer.concat([
    Buffer.from([3, 3]), Buffer.alloc(32, random), Buffer.from([sid.length]), sid,
    Buffer.from([0, 2, 0x13, 1, 1, 0]), u16(ext.length), ext,
  ]), cuts);
}

function serverHello({ retry = true, version = 0x0304, cuts = [], cookie = true } = {}) {
  const ext = Buffer.concat([
    ...(version === 0x0304 ? [extension(43, u16(version))] : []),
    ...(cookie ? [extension(44, Buffer.from([0, 3, 8, 9, 10]))] : []),
  ]);
  return records(2, Buffer.concat([
    Buffer.from([3, 3]), retry ? Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex') : Buffer.alloc(32, 9),
    Buffer.from([1, 7, 0x13, 1, 0]), u16(ext.length), ext,
  ]), cuts);
}

function setup(t, role = 'client', limits) {
  const socket = new PassThrough();
  const session = new RelaySession(socket, { limits });
  const original = clientHello();
  const prefix = role === 'client' ? original : replaceFirstSniInTcpBuffer(original, RELAY).prefixBuf;
  const guard = createHelloRetryGuard(session, {
    parsed: parseFirstTlsClientHelloFromTcpBuf(prefix), prefix, role, relayHost: RELAY, originHost: HOST,
  });
  guard.start();
  t.after(async () => {
    session.fail(relayError('TLS_RELAY_TEST_STOP'));
    await session.closed;
    assert.equal(session.timers.size, 0);
  });
  return { guard, session, socket, prefix };
}

function byteFeed(fn, bytes) {
  const chunks = [];
  for (const byte of bytes) chunks.push(fn(Buffer.from([byte])));
  return Buffer.concat(chunks);
}

for (const role of ['client', 'exit']) {
  test(`${role}: fragmented HRR/CH2, CCS, cookie and record layout roundtrip`, (t) => {
    const { guard } = setup(t, role);
    const hrr = Buffer.concat([CCS, serverHello({ cuts: [1, 3, 17] }), CCS]);
    assert.deepEqual(byteFeed(guard.reverse, hrr), hrr);
    const original = clientHello({ cookie: true, cuts: [1, 2, 3, 60, 61] });
    const encoded = replaceFirstSniInTcpBuffer(original, RELAY);
    assert.ok(encoded.ok);
    const input = role === 'client' ? original : encoded.prefixBuf;
    const output = byteFeed(guard.forward, Buffer.concat([CCS, input]));
    assert.deepEqual(output.subarray(0, CCS.length), CCS);
    const actual = output.subarray(CCS.length);
    assert.equal(parseFirstTlsClientHelloFromTcpBuf(actual).sni[0], role === 'client' ? RELAY : HOST);
    if (role === 'exit') assert.deepEqual(actual, original);
    else assert.deepEqual(restoreFirstSniInTcpBuffer(actual, RELAY, HOST).prefixBuf, original);
    const final = Buffer.concat([serverHello({ retry: false }), CCS, ENCRYPTED]);
    assert.deepEqual(byteFeed(guard.reverse, final), final);
    assert.deepEqual(guard.forward(ENCRYPTED), ENCRYPTED);
  });

  for (const change of ['hostname', 'random', 'sid']) {
    test(`${role}: CH2 ${change} mismatch is rejected before any CH2 bytes leave`, (t) => {
      const { guard } = setup(t, role);
      guard.reverse(serverHello());
      const changed = clientHello({
        hostname: change === 'hostname' ? 'other.example' : role === 'client' ? HOST : RELAY,
        random: change === 'random' ? 4 : 0xab,
        sid: change === 'sid' ? Buffer.from([8]) : Buffer.from([7]),
      });
      assert.equal(guard.forward(changed.subarray(0, -1)).length, 0);
      assert.throws(() => guard.forward(changed.subarray(-1)), { code: 'TLS_RELAY_RETRY_IDENTITY' });
    });
  }

  test(`${role}: unsolicited CH2, then duplicate HRR after a retry, fail closed`, (t) => {
    const { guard } = setup(t, role);
    const second = clientHello({ hostname: role === 'client' ? HOST : RELAY });
    assert.throws(() => guard.forward(second), { code: 'TLS_RELAY_RETRY_SEQUENCE' });
    guard.reverse(serverHello());
    guard.forward(second);
    assert.throws(() => guard.reverse(serverHello()), { code: 'TLS_RELAY_RETRY_SEQUENCE' });
  });
}

test('TLS 1.3 offer with a normal TLS 1.2 ServerHello enters raw forwarding', (t) => {
  const { guard, session } = setup(t);
  const hello = serverHello({ retry: false, version: 0x0303, cookie: false });
  assert.deepEqual(guard.reverse(hello), hello);
  const opaque = Buffer.from([0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 1, 1]);
  assert.deepEqual(guard.forward(opaque), opaque);
  assert.equal(session.timers.size, 0);
});

test('dummy CCS and early-data records do not disable HRR inspection', (t) => {
  const { guard } = setup(t);
  const early = Buffer.concat([CCS, ENCRYPTED]);
  assert.deepEqual(guard.forward(early), early);
  guard.reverse(serverHello());
  const rewritten = guard.forward(clientHello());
  assert.equal(parseFirstTlsClientHelloFromTcpBuf(rewritten).sni[0], RELAY);
});

test('malformed CCS, interleaved records and HRR without TLS 1.3 are rejected', (t) => {
  const one = setup(t).guard;
  assert.throws(() => one.reverse(Buffer.from([0x14, 3, 3, 0, 1, 2])), { code: 'TLS_RELAY_RETRY_CCS' });
  const two = setup(t).guard;
  assert.throws(() => two.reverse(serverHello({ version: 0x0303 })), { code: 'TLS_RELAY_SERVER_HELLO' });
  const three = setup(t).guard;
  const fragmented = serverHello({ cuts: [2] });
  assert.equal(three.reverse(fragmented.subarray(0, 7)).length, 0);
  assert.throws(() => three.reverse(CCS), { code: 'TLS_RELAY_RETRY_SEQUENCE' });
});

test('CH2 coalesced with another handshake cannot leak it around the guard', (t) => {
  const { guard } = setup(t);
  guard.reverse(serverHello());
  const first = clientHello();
  const input = Buffer.concat([first, first.subarray(5)]);
  input.writeUInt16BE(input.length - 5, 3);
  assert.throws(() => guard.forward(input), { code: 'TLS_RELAY_RETRY_SEQUENCE' });
});

test('coalesced initial TLS 1.3 handshake suffix is rejected before a bridge is created', (t) => {
  const { session } = setup(t);
  const first = clientHello();
  const prefix = Buffer.concat([first, Buffer.from([1, 0])]);
  prefix.writeUInt16BE(prefix.length - 5, 3);
  assert.throws(() => createHelloRetryGuard(session, {
    parsed: parseFirstTlsClientHelloFromTcpBuf(prefix), prefix, role: 'client', relayHost: RELAY, originHost: HOST,
  }), { code: 'TLS_RELAY_RETRY_SEQUENCE' });
});

test('record and fragmented handshake limits reject without waiting for more data', (t) => {
  const one = setup(t, 'client', { maxHelloBytes: 100 }).guard;
  one.reverse(serverHello());
  assert.throws(() => one.forward(Buffer.from([0x16, 3, 3, 0, 101])), { code: 'TLS_RELAY_HANDSHAKE_LIMIT' });
  const two = setup(t, 'client', { maxHelloBytes: 100 }).guard;
  two.reverse(serverHello());
  const fragmented = clientHello({ cuts: Array.from({ length: 50 }, (_, i) => i + 1) });
  assert.throws(() => two.forward(fragmented), { code: 'TLS_RELAY_HANDSHAKE_LIMIT' });
  const three = setup(t, 'client', { maxPendingBytes: 32 }).guard;
  three.reverse(serverHello());
  assert.throws(() => three.forward(clientHello()), { code: 'TLS_RELAY_PENDING_LIMIT' });
});

test('EOF in partial CH2 is rejected; abort clears the handshake deadline', (t) => {
  const { guard, session } = setup(t);
  guard.reverse(serverHello());
  guard.forward(clientHello().subarray(0, 8));
  assert.throws(() => guard.end('client'), { code: 'TLS_RELAY_HANDSHAKE_EOF' });
  session.fail(relayError('TLS_RELAY_TEST_ABORT'));
  assert.equal(session.timers.size, 0);
  assert.throws(() => guard.forward(Buffer.alloc(0)), { code: 'TLS_RELAY_TEST_ABORT' });
});

for (const phase of ['server-first', 'client-retry', 'server-final']) {
  test(`${phase}: absolute handshake deadline is not prolonged by CCS`, { timeout: 2000 }, async (t) => {
    const { guard, session } = setup(t, 'client', { helloTimeoutMs: 60 });
    if (phase !== 'server-first') guard.reverse(serverHello());
    if (phase === 'server-final') guard.forward(clientHello());
    for (let i = 0; i < 10 && !session.signal.aborted; i++) {
      guard.reverse(CCS);
      await delay(15);
    }
    assert.ok(session.signal.aborted);
    assert.equal((await session.closed).code, 'TLS_RELAY_HANDSHAKE_TIMEOUT');
    assert.equal(session.timers.size, 0);
  });
}
