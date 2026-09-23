/** Runtime hardening regressions. Harness idle timers are explicitly disabled. */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import net from 'node:net';
import { Duplex } from 'node:stream';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';
import { RelaySession, relayError, relayLimits } from './lib/transparent-tls-io.mjs';
import { attachTransparentTlsClientSession, wireTransparentTlsEncSniSession,
  logEncSniWire, logComboTlsExitBranch } from './lib/transparent-tls-runtime.mjs';
import { buildRelayHostname, encodeRelaySniLabel } from './lib/transparent-tls-enc-sni.mjs';
import { replaceFirstSniInTcpBuffer, restoreFirstSniInTcpBuffer } from './lib/transparent-tls-ch-rebuild.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';
import { HELLO_RETRY_RANDOM_HEX } from './lib/transparent-tls-retry.mjs';
import { EncSniReplayGuard } from './lib/transparent-tls-replay.mjs';

async function within(promise, ms = 1500) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('test deadline: runtime did not finish')), ms);
    })]);
  } finally { clearTimeout(timer); }
}

// Controllable Duplex: no kernel buffer sizes or external blackhole addresses.
class TestSocket extends Duplex {
  constructor({ blocked = false } = {}) {
    super({ highWaterMark: 16 });
    this.connecting = true;
    this.blocked = blocked;
    this.writes = [];
    this.pending = [];
  }
  _read() {}
  _write(chunk, encoding, callback) {
    this.writes.push(Buffer.from(chunk));
    if (this.blocked) this.pending.push(callback);
    else callback();
  }
  _destroy(error, callback) {
    for (const done of this.pending.splice(0)) done();
    callback(error);
  }
  unblock() {
    this.blocked = false;
    for (const callback of this.pending.splice(0)) callback();
  }
  connected() { this.connecting = false; this.emit('connect'); }
  bytes() { return Buffer.concat(this.writes); }
}

const PSK = Buffer.alloc(32, 42);
const PUBLIC = 'relay.example';
const HOST = 'origin.example';
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
function hello(hostname, tls13 = false, { noSni = false, ech = false } = {}) {
  const host = Buffer.from(hostname);
  const sni = Buffer.concat([u16(host.length + 3), Buffer.from([0]), u16(host.length), host]);
  const ext = Buffer.concat([
    ...(noSni ? [] : [u16(0), u16(sni.length), sni]),
    ...(tls13 ? [Buffer.from([0, 43, 0, 3, 2, 3, 4])] : []),
    // Opaque synthetic ECH bytes for the routing-policy test, NOT an ECH handshake.
    ...(ech ? [Buffer.from([0xfe, 0x0d, 0, 1, 0])] : []),
  ]);
  const body = Buffer.concat([
    Buffer.from([3, 3]), Buffer.alloc(32, 0xab), Buffer.from([0, 0, 2, 0x13, 1, 1, 0]), u16(ext.length), ext,
  ]);
  const hs = Buffer.alloc(4);
  hs[0] = 1;
  hs.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(body.length + 4), hs, body]);
}
const originalHello = hello(HOST);
const encodedName = buildRelayHostname(encodeRelaySniLabel(PSK, { hostname: HOST, port: 443 }), PUBLIC);
const encodedHello = replaceFirstSniInTcpBuffer(originalHello, encodedName).prefixBuf;

function endpoint(t, role, limits = {}, { blocked = false, connectorError, tls13 = false } = {}) {
  const inbound = new TestSocket();
  const outbound = new TestSocket({ blocked });
  let resolveConnecting;
  const connecting = new Promise((resolve) => { resolveConnecting = resolve; });
  let calls = 0;
  const errors = [];
  const connector = () => {
    calls++;
    resolveConnecting();
    if (connectorError) throw connectorError;
    return outbound;
  };
  const options = {
    // Each synthetic endpoint is an independent exit fixture; its constant token
    // is intentionally reused across unrelated tests, not across live admissions.
    replayGuard: new EncSniReplayGuard(),
    vpnSecretBuf: PSK, publicName: PUBLIC, limits, onSessionError: (e) => errors.push(e),
    explicitDestination: { address: '127.0.0.1', port: 443 },
    upstreamHost: '127.0.0.1', upstreamPort: 12345,
    connectExit: connector, connectOrigin: connector,
  };
  const session = role === 'exit' ? wireTransparentTlsEncSniSession(inbound, options) : null;
  const ready = role === 'client'
    ? attachTransparentTlsClientSession(inbound, options).then((value) => ({ session: value }), (error) => ({ error }))
    : session.ready.then(() => ({ session, error: errors[0] }));
  t.after(() => { inbound.destroy(); outbound.destroy(); });
  return {
    inbound, outbound, ready, connecting, errors, session,
    hello: tls13 ? (role === 'client' ? hello(HOST, true) : replaceFirstSniInTcpBuffer(hello(HOST, true), encodedName).prefixBuf)
      : role === 'client' ? originalHello : encodedHello,
    get calls() { return calls; },
  };
}

for (const role of ['client', 'exit']) {
  test(`${role}: opaque ECH without outer SNI is rejected before any outgoing connection`, async (t) => {
    const e = endpoint(t, role);
    e.inbound.push(hello(HOST, true, { noSni: true, ech: true }));
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_HELLO');
    assert.equal(e.calls, 0, 'no fallback to original IP, inner-name guessing or raw transport');
    assert.ok(e.inbound.destroyed);
  });

  test(`${role}: coalesced TLS 1.3 ClientHello cannot bypass retry inspection`, async (t) => {
    const e = endpoint(t, role, {}, { tls13: true });
    const input = Buffer.concat([e.hello, e.hello.subarray(5)]);
    input.writeUInt16BE(input.length - 5, 3);
    e.inbound.push(input);
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_RETRY_SEQUENCE');
    assert.equal(e.calls, 0);
    assert.ok(e.inbound.destroyed);
  });

  for (const stall of [false, true]) {
    test(`${role}: CH2 backpressure ${stall ? 'expires' : 'drains without losing bytes'}`, async (t) => {
      const e = endpoint(t, role, { writeTimeoutMs: 60 }, { tls13: true });
      e.inbound.push(e.hello);
      await within(e.connecting);
      e.outbound.connected();
      const { session, error } = await within(e.ready);
      assert.ifError(error);
      const firstLength = e.outbound.bytes().length;
      const body = Buffer.concat([Buffer.from([3, 3]), Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex'),
        Buffer.from([0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4])]);
      const header = Buffer.from([0x16, 3, 3, 0, body.length + 4, 2, 0, 0, body.length]);
      e.outbound.push(Buffer.concat([header, body]));
      await delay(0);
      e.outbound.blocked = true;
      e.inbound.push(e.hello);
      await delay(0);
      assert.ok(e.inbound.isPaused());
      const second = e.outbound.bytes().subarray(firstLength);
      const first = parseFirstTlsClientHelloFromTcpBuf(e.outbound.bytes()).sni[0];
      assert.equal(parseFirstTlsClientHelloFromTcpBuf(second).sni[0], first);
      if (stall) {
        assert.equal((await within(session.closed)).code, 'TLS_RELAY_WRITE_TIMEOUT');
      } else {
        e.outbound.unblock();
        await delay(0);
        assert.equal(e.inbound.isPaused(), false);
        assert.equal(e.outbound.bytes().length, firstLength + second.length);
        session.fail(relayError('TLS_RELAY_TEST_STOP'));
        await within(session.closed);
      }
      assert.equal(e.outbound.listenerCount('drain'), 0);
      assert.equal(session.timers.size, 0);
      assert.equal(e.calls, 1, 'retry never opens another origin/exit connection');
    });
  }

  test(`${role}: connection deadline and teardown without harness`, async (t) => {
    const e = endpoint(t, role, { connectTimeoutMs: 40 });
    e.inbound.push(e.hello);
    const result = await within(e.ready);
    assert.equal(result.error.code, 'TLS_RELAY_CONNECT_TIMEOUT');
    assert.ok(e.inbound.destroyed && e.outbound.destroyed);
    assert.equal(e.outbound.listenerCount('connect'), 0);
    assert.equal(e.errors.length, 1);
    if (result.session) assert.equal(result.session.timers.size, 0);
  });

  test(`${role}: bytes coalesced with hello and arriving during connect are ordered`, async (t) => {
    const e = endpoint(t, role, {}, { blocked: true });
    const tail = Buffer.from('coalesced tail');
    const later = Buffer.from('arrived during connect');
    e.inbound.push(Buffer.concat([e.hello, tail]));
    await within(e.connecting);
    assert.ok(e.inbound.isPaused());
    e.inbound.push(later);
    e.outbound.connected();
    await delay(0);
    assert.ok(e.inbound.isPaused(), 'prelude backpressure keeps source paused');
    e.outbound.unblock();
    const { session, error } = await within(e.ready);
    assert.ifError(error);
    await delay(0);
    let actual = e.outbound.bytes();
    if (role === 'client') {
      // Token encryption is randomized; restore the emitted SNI before comparison.
      const name = parseFirstTlsClientHelloFromTcpBuf(actual).sni[0];
      const restored = restoreFirstSniInTcpBuffer(actual, name, HOST);
      assert.ok(restored.ok);
      actual = Buffer.concat([restored.prefixBuf, actual.subarray(actual.readUInt16BE(3) + 5)]);
    }
    assert.deepEqual(actual, Buffer.concat([originalHello, tail, later]));
    session.fail(relayError('TLS_RELAY_TEST_STOP'));
    assert.equal(session.timers.size, 0);
  });

  test(`${role}: prelude limit refuses connector before any outgoing socket`, async (t) => {
    const e = endpoint(t, role, { maxPendingBytes: 256 });
    e.inbound.push(Buffer.concat([e.hello, Buffer.alloc(257)]));
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_PENDING_LIMIT');
    assert.equal(e.calls, 0);
  });

  test(`${role}: unsupported record growth or oversized input fails before connecting`, async (t) => {
    const e = endpoint(t, role);
    const size = role === 'client' ? 16384 : 16385;
    const input = Buffer.alloc(5 + size);
    e.hello.copy(input);
    input.writeUInt16BE(size, 3);
    e.inbound.push(input);
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_REBUILD');
    assert.equal(e.calls, 0);
    assert.ok(e.inbound.destroyed);
    assert.equal(e.outbound.bytes().length, 0);
  });

  test(`${role}: fragmented ClientHello preserves same-record suffix and following records`, async (t) => {
    const e = endpoint(t, role);
    const suffix = Buffer.from([0x0b, 0, 0, 2, 0xaa, 0xbb]);
    const tail = Buffer.from([0x14, 3, 3, 0, 1, 1, 0x17, 3]);
    const payload = Buffer.concat([originalHello.subarray(5), suffix]);
    const split = payload.indexOf(Buffer.from(HOST)) + 1;
    const records = [payload.subarray(0, split), payload.subarray(split)].map((body) => {
      const header = Buffer.from([0x16, 3, 1, 0, 0]);
      header.writeUInt16BE(body.length, 3);
      return Buffer.concat([header, body]);
    });
    const original = Buffer.concat([...records, tail]);
    const encoded = replaceFirstSniInTcpBuffer(original, encodedName);
    assert.ok(encoded.ok);
    const input = role === 'client' ? original : Buffer.concat([encoded.prefixBuf, encoded.tailAfterPrefix]);
    e.inbound.push(input);
    await within(e.connecting);
    e.outbound.connected();
    const { session, error } = await within(e.ready);
    assert.ifError(error);
    const actual = e.outbound.bytes();
    if (role === 'client') {
      const name = parseFirstTlsClientHelloFromTcpBuf(actual).sni[0];
      const restored = restoreFirstSniInTcpBuffer(actual, name, HOST);
      assert.ok(restored.ok);
      assert.deepEqual(Buffer.concat([restored.prefixBuf, restored.tailAfterPrefix]), input);
    } else {
      assert.deepEqual(actual, original);
      const parsed = parseFirstTlsClientHelloFromTcpBuf(actual);
      assert.deepEqual(actual.subarray(parsed.bytesConsumed), tail);
      assert.deepEqual(actual.subarray(parsed.bytesConsumed - suffix.length, parsed.bytesConsumed), suffix);
    }
    session.fail(relayError('TLS_RELAY_TEST_STOP'));
    await within(session.closed);
    assert.equal(session.timers.size, 0);
  });

  test(`${role}: peer disconnect cancels connect and ignores late connect`, async (t) => {
    const e = endpoint(t, role);
    e.inbound.push(e.hello);
    await within(e.connecting);
    e.inbound.destroy();
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_CLOSED');
    e.outbound.connected();
    await delay(0);
    assert.ok(e.outbound.destroyed);
    assert.equal(e.outbound.bytes().length, 0);
    assert.equal(e.outbound.listenerCount('connect'), 0);
  });

  test(`${role}: stalled initial write expires and removes drain listener`, async (t) => {
    const e = endpoint(t, role, { writeTimeoutMs: 40 }, { blocked: true });
    e.inbound.push(e.hello);
    await within(e.connecting);
    e.outbound.connected();
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_WRITE_TIMEOUT');
    assert.equal(e.outbound.listenerCount('drain'), 0);
    assert.ok(e.inbound.destroyed && e.outbound.destroyed);
  });

  test(`${role}: abort during drain clears waiters and handles queued socket errors`, async (t) => {
    const e = endpoint(t, role, {}, { blocked: true });
    e.inbound.push(e.hello);
    await within(e.connecting);
    e.outbound.connected();
    await delay(0);
    assert.equal(e.outbound.listenerCount('drain'), 1);
    e.inbound.destroy(new Error('test disconnect'));
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_SOCKET');
    assert.equal(e.outbound.listenerCount('drain'), 0);
    assert.ok(e.outbound.destroyed);
    assert.equal(e.errors.length, 1);
  });

  test(`${role}: connector errors expose a stable code, not a hostname`, async (t) => {
    const e = endpoint(t, role, {}, { connectorError: new Error(`getaddrinfo ENOTFOUND ${HOST}`) });
    e.inbound.push(e.hello);
    const { error } = await within(e.ready);
    assert.equal(error.code, 'TLS_RELAY_CONNECT');
    assert.ok(!error.message.includes(HOST));
  });
}

for (const reverse of [false, true]) {
  test(`streaming backpressure ${reverse ? 'reverse' : 'forward'} pauses, resumes, then times out`, async () => {
    const a = new TestSocket();
    const b = new TestSocket();
    const session = new RelaySession(a, { limits: { writeTimeoutMs: 60 } });
    session.add(b);
    try {
      await session.bridge(a, b, Buffer.alloc(0));
      const [source, destination] = reverse ? [b, a] : [a, b];
      destination.blocked = true;
      const payload = Buffer.alloc(4096, 9);
      source.push(payload);
      await delay(0);
      assert.ok(source.isPaused());
      assert.equal(destination.writableLength, payload.length);
      destination.unblock();
      await delay(0);
      assert.equal(source.isPaused(), false);
      assert.equal(session.timers.size, 0);
      destination.blocked = true;
      source.push(payload);
      const error = await within(session.closed);
      assert.equal(error.code, 'TLS_RELAY_WRITE_TIMEOUT');
      assert.equal(session.timers.size, 0);
      assert.equal(destination.listenerCount('drain'), 0);
      assert.equal(source.listenerCount('data'), 0);
      assert.ok(a.destroyed && b.destroyed);
    } finally { a.destroy(); b.destroy(); }
  });
}

for (const firstFin of ['client', 'origin', 'client-stall']) {
  test(`real TCP ${firstFin} half-close preserves reverse data or expires its close deadline`, async (t) => {
    const sockets = new Set(), servers = [], received = [], replies = [];
    const track = (socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.once('close', () => sockets.delete(socket));
      return socket;
    };
    t.after(async () => {
      for (const socket of sockets) socket.destroy();
      await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    });
    let originEnded;
    const originDone = new Promise((resolve) => { originEnded = resolve; });
    const origin = net.createServer({ allowHalfOpen: true }, (socket) => {
      track(socket);
      socket.on('data', (chunk) => received.push(chunk));
      socket.on('end', () => {
        originEnded();
        if (firstFin === 'client') setImmediate(() => socket.end('late reply'));
      });
      if (firstFin === 'origin') socket.end('late reply');
    });
    servers.push(origin);
    origin.listen(0, '127.0.0.1');
    await once(origin, 'listening');
    let resolveReady;
    const ready = new Promise((resolve) => { resolveReady = resolve; });
    let session;
    // Intentionally use Node's default allowHalfOpen=false on BOTH relay sockets.
    const relay = net.createServer((socket) => {
      track(socket);
      session = new RelaySession(socket, { limits: { writeTimeoutMs: firstFin === 'client-stall' ? 60 : 500 } });
      (async () => {
        const upstream = await session.connect(() => track(net.connect(origin.address().port, '127.0.0.1')));
        await session.bridge(socket, upstream, Buffer.alloc(0));
        resolveReady();
      })().catch((error) => session.fail(error));
    });
    servers.push(relay);
    relay.listen(0, '127.0.0.1');
    await once(relay, 'listening');
    const app = track(net.connect({ host: '127.0.0.1', port: relay.address().port, allowHalfOpen: true }));
    app.on('data', (chunk) => replies.push(chunk));
    const appDone = once(app, 'end');
    app.on('end', () => { if (firstFin === 'origin') setImmediate(() => app.end('late request')); });
    await within(ready);
    if (firstFin !== 'origin') app.end('late request');
    await within(Promise.all([appDone, originDone]));
    assert.equal(Buffer.concat(received).toString(), 'late request');
    assert.equal(Buffer.concat(replies).toString(), firstFin === 'client-stall' ? '' : 'late reply');
    const error = await within(session.closed);
    if (firstFin === 'client-stall') assert.equal(error.code, 'TLS_RELAY_CLOSE_TIMEOUT');
    else assert.equal(error, null);
    assert.equal(session.timers.size, 0);
  });
}

test('graceful EOF flushes a blocked destination without truncating payload', async () => {
  const a = new TestSocket();
  const b = new TestSocket({ blocked: true });
  const session = new RelaySession(a);
  session.add(b);
  try {
    await session.bridge(a, b, Buffer.alloc(0));
    const payload = Buffer.alloc(4096, 7);
    a.push(payload);
    a.push(null);
    await delay(0);
    assert.equal(b.destroyed, false);
    b.unblock();
    await delay(0);
    assert.deepEqual(b.bytes(), payload);
    assert.ok(b.writableFinished);
    b.push(null);
    assert.equal(await within(session.closed), null);
    assert.equal(session.timers.size, 0);
  } finally { a.destroy(); b.destroy(); }
});

test('limits reject typos, disabled timers and parser-limit bypasses', () => {
  for (const limits of [{ helloTimeoutMs: 0 }, { connectTimeoutMs: -1 }, { maxHelloBytes: 1e6 },
    { typo: 10 }, { writeTimeoutMs: 2 ** 32 }, { maxPendingBytes: NaN }]) {
    assert.throws(() => relayLimits(limits), { code: 'TLS_RELAY_CONFIG' });
  }
});

test('graceful half-close has a deadline if the other peer never ends', async () => {
  const a = new TestSocket();
  const b = new TestSocket();
  const session = new RelaySession(a, { limits: { writeTimeoutMs: 40 } });
  session.add(b);
  try {
    await session.bridge(a, b, Buffer.alloc(0));
    a.push(null);
    const error = await within(session.closed);
    assert.equal(error.code, 'TLS_RELAY_CLOSE_TIMEOUT');
    assert.equal(session.timers.size, 0);
    assert.equal(a.listenerCount('error'), 0);
    assert.equal(b.listenerCount('error'), 0);
  } finally { a.destroy(); b.destroy(); }
});

test('initial peek buffer follows the same limits and remains paused before connect', async () => {
  const inbound = new TestSocket();
  const outbound = new TestSocket();
  const session = wireTransparentTlsEncSniSession(inbound, {
    replayGuard: new EncSniReplayGuard(),
    vpnSecretBuf: PSK, publicName: PUBLIC, initialBuf: encodedHello,
    connectOrigin: () => outbound, limits: { connectTimeoutMs: 40 },
  });
  assert.ok(inbound.isPaused());
  const error = await within(session.closed);
  assert.equal(error.code, 'TLS_RELAY_CONNECT_TIMEOUT');
  assert.equal(session.timers.size, 0);
  for (const limits of [{ maxHelloBytes: 32 }, { maxPendingBytes: 32 }]) {
    let connected = false;
    const rejected = wireTransparentTlsEncSniSession(new TestSocket(), {
      vpnSecretBuf: PSK, publicName: PUBLIC, initialBuf: encodedHello, limits,
      connectOrigin: () => { connected = true; return new TestSocket(); },
    });
    const reason = await within(rejected.closed);
    assert.equal(reason.code, limits.maxHelloBytes ? 'TLS_RELAY_HELLO_LIMIT' : 'TLS_RELAY_PENDING_LIMIT');
    assert.equal(connected, false);
    assert.equal(rejected.timers.size, 0);
  }
});

test('real TLS HTTP/1.1 and HTTP/2 still work with harness idle timers disabled', { timeout: 5000 }, async (t) => {
  const lab = await startTransparentTlsLab({ sessionTimeoutMs: 0 });
  t.after(() => lab.close());
  const body = Buffer.alloc(512 * 1024, 19);
  for (const httpVersion of ['1.1', '2']) {
    const result = await requestThroughLab(lab, { httpVersion, path: '/echo', body });
    assert.deepEqual(result.body, body);
  }
  for (const capture of lab.captures.filter((c) => c.stage === 'client')) assertRelayTrace(lab, capture.id);
});

test('wire and combo logs hide SNI unless explicitly verbose', (t) => {
  const lines = [];
  t.mock.method(console, 'log', (...args) => lines.push(args.join(' ')));
  const info = { originSni: HOST, encSni: encodedName, wireSni: encodedName };
  logEncSniWire('client', 'transparent-tls', info);
  logComboTlsExitBranch('transparent', '127.0.0.1:1', info);
  assert.ok(!lines.join('\n').includes(HOST));
  assert.ok(!lines.join('\n').includes(encodedName));
  logEncSniWire('exit', 'combo-tls', { ...info, sensitive: true });
  assert.ok(lines.at(-1).includes(HOST));
  assert.ok(lines.at(-1).includes(encodedName));
});

for (const role of ['client', 'exit']) {
  test(`${role}: absolute ClientHello deadline with harness timers disabled`, { timeout: 4000 }, async (t) => {
    const lab = await startTransparentTlsLab({
      sessionTimeoutMs: 0, [`${role}Limits`]: { helloTimeoutMs: 80 },
    });
    t.after(() => lab.close());
    const socket = lab.track(net.connect({ host: lab.host, port: lab[`${role}Port`] }));
    await once(socket, 'connect');
    const closed = once(socket, 'close');
    socket.write(Buffer.from([0x16]));
    // Slow progress must not reset an absolute handshake deadline.
    const drip = setInterval(() => { if (!socket.destroyed) socket.write(Buffer.from([0x03])); }, 20);
    try { await within(closed, 500); } finally { clearInterval(drip); }
    assert.ok(lab.runtimeErrors.some((e) => e.role === role && e.code === 'TLS_RELAY_HELLO_TIMEOUT'));
    assert.equal(lab.stats().originConnections, 0);
  });

  test(`${role}: announced oversized TLS record rejected before its body arrives`, { timeout: 4000 }, async (t) => {
    const lab = await startTransparentTlsLab({
      sessionTimeoutMs: 0, [`${role}Limits`]: { maxHelloBytes: 1024 },
    });
    t.after(() => lab.close());
    const socket = lab.track(net.connect({ host: lab.host, port: lab[`${role}Port`] }));
    await once(socket, 'connect');
    const closed = once(socket, 'close');
    socket.write(Buffer.from([0x16, 0x03, 0x01, 0x40, 0x00]));
    await within(closed, 500);
    assert.ok(lab.runtimeErrors.some((e) => e.role === role && e.code === 'TLS_RELAY_HELLO_LIMIT'));
    assert.equal(lab.stats().originConnections, 0);
  });
}
