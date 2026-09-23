/** Bounded real loopback load/fault tests. No TUN, external targets or throughput claims. */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';
import { startLabConnectProxy } from './lib/transparent-connect-lab.mjs';
import { RelaySession } from './lib/transparent-tls-io.mjs';

const OPTIONS = { timeout: 20_000 };
async function until(check, ms = 4000) {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error('load-test observation deadline');
    await delay(5);
  }
}
async function setup(t, { limits, proxyOptions } = {}) {
  const lab = await startTransparentTlsLab({ sessionTimeoutMs: 0, clientLimits: limits, exitLimits: limits });
  let proxy;
  t.after(async () => { await proxy?.close(); await lab.close(); assert.equal(lab.stats().sockets, 0); });
  proxy = await startLabConnectProxy(lab, proxyOptions);
  const idle = () => until(() => lab.stats().sockets + proxy.stats().clients + proxy.stats().upstreams + proxy.stats().headerTimers === 0);
  return { lab, proxy, idle };
}
function tunnel(proxy) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: proxy.host, port: proxy.port, method: 'CONNECT', path: proxy.authority,
      headers: { host: proxy.authority }, agent: false });
    const timer = setTimeout(() => req.destroy(new Error('test CONNECT deadline')), 4000);
    req.once('error', (error) => { clearTimeout(timer); reject(error); });
    req.once('connect', (res, socket, head) => {
      clearTimeout(timer); socket.on('error', () => {});
      if (res.statusCode !== 200 || head.length) { socket.destroy(); reject(new Error('CONNECT rejected')); }
      else resolve(socket);
    });
    req.end();
  });
}
async function echo(lab, proxy, i = 0) {
  const socket = await tunnel(proxy);
  try {
    const body = Buffer.alloc(256 * 1024, i % 251);
    const response = await requestThroughLab(lab, { httpVersion: i % 2 ? '2' : '1.1',
      body, path: '/echo', tlsOptions: { socket } });
    assert.deepEqual(response.body, body);
  } finally { socket.destroy(); }
}

test('six waves of 12 independent verified CONNECT/TLS sessions leave no live sockets', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t);
  let peakRss = process.memoryUsage().rss;
  for (let wave = 0; wave < 6; wave++) {
    await Promise.all(Array.from({ length: 12 }, (_, i) => echo(lab, proxy, wave * 12 + i)));
    await idle();
    const hellos = lab.captures.filter((hello) => hello.stage === 'client');
    assert.equal(hellos.length, 12);
    assert.equal(new Set(hellos.map((hello) => hello.id)).size, 12);
    for (const hello of hellos) assertRelayTrace(lab, hello.id);
    assert.equal(lab.runtimeErrors.length, 0);
    // Verify before recycling the bounded capture ring; do not retain every payload.
    lab.captures.length = 0;
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }
  assert.equal(proxy.stats().tunnels, 72);
  assert.equal(lab.stats().tlsConnections, 72);
  t.diagnostic(`72 verified TLS sessions, 18 MiB echoed; sampled RSS peak ${Math.ceil(peakRss / 1048576)} MiB (diagnostic, not a leak bound)`);
});

test('repeated disconnects during ClientHello do not exhaust admission or affect healthy sessions', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t);
  for (let wave = 0; wave < 6; wave++) {
    const sockets = await Promise.all(Array.from({ length: 12 }, () => tunnel(proxy)));
    for (const socket of sockets) {
      socket.write(Buffer.from([0x16, 3, 3, 2, 0, 1]));
      socket.destroy();
    }
    await idle();
    assert.equal(lab.stats().originConnections, wave);
    await echo(lab, proxy, wave);
    await idle();
  }
  assert.equal(lab.stats().tlsConnections, 6);
});

test('concurrent post-handshake upload aborts preserve other TLS sessions', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t);
  for (let wave = 0; wave < 4; wave++) {
    const clients = await Promise.all(Array.from({ length: 6 }, async () => {
      const raw = await tunnel(proxy);
      const socket = tls.connect({ socket: raw, servername: 'localhost', ca: lab.cert, ALPNProtocols: ['http/1.1'] });
      socket.on('error', () => {}); t.after(() => socket.destroy());
      await once(socket, 'secureConnect');
      socket.write(`POST /echo HTTP/1.1\r\nHost: ${proxy.authority}\r\nContent-Length: 1048576\r\n\r\n`);
      socket.write(Buffer.alloc(32 * 1024));
      return socket;
    }));
    const healthy = echo(lab, proxy, wave);
    await until(() => lab.stats().requests >= (wave + 1) * 7 - 1);
    for (const socket of clients) socket.destroy();
    await healthy; await idle();
    assert.equal(lab.stats().requests, (wave + 1) * 7);
  }
});

test('six drip-fed incomplete ClientHellos hit absolute runtime deadlines with harness timers off', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t, { limits: { helloTimeoutMs: 250 } });
  const sockets = await Promise.all(Array.from({ length: 6 }, () => tunnel(proxy)));
  for (const socket of sockets) {
    t.after(() => socket.destroy());
    socket.resume(); socket.write(Buffer.from([0x16, 3, 3, 2, 0]));
    const timer = setInterval(() => { if (!socket.destroyed) socket.write(Buffer.from([0])); }, 20);
    socket.once('close', () => clearInterval(timer)); t.after(() => clearInterval(timer));
  }
  await idle();
  assert.equal(lab.stats().originConnections, 0);
  assert.equal(lab.runtimeErrors.filter((error) => error.role === 'client' && error.code === 'TLS_RELAY_HELLO_TIMEOUT').length, 6);
});

test('slow CONNECT headers expire despite progress and release all admission slots', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t, { proxyOptions: { headerTimeoutMs: 250, maxConnections: 6 } });
  const replies = await Promise.all(Array.from({ length: 6 }, async () => {
    const socket = net.connect(proxy.port, proxy.host); socket.on('error', () => {});
    t.after(() => socket.destroy());
    let reply = ''; socket.on('data', (data) => { reply += data; });
    const closed = new Promise((resolve) => socket.once('close', resolve));
    await once(socket, 'connect'); socket.write('CONNECT ');
    const timer = setInterval(() => { if (!socket.destroyed) socket.write('a'); }, 20);
    t.after(() => clearInterval(timer));
    try { await closed; } finally { clearInterval(timer); }
    return reply;
  }));
  for (const reply of replies) assert.match(reply, /^HTTP\/1.1 408 /);
  await idle(); assert.equal(lab.stats().originConnections, 0);
  await echo(lab, proxy); await idle();
});

// Isolate the real TCP pump from TLS and HTTP buffering. Fixed byte budget only;
// if this host's kernel absorbs it all, fail instead of claiming backpressure.
for (const direction of ['forward', 'reverse']) for (const outcome of ['resume', 'timeout']) {
  test(`real TCP ${direction} slow reader: bounded queues and ${outcome}`, OPTIONS, async (t) => {
    const sockets = new Set(), servers = [];
    const own = (socket) => { sockets.add(socket); socket.on('error', () => {}); return socket; };
    t.after(async () => {
      for (const socket of sockets) socket.destroy();
      await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    });
    async function listener() {
      const server = net.createServer({ allowHalfOpen: true }); servers.push(server);
      server.on('connection', own); server.listen(0, '127.0.0.1'); await once(server, 'listening');
      return server;
    }
    const backend = await listener(), front = await listener();
    const inbound = once(front, 'connection'), accepted = once(backend, 'connection');
    const client = own(net.connect({ host: '127.0.0.1', port: front.address().port, allowHalfOpen: true }));
    const [source] = await inbound;
    const session = new RelaySession(source, { limits: { writeTimeoutMs: 1500 } });
    const destination = await session.connect(() => own(net.connect({ host: '127.0.0.1', port: backend.address().port, allowHalfOpen: true })));
    const [peer] = await accepted;
    t.after(() => session.fail(new Error('test cleanup')));
    const writer = direction === 'forward' ? client : peer, reader = direction === 'forward' ? peer : client;
    const relayRead = direction === 'forward' ? source : destination, relayWrite = direction === 'forward' ? destination : source;
    reader.pause();
    await session.bridge(source, destination, Buffer.alloc(0));
    const chunk = Buffer.alloc(64 * 1024, 0x5a), count = 512; // 32 MiB max
    let received = 0, bad = false;
    reader.on('data', (bytes) => { received += bytes.length; if (bytes.some((byte) => byte !== 0x5a)) bad = true; });
    reader.pause();
    const writerClosed = new Promise((resolve) => writer.once('close', resolve));
    const writing = (async () => {
      for (let i = 0; i < count; i++) {
        if (writer.destroyed) return;
        if (!writer.write(chunk)) {
          await Promise.race([once(writer, 'drain').catch(() => {}), writerClosed]);
        }
      }
      if (!writer.destroyed) writer.end();
    })();
    // Monitor the owned relay sockets, not process RSS (V8/kernel caches are unrelated).
    let maxRead = 0, maxWrite = 0;
    const sample = () => { maxRead = Math.max(maxRead, relayRead.readableLength); maxWrite = Math.max(maxWrite, relayWrite.writableLength); };
    const sampler = setInterval(sample, 5); t.after(() => clearInterval(sampler));
    await until(() => relayRead.isPaused() && relayWrite.writableNeedDrain, 1000); sample();
    assert.ok(maxRead <= relayRead.readableHighWaterMark + chunk.length);
    assert.ok(maxWrite <= relayWrite.writableHighWaterMark + chunk.length);
    if (outcome === 'resume') {
      const ended = once(reader, 'end'); reader.resume(); await writing; await ended;
      assert.equal(received, count * chunk.length); assert.equal(bad, false);
      reader.end(); await session.closed;
      assert.equal(session.error, undefined);
    } else {
      const error = await session.closed;
      assert.equal(error.code, 'TLS_RELAY_WRITE_TIMEOUT');
      writer.destroy(); reader.destroy(); await writing;
    }
    clearInterval(sampler);
    assert.ok(maxRead <= relayRead.readableHighWaterMark + chunk.length);
    assert.ok(maxWrite <= relayWrite.writableHighWaterMark + chunk.length);
    assert.equal(session.sockets.size + session.timers.size, 0);
    assert.equal(relayRead.listenerCount('data') + relayWrite.listenerCount('drain'), 0);
    t.diagnostic(`peak relay readable/writable queues: ${maxRead}/${maxWrite} bytes`);
  });
}

async function gate(t) {
  const lab = await startTransparentTlsLab({ holdResponses: true, sessionTimeoutMs: 0 });
  t.after(() => lab.close());
  const socket = tls.connect({ host: lab.host, port: lab.clientPort, servername: 'localhost', ca: lab.cert, ALPNProtocols: ['h2'] });
  socket.on('error', () => {}); t.after(() => socket.destroy());
  const session = http2.connect(`https://localhost:${lab.originPort}`, { createConnection: () => socket });
  session.on('error', () => {}); t.after(() => session.destroy());
  return { lab, request() {
    const req = session.request({ ':path': '/hold' });
    req.on('error', () => {}); req.resume();
    const response = once(req, 'response').then(([headers]) => headers[':status']);
    response.catch(() => {}); // cleanup after a failed assertion must not orphan rejections
    req.end(); return { req, response };
  } };
}

test('opt-in response gate caps held streams and release is idempotent', OPTIONS, async (t) => {
  const { lab, request } = await gate(t);
  const pending = Array.from({ length: 16 }, request);
  await until(() => lab.stats().heldResponses === 16);
  assert.equal(await request().response, 503);
  lab.releaseHeldResponses(); lab.releaseHeldResponses();
  assert.deepEqual(await Promise.all(pending.map(({ response }) => response)), Array(16).fill(200));
  await until(() => lab.stats().heldResponses === 0);
  const abandoned = request(); abandoned.response.catch(() => {});
  await until(() => lab.stats().heldResponses === 1);
  await lab.close(); assert.equal(lab.stats().heldResponses, 0);
});

test('response gate has its own absolute deadline', OPTIONS, async (t) => {
  const { lab, request } = await gate(t);
  assert.equal(await request().response, 504);
  await until(() => lab.stats().heldResponses === 0);
});

test('response gate is disabled by default and cannot target an external backend', OPTIONS, async (t) => {
  const { lab, proxy, idle } = await setup(t);
  const response = await requestThroughLab(lab, { path: '/hold' });
  assert.equal(JSON.parse(response.body).ok, true);
  await idle(); assert.equal(lab.stats().heldResponses, 0);
  await assert.rejects(startTransparentTlsLab({ holdResponses: 'true' }), /holdResponses/);
  await assert.rejects(startTransparentTlsLab({ holdResponses: true, externalOriginPort: 12345 }), /internal lab origin/);
  assert.equal(proxy.stats().tunnels, 0);
});
