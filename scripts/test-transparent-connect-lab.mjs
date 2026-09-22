import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { startLabConnectProxy } from './lib/transparent-connect-lab.mjs';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';

async function until(predicate) {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('test observation deadline');
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function setup(t, options) {
  const lab = await startTransparentTlsLab();
  let proxy;
  t.after(async () => {
    await proxy?.close(); await lab.close();
    if (proxy) assert.equal(proxy.stats().clients + proxy.stats().upstreams + proxy.stats().headerTimers, 0);
    assert.equal(lab.stats().sockets, 0);
  });
  proxy = await startLabConnectProxy(lab, options);
  return { lab, proxy };
}

function connect(proxy) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: proxy.host, port: proxy.port, method: 'CONNECT', path: proxy.authority,
      headers: { host: proxy.authority }, agent: false });
    req.once('error', reject);
    req.once('connect', (res, socket, head) => {
      if (res.statusCode !== 200 || head.length) { socket.destroy(); reject(new Error('CONNECT failed')); }
      else resolve(socket);
    });
    req.end();
  });
}

async function raw(proxy, bytes, fragmented = false) {
  const socket = net.connect(proxy.port, proxy.host);
  socket.on('error', () => {});
  const chunks = [];
  socket.on('data', (chunk) => chunks.push(chunk));
  const closed = once(socket, 'close');
  await once(socket, 'connect');
  if (fragmented) for (const byte of Buffer.from(bytes)) socket.write(Buffer.from([byte]));
  else socket.write(bytes);
  await closed;
  return Buffer.concat(chunks).toString();
}

for (const httpVersion of ['1.1', '2']) test(`verified HTTP/${httpVersion} through CONNECT preserves real ClientHello`, { timeout: 5000 }, async (t) => {
  const { lab, proxy } = await setup(t);
  const socket = await connect(proxy);
  const body = Buffer.alloc(128 * 1024, 7);
  const result = await requestThroughLab(lab, { httpVersion, path: '/echo', body, tlsOptions: { socket } });
  assert.deepEqual(result.body, body);
  assertRelayTrace(lab);
  assert.equal(proxy.stats().tunnels, 1);
});

test('CONNECT does not bypass certificate validation', { timeout: 5000 }, async (t) => {
  const { lab, proxy } = await setup(t);
  const socket = await connect(proxy);
  await assert.rejects(requestThroughLab(lab, { ca: [], tlsOptions: { socket } }), /self.signed|issuer|verify/i);
  assert.equal(lab.stats().requests, 0);
});

for (const target of ['example.com:443', '127.0.0.1:443', '[::1]:443', 'localhost:22',
  'user@localhost:443', 'localhost:443/path', 'localhost:0443']) {
  test(`CONNECT rejects non-allowlisted authority ${target}`, { timeout: 3000 }, async (t) => {
    const { lab, proxy } = await setup(t);
    assert.match(await raw(proxy, `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`), /^HTTP\/1.1 403 /);
    assert.equal(lab.stats().originConnections, 0);
    assert.equal(proxy.stats().tunnels, 0);
  });
}

for (const extra of ['Content-Length: 0\r\n', 'Transfer-Encoding: chunked\r\n', 'Host: duplicate\r\n']) {
  test(`CONNECT rejects ambiguous framing ${extra.trim()}`, { timeout: 3000 }, async (t) => {
    const { lab, proxy } = await setup(t);
    assert.match(await raw(proxy, `CONNECT ${proxy.authority} HTTP/1.1\r\nHost: ${proxy.authority}\r\n${extra}\r\n`), /^HTTP\/1.1 400 /);
    assert.equal(lab.stats().originConnections, 0);
  });
}

test('ordinary HTTP is not forwarded', { timeout: 3000 }, async (t) => {
  const { lab, proxy } = await setup(t);
  assert.match(await raw(proxy, 'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n'), /^HTTP\/1.1 405 /);
  assert.equal(lab.stats().originConnections, 0);
});

test('header size and count are bounded', { timeout: 3000 }, async (t) => {
  const { proxy } = await setup(t);
  for (const headers of [`X-Long: ${'a'.repeat(9000)}\r\n`, 'X: a\r\n'.repeat(34)]) {
    assert.match(await raw(proxy, `CONNECT ${proxy.authority} HTTP/1.1\r\nHost: ${proxy.authority}\r\n${headers}\r\n`), /^HTTP\/1.1 431 /);
  }
});

test('absolute header deadline and admission limit release resources', { timeout: 3000 }, async (t) => {
  const { proxy } = await setup(t, { maxConnections: 1, headerTimeoutMs: 80 });
  const first = raw(proxy, 'CON');
  // Admission is observable; do not rely on a guessed sleep.
  await until(() => proxy.stats().clients);
  assert.match(await raw(proxy, 'CON'), /^HTTP\/1.1 503 /);
  assert.match(await first, /^HTTP\/1.1 408 /);
});

test('fragmented CONNECT and coalesced tunnel bytes are preserved exactly', { timeout: 3000 }, async (t) => {
  const received = [];
  const target = net.createServer((socket) => { socket.on('data', (b) => received.push(b)); socket.pipe(socket); });
  target.listen(0, '127.0.0.1'); await once(target, 'listening');
  const proxy = await startLabConnectProxy({ host: '127.0.0.1', originName: 'localhost', originPort: 4433, clientPort: target.address().port });
  t.after(async () => { await proxy.close(); await new Promise((resolve) => target.close(resolve)); });
  const payload = Buffer.from([0x16, 3, 1, 0, 3, 1, 2, 3]);
  for (const fragmented of [false, true]) {
    const socket = net.connect(proxy.port, proxy.host);
    t.after(() => socket.destroy());
    const chunks = [];
    socket.on('data', (b) => chunks.push(b));
    const wire = Buffer.concat([Buffer.from('CONNECT localhost:4433 HTTP/1.1\r\nHost: localhost:4433\r\n\r\n'), payload]);
    if (fragmented) for (const byte of wire) socket.write(Buffer.from([byte])); else socket.write(wire);
    await until(() => Buffer.concat(chunks).length >= 39 + payload.length);
    const response = Buffer.concat(chunks), end = response.indexOf('\r\n\r\n') + 4;
    assert.match(response.subarray(0, end).toString(), /^HTTP\/1.1 200 /);
    assert.deepEqual(response.subarray(end), payload);
    socket.destroy();
  }
  assert.deepEqual(Buffer.concat(received), Buffer.concat([payload, payload]));
});

test('failed upstream never returns CONNECT success and releases resources', { timeout: 3000 }, async (t) => {
  const unused = net.createServer();
  unused.listen(0, '127.0.0.1'); await once(unused, 'listening');
  const clientPort = unused.address().port;
  await new Promise((resolve) => unused.close(resolve));
  const proxy = await startLabConnectProxy({ host: '127.0.0.1', originName: 'localhost', originPort: 4433, clientPort });
  t.after(() => proxy.close());
  assert.doesNotMatch(await raw(proxy, 'CONNECT localhost:4433 HTTP/1.1\r\nHost: localhost:4433\r\n\r\n'), /200/);
  await until(() => proxy.stats().clients + proxy.stats().upstreams + proxy.stats().headerTimers === 0);
  assert.equal(proxy.stats().tunnels, 0);
});

test('CONNECT configuration cannot select external routing or unbounded limits', async () => {
  const lab = { host: '127.0.0.1', originName: 'localhost', originPort: 4433, clientPort: 4434 };
  for (const altered of [{ host: '0.0.0.0' }, { originName: 'example.com' }, { clientPort: 443 }, { originPort: 65536 }]) {
    await assert.rejects(startLabConnectProxy({ ...lab, ...altered }), /fixed localhost/);
  }
  for (const options of [{ port: 80 }, { maxConnections: 0 }, { headerTimeoutMs: 0 }, { idleTimeoutMs: Infinity }]) {
    await assert.rejects(startLabConnectProxy(lab, options), /invalid/);
  }
});
