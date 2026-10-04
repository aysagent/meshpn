import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import net from 'node:net';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { watchH2Health } from './lib/vpn-h2-health.mjs';
import { watchConnectDeadline } from './lib/vpn-connect-deadline.mjs';
import { loadTlsDateFixture, startDateExit, fixtureCert } from './lib/vpn-http-date-fixture.mjs';

function clock() {
  const timers = [];
  return { timers, schedule(fn, ms) { const t = { fn, ms, unref() {} }; timers.push(t); return t; },
    cancel(t) { if (t) t.cancelled = true; }, fire(t) { if (!t.cancelled) t.fn(); } };
}
function health() {
  const c = clock(), wire = new EventEmitter(), session = new EventEmitter();
  let ack, destroyed = 0, pings = 0;
  session.ping = fn => { ack = fn; pings++; return true; };
  wire.destroy = () => { destroyed++; wire.destroyed = true; wire.emit('close'); };
  const watcher = watchH2Health(session, wire, { ...c, log() {} });
  return { c, wire, session, watcher, ack: (...args) => ack(...args), destroyed: () => destroyed, pings: () => pings };
}
test('H2 ACK renews one probe; writes cannot postpone a missing ACK', () => {
  const f = health(); f.c.fire(f.c.timers[0]); assert.equal(f.pings(), 1);
  assert.equal(f.c.timers[0].ms, 2000); assert.equal(f.c.timers[1].ms, 5000);
  f.wire.emit('data', Buffer.from('unrelated data')); f.c.fire(f.c.timers[1]);
  assert.equal(f.destroyed(), 1); f.ack(); assert.equal(f.c.timers.length, 2);
});
test('healthy delayed ACK cancels deadline without creating concurrent pings', () => {
  const f = health(); f.c.fire(f.c.timers[0]); f.ack();
  f.c.fire(f.c.timers[1]); assert.equal(f.destroyed(), 0);
  f.c.fire(f.c.timers[2]); assert.equal(f.pings(), 2);
  f.watcher.stop(); assert.equal(f.wire.listenerCount('close'), 0); assert.equal(f.session.listenerCount('close'), 0);
  f.c.fire(f.c.timers[3]); assert.equal(f.destroyed(), 0);
});
for (const mode of ['error', 'refused', 'throw', 'close']) test('H2 health cleanup: ' + mode, () => {
  const f = health();
  if (mode === 'refused') f.session.ping = () => false;
  if (mode === 'throw') f.session.ping = () => { throw Error('closed'); };
  f.c.fire(f.c.timers[0]);
  if (mode === 'error') f.ack(Error('cancelled'));
  if (mode === 'close') { f.session.emit('close'); f.ack(); }
  assert.equal(f.destroyed(), mode === 'close' ? 0 : 1);
  assert.equal(f.wire.listenerCount('close'), 0); assert.equal(f.session.listenerCount('close'), 0);
});
test('connect deadline separates SYN, total TLS deadline and abort; finish cleans all', () => {
  for (const mode of ['tcp', 'total', 'abort', 'finish', 'pre-abort']) {
    const c = clock(), socket = new EventEmitter(), controller = new AbortController(), failures = [];
    if (mode === 'pre-abort') controller.abort();
    const stop = watchConnectDeadline(socket, e => failures.push(e.message), { ...c, signal: controller.signal });
    assert.deepEqual(c.timers.map(t => t.ms), mode === 'pre-abort' ? [] : [3000, 10000]);
    if (mode === 'tcp') c.fire(c.timers[0]);
    if (mode === 'total') { socket.emit('connect'); c.fire(c.timers[0]); assert.equal(failures.length, 0); c.fire(c.timers[1]); }
    if (mode === 'abort') controller.abort();
    stop(); for (const t of c.timers) c.fire(t);
    assert.equal(failures.length, mode === 'finish' ? 0 : 1); assert.equal(socket.listenerCount('connect'), 0);
  }
});
test('helper response reader rejects EOF/close/error and cleans its wait listeners', async () => {
  const api = loadTlsDateFixture();
  for (const mode of ['eof', 'partial', 'close', 'error', 'already-closed']) {
    const input = new PassThrough();
    if (mode === 'already-closed') input.destroy();
    const failed = assert.rejects(api.readExactFromReadable(input, 4));
    if (mode === 'eof') input.end();
    if (mode === 'partial') input.end(Buffer.from([1, 2]));
    if (mode === 'close') input.destroy();
    if (mode === 'error') input.destroy(Error('injected IO error'));
    await failed;
    for (const name of ['readable', 'end', 'close', 'error']) assert.equal(input.listenerCount(name), 0, mode + '/' + name);
  }
  const input = new PassThrough();
  const header = api.readExactFromReadable(input, 4);
  input.write(Buffer.from('headbody'));
  assert.equal((await header).toString(), 'head');
  assert.equal((await api.readExactFromReadable(input, 4)).toString(), 'body'); input.destroy();
});

test('actual TLS attempt aborts while peer accepts TCP but sends no TLS reply', async () => {
  const sockets = new Set();
  const server = net.createServer(s => { sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const controller = new AbortController(), api = loadTlsDateFixture();
    const accepted = once(server, 'connection');
    const connecting = api.connectCleanVpnTlsClient({ host: '127.0.0.1', port: server.address().port,
      ca: fixtureCert, servername: 'localhost', vpnSecret: randomBytes(32), fastRecovery: true, signal: controller.signal });
    const rejected = assert.rejects(connecting, /cancelled/);
    await accepted; await delay(40); controller.abort(); await rejected;
  } finally { for (const s of sockets) s.destroy(); await new Promise(r => server.close(r)); }
});

for (const connector of ['connectCleanVpnTlsClient', 'connectCleanVpnBoringTlsClient'])
test(connector + ': real authenticated H2 closes a silent transport and permits a fresh TLS session', async t => {
  const helper = fileURLToPath(new URL('../native/boring_tls/build/boring-tls-helper', import.meta.url));
  if (connector.includes('Boring') && !fs.existsSync(helper)) return t.skip('optional BoringSSL helper is not built');
  const secret = randomBytes(32), exit = await startDateExit({ protocol: 'h2', secret });
  const sockets = new Set(); let blocked = false, lag = 0;
  const proxy = net.createServer(client => {
    const upstream = net.connect(exit.port, '127.0.0.1');
    for (const s of [client, upstream]) { sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); }
    const forward = (from, to) => from.on('data', b => {
      if (blocked) return;
      const send = () => { if (!blocked && !to.destroyed) to.write(b); };
      if (lag) setTimeout(send, lag); else send();
    });
    forward(client, upstream); forward(upstream, client);
    client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy());
  });
  proxy.listen(0, '127.0.0.1'); await once(proxy, 'listening');
  const api = loadTlsDateFixture({ healthOptions: { intervalMs: 20, timeoutMs: 500, log() {} } });
  const opts = { host: '127.0.0.1', port: proxy.address().port, ca: fixtureCert.toString(),
    servername: 'localhost', vpnSecret: secret, fastRecovery: true, boringTlsHelperPath: helper };
  let wire, next;
  try {
    wire = await api[connector](opts);
    await delay(250); assert.equal(wire.destroyed, false);
    lag = 100; await delay(700); assert.equal(wire.destroyed, false, 'healthy delayed PING ACK must remain accepted');
    blocked = true; lag = 0;
    await Promise.race([once(wire, 'close'), delay(1500).then(() => { throw Error('stale H2 did not close'); })]);
    assert.equal(wire.destroyed, true);
    // These proxy connections deliberately lost TLS records. Discard them
    // before restoring delivery; resuming their record sequence is invalid TLS.
    for (const s of sockets) s.destroy();
    await delay(30); blocked = false;
    next = await api[connector](opts); assert.equal(next.destroyed, false);
    assert.equal(exit.bridges(), 2);
  } finally {
    wire?.destroy(); next?.destroy(); for (const s of sockets) s.destroy();
    await new Promise(r => proxy.close(r)); await exit.close();
  }
});

test('actual BoringSSL attempt aborts on a silent TCP peer without leaving its helper alive', async t => {
  const helper = fileURLToPath(new URL('../native/boring_tls/build/boring-tls-helper', import.meta.url));
  if (!fs.existsSync(helper)) return t.skip('optional BoringSSL helper is not built');
  const sockets = new Set(); let child;
  const server = net.createServer(s => { sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const api = loadTlsDateFixture({ spawnChild: (...args) => { child = spawn(...args); return child; } });
    const controller = new AbortController(), accepted = once(server, 'connection');
    const connecting = api.connectCleanVpnBoringTlsClient({ host: '127.0.0.1', port: server.address().port,
      ca: fixtureCert.toString(), servername: 'localhost', vpnSecret: randomBytes(32),
      boringTlsHelperPath: helper, fastRecovery: true, signal: controller.signal });
    const rejected = assert.rejects(connecting);
    await accepted; const closed = once(child, 'close'); controller.abort(); await closed;
    await Promise.race([rejected, delay(1000).then(() => { throw Error('killed helper left connection pending'); })]);
    assert.equal(child.signalCode, 'SIGKILL');
  } finally { child?.kill('SIGKILL'); for (const s of sockets) s.destroy(); await new Promise(r => server.close(r)); }
});
