import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import dgram from 'node:dgram';
import { once, getEventListeners } from 'node:events';
import { validateDnsReadyName, queryDnsReadiness, probeDnsAdapterReady } from './lib/dns-adapter-ready.mjs';
import { createDnsSystemdNotifier } from './lib/dns-systemd-notify.mjs';
import { makeDnsQuery, fixtureDnsAnswer } from './lib/lab-dns-wire.mjs';

test('readiness name is explicit, public-shaped, and not denied by configured QNAME policy', () => {
  assert.equal(validateDnsReadyName('READY.Example'), 'ready.example');
  for (const name of [undefined, '', 'localhost', 'host.local', 'x.internal', 'x.home.arpa', '127.0.0.1', '::1',
    'a..example', '*.example.com', 'example.com.', 'https://example.com', 'a'.repeat(64) + '.test']) assert.throws(() => validateDnsReadyName(name));
  assert.throws(() => validateDnsReadyName('ready.example', { schema: 1, denySuffixes: ['example'] }));
  assert.equal(validateDnsReadyName('ready.example', { schema: 1, denySuffixes: ['auto.internal'] }), 'ready.example');
});
test('query rejects privileged ports, malformed packets/deadlines and pre-aborted signals before sockets', async () => {
  const q = makeDnsQuery('ready.test'), aborted = AbortSignal.abort();
  for (const [port, packet, options] of [[53, q, {}], [0, q, {}], [65536, q, {}], [1053, Buffer.alloc(0), {}],
    [1053, q, { timeoutMs: 0 }], [1053, q, { timeoutMs: Infinity }], [1053, q, { signal: aborted }]]) {
    await assert.rejects(queryDnsReadiness(port, packet, options), { code: 'DNS_ADAPTER_NOT_READY' });
  }
});
for (const mode of ['fragmented', 'short-length', 'truncated', 'oversized', 'hold']) test(`readiness TCP ${mode} is bounded and releases abort listener`, async (t) => {
  const sockets = new Set(), q = makeDnsQuery('ready.test');
  const server = net.createServer({ allowHalfOpen: true }, (s) => {
    sockets.add(s); s.on('error', () => {}); s.on('close', () => sockets.delete(s));
    s.on('data', () => {
      if (mode === 'hold') return;
      if (mode === 'short-length') { s.end(Buffer.from([0, 1, 0])); return; }
      if (mode === 'truncated') { s.end(Buffer.from([0, 20, 0])); return; }
      if (mode === 'oversized') { s.end(Buffer.alloc(65538)); return; }
      const answer = fixtureDnsAnswer(q), frame = Buffer.alloc(answer.length + 2); frame.writeUInt16BE(answer.length); answer.copy(frame, 2);
      s.write(frame.subarray(0, 1)); setImmediate(() => s.end(frame.subarray(1)));
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const s of sockets) s.destroy(); await new Promise((r) => server.close(r)); });
  const controller = new AbortController(), pending = queryDnsReadiness(server.address().port, q, { tcp: true, timeoutMs: 100, signal: controller.signal });
  if (mode === 'fragmented') assert.deepEqual(await pending, fixtureDnsAnswer(q));
  else await assert.rejects(pending, { code: 'DNS_ADAPTER_NOT_READY' });
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});
test('UDP client deadline and cancellation release sockets/listeners without DNS lookup fallback', async (t) => {
  const server = dgram.createSocket('udp4'); server.bind(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise((r) => server.close(r)));
  for (const cancel of [false, true]) {
    const controller = new AbortController();
    const pending = queryDnsReadiness(server.address().port, makeDnsQuery('ready.test'), { timeoutMs: 30, signal: controller.signal });
    if (cancel) controller.abort();
    await assert.rejects(pending, { code: 'DNS_ADAPTER_NOT_READY' }); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});
test('a positive localhost responder without owned adapter forwarding is not protected readiness', async (t) => {
  const udp = dgram.createSocket('udp4'), sockets = new Set();
  udp.on('message', (q, peer) => udp.send(fixtureDnsAnswer(q), peer.port, peer.address));
  const tcp = net.createServer((s) => {
    sockets.add(s); s.on('error', () => {}); s.on('close', () => sockets.delete(s));
    s.on('data', (frame) => { const reply = fixtureDnsAnswer(frame.subarray(2)), packet = Buffer.alloc(reply.length + 2);
      packet.writeUInt16BE(reply.length); reply.copy(packet, 2); s.end(packet); });
  });
  tcp.listen(0, '127.0.0.1'); await once(tcp, 'listening'); udp.bind(tcp.address().port, '127.0.0.1'); await once(udp, 'listening');
  t.after(async () => { for (const s of sockets) s.destroy(); await Promise.all([new Promise((r) => udp.close(r)), new Promise((r) => tcp.close(r))]); });
  await assert.rejects(probeDnsAdapterReady({ port: tcp.address().port,
    stats: () => ({ stub: { succeeded: 0, forwarded: 0 }, transport: { connections: 0, closing: false } }) }, { name: 'ready.test' }),
  { code: 'DNS_ADAPTER_NOT_READY' });
});
function notifyFixture() {
  const calls = [], reads = [];
  return { calls, reads, deps: { pid: 42, ppid: 1, env: { NOTIFY_SOCKET: '/run/systemd/notify', INVOCATION_ID: 'a'.repeat(32), SECRET: 'must-not-inherit' },
    read: async (path) => { reads.push(path); return 'systemd\n'; }, stat: async () => ({ isSocket: () => true }),
    run: async (...args) => { calls.push(args); return { stdout: '', stderr: '' }; } } };
}
test('notifier preflight is offline; ready uses own PID, minimal environment and reception barrier exactly once', async () => {
  const f = notifyFixture(), ready = await createDnsSystemdNotifier(f.deps); assert.equal(f.calls.length, 0);
  await ready(); assert.equal(f.calls.length, 1);
  const [file, args, options] = f.calls[0]; assert.equal(file, '/usr/bin/systemd-notify'); assert.deepEqual(args, ['--ready', '--pid=42']);
  assert.equal(options.env.SECRET, undefined); assert.equal(options.timeout, 3000); assert.equal(options.killSignal, 'SIGKILL');
  assert.ok(!args.includes('--no-block')); await assert.rejects(ready(), { code: 'DNS_SYSTEMD_NOTIFY_REFUSED' });
});
for (const kind of ['parent', 'pid1', 'socket-path', 'socket-kind', 'invocation']) test(`notify refuses ${kind} before sending`, async () => {
  const f = notifyFixture();
  if (kind === 'parent') f.deps.ppid = 2;
  if (kind === 'pid1') f.deps.read = async () => 'other';
  if (kind === 'socket-path') f.deps.env.NOTIFY_SOCKET = '/tmp/other';
  if (kind === 'socket-kind') f.deps.stat = async () => ({ isSocket: () => false });
  if (kind === 'invocation') f.deps.env.INVOCATION_ID = 'SECRET';
  await assert.rejects(createDnsSystemdNotifier(f.deps), { code: 'DNS_SYSTEMD_NOTIFY_REFUSED' }); assert.equal(f.calls.length, 0);
});
test('notifier cancellation and subprocess failure never become success or expose stderr', async () => {
  const f = notifyFixture(), ready = await createDnsSystemdNotifier(f.deps);
  await assert.rejects(ready(AbortSignal.abort()), { code: 'DNS_SYSTEMD_NOTIFY_REFUSED' }); assert.equal(f.calls.length, 0);
  f.deps.run = async () => { throw new Error('SECRET'); };
  const broken = await createDnsSystemdNotifier(f.deps);
  await assert.rejects(broken(), (e) => e.code === 'DNS_SYSTEMD_NOTIFY_REFUSED' && !String(e).includes('SECRET'));
});
