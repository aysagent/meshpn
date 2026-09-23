import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import https from 'node:https';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import { once } from 'node:events';
import { readFile, mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { compileDnsUpstream, compileLabDnsUpstream } from './lib/dns-upstream-config.mjs';
import { createDnsExitTransport, createLabDnsExitTransport, dnsExitTransportTarget } from './lib/dns-exit-transport.mjs';
import { startLabDohStub } from './lib/lab-doh-stub.mjs';
import { queryLabDns } from './lib/transparent-dns-lab.mjs';
import { wireTransparentTlsEncSniSession } from './lib/transparent-tls-runtime.mjs';
import { ExitDestinationPolicy } from './lib/transparent-tls-destination.mjs';
import { EncSniReplayGuard } from './lib/transparent-tls-replay.mjs';
import { makeDnsQuery, fixtureDnsAnswer, validateDnsResponse } from './lib/lab-dns-wire.mjs';
import { parseDnsExitArgs, readDnsExitSecret } from './dns-exit-adapter.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { child } from './lib/browser-lab-driver.mjs';
import { startDnsExitAdapter } from './lib/dns-exit-adapter.mjs';

const cert = await readFile(new URL('./fixtures/boring-tls-local.cert.pem', import.meta.url), 'utf8');
const key = await readFile(new URL('./fixtures/boring-tls-local.key.pem', import.meta.url));
const input = { schema: 1, transport: 'doh', hostname: 'resolver.test', port: 443, path: '/custom/dns',
  bootstrap: { addresses: ['93.184.216.34'] }, trust: { mode: 'custom', certificates: [cert] } };
const publicOptions = () => ({ profile: compileDnsUpstream(input), exitAddress: '93.184.216.35', exitPort: 443,
  publicName: 'relay.test', secret: randomBytes(32) });

for (const [label, patch] of [
  ['hostname exit', { exitAddress: 'exit.test' }], ['loopback exit', { exitAddress: '127.0.0.1' }],
  ['private exit', { exitAddress: '10.1.2.3' }], ['multicast', { exitAddress: 'ff02::1' }],
  ['port zero', { exitPort: 0 }], ['port string', { exitPort: '443' }], ['invalid port', { exitPort: 65536 }],
  ['short PSK', { secret: Buffer.alloc(31) }], ['hex PSK', { secret: 'a'.repeat(64) }],
  ['suffix URL', { publicName: 'https://relay.test' }], ['suffix wildcard', { publicName: '*.relay.test' }],
  ['suffix empty label', { publicName: 'relay..test' }], ['trailing dot', { publicName: 'relay.test.' }],
  ['suffix too long for enc-SNI', { publicName: `${'x'.repeat(63)}.${'x'.repeat(63)}.${'x'.repeat(63)}.test` }],
  ['cloned profile', { profile: { ...compileDnsUpstream(input) } }],
  ['lab profile', { profile: compileLabDnsUpstream({ ...input, hostname: 'localhost', bootstrap: { addresses: ['127.0.0.1'] } }) }],
  ['lookup override', { lookup() {} }], ['direct socket override', { connectExit() {} }],
]) test(`exit transport preflight rejects ${label}`, () => assert.throws(() => createDnsExitTransport({ ...publicOptions(), ...patch }), { code: 'DNS_EXIT_CONFIG' }));

test('public IPv4/IPv6 transport creation is offline, branded, and close is idempotent', async () => {
  for (const exitAddress of ['93.184.216.35', '2606:4700::1111']) {
    const transport = createDnsExitTransport({ ...publicOptions(), exitAddress });
    assert.equal(transport.stats().connections, 0);
    assert.throws(() => dnsExitTransportTarget({ ...transport }), { code: 'DNS_EXIT_CONFIG' });
    const first = transport.close(); assert.equal(transport.close(), first); await first;
    assert.throws(() => dnsExitTransportTarget(transport), { code: 'DNS_EXIT_CONFIG' });
    assert.equal(transport.stats().sockets, 0);
  }
});

async function fixture(t, { badCa = false, wrongName = false, wrongSecret = false, mode = 'normal', timeoutMs = 300 } = {}) {
  let bodies = 0, attempts = 0;
  const wire = [];
  const sockets = new Set(), sessions = [];
  const track = (s) => { sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); };
  const origin = https.createServer({ key, cert, minVersion: 'TLSv1.3' }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const chunks = []; req.on('data', (b) => chunks.push(b));
    req.on('end', () => {
      bodies++;
      assert.equal(req.url, '/custom/dns'); assert.equal(req.headers.host, `localhost:${origin.address().port}`);
      assert.equal(req.socket.servername, 'localhost');
      if (mode === 'hold') return;
      if (mode === 'reset') { req.socket.destroy(); return; }
      if (mode === 'redirect') { res.writeHead(302, { location: 'http://resolver.test:53' }).end(); return; }
      res.writeHead(200, { 'content-type': 'application/dns-message' }).end(fixtureDnsAnswer(Buffer.concat(chunks)));
    });
  });
  origin.on('connection', track); origin.on('tlsClientError', () => {});
  origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
  const secret = randomBytes(32), publicName = 'relay.test';
  const profile = compileLabDnsUpstream({ ...input, hostname: wrongName ? 'wrong.test' : 'localhost', port: origin.address().port,
    bootstrap: { addresses: ['127.0.0.1'] }, trust: badCa ? { mode: 'bundled' } : input.trust });
  const destinationPolicy = new ExitDestinationPolicy({ loopback: { hostname: profile.hostname, port: profile.port } });
  const replayGuard = new EncSniReplayGuard();
  const exit = net.createServer((socket) => {
    track(socket);
    socket.on('data', (bytes) => wire.push(Buffer.from(bytes)));
    sessions.push(wireTransparentTlsEncSniSession(socket, { vpnSecretBuf: secret, publicName, replayGuard, destinationPolicy,
      connectOrigin(address, port) { attempts++; return net.connect({ host: address, port }); } }));
  });
  exit.listen(0, '127.0.0.1'); await once(exit, 'listening');
  const options = { profile, exitAddress: '127.0.0.1', exitPort: exit.address().port, publicName,
    secret: wrongSecret ? randomBytes(32) : Buffer.from(secret) };
  const transport = createLabDnsExitTransport(options);
  // Transport owns snapshots, not the caller's mutable key/options.
  options.secret.fill(0); options.exitAddress = 'resolver.test'; options.exitPort = 1;
  const stub = await startLabDohStub({ exitTransport: transport, timeoutMs, maxInflight: 2 });
  t.after(async () => {
    await stub.close(); await transport.close();
    for (const socket of sockets) socket.destroy();
    await Promise.all(sessions.filter(Boolean).map((session) => session.closed));
    await Promise.all([origin, exit].map((server) => new Promise((resolve) => server.close(resolve))));
    await delay(10);
    for (const field of ['sockets', 'jobs']) assert.equal(transport.stats()[field], 0, field);
    for (const field of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stub.stats()[field], 0, field);
    for (const session of sessions.filter(Boolean)) assert.equal(session.timers.size, 0);
    assert.equal(sockets.size, 0);
  });
  return { stub, transport, wire, exitPort: exit.address().port, originPort: origin.address().port,
    counts: () => ({ bodies, attempts }), stopExit: () => new Promise((resolve) => exit.close(resolve)) };
}
for (const tcp of [false, true]) for (const type of [1, 28]) test(`in-memory relay ${tcp ? 'TCP' : 'UDP'} type ${type}: verified TLS, identity/path, snapshot, no listener`, async (t) => {
  const lab = await fixture(t);
  const packet = makeDnsQuery('private-adapter.dns-lab.test', type, 4321);
  const reply = await queryLabDns(lab.stub.port, packet, { tcp, fragment: true });
  assert.equal(validateDnsResponse(reply, packet).counts[0], 1);
  assert.deepEqual(lab.counts(), { bodies: 1, attempts: 1 });
  assert.equal(lab.transport.stats().connections, 1);
});
for (const options of [{ badCa: true }, { wrongName: true }, { wrongSecret: true }, { mode: 'hold' }, { mode: 'reset' }, { mode: 'redirect' }]) {
  test(`in-memory relay fails closed: ${JSON.stringify(options)}`, async (t) => {
    const lab = await fixture(t, options), packet = makeDnsQuery('private-adapter.dns-lab.test', 1, 77);
    const reply = await queryLabDns(lab.stub.port, packet);
    assert.equal(validateDnsResponse(reply, packet).flags & 15, 2);
    assert.equal(lab.counts().bodies, options.mode ? 1 : 0);
    assert.equal(lab.transport.stats().connections, 1);
    assert.equal(lab.counts().attempts, options.wrongSecret ? 0 : 1);
  });
}
test('numeric exit unavailable: SERVFAIL, no origin attempt', async (t) => {
  const lab = await fixture(t); await lab.stopExit();
  const packet = makeDnsQuery('private-adapter.dns-lab.test', 1);
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, packet), packet).flags & 15, 2);
  assert.deepEqual(lab.counts(), { bodies: 0, attempts: 0 });
});
test('shutdown aborts a held TLS request and drains resources', async (t) => {
  const lab = await fixture(t, { mode: 'hold', timeoutMs: 1000 });
  const request = queryLabDns(lab.stub.port, makeDnsQuery('private-adapter.dns-lab.test', 1), { tcp: true }).catch(() => {});
  const deadline = Date.now() + 2000;
  while (!lab.counts().bodies) { assert.ok(Date.now() < deadline); await delay(5); }
  await lab.transport.close(); await request; await lab.stub.close();
  assert.equal(lab.transport.stats().jobs, 0);
});
test('no system lookup, direct resolver or plaintext QNAME on client-exit wire', async (t) => {
  const lab = await fixture(t);
  let lookups = 0;
  for (const api of [dns, dnsPromises]) for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
    const original = api[name];
    t.mock.method(api, name, (...args) => {
      // dgram invokes lookup for numeric bind/send, without an actual DNS query.
      if (name === 'lookup' && net.isIP(args[0])) return original.apply(api, args);
      lookups++; throw new Error('lookup forbidden');
    });
  }
  const connects = [], connect = net.Socket.prototype.connect;
  t.mock.method(net.Socket.prototype, 'connect', function (...args) {
    const options = Array.isArray(args[0]) ? args[0][0] : args[0];
    connects.push({ address: options.host, port: options.port }); return connect.apply(this, args);
  });
  const packet = makeDnsQuery('private-adapter.dns-lab.test', 28);
  assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, packet), packet).counts[0], 1);
  assert.equal(lookups, 0); assert.equal(lab.transport.stats().connections, 1);
  const wire = Buffer.concat(lab.wire); assert.ok(wire.length > 100);
  assert.equal(wire.includes(Buffer.from('private-adapter')), false);
  assert.equal(wire.includes(packet.subarray(12)), false);
  assert.equal(lab.counts().bodies, 1);
  assert.deepEqual(connects, [{ address: '127.0.0.1', port: lab.exitPort }, { address: '127.0.0.1', port: lab.originPort }]);
});
test('invalid limits and occupied listen port roll back adapter startup without connecting', async () => {
  await assert.rejects(startDnsExitAdapter({ ...publicOptions(), maxInflight: 0 }), { code: 'DNS_CONFIG' });
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try { await assert.rejects(startDnsExitAdapter({ ...publicOptions(), port: server.address().port }), { code: 'EADDRINUSE' }); }
  finally { await new Promise((resolve) => server.close(resolve)); }
});

const argv = ['--config=/private/config.json', '--exit-ip=93.184.216.35', '--exit-port=443', '--public-name=relay.test',
  '--shared-hmac-key=/private/key', '--listen-port=1053'];
for (const args of [[], argv.slice(1), [...argv, argv[0]], [...argv, '--direct=true'], [...argv, '--help'],
  argv.map((x) => x === '--listen-port=1053' ? '--listen-port=53' : x),
  argv.map((x) => x === '--exit-port=443' ? '--exit-port=443junk' : x)]) {
  test(`CLI rejects invalid arguments ${JSON.stringify(args)}`, () => assert.throws(() => parseDnsExitArgs(args), /DNS_EXIT_ADAPTER_INVALID/));
}
test('CLI help is offline; errors are redacted', async () => {
  assert.equal(parseDnsExitArgs(argv)['listen-port'], 1053);
  for (const [args, code] of [[['--help'], 0], [argv, 1]]) {
    const result = await runCommand(process.execPath, ['scripts/dns-exit-adapter.mjs', ...args], { env: cleanEnvironment(process.env) });
    assert.equal(result.code, code); assert.equal(result.reason, null);
    if (code) { assert.equal(result.stderr.trim(), 'DNS_EXIT_ADAPTER_INVALID'); assert.equal(result.stdout, ''); }
  }
});
test('PSK reader requires exactly 32 binary bytes, private regular file, no symlink', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-exit-key-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'key'), secret = randomBytes(32);
  await writeFile(path, secret, { mode: 0o600 }); assert.deepEqual(await readDnsExitSecret(path), secret);
  await symlink(path, join(dir, 'link')); await assert.rejects(readDnsExitSecret(join(dir, 'link')), /DNS_EXIT_ADAPTER_INVALID/);
  await assert.rejects(readDnsExitSecret(dir), /DNS_EXIT_ADAPTER_INVALID/);
  await chmod(path, 0o644); await assert.rejects(readDnsExitSecret(path), /DNS_EXIT_ADAPTER_INVALID/);
  await chmod(path, 0o600);
  for (const size of [0, 31, 33, 65536]) { await writeFile(path, Buffer.alloc(size)); await assert.rejects(readDnsExitSecret(path), /DNS_EXIT_ADAPTER_INVALID/); }
});
for (const signal of ['SIGINT', 'SIGTERM']) test(`CLI explicit bind then ${signal} releases listener without resolver traffic`, { timeout: 10000 }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-dns-exit-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'upstream.json'), secret = join(dir, 'key');
  await writeFile(config, JSON.stringify(input), { mode: 0o600 }); await writeFile(secret, randomBytes(32), { mode: 0o600 });
  const portProbe = net.createServer(); portProbe.listen(0, '127.0.0.1'); await once(portProbe, 'listening');
  const port = portProbe.address().port; await new Promise((resolve) => portProbe.close(resolve));
  const proc = child(process.execPath, ['scripts/dns-exit-adapter.mjs', `--config=${config}`, '--exit-ip=93.184.216.35',
    '--exit-port=443', '--public-name=relay.test', `--shared-hmac-key=${secret}`, `--listen-port=${port}`], { env: cleanEnvironment(process.env) });
  t.after(() => proc.stop());
  const ready = await proc.waitFor(/DNS_EXIT_ADAPTER (\{[^\n]+\})/, 5000);
  assert.deepEqual(JSON.parse(ready[1]), { status: 'listening', address: '127.0.0.1', port, systemDnsChanged: false });
  await proc.stop(signal); assert.equal(proc.proc.exitCode, 0);
  portProbe.listen(port, '127.0.0.1'); await once(portProbe, 'listening'); await new Promise((resolve) => portProbe.close(resolve));
});
