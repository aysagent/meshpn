/** Real ECH, not GREASE: isolated Go crypto/tls endpoints, no external packages. */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import net from 'node:net';
import { once } from 'node:events';
import test, { before, after } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { startTransparentTlsLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';

const exec = promisify(execFile);
const OUTER = 'public.ech.test', INNER = 'hidden.ech.test';
const PAYLOAD = Buffer.from('ECH real application payload\n'.repeat(1024));
let dir, binary;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'meshpn-ech-test-'));
  binary = join(dir, 'ech-fixture');
  try {
    await exec(process.env.MESHPN_ECH_GO || 'go', ['build', '-trimpath', '-o', binary,
      fileURLToPath(new URL('./fixtures/transparent-ech/main.go', import.meta.url))], {
      timeout: 120_000, maxBuffer: 128 * 1024,
      env: { ...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off',
        GOENV: 'off', GOFLAGS: '', GOWORK: 'off', CGO_ENABLED: '0', GOCACHE: join(dir, 'cache') },
    });
  } catch {
    throw new Error('ECH tests require Go 1.24+ (MESHPN_ECH_GO or PATH); fixture build failed');
  }
}, { timeout: 130_000 });
after(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

/** Each plaintext handshake record becomes one-byte records. TLS handshake
 * bytes/AAD are untouched. Used for BOTH CH1 and CH2, never a mock ECH flight. */
async function fragmentingProxy(t, lab) {
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    lab.track(socket);
    const upstream = lab.track(net.connect({ host: lab.host, port: lab.clientPort, allowHalfOpen: true }));
    upstream.pipe(socket);
    socket.once('close', () => upstream.destroy());
    upstream.once('close', () => socket.destroy());
    let pending = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 128 * 1024) { socket.destroy(); return; }
      while (pending.length >= 5) {
        const length = 5 + pending.readUInt16BE(3);
        if (length > 16645) { socket.destroy(); return; }
        if (pending.length < length) return;
        const record = pending.subarray(0, length);
        pending = pending.subarray(length);
        if (record[0] !== 0x16) { upstream.write(record); continue; }
        const out = Buffer.alloc((length - 5) * 6);
        for (let i = 5; i < length; i++) {
          const at = (i - 5) * 6;
          record.copy(out, at, 0, 3);
          out.writeUInt16BE(1, at + 3);
          out[at + 5] = record[i];
        }
        upstream.write(out);
      }
    });
    socket.on('end', () => upstream.end());
  });
  t.after(async () => {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  });
  server.listen(0, lab.host);
  await once(server, 'listening');
  return server.address().port;
}

async function fixture(t, mode = 'accept', fragmented = false) {
  const child = spawn(binary, [mode], { stdio: ['pipe', 'pipe', 'pipe'] });
  let pending = '', failed = false, exited = false, total = 0;
  const messages = [];
  child.on('error', () => { failed = true; });
  child.stdin.on('error', () => {});
  child.stderr.on('data', () => { failed = true; });
  child.stdout.on('data', (chunk) => {
    total += chunk.length;
    if (total > 64 * 1024) { failed = true; child.kill('SIGKILL'); return; }
    pending += chunk.toString();
    let end;
    while ((end = pending.indexOf('\n')) >= 0) {
      try { messages.push(JSON.parse(pending.slice(0, end))); } catch { failed = true; }
      pending = pending.slice(end + 1);
    }
  });
  const closed = new Promise((resolve) => child.once('close', () => { exited = true; resolve(); }));
  t.after(async () => { if (!exited) child.kill('SIGKILL'); await closed; });
  async function next() {
    const end = Date.now() + 10_000;
    while (!messages.length) {
      if (failed || exited || Date.now() > end) throw new Error('ECH fixture failed or timed out');
      await delay(10);
    }
    return messages.shift();
  }
  const ready = await next();
  assert.equal(ready.ready, true);
  const lab = await startTransparentTlsLab({ originName: OUTER, externalOriginPort: ready.port, sessionTimeoutMs: 0 });
  t.after(async () => { await lab.close(); assert.equal(lab.stats().sockets, 0); });
  const port = fragmented ? await fragmentingProxy(t, lab) : lab.clientPort;
  return { lab, async request(http = '1.1', mode = '') {
    child.stdin.write(JSON.stringify({ port, http, mode }) + '\n');
    return next();
  } };
}

function assertSuccess(result, http, requests = 1) {
  assert.equal(result.error, undefined);
  assert.equal(result.clientECH, true);
  assert.equal(result.echAccepted, true);
  assert.equal(result.verified, true);
  assert.equal(result.serverName, INNER);
  assert.equal(result.http, `HTTP/${http === '2' ? '2.0' : http}`);
  assert.equal(result.requests, requests);
  assert.equal(result.bytes, PAYLOAD.length);
  assert.equal(result.sha256, createHash('sha256').update(PAYLOAD).digest('hex'));
}

function echExtension(body) {
  let at = 34;
  at += 1 + body[at];
  at += 2 + body.readUInt16BE(at);
  at += 1 + body[at];
  const end = at + 2 + body.readUInt16BE(at);
  assert.equal(end, body.length);
  at += 2;
  const extensions = new Map();
  while (at < end) {
    assert.ok(at + 4 <= end);
    const type = body.readUInt16BE(at), size = body.readUInt16BE(at + 2);
    at += 4;
    assert.ok(at + size <= end && !extensions.has(type));
    extensions.set(type, body.subarray(at, at + size));
    at += size;
  }
  const ech = extensions.get(0xfe0d);
  assert.ok(ech?.length > 10, 'real ECH outer extension');
  assert.equal(ech[0], 0, 'ECHClientHello.type outer');
  const encLength = ech.readUInt16BE(6);
  const payloadAt = 8 + encLength;
  assert.ok(payloadAt + 2 <= ech.length);
  const size = ech.readUInt16BE(payloadAt);
  assert.ok(size >= 16 && payloadAt + 2 + size === ech.length);
  return { wire: ech, encLength, configId: ech[5] };
}

function assertOuterTrace(lab, flight = 1) {
  const hello = lab.captures.findLast((c) => c.stage === 'client' && c.flight === flight);
  assert.ok(hello, 'real outer ClientHello captured');
  assertRelayTrace(lab, hello.id, flight);
  const ech = echExtension(hello.body);
  assert.equal(ech.encLength, flight === 1 ? 32 : 0, 'CH2 reuses the HPKE context with empty enc');
  for (const stage of ['exit', 'origin']) {
    const other = lab.captures.find((c) => c.stage === stage && c.id === hello.id && c.flight === flight);
    assert.ok(ech.wire.equals(echExtension(other.body).wire), 'encrypted ECH bytes are untouched');
  }
  for (const capture of lab.captures) {
    assert.ok(!capture.prefix.includes(Buffer.from(INNER)), 'hidden hostname never appears in plaintext captures');
  }
  return hello;
}

for (const http of ['1.1', '2']) {
  test(`real accepted ECH HTTP/${http}: outer route, inner authentication and resumption`, { timeout: 20_000 }, async (t) => {
    const { lab, request } = await fixture(t);
    const first = await request(http);
    assertSuccess(first, http);
    assert.equal(first.clientResumed, false);
    assertOuterTrace(lab);
    const second = await request(http);
    assertSuccess(second, http, 2);
    assert.equal(second.clientResumed, true);
    assert.equal(second.resumed, true);
    assertOuterTrace(lab);
    assert.equal(lab.stats().originConnections, 2);
    assert.deepEqual(lab.runtimeErrors, []);
  });

  test(`real ECH HTTP/${http} with HRR restores both fragmented outer hellos`, { timeout: 20_000 }, async (t) => {
    const { lab, request } = await fixture(t, 'hrr', true);
    assertSuccess(await request(http), http);
    const first = assertOuterTrace(lab, 1);
    const second = assertOuterTrace(lab, 2);
    assert.equal(first.id, second.id);
    assert.ok(first.records.length > 100 && second.records.length > 100);
    assert.equal(echExtension(first.body).configId, echExtension(second.body).configId);
    assert.ok(!echExtension(first.body).wire.equals(echExtension(second.body).wire), 'CH2 is freshly encrypted');
    const wire = lab.captures.filter((c) => c.stage === 'exit' && c.id === first.id);
    assert.equal(wire[0].sni, wire[1].sni, 'route token and origin connection are unchanged');
    assert.equal(lab.stats().originConnections, 1);
    assert.deepEqual(lab.runtimeErrors, []);
  });
}

test('stale ECH config fails before HTTP; only an explicit retry uses authenticated retry configs', { timeout: 20_000 }, async (t) => {
  const { lab, request } = await fixture(t);
  const rejected = await request('1.1', 'stale');
  assert.equal(rejected.error, 'ECH_REJECTED');
  assert.equal(rejected.retryAvailable, true);
  assert.equal(rejected.requests, 0);
  assert.equal(lab.stats().originConnections, 1);
  assertOuterTrace(lab);
  assertSuccess(await request('1.1', 'retry'), '1.1');
  assert.equal(lab.stats().originConnections, 2);
  assertOuterTrace(lab);
});

for (const [serverMode, clientMode, expected] of [
  ['unsupported', '', 'ECH_REJECTED'],
  ['bad-inner', '', 'CERT_HOSTNAME'],
  ['bad-outer', 'stale', 'CERT_HOSTNAME'],
  ['accept', 'bad-ca', 'CERT_AUTHORITY'],
]) test(`ECH failure ${serverMode}/${clientMode}: no HTTP or silent non-ECH reconnect`, { timeout: 20_000 }, async (t) => {
  const { lab, request } = await fixture(t, serverMode);
  const result = await request('1.1', clientMode);
  assert.equal(result.error, expected);
  assert.equal(result.requests, 0);
  assert.ok(!result.retryAvailable);
  assert.equal(lab.stats().originConnections, 1);
  assertOuterTrace(lab);
});
