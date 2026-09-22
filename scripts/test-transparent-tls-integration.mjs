/** Real loopback sockets and verified TLS, no TUN/native helper/root/dependencies. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  startTransparentTlsLab, requestThroughLab, assertRelayTrace,
} from './lib/transparent-tls-lab.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';

const TEST_OPTS = { timeout: 15_000 };

async function labFor(t, options) {
  const lab = await startTransparentTlsLab(options);
  t.after(async () => {
    await lab.close();
    assert.equal(lab.stats().sockets, 0, 'all tracked sockets closed');
  });
  return lab;
}

for (const httpVersion of ['1.1', '2']) {
  test(`verified TLS 1.3 + HTTP/${httpVersion}: payload, SNI, full ClientHello, JA3/JA4`, TEST_OPTS, async (t) => {
    const lab = await labFor(t);
    const payload = randomBytes(512 * 1024);
    const response = await requestThroughLab(lab, { httpVersion, body: payload, path: '/echo' });
    assert.equal(response.tlsVersion, 'TLSv1.3');
    assert.deepEqual(response.body, payload);
    const trace = assertRelayTrace(lab);
    assert.equal(trace.restored, true);
    assert.equal(lab.stats().requests, 1);
  });
}

test('TLS 1.2 also passes through without TLS termination at relay', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const response = await requestThroughLab(lab, {
    tlsOptions: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
  });
  assert.equal(response.tlsVersion, 'TLSv1.2');
  assert.equal(JSON.parse(response.body).servername, 'localhost');
  assertRelayTrace(lab);
});

test('simultaneous sessions are matched by ClientHello random, not arrival order', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await Promise.all(Array.from({ length: 6 }, (_, i) => requestThroughLab(lab, {
    httpVersion: i % 2 ? '2' : '1.1', body: Buffer.alloc(4096, i), path: '/echo',
  }).then((result) => assert.deepEqual(result.body, Buffer.alloc(4096, i)))));
  const clients = lab.captures.filter((capture) => capture.stage === 'client');
  assert.equal(clients.length, 6);
  assert.equal(new Set(clients.map((capture) => capture.id)).size, 6);
  for (const capture of clients) assertRelayTrace(lab, capture.id);
});

/** Test-only byte shaper; alters TLS record boundaries, not handshake contents. */
async function fragmentingProxy(t, lab) {
  const server = net.createServer((socket) => {
    lab.track(socket);
    const upstream = lab.track(net.connect({ host: lab.host, port: lab.clientPort }));
    upstream.pipe(socket);
    socket.once('close', () => upstream.destroy());
    upstream.once('close', () => socket.destroy());
    const chunks = [];
    let total = 0;
    const onData = (chunk) => {
      total += chunk.length;
      if (total > 64 * 1024) return socket.destroy(new Error('test shaper limit'));
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      const parsed = parseFirstTlsClientHelloFromTcpBuf(all);
      if (parsed.needMore) return;
      socket.pause();
      socket.off('data', onData);
      if (!parsed.ok) return socket.destroy(new Error(parsed.reason));
      const message = Buffer.alloc(4 + parsed.clientHelloBody.length);
      message[0] = 1;
      message.writeUIntBE(parsed.clientHelloBody.length, 1, 3);
      parsed.clientHelloBody.copy(message, 4);
      const split = 43;
      const records = [message.subarray(0, split), message.subarray(split)].map((body) => {
        const header = Buffer.from([0x16, all[1], all[2], 0, 0]);
        header.writeUInt16BE(body.length, 3);
        return Buffer.concat([header, body]);
      });
      const wire = Buffer.concat([...records, all.subarray(parsed.bytesConsumed)]);
      (async () => {
        for (let at = 0; at < wire.length; at += 37) {
          if (upstream.destroyed || socket.destroyed) return;
          if (!upstream.write(wire.subarray(at, at + 37))) await once(upstream, 'drain');
          await delay(1);
        }
        socket.pipe(upstream);
        socket.resume();
      })().catch((error) => socket.destroy(error));
    };
    socket.on('data', onData);
  });
  server.listen(0, lab.host);
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return server.address().port;
}

test('real handshake fragmented across TLS records and TCP writes', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const port = await fragmentingProxy(t, lab);
  const response = await requestThroughLab(lab, { port });
  assert.equal(JSON.parse(response.body).ok, true);
  const trace = assertRelayTrace(lab);
  assert.equal(trace.records.client.length, 2);
  // Current runtime deliberately rebuilds one record: record-layout fidelity is NOT claimed.
  assert.equal(trace.records.origin.length, 1);
  assert.ok(lab.captures.find((capture) => capture.stage === 'client').chunkCount > 1);
});

test('wrong enc-SNI PSK is rejected before an origin connection', TEST_OPTS, async (t) => {
  const lab = await labFor(t, { clientPsk: randomBytes(32) });
  await assert.rejects(requestThroughLab(lab));
  assert.equal(lab.stats().originConnections, 0);
  assert.equal(lab.stats().requests, 0);
});

test('untrusted origin certificate is rejected by the application', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await assert.rejects(requestThroughLab(lab, { ca: [] }), /self.signed|issuer|verify/i);
  assert.equal(lab.stats().requests, 0);
  assertRelayTrace(lab);
});

test('origin certificate hostname mismatch is not bypassed', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await assert.rejects(requestThroughLab(lab, {
    tlsOptions: { checkServerIdentity: (_hostname, certificate) => tls.checkServerIdentity('wrong.invalid', certificate) },
  }), /hostname|altnames/i);
  assert.equal(lab.stats().requests, 0);
});

test('missing SNI is rejected without opening an origin socket', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await assert.rejects(requestThroughLab(lab, { tlsOptions: { servername: '' } }));
  assert.equal(lab.stats().originConnections, 0);
});

test('lab connector refuses non-lab destinations even with a valid route token', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await assert.rejects(requestThroughLab(lab, { tlsOptions: { servername: 'example.com' } }));
  assert.equal(lab.stats().originConnections, 0);
});

test('SNI too long for enc-SNI is rejected cleanly', TEST_OPTS, async (t) => {
  const name = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.test`;
  const lab = await labFor(t, { originName: name });
  await assert.rejects(requestThroughLab(lab));
  assert.equal(lab.stats().originConnections, 0);
  assert.ok(lab.diagnostics.some((message) => /enc-SNI encode/.test(message)));
});

test('partial ClientHello, shutdown and idempotent cleanup', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const socket = lab.track(net.connect({ host: lab.host, port: lab.clientPort }));
  await once(socket, 'connect');
  socket.write(Buffer.from([0x16, 0x03, 0x01]));
  await delay(10);
  await lab.close();
  await lab.close();
  assert.equal(lab.stats().sockets, 0);
});

test('malformed ClientHello is rejected and the lab remains usable', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const socket = lab.track(net.connect({ host: lab.host, port: lab.clientPort }));
  await once(socket, 'connect');
  const closed = once(socket, 'close');
  socket.write(Buffer.from([0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0]));
  await closed;
  assert.equal(lab.stats().originConnections, 0);
  assert.equal(JSON.parse((await requestThroughLab(lab)).body).ok, true);
});

test('harness idle timeout closes an incomplete ClientHello (not production hardening)', TEST_OPTS, async (t) => {
  const lab = await labFor(t, { sessionTimeoutMs: 100 });
  const socket = lab.track(net.connect({ host: lab.host, port: lab.clientPort }));
  // Do not let the test client's own timer produce a false positive.
  socket.setTimeout(0);
  await once(socket, 'connect');
  const closed = once(socket, 'close');
  socket.write(Buffer.from([0x16, 0x03, 0x01]));
  await closed;
  assert.equal(lab.stats().originConnections, 0);
});

test('invalid/privileged ports fail before starting listeners', TEST_OPTS, async () => {
  for (const clientPort of [-1, 443, 65536, 1.5]) {
    await assert.rejects(startTransparentTlsLab({ clientPort }), /ports must/);
  }
});

test('startup port conflict cleans up listeners already created', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  await assert.rejects(startTransparentTlsLab({ clientPort: lab.clientPort }), { code: 'EADDRINUSE' });
  const response = await requestThroughLab(lab);
  assert.equal(JSON.parse(response.body).ok, true);
});

test('CLI --serve self-check, manual HTTPS connection and SIGTERM cleanup', TEST_OPTS, async (t) => {
  const entry = fileURLToPath(new URL('./transparent-tls-lab.mjs', import.meta.url));
  const child = spawn(process.execPath, [entry, '--serve'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(child, 'exit');
  // Make an early child spawn failure handled even before teardown awaits it.
  exited.catch(() => {});
  t.after(async () => {
    if (child.exitCode == null && child.signalCode == null) child.kill('SIGTERM');
    const killTimer = setTimeout(() => child.kill('SIGKILL'), 2000);
    try { await exited; } finally { clearTimeout(killTimer); }
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-8192); });
  const ready = await new Promise((resolve, reject) => {
    let stdout = '';
    const deadline = setTimeout(() => reject(new Error(`CLI startup timeout: ${stderr}`)), 5000);
    const fail = (error) => { clearTimeout(deadline); reject(error); };
    child.once('error', fail);
    child.once('exit', (code) => fail(new Error(`CLI exited before ready: ${code}: ${stderr}`)));
    child.stdout.on('data', (chunk) => {
      stdout = (stdout + chunk).slice(-32 * 1024);
      const match = /^LAB_READY (.+)$/m.exec(stdout);
      if (match) {
        clearTimeout(deadline);
        resolve(JSON.parse(match[1]));
      }
    });
  });
  assert.equal(ready.host, '127.0.0.1');
  const payload = await new Promise((resolve, reject) => {
    const request = https.get({
      host: ready.host, port: ready.clientPort, servername: 'localhost',
      ca: readFileSync(ready.ca), rejectUnauthorized: true, agent: false,
      headers: { host: `localhost:${ready.originPort}` },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => resolve(Buffer.concat(chunks)));
    });
    request.on('error', reject);
    request.setTimeout(5000, () => request.destroy(new Error('manual HTTPS timeout')));
  });
  assert.equal(JSON.parse(payload).ok, true);
  child.kill('SIGTERM');
  const [code, signal] = await exited;
  assert.equal(code, 0, stderr);
  assert.equal(signal, null);
});
