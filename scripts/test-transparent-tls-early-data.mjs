/** Real OpenSSL 0-RTT endpoints; no native build, TUN, or certificate bypass. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, writeFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { startTransparentTlsLab, assertRelayTrace, LAB_CERT_PATH } from './lib/transparent-tls-lab.mjs';
import { HELLO_RETRY_RANDOM_HEX } from './lib/transparent-tls-retry.mjs';
import { ja3DebugFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';

const KEY = fileURLToPath(new URL('./fixtures/boring-tls-local.key.pem', import.meta.url));
const TIMEOUT = 8000;

// OpenSSL's diagnostic output may contain session secrets. Never include it in
// assertion errors, logs, or on-disk artifacts; keep each stream bounded.
function processFor(t, args, unbuffered = false) {
  // s_server mixes stdio diagnostics with raw payload writes. Disable stdio
  // buffering so its "Early data received" delimiter precedes the actual bytes.
  const child = spawn(unbuffered ? 'stdbuf' : 'openssl',
    unbuffered ? ['-o0', 'openssl', ...args] : args, { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', failed, exited = false;
  child.on('error', () => { failed = 'requires openssl and stdbuf (GNU coreutils)'; });
  child.stdin.on('error', () => {});
  for (const [stream, append] of [[child.stdout, (s) => { stdout += s; }],
    [child.stderr, (s) => { stderr += s; }]]) {
    stream.on('data', (bytes) => {
      if (failed) return;
      if (stdout.length + stderr.length + bytes.length > 512 * 1024) {
        failed = 'openssl output limit'; child.kill('SIGKILL');
        return;
      }
      append(bytes.toString());
    });
  }
  const closed = new Promise((resolve) => child.once('close', (code) => { exited = true; resolve(code); }));
  t.after(async () => {
    if (!exited) child.kill('SIGKILL');
    await closed;
    stdout = ''; stderr = '';
  });
  return {
    child, closed,
    output: () => stdout,
    async until(predicate, label) {
      const end = Date.now() + TIMEOUT;
      while (!predicate(stdout, stderr)) {
        if (failed || exited || Date.now() > end) throw new Error(`OpenSSL: ${failed ?? label}`);
        await delay(10);
      }
    },
  };
}

/** Delay real encrypted early records until HRR has crossed BOTH relay guards.
 * Preserves byte order in each TCP direction; no timer-based scheduling guess. */
async function earlyAfterHrr(t, port) {
  const sockets = new Set();
  let delayedBytes = 0;
  const server = net.createServer((peer) => {
    const upstream = net.connect({ host: '127.0.0.1', port });
    for (const socket of [peer, upstream]) {
      sockets.add(socket);
      socket.on('error', () => { peer.destroy(); upstream.destroy(); });
      socket.once('close', () => { sockets.delete(socket); peer.destroy(); upstream.destroy(); });
    }
    let pending = Buffer.alloc(0), reverse = Buffer.alloc(0), early = Buffer.alloc(0), released = false;
    const release = () => {
      if (!early.length || !reverse.includes(Buffer.from(HELLO_RETRY_RANDOM_HEX, 'hex'))) return;
      delayedBytes += early.length;
      released = true;
      upstream.write(early);
      if (pending.length) upstream.write(pending);
      peer.write(reverse);
      early = reverse = pending = Buffer.alloc(0);
    };
    peer.on('data', (chunk) => {
      if (released) { upstream.write(chunk); return; }
      pending = Buffer.concat([pending, chunk]);
      if (pending.length + early.length > 64 * 1024) { peer.destroy(); return; }
      while (pending.length >= 5) {
        const length = 5 + pending.readUInt16BE(3);
        if (pending.length < length) break;
        const record = pending.subarray(0, length);
        pending = pending.subarray(length);
        if (record[0] === 0x17) early = Buffer.concat([early, record]);
        else upstream.write(record);
      }
      release();
    });
    upstream.on('data', (chunk) => {
      if (released) { peer.write(chunk); return; }
      reverse = Buffer.concat([reverse, chunk]);
      if (reverse.length > 64 * 1024) { upstream.destroy(); return; }
      release();
    });
    peer.on('end', () => upstream.end());
    upstream.on('end', () => peer.end());
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { port: server.address().port, delayedBytes: () => delayedBytes };
}

async function fixture(t, groups = 'X25519') {
  const cleanups = [];
  const owner = { after: (fn) => cleanups.push(fn) };
  t.after(async () => {
    const errors = [];
    for (const cleanup of cleanups.reverse()) {
      try { await cleanup(); } catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, 'early-data fixture cleanup');
  });
  const dir = await mkdtemp(join(tmpdir(), 'meshpn-early-data-'));
  owner.after(() => rm(dir, { recursive: true, force: true }));
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
  const ticket = join(dir, 'session.pem');
  const earlyFile = join(dir, 'early.txt');
  await writeFile(ticket, '', { mode: 0o600 });
  const payload = `EARLY_BEGIN_${'0123456789abcdef'.repeat(256)}_EARLY_END\n`;
  await writeFile(earlyFile, payload, { mode: 0o600 });
  const server = processFor(owner, ['s_server', '-accept', '127.0.0.1:0',
    '-cert', LAB_CERT_PATH, '-key', KEY, '-tls1_3', '-early_data',
    '-max_early_data', '16384', '-recv_max_early_data', '16384',
    '-num_tickets', '1', '-groups', groups, '-anti_replay'], true);
  await server.until((out) => /ACCEPT 127\.0\.0\.1:(\d+)/.test(out), 'server readiness deadline');
  const externalOriginPort = Number(/ACCEPT 127\.0\.0\.1:(\d+)/.exec(server.output())[1]);
  const lab = await startTransparentTlsLab({ externalOriginPort, sessionTimeoutMs: 0 });
  owner.after(async () => { await lab.close(); assert.equal(lab.stats().sockets, 0); });
  assert.throws(() => lab.rotateTicketKeys(), /external origin/);
  assert.throws(() => lab.setOriginGroups('P-256'), /external origin/);
  async function connect({ early = false, clientGroups = groups, port = lab.clientPort, smallRecords = false } = {}) {
    const client = processFor(owner, ['s_client', '-connect', `127.0.0.1:${port}`,
      '-servername', 'localhost', '-verify_hostname', 'localhost', '-verify_return_error',
      '-CAfile', LAB_CERT_PATH, '-tls1_3', '-groups', clientGroups, '-nocommands',
      ...(smallRecords ? ['-max_send_frag', '512'] : []),
      ...(early ? ['-sess_in', ticket, '-early_data', earlyFile] : ['-sess_out', ticket])]);
    await client.until((out) => /Early data was (?:not sent|accepted|rejected)/.test(out), 'handshake deadline');
    assert.ok(/Verify return code: 0 \(ok\)/.test(client.output()), 'verified origin certificate');
    return client;
  }
  async function finish(client, marker) {
    client.child.stdin.write(`${marker}\n`);
    await server.until((out) => out.includes(`${marker}\n`), 'post-handshake data deadline');
    server.child.stdin.write(`REPLY_${marker}\n`);
    await client.until((out) => out.includes(`REPLY_${marker}\n`), 'reverse application data deadline');
    assert.equal(client.output().split(`REPLY_${marker}\n`).length - 1, 1);
    client.child.stdin.end();
    await client.until(() => client.child.exitCode !== null || client.child.signalCode !== null,
      'client shutdown deadline');
    assert.equal(await client.closed, 0, 'client closed cleanly');
  }
  const seed = await connect();
  const ticketDeadline = Date.now() + TIMEOUT;
  while (!(await stat(ticket)).size) {
    assert.ok(Date.now() < ticketDeadline, 'early-data session file deadline');
    await delay(10);
  }
  await finish(seed, 'WARMUP_DONE');
  assert.ok((await stat(ticket)).size > 0);
  assert.equal((await stat(ticket)).mode & 0o777, 0o600);
  return { lab, server, connect, finish, payload };
}

function assertEarlyHello(lab, expectedEarly, flight = 1) {
  const hello = lab.captures.findLast((c) => c.stage === 'client' && c.flight === flight);
  assert.ok(hello);
  assertRelayTrace(lab, hello.id, flight);
  const extensions = ja3DebugFromTcpBuf(hello.prefix).extTypes;
  assert.equal(extensions.includes(42), expectedEarly, 'actual early_data offer on the wire');
  assert.equal(extensions.at(-1), 41, 'PSK is still last');
  return hello;
}

for (const smallRecords of [false, true]) test(`real 0-RTT accepted once, then ticket rejected (small records=${smallRecords})`, { timeout: 30000 }, async (t) => {
  const { lab, server, connect, finish, payload } = await fixture(t);
  const accepted = await connect({ early: true, smallRecords });
  assert.ok(accepted.output().includes('Early data was accepted'));
  assert.ok(/Reused, TLSv1.3/.test(accepted.output()));
  await finish(accepted, 'ACCEPTED_DONE');
  assert.equal(server.output().split(payload).length - 1, 1, 'origin received exact early payload once');
  assert.ok(/Early data received:\n([\s\S]*?)\nEnd of early data/.exec(server.output())?.[1] === payload,
    'origin early-data API delivered precisely the payload, with no extra bytes');
  assertEarlyHello(lab, true);
  const rejected = await connect({ early: true, smallRecords });
  assert.ok(rejected.output().includes('Early data was rejected'));
  assert.ok(/New, TLSv1.3/.test(rejected.output()), 'single-use ticket falls back to full handshake');
  await finish(rejected, 'REJECTED_DONE');
  assert.equal(server.output().split(payload).length - 1, 1, 'rejected data never delivered or resent');
  assert.ok(server.output().includes('Early data was rejected'), 'origin confirms rejection');
  assertEarlyHello(lab, true);
  assert.equal(lab.stats().originConnections, 3);
  assert.deepEqual(lab.runtimeErrors, []);
});

for (const delayed of [false, true]) test(`real 0-RTT with HRR (late early records=${delayed}): CH2 and explicit application retry`, { timeout: 30000 }, async (t) => {
  const { lab, server, connect, finish, payload } = await fixture(t, 'P-256');
  const gate = delayed ? await earlyAfterHrr(t, lab.clientPort) : undefined;
  const client = await connect({ early: true, clientGroups: 'X25519:P-256', port: gate?.port, smallRecords: delayed });
  assert.ok(client.output().includes('Early data was rejected'));
  client.child.stdin.write('AFTER_HRR\n');
  await server.until((out) => out.includes('AFTER_HRR\n'), 'post-HRR marker deadline');
  assert.equal(server.output().split(payload).length - 1, 0, 'HRR never delivers early data');
  client.child.stdin.write(payload); // explicit application decision, NEVER automatic relay replay
  await finish(client, 'HRR_DONE');
  assert.equal(server.output().split(payload).length - 1, 1, 'explicit 1-RTT retry arrives exactly once');
  if (gate) assert.ok(gate.delayedBytes() > 0, 'real encrypted early records crossed HRR');
  const hello = assertEarlyHello(lab, true);
  assert.equal(assertEarlyHello(lab, false, 2).id, hello.id);
  const wire = lab.captures.filter((c) => c.stage === 'exit' && c.id === hello.id);
  assert.equal(wire[0].sni, wire[1].sni, 'same enc-SNI across retry');
  assert.ok(!wire[1].prefix.includes(Buffer.from(lab.originName)));
  assert.equal(lab.stats().originConnections, 2);
  assert.deepEqual(lab.runtimeErrors, []);
});

test('external lab origin hook rejects non-bound or privileged ports', async () => {
  for (const externalOriginPort of [0, -1, 443, 65536, 'localhost', NaN]) {
    await assert.rejects(startTransparentTlsLab({ externalOriginPort }), /port/i);
  }
});
