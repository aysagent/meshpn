/** Adapter process death with live resolved, durable controller journal and independent DNS guard. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { mkdir, writeFile, readFile, readlink } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { createResolvedJournalBackend, resolvedMethod } from './dns-resolved-backend.mjs';
import { readResolvedJournal } from './dns-resolved-journal.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { drainAdapter } from './dns-adapter-soak.mjs';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';

async function until(predicate) {
  const deadline = performance.now() + 3000;
  while (!(await predicate())) { assert.ok(performance.now() < deadline, 'adapter process lab deadline'); await delay(10); }
}
export function assertProcessAdapterIdle(snapshot) {
  assert.ok(snapshot?.owned && snapshot.resources, 'fresh adapter snapshot required');
  for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(snapshot.owned.stub[key], 0, key);
  for (const key of ['sockets', 'jobs']) assert.equal(snapshot.owned.transport[key], 0, key);
  assert.ok(Number.isSafeInteger(snapshot.resources.rss) && snapshot.resources.rss > 0 && snapshot.resources.rss < 192 * 1048576);
  assert.ok(Number.isSafeInteger(snapshot.resources.fds) && snapshot.resources.fds > 0 && snapshot.resources.fds < 64);
}
export async function runAdapterCrashLab({ directory, lab, bus, ifindex, identity, setGuard, lookup, hits }) {
  await assertDnsMountNamespace();
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) scope[key] = await readlink(`/proc/self/ns/${key}`);
  const baseline = { DNSEx: [[2, [127, 0, 0, 55], 0, '']], Domains: [['baseline.test', false]], DefaultRoute: false };
  await setGuard(true);
  for (const [key, value] of Object.entries(baseline)) await bus.set(await bus.owner(), resolvedMethod(key, value, ifindex));
  await setGuard(false);
  const query = (name, expected, tcp = false, family = 4) => lookup(name, expected, tcp, family, 'baseline.test', expected === null);
  await query('adapter-process-baseline', '203.0.113.8');
  const worker = await lab.createProcessAdapter(), port = worker.port;
  const path = join(directory, 'adapter-process-journal'); await mkdir(path, { mode: 0o700 });
  await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 });
  const probe = async () => {
    assert.ok(worker.running(), 'adapter process absent');
    await worker.refresh();
    for (const tcp of [false, true]) {
      const q = makeDnsQuery('adapter-readiness.test');
      assert.equal(validateDnsResponse(await queryLabDns(port, q, { tcp }), q).flags & 15, 0, 'protected adapter readiness failed');
    }
  };
  const backend = createResolvedJournalBackend({ bus, ifindex, identity, scope, port,
    ensureGuard: () => setGuard(true), removeGuard: () => setGuard(false), probe });
  const run = async (operation, success = true) => {
    const result = await controller(path, operation, backend, undefined, 'resolved').done;
    assert.equal(result.code, success ? 0 : 2, result.stderr); return result.result;
  };
  const guard = async () => {
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    }
  };
  const idle = async () => {
    await until(async () => { try { assertProcessAdapterIdle(await worker.refresh()); return true; } catch { return false; } });
    await drainAdapter(lab);
  };
  let killed = 0, starts = 0, startupFailures = 0, refused = 0;
  const start = async () => { await worker.start(); starts++; assert.equal(worker.port, port); };
  const kill = async () => { assert.equal((await worker.stop('SIGKILL')).signal, 'SIGKILL'); killed++; assert.equal(worker.running(), false); assert.equal(worker.stats(), undefined); };
  const before = hits();
  try {
    await run('enable', false); refused++;
    const id = (await readResolvedJournal(path)).id;
    const blocked = async (label, recover = true) => {
      const view = await backend.view(), journal = await readFile(join(path, 'journal.json'));
      if (recover) { await run('recover', false); refused++; }
      assert.deepEqual(await backend.view(), view); assert.deepEqual(await readFile(join(path, 'journal.json')), journal);
      await guard();
      await query(`${label}-udp-blocked`, null); await query(`${label}-tcp-blocked`, null, true);
      assert.equal(hits(), before);
    };
    await blocked('adapter-not-started');
    // Binding both sockets is not protected upstream readiness.
    await lab.stopExit(); await start(); await blocked('adapter-bound-exit-down');
    await lab.restartExit();
    const recover = async (label) => {
      assert.equal((await run('recover')).id, id); await guard();
      await query(`${label}-a`, '192.0.2.123'); await query(`${label}-aaaa`, '2001:db8::12', true, 6);
      assert.equal(hits(), before); await idle();
    };
    await recover('adapter-initial-ready');
    const managed = await backend.view();
    for (let wave = 0; wave < 3; wave++) {
      await kill(); assert.deepEqual(await backend.view(), managed); await blocked(`adapter-idle-kill-${wave}`);
      await start(); await recover(`adapter-idle-restart-${wave}`);
    }
    // Kill after real UDP and TCP queries reach held DoH origin, not just after bind.
    lab.setMode('hold'); const bodies = lab.stats().resolverBodies;
    const pending = [false, true].map((tcp, index) => {
      const q = makeDnsQuery(`adapter-inflight-${index}.test`);
      return queryLabDns(port, q, { tcp, timeoutMs: 2500 }).then((reply) => {
        assert.notEqual(validateDnsResponse(reply, q).flags & 15, 0, 'killed in-flight query unexpectedly succeeded');
      }, () => {});
    });
    try {
      await until(() => lab.stats().resolverBodies === bodies + 2);
      const inFlight = await worker.refresh(); assert.equal(inFlight.owned.stub.inflight, 2); assert.equal(inFlight.owned.stub.requests, 2);
      await kill();
    }
    finally { lab.setMode('normal'); await Promise.all(pending); }
    await blocked('adapter-inflight-kill'); await drainAdapter(lab);
    // Explicit port binding only: neither protocol may silently choose a new port.
    for (const protocol of ['udp', 'tcp']) {
      const occupied = protocol === 'udp' ? dgram.createSocket('udp4') : net.createServer((socket) => socket.destroy());
      if (protocol === 'udp') occupied.bind(port, '127.0.0.1'); else occupied.listen(port, '127.0.0.1');
      await once(occupied, 'listening');
      try {
        await assert.rejects(worker.start()); startupFailures++; assert.equal(worker.running(), false);
        await blocked(`adapter-${protocol}-port-conflict`);
      } finally { await new Promise((resolve) => occupied.close(resolve)); }
    }
    await start(); await recover('adapter-inflight-restart');
    const stopped = await worker.stop(); assert.equal(stopped.code, 0); assert.equal(stopped.signal, null);
    assertProcessAdapterIdle(worker.stats()); await blocked('adapter-graceful-stop');
    // Explicit disable remains possible without a live adapter; recovery never does this automatically.
    const released = await run('disable'); assert.equal(released.id, id); assert.equal(released.status, 'released');
    assert.deepEqual((await backend.view()).settings, baseline);
    await query('adapter-process-explicit-disable', '203.0.113.8', true); assert.ok(hits() > before);
    for (const key of ['TCPSocketWrap', 'TCPServerWrap', 'UDPWrap', 'Timeout']) assert.equal(worker.stats().resources.active[key] ?? 0, 0, key);
    await drainAdapter(lab);
    return { status: 'passed', adapterSigkills: killed, starts, startupFailures, refusedOperations: refused,
      inFlightQueries: 2, stableEndpoint: true, baselineQueriesDuringProtection: 0,
      gracefulShutdown: true, disableWhileAdapterDown: true, rebootTested: false, automaticRestart: false };
  } finally { await worker.close(); }
}
