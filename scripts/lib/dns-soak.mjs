/** Bounded lab-only workload and resource budgets. */
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';

export function dnsSoakOptions(args) {
  const result = { seconds: 60, concurrency: 4 }, seen = new Set();
  for (const arg of args) {
    if (arg === '--help' && args.length === 1) return { ...result, help: true };
    const match = /^--(seconds|concurrency|report)=(.+)$/.exec(arg);
    assert.ok(match && !seen.has(match[1]), 'invalid/duplicate DNS soak option'); seen.add(match[1]);
    if (match[1] === 'report') result.report = match[2];
    else { assert.match(match[2], /^[1-9]\d*$/); result[match[1]] = Number(match[2]); }
  }
  assert.ok(result.seconds >= 1 && result.seconds <= 600);
  assert.ok(result.concurrency >= 1 && result.concurrency <= 8);
  return result;
}

export function assertDnsIdle(lab) {
  const stats = lab.stats(), relay = lab.relay.stats();
  for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stats.stub[key], 0, key);
  assert.equal(stats.resolverSockets, 0); assert.equal(relay.sockets, 0);
  assert.equal(relay.pendingClients, 0);
  for (const key of ['relaySessions', 'relayTimers', 'cleanupFailures']) assert.equal(relay[key], 0, key);
  return { dns: stats, relay };
}

export function assertDnsSoakResult(result, options) {
  assert.equal(result.schema, 1); assert.equal(result.status, 'passed');
  assert.equal(result.seconds, options.seconds); assert.equal(result.concurrency, options.concurrency);
  assert.equal(result.warmupWaves, 10); assert.ok(Number.isInteger(result.waves) && result.waves > 0);
  assert.ok(result.measuredMs >= options.seconds * 1000); assert.ok(result.samples.length > 0);
  const queries = result.waves * options.concurrency;
  assert.deepEqual(result.totals, { replies: queries * 8, servfail: queries * 4, nxdomain: queries,
    truncated: result.waves * Math.ceil(options.concurrency / 2), restarts: result.waves });
  assert.equal(result.pcap.positiveControl, true); assert.equal(result.pcap.localStubPlaintext, true);
  assert.equal(result.pcap.protectedPlaintext, false); assert.ok(result.pcap.packets > 0);
  assert.equal(result.cleanupFailed ?? false, false);
  for (const sample of result.samples) assertDnsResources(sample.resources, result.baseline);
  assertDnsResources(result.final.resources, result.baseline, true);
  assertDnsIdle({ stats: () => result.final.owned.dns, relay: { stats: () => result.final.owned.relay } });
  const stats = result.final.owned.dns.stub, allQueries = 16 + (result.waves + result.warmupWaves) * options.concurrency * 8;
  assert.equal(stats.queries, allQueries); assert.equal(stats.forwarded, allQueries); assert.equal(stats.rejected, 0);
  assert.equal(stats.succeeded, allQueries / 2); assert.equal(stats.failed, allQueries / 2);
}

export async function drainDns(lab) {
  const deadline = performance.now() + 3000;
  for (;;) {
    try { return assertDnsIdle(lab); }
    catch (error) { if (performance.now() >= deadline) throw error; }
    await delay(10);
  }
}

export function assertDnsResources(sample, baseline, final = false) {
  assert.equal(sample.tree.live, 1, 'unexpected child process'); assert.equal(sample.tree.zombies, 0);
  assert.ok(sample.worker.memory.rss <= 256 * 1048576, 'RSS ceiling');
  assert.ok(sample.worker.fds <= 128, 'FD ceiling');
  if (baseline) {
    assert.ok(sample.worker.fds <= baseline.worker.fds, 'idle FD growth');
    const memory = baseline.warmupHighWater ?? baseline.worker.memory;
    assert.ok(sample.worker.memory.rss <= memory.rss + 64 * 1048576, 'RSS growth');
    assert.ok(sample.worker.memory.heapUsed <= memory.heapUsed + 32 * 1048576, 'heap growth');
  }
  for (const key of ['TCPSocketWrap', 'ProcessWrap', 'Timeout']) assert.equal(sample.worker.active[key] ?? 0, 0, key);
  if (final) for (const key of ['TCPServerWrap', 'UDPWrap']) assert.equal(sample.worker.active[key] ?? 0, 0, key);
}

export async function dnsWave(lab, query, name, concurrency, signal) {
  const totals = { replies: 0, servfail: 0, nxdomain: 0, truncated: 0, restarts: 0 };
  for (const mode of ['normal', 'nxdomain', 'large', 'reset', 'hold', 'redirect', 'offline', 'normal']) {
    signal?.throwIfAborted();
    if (mode === 'offline') await lab.stopOrigin(); else lab.setMode(mode);
    try {
      await Promise.all(Array.from({ length: concurrency }, async (_, i) => {
        const tcp = i % 2 === 1, packet = makeDnsQuery(name, i % 2 ? 28 : 1, 100 + i);
        const result = validateDnsResponse(await query(lab.stub.port, packet, { tcp, fragment: tcp }), packet);
        const failed = ['reset', 'hold', 'redirect', 'offline'].includes(mode);
        assert.equal(result.flags & 15, failed ? 2 : mode === 'nxdomain' ? 3 : 0);
        if (failed) totals.servfail++;
        else if (mode === 'nxdomain') totals.nxdomain++;
        else if (mode === 'large' && !tcp) { assert.ok(result.flags & 0x200); totals.truncated++; }
        else assert.equal(result.counts[0], mode === 'large' ? 40 : 1);
        totals.replies++;
      }));
    } finally { if (mode === 'offline') { await lab.restartOrigin(); totals.restarts++; } }
    await drainDns(lab);
  }
  return totals;
}
