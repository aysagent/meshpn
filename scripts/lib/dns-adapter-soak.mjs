import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { dnsSoakOptions, dnsWave, assertDnsIdle, assertDnsResources } from './dns-soak.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';

export function adapterSoakOptions(args) {
  const extra = { family: 4, modeTag: 'transparent-tls' }, seen = new Set(), base = [];
  for (const arg of args) {
    const match = /^--(family|mode)=(.*)$/.exec(arg);
    if (!match) { base.push(arg); continue; }
    assert.ok(!seen.has(match[1])); seen.add(match[1]);
    if (match[1] === 'family') { assert.ok(['4', '6'].includes(match[2])); extra.family = Number(match[2]); }
    else { assert.ok(['transparent-tls', 'combo-tls'].includes(match[2])); extra.modeTag = match[2]; }
  }
  if (args.includes('--help')) assert.equal(args.length, 1);
  return { ...dnsSoakOptions(base), ...extra };
}
export function assertAdapterIdle(stats) {
  for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stats.stub[key], 0, key);
  for (const key of ['sockets', 'jobs']) assert.equal(stats.transport[key], 0, key);
  for (const key of ['resolverSockets', 'exitSockets', 'sessions', 'relayTimers', 'dnsCalls']) assert.equal(stats[key], 0, key);
  assert.ok(stats.replay.entries <= stats.replay.maxEntries);
}
export async function drainAdapter(lab) {
  await until(() => { try { assertAdapterIdle(lab.stats()); return true; } catch { return false; } });
  assertDnsIdle(lab);
}
async function until(predicate) {
  const deadline = performance.now() + 3000;
  while (!predicate()) { assert.ok(performance.now() < deadline, 'adapter drain/readiness deadline'); await delay(5); }
}
export const emptyAdapterTotals = () => ({ replies: 0, servfail: 0, nxdomain: 0, truncated: 0, restarts: 0, rejected: 0, cancelled: 0 });
export async function adapterWave(lab, name, concurrency, signal) {
  const totals = { ...emptyAdapterTotals(), ...await dnsWave(lab, queryLabDns, name, concurrency, signal) };
  await drainAdapter(lab);
  async function failed(i = 0) {
    const q = makeDnsQuery(name, i % 2 ? 28 : 1, 1000 + i);
    assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q), q).flags & 15, 2);
    totals.replies++; totals.servfail++;
  }
  // Whole listener down, accepted-but-silent exit, then cut established DoH.
  signal.throwIfAborted(); await lab.stopExit();
  try { await Promise.all(Array.from({ length: concurrency }, (_, i) => failed(i))); }
  finally { await lab.restartExit(); totals.restarts++; }
  await drainAdapter(lab);
  lab.setExitMode('hold');
  try { await Promise.all(Array.from({ length: concurrency }, (_, i) => failed(i))); }
  finally { lab.setExitMode('normal'); }
  await drainAdapter(lab);
  lab.setMode('hold');
  let before = lab.stats().resolverBodies;
  let pending = Array.from({ length: concurrency }, (_, i) => failed(i));
  try { await until(() => lab.stats().resolverBodies === before + concurrency); lab.cutExit(); }
  finally { await Promise.all(pending); }
  await drainAdapter(lab);
  // Fill the real adapter's in-flight budget, then prove excess work does not dial.
  before = lab.stats().resolverBodies;
  const rejectedBefore = lab.stats().stub.rejected;
  pending = Array.from({ length: concurrency }, (_, i) => failed(i));
  try {
    await until(() => lab.stats().resolverBodies === before + concurrency);
    const connects = lab.stats().transport.connections;
    await failed(); assert.equal(lab.stats().transport.connections, connects, 'excess query created connection');
    assert.equal(lab.stats().stub.rejected, rejectedBefore + 1); totals.rejected++;
  } finally { await Promise.all(pending); }
  await drainAdapter(lab);
  // Cancel a TCP requester after its DNS body reaches the held origin.
  signal.throwIfAborted(); before = lab.stats().resolverBodies;
  const socket = net.connect({ host: '127.0.0.1', port: lab.stub.port }); socket.on('error', () => {});
  const closed = new Promise((resolve) => socket.once('close', resolve));
  try {
    await once(socket, 'connect');
    const q = makeDnsQuery(name, 28, 2000), frame = Buffer.alloc(q.length + 2); frame.writeUInt16BE(q.length); q.copy(frame, 2);
    socket.write(frame); await until(() => lab.stats().resolverBodies === before + 1); socket.resetAndDestroy();
  } finally { socket.destroy(); await closed; }
  await drainAdapter(lab); totals.cancelled++; lab.setMode('normal'); signal.throwIfAborted();
  return totals;
}
export function assertAdapterSoakResult(result, options) {
  assert.equal(result.schema, 1); assert.equal(result.kind, 'dns-exit-adapter'); assert.equal(result.status, 'passed');
  for (const key of ['seconds', 'concurrency', 'family', 'modeTag']) assert.equal(result[key], options[key]);
  assert.equal(result.warmupWaves, 10); assert.ok(Number.isInteger(result.waves) && result.waves > 0);
  assert.ok(result.measuredMs >= options.seconds * 1000); assert.ok(result.samples.length >= 2);
  const n = options.concurrency, w = result.waves;
  assert.deepEqual(result.totals, { replies: w * (12 * n + 1), servfail: w * (8 * n + 1), nxdomain: w * n,
    truncated: w * Math.ceil(n / 2), restarts: w * 2, rejected: w, cancelled: w });
  assert.equal(result.pcap.positiveControl, true); assert.equal(result.pcap.localStubPlaintext, true);
  assert.equal(result.pcap.protectedPlaintext, false); assert.equal(result.pcap.unexpectedEndpoints, 0);
  assert.ok(result.pcap.packets > 0); assert.equal(result.cleanupFailed ?? false, false);
  for (const name of ['stub', 'control', 'exit', 'resolver', 'refused']) for (const direction of ['request', 'response']) {
    assert.ok(result.pcap.endpointPackets[name][direction] > 0);
    if (name === 'refused') assert.equal(result.pcap.bytes[name][direction], 0);
    else assert.ok(result.pcap.bytes[name][direction] > 0);
  }
  for (const sample of result.samples) { assertAdapterIdle(sample.owned); assertDnsResources(sample.resources, result.baseline); }
  assertAdapterIdle(result.final.owned); assertDnsResources(result.final.resources, result.baseline, true);
  for (const [key, perWave] of Object.entries({ queries: 12 * n + 2, forwarded: 12 * n + 1, succeeded: 4 * n, failed: 8 * n + 1, rejected: 1 })) {
    assert.equal(result.final.owned.stub[key] - result.baselineCounters[key], w * perWave, key);
  }
  assert.equal(result.final.owned.stub.peakInflight, n);
  assert.equal(result.final.owned.transport.connections - result.baselineTraffic.connections, w * (12 * n + 1));
  assert.equal(result.final.owned.attempts - result.baselineTraffic.attempts, w * (20 * n + 2));
  assert.equal(result.final.owned.resolverBodies - result.baselineTraffic.bodies, w * (9 * n + 1));
}
