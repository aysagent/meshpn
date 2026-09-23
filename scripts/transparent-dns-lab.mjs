#!/usr/bin/env node
/** Bounded smoke, explicit clients only; never changes system DNS. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { startTransparentDnsLab, queryLabDns } from './lib/transparent-dns-lab.mjs';
import { makeDnsQuery, validateDnsResponse, parseDns } from './lib/lab-dns-wire.mjs';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/transparent-dns-lab.mjs\nBounded UDP/TCP -> DoH over transparent TLS smoke, loopback only. No OS DNS changes. Test certificates only.');
    return;
  }
  if (args.length) throw new Error('DNS_LAB_ARGS');
  const marker = `secret-${randomBytes(12).toString('hex')}`, tails = new Map();
  const wire = { exit: 0, origin: 0 }; let exposed = false, observed = 0, lab, aborted = false;
  const onSignal = () => { aborted = true; void lab?.close(); };
  process.once('SIGINT', onSignal); process.once('SIGTERM', onSignal);
  const deadline = setTimeout(onSignal, 15000);
  let passed = false;
  try {
    lab = await startTransparentDnsLab({ timeoutMs: 200, observeWire(stage, chunk, { peerPort }) {
      if (!(stage in wire)) return;
      observed += chunk.length; if (observed > 1024 * 1024) throw new Error('DNS_AUDIT_LIMIT');
      wire[stage] += chunk.length;
      const key = `${stage}:${peerPort}`, combined = Buffer.concat([tails.get(key) ?? Buffer.alloc(0), chunk]);
      if (combined.includes(Buffer.from(marker))) exposed = true;
      tails.set(key, Buffer.from(combined.subarray(-marker.length)));
    } });
    if (aborted) throw new Error('DNS_LAB_ABORTED');
    for (const tcp of [false, true]) for (const type of [1, 28]) {
      const q = makeDnsQuery(`${marker}.dns-lab.test`, type, 3456);
      assert.equal(validateDnsResponse(await queryLabDns(lab.stub.port, q, { tcp, fragment: true }), q).counts[0], 1);
    }
    lab.setMode('nxdomain'); assert.equal(parseDns(await queryLabDns(lab.stub.port, makeDnsQuery(`${marker}.dns-lab.test`))).flags & 15, 3);
    for (const mode of ['reset', 'hold', 'redirect']) {
      lab.setMode(mode);
      assert.equal(parseDns(await queryLabDns(lab.stub.port, makeDnsQuery(`${marker}.dns-lab.test`))).flags & 15, 2);
    }
    assert.equal(exposed, false); assert.ok(wire.exit > 0 && wire.origin > 0); assert.equal(aborted, false);
    passed = true;
  } finally {
    await lab?.close(); clearTimeout(deadline);
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal);
  }
  const stats = lab.stats();
  for (const key of ['inflight', 'tcpSockets', 'tlsSockets', 'requests', 'jobs', 'timers']) assert.equal(stats.stub[key], 0);
  assert.equal(stats.resolverSockets, 0); assert.equal(lab.relay.stats().sockets, 0);
  assert.equal(aborted, false);
  console.log(`DNS_LAB_RESULT ${JSON.stringify({ schema: 1, status: passed ? 'passed' : 'failed',
    scope: 'loopback-only-not-system-dns', wireBytes: wire, exposed, stats })}`);
}
main().catch(() => { console.error('[dns-lab] FAILED'); process.exitCode = 1; });
