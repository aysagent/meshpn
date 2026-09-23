import assert from 'node:assert/strict';
import test from 'node:test';
import { auditDnsPcap, assertDnsCaptureExit } from './lib/dns-lab-pcap.mjs';
import { dnsSoakOptions, assertDnsResources, assertDnsSoakResult } from './lib/dns-soak.mjs';

const marker = 'secret-123456789abcdef', config = { marker, stubPort: 10001, controlPort: 10002, protectedPorts: [10003, 10004] };
function row(port, response, data, { tcp = false, seq = 1 } = {}) {
  const src = response ? port : 20000, dst = response ? 20000 : port;
  return ['100', '100', '127.0.0.1', '127.0.0.1', tcp ? String(port) : '', tcp ? src : '', tcp ? dst : '',
    tcp ? seq : '', tcp ? Buffer.from(data).toString('hex') : '', tcp ? '' : src, tcp ? '' : dst,
    tcp ? '' : Buffer.from(data).toString('hex')].join('\t');
}
function rows() {
  return [10001, 10002, 10003, 10004].flatMap((port) => [false, true].map((response) =>
    row(port, response, port < 10003 ? marker : 'encrypted fixture bytes', { tcp: port >= 10003 })));
}
const audit = (data) => auditDnsPcap(`${data.join('\n')}\n`, config);
test('independent audit requires control and stub plaintext, protected payload in both directions', () => {
  const result = audit(rows()); assert.equal(result.positiveControl, true); assert.equal(result.protectedPlaintext, false);
});
for (const response of [false, true]) test(`protected plaintext ${response ? 'response' : 'request'} fails`, () => {
  assert.throws(() => audit([...rows(), row(10003, response, marker, { tcp: true, seq: 24 })]), /plaintext on protected leg/);
});
test('split/out-of-order TCP marker is detected and identical retransmits allowed', () => {
  const parts = [row(10002, false, marker.slice(0, 9), { tcp: true }),
    row(10002, false, marker.slice(9), { tcp: true, seq: 10 })];
  const base = rows().filter((_, i) => i !== 2);
  assert.equal(audit([...base, parts[1], parts[0], parts[0]]).positiveControl, true);
  const protectedParts = parts.map((line) => line.replaceAll('10002', '10003'));
  const changed = [...rows().filter((_, i) => i !== 4), ...protectedParts.reverse()];
  assert.throws(() => audit(changed), /plaintext on protected leg/);
});
for (const [name, mutate] of [
  ['empty', () => []], ['missing control', (r) => r.filter((_, i) => i < 2 || i > 3)],
  ['missing direction', (r) => r.slice(0, -1)], ['unknown endpoint', (r) => [...r, row(10500, false, marker)]],
  ['non-loopback', (r) => r.map((x) => x.replace('127.0.0.1', '8.8.8.8'))],
  ['truncated', (r) => r.map((x) => x.replace(/^100/, '99'))],
  ['capture gap', (r) => [...r, row(10003, false, 'tail', { tcp: true, seq: 40 })]],
  ['missing prefix', (r) => r.map((x) => x.replace('\t1\t', '\t2\t'))],
  ['conflicting retransmit', (r) => [...r, row(10003, false, 'bad', { tcp: true })]],
  ['UDP on protected port', (r) => [...r, row(10003, false, marker)]],
]) test(`audit rejects ${name}`, () => assert.throws(() => audit(mutate(rows()))));

test('tcpdump must complete without drops or packet-limit exhaustion', () => {
  assertDnsCaptureExit(0, null, '100 packets captured\n200 packets received by filter\n0 packets dropped by kernel\n');
  for (const [code, signal, text] of [[1, null, ''], [0, 'SIGKILL', ''], [0, null, ''],
    [0, null, '0 packets captured\n0 packets dropped by kernel\n'],
    [0, null, '20000 packets captured\n0 packets dropped by kernel\n'],
    [0, null, '10 packets captured\n1 packets dropped by kernel\n']]) assert.throws(() => assertDnsCaptureExit(code, signal, text));
});
test('DNS soak options are explicitly bounded', () => {
  assert.deepEqual(dnsSoakOptions([]), { seconds: 60, concurrency: 4 });
  assert.deepEqual(dnsSoakOptions(['--seconds=600', '--concurrency=8']), { seconds: 600, concurrency: 8 });
});
for (const arg of ['--seconds=0', '--seconds=601', '--seconds=01', '--seconds=NaN', '--concurrency=9', '--concurrency=0', '--serve', '--report=']) {
  test(`invalid DNS soak option ${arg}`, () => assert.throws(() => dnsSoakOptions([arg])));
}
test('duplicates/help with options fail', () => {
  assert.throws(() => dnsSoakOptions(['--seconds=1', '--seconds=2']));
  assert.throws(() => dnsSoakOptions(['--help', '--seconds=2']));
});
const sample = () => ({ tree: { live: 1, zombies: 0 }, worker: { fds: 25, memory: { rss: 80 * 1048576, heapUsed: 10 * 1048576 }, active: {} } });
test('resource budgets reject idle FD, RSS, heap, process, timer or socket growth', () => {
  const base = sample(); assertDnsResources(base, base, true);
  for (const mutate of [(s) => s.worker.fds++, (s) => s.worker.memory.rss += 65 * 1048576,
    (s) => s.worker.memory.heapUsed += 33 * 1048576, (s) => s.tree.live++, (s) => s.tree.zombies++,
    ...['Timeout', 'TCPSocketWrap', 'TCPServerWrap', 'UDPWrap', 'ProcessWrap'].map((key) => (s) => { s.worker.active[key] = 1; })]) {
    const changed = sample(); mutate(changed); assert.throws(() => assertDnsResources(changed, base, true));
  }
});
test('memory baseline uses observed warmup high-water, not a single post-GC trough', () => {
  const base = sample(); base.warmupHighWater = { rss: 100 * 1048576, heapUsed: 30 * 1048576 };
  const current = sample(); current.worker.memory.heapUsed = 50 * 1048576;
  assertDnsResources(current, base);
  current.worker.memory.heapUsed = 63 * 1048576;
  assert.throws(() => assertDnsResources(current, base), /heap growth/);
});
function validResult() {
  const zero = { inflight: 0, tcpSockets: 0, tlsSockets: 0, requests: 0, jobs: 0, timers: 0 };
  return { schema: 1, status: 'passed', seconds: 1, concurrency: 1, warmupWaves: 10, waves: 1, measuredMs: 1000,
    samples: [{ resources: sample() }], baseline: sample(),
    totals: { replies: 8, servfail: 4, nxdomain: 1, truncated: 1, restarts: 1 },
    pcap: { positiveControl: true, localStubPlaintext: true, protectedPlaintext: false, packets: 20 },
    final: { resources: sample(), owned: { dns: { resolverSockets: 0, stub: { ...zero, queries: 104, forwarded: 104,
      rejected: 0, succeeded: 52, failed: 52 } }, relay: { sockets: 0, pendingClients: 0, relaySessions: 0, relayTimers: 0, cleanupFailures: 0 } } } };
}
test('parent validates completed workload, counters, capture and final resources', () => {
  assertDnsSoakResult(validResult(), { seconds: 1, concurrency: 1 });
  for (const mutate of [(r) => r.waves++, (r) => r.totals.replies--, (r) => { r.pcap.positiveControl = false; },
    (r) => r.final.owned.dns.stub.queries--, (r) => r.final.owned.relay.relayTimers++, (r) => { r.samples = []; }]) {
    const result = validResult(); mutate(result); assert.throws(() => assertDnsSoakResult(result, { seconds: 1, concurrency: 1 }));
  }
});
