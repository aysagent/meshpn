import assert from 'node:assert/strict';
import test from 'node:test';
import { auditAdapterPcap } from './lib/dns-adapter-pcap.mjs';
import { adapterSoakOptions, assertAdapterSoakResult, assertAdapterIdle } from './lib/dns-adapter-soak.mjs';

const marker = 'secret-123456789abcdef';
function config(family = 4) {
  const addresses = family === 4 ? ['93.184.216.34', '93.184.216.35', '93.184.216.36']
    : ['2606:4700::1112', '2606:4700::1111', '2606:4700::1113'];
  return { marker, endpoints: { stub: { address: '127.0.0.1', port: 10001 }, control: { address: '127.0.0.1', port: 10002 },
    exit: { address: addresses[2], port: 10003 }, resolver: { address: addresses[1], port: 10004 }, refused: { address: addresses[0], port: 10004 } } };
}
function row(c, name, response, data, seq = 1) {
  const e = c.endpoints[name], tcp = !['stub', 'control'].includes(name), v6 = e.address.includes(':');
  const src = response ? e.port : 20000, dst = response ? 20000 : e.port;
  return ['100', '100', v6 ? '' : e.address, v6 ? '' : e.address, v6 ? e.address : '', v6 ? e.address : '',
    tcp ? name === 'refused' ? '99' : String(e.port) : '', tcp ? src : '', tcp ? dst : '', tcp ? seq : '',
    tcp ? Buffer.from(data).toString('hex') : '', tcp ? '' : src, tcp ? '' : dst, tcp ? '' : Buffer.from(data).toString('hex')].join('\t');
}
function rows(c) { return Object.keys(c.endpoints).flatMap((name) => [false, true].map((r) => row(c, name, r,
  ['stub', 'control'].includes(name) ? marker : name === 'refused' ? '' : 'encrypted'))); }
const audit = (r, c) => auditAdapterPcap(`${r.join('\n')}\n`, c);
for (const family of [4, 6]) {
  const c = config(family);
  test(`IPv${family} captures exactly stub/control/exit/resolver/refused with both directions`, () => {
    const result = audit(rows(c), c); assert.equal(result.positiveControl, true); assert.equal(result.protectedPlaintext, false);
    assert.equal(result.unexpectedEndpoints, 0);
  });
  for (const name of ['exit', 'resolver']) for (const response of [false, true]) {
    test(`IPv${family} ${name} plaintext ${response ? 'response' : 'request'} fails even when split/reordered`, () => {
      const r = rows(c).filter((_, i) => i !== (name === 'exit' ? 4 : 6) + Number(response));
      const first = row(c, name, response, marker.slice(0, 5)), last = row(c, name, response, marker.slice(5), 6);
      assert.throws(() => audit([...r, last, first, first], c), /plaintext\/control mismatch/);
    });
  }
}
const c = config();
for (const [name, mutate] of [
  ['empty capture', () => []], ['missing control', (r) => r.filter((_, i) => i !== 2 && i !== 3)],
  ['missing response', (r) => r.filter((_, i) => i !== 7)],
  ['missing refused candidate', (r) => r.slice(0, -2)],
  ['unexpected endpoint', (r) => [...r, row(c, 'exit', false, 'extra').replaceAll('10003', '53')]],
  ['unexpected peer', (r) => r.map((s) => s.replace('93.184.216.36', '8.8.8.8'))],
  ['truncation', (r) => r.map((s) => s.replace(/^100/, '99'))],
  ['gap', (r) => [...r, row(c, 'exit', false, 'tail', 50)]],
  ['missing prefix', (r) => r.map((s) => s.replace('\t1\t', '\t2\t'))],
  ['conflicting retransmit', (r) => [...r, row(c, 'exit', false, 'different')]],
  ['refused payload', (r) => [...r, row(c, 'refused', false, 'invalid')]],
  ['unexpected UDP', (r) => [...r, row(c, 'control', false, marker).replaceAll('127.0.0.1', '93.184.216.36').replaceAll('10002', '10003')]],
]) test(`adapter audit rejects ${name}`, () => assert.throws(() => audit(mutate(rows(c)), c)));
test('identical retransmission is accepted without counting it twice', () => {
  assert.deepEqual(audit([...rows(c), rows(c)[4]], c).bytes, audit(rows(c), c).bytes);
});
test('adapter CLI bounded options and explicit family/mode', () => {
  assert.deepEqual(adapterSoakOptions([]), { seconds: 60, concurrency: 4, family: 4, modeTag: 'transparent-tls' });
  assert.deepEqual(adapterSoakOptions(['--seconds=600', '--concurrency=8', '--family=6', '--mode=combo-tls']),
    { seconds: 600, concurrency: 8, family: 6, modeTag: 'combo-tls' });
});
for (const args of [['--family=5'], ['--family=06'], ['--mode=tls'], ['--family=4', '--family=6'],
  ['--mode=combo-tls', '--mode=combo-tls'], ['--help', '--family=6'], ['--seconds=601'], ['--concurrency=0'], ['--exit-ip=8.8.8.8']]) {
  test(`invalid adapter soak options ${args.join(' ')}`, () => assert.throws(() => adapterSoakOptions(args)));
}
const stats = () => ({ stub: { inflight: 0, tcpSockets: 0, tlsSockets: 0, requests: 0, jobs: 0, timers: 0,
  queries: 14, forwarded: 13, succeeded: 4, failed: 9, rejected: 1, peakInflight: 1 },
  transport: { sockets: 0, jobs: 0, connections: 13 }, resolverSockets: 0, exitSockets: 0, sessions: 0, relayTimers: 0, dnsCalls: 0,
  attempts: 22, resolverBodies: 10,
  replay: { entries: 10, maxEntries: 65536 } });
const resources = () => ({ tree: { live: 1, zombies: 0 }, worker: { fds: 20, active: {}, memory: { rss: 80 * 1048576, heapUsed: 10 * 1048576 } } });
function result() {
  return { schema: 1, kind: 'dns-exit-adapter', status: 'passed', seconds: 1, concurrency: 1, family: 4, modeTag: 'transparent-tls',
    warmupWaves: 10, waves: 1, measuredMs: 1000, samples: [1, 2].map(() => ({ owned: stats(), resources: resources() })),
    baseline: resources(), baselineCounters: { queries: 0, forwarded: 0, succeeded: 0, failed: 0, rejected: 0 },
    baselineTraffic: { attempts: 0, bodies: 0, connections: 0 },
    totals: { replies: 13, servfail: 9, nxdomain: 1, truncated: 1, restarts: 2, rejected: 1, cancelled: 1 },
    pcap: audit(rows(c), c), final: { owned: stats(), resources: resources() } };
}
test('parent independently validates exact workload, idle resources and capture', () => {
  const options = adapterSoakOptions(['--seconds=1', '--concurrency=1']); assertAdapterSoakResult(result(), options);
  for (const mutate of [(r) => r.waves++, (r) => r.totals.cancelled--, (r) => r.totals.rejected--,
    (r) => r.final.owned.stub.queries++, (r) => r.final.owned.stub.peakInflight++, (r) => r.final.owned.transport.jobs++,
    (r) => r.final.owned.dnsCalls++, (r) => { r.samples = []; }, (r) => { r.pcap.positiveControl = false; },
    (r) => r.pcap.unexpectedEndpoints++, (r) => r.final.resources.worker.fds++,
    (r) => r.final.owned.attempts++, (r) => r.final.owned.transport.connections++, (r) => r.final.owned.resolverBodies++,
    (r) => { r.pcap.endpointPackets.refused.response = 0; }, (r) => { r.pcap.bytes.exit.response = 0; }]) {
    const r = result(); mutate(r); assert.throws(() => assertAdapterSoakResult(r, options));
  }
});
test('idle validation includes actual adapter sockets/jobs and exit sessions/timers', () => {
  for (const mutate of [(s) => s.transport.sockets++, (s) => s.transport.jobs++, (s) => s.exitSockets++,
    (s) => s.sessions++, (s) => s.relayTimers++, (s) => { s.replay.entries = 65537; }]) {
    const s = stats(); mutate(s); assert.throws(() => assertAdapterIdle(s));
  }
});
