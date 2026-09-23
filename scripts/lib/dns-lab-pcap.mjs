/** Independent tshark payload audit. No TLS keys, DNS dissector or in-process taps. */
import assert from 'node:assert/strict';

export const DNS_PCAP_FIELDS = ['frame.cap_len', 'frame.len', 'ip.src', 'ip.dst', 'tcp.stream',
  'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.payload', 'udp.srcport', 'udp.dstport', 'udp.payload'];

export function auditDnsPcap(output, { stubPort, controlPort, protectedPorts, marker }) {
  assert.match(marker, /^[a-z0-9-]{16,63}$/);
  const endpoints = [stubPort, controlPort, ...protectedPorts];
  assert.equal(new Set(endpoints).size, endpoints.length);
  const streams = new Map(), totals = {}, exposed = {}, packets = output.replace(/\n$/, '').split('\n');
  assert.ok(output.length > 0 && output.length <= 16 * 1024 * 1024 && packets.length < 20000);
  for (const port of endpoints) totals[port] = { request: 0, response: 0 };
  function inspect(port, direction, data) {
    totals[port][direction] += data.length;
    if (data.includes(Buffer.from(marker))) (exposed[port] ??= new Set()).add(direction);
  }
  for (const row of packets) {
    const f = row.split('\t'); assert.equal(f.length, DNS_PCAP_FIELDS.length, 'pcap field count');
    assert.ok(Number(f[0]) > 0); assert.equal(f[0], f[1], 'truncated packet');
    assert.equal(f[2], '127.0.0.1'); assert.equal(f[3], '127.0.0.1');
    const tcp = f[4] !== '', src = Number(tcp ? f[5] : f[9]), dst = Number(tcp ? f[6] : f[10]);
    const matched = endpoints.filter((port) => port === src || port === dst);
    assert.equal(matched.length, 1, 'unexpected/ambiguous endpoint');
    const port = matched[0], direction = port === dst ? 'request' : 'response';
    if (!tcp) assert.ok(port === stubPort || port === controlPort, 'unexpected UDP');
    const hex = tcp ? f[8] : f[11]; assert.match(hex, /^(?:[a-fA-F0-9]{2})*$/);
    const data = Buffer.from(hex, 'hex'); if (!data.length) continue;
    if (!tcp) { inspect(port, direction, data); continue; }
    assert.match(f[4], /^\d+$/); assert.match(f[7], /^\d+$/);
    const key = `${f[4]}:${src}:${dst}`;
    const stream = streams.get(key) ?? { port, direction, segments: [] };
    stream.segments.push({ seq: Number(f[7]), data }); streams.set(key, stream);
  }
  // Sort and verify retransmissions/overlap before searching; labels split across
  // segments must not bypass the detector. A gap/ambiguous retransmit is failure.
  for (const { port, direction, segments } of streams.values()) {
    segments.sort((a, b) => a.seq - b.seq);
    const start = segments[0].seq; assert.equal(start, 1, 'missing TCP prefix');
    let data = Buffer.alloc(0);
    for (const segment of segments) {
      const offset = segment.seq - start; assert.ok(offset <= data.length, 'TCP capture gap');
      const overlap = Math.min(data.length - offset, segment.data.length);
      assert.ok(data.subarray(offset, offset + overlap).equals(segment.data.subarray(0, overlap)), 'conflicting retransmit');
      data = Buffer.concat([data, segment.data.subarray(overlap)]);
      assert.ok(data.length <= 1024 * 1024, 'stream budget');
    }
    inspect(port, direction, data);
  }
  for (const port of endpoints) for (const direction of ['request', 'response']) {
    assert.ok(totals[port][direction] > 0, 'empty capture direction');
    assert.equal(exposed[port]?.has(direction) ?? false, port === stubPort || port === controlPort,
      'missing positive control or plaintext on protected leg');
  }
  return { packets: packets.length, positiveControl: true, localStubPlaintext: true,
    protectedPlaintext: false, bytes: totals };
}

export function assertDnsCaptureExit(code, signal, diagnostics) {
  assert.equal(code, 0); assert.equal(signal, null);
  const captured = /(?:^|\n)(\d+) packets captured\n/.exec(diagnostics);
  const dropped = /(?:^|\n)(\d+) packets dropped by kernel(?:\n|$)/.exec(diagnostics);
  assert.ok(captured && Number(captured[1]) > 0 && Number(captured[1]) < 20000, 'capture limit/empty capture');
  assert.ok(dropped && Number(dropped[1]) === 0, 'capture drops/unknown statistics');
  return Number(captured[1]);
}
