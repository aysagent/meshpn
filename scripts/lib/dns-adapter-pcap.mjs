/** Independent numeric endpoint + reassembled payload audit, IPv4 and IPv6. */
import assert from 'node:assert/strict';
export const ADAPTER_PCAP_FIELDS = ['frame.cap_len', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
  'tcp.stream', 'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.payload', 'udp.srcport', 'udp.dstport', 'udp.payload'];

export function auditAdapterPcap(output, { endpoints, marker }) {
  assert.match(marker, /^[a-z0-9-]{16,63}$/);
  assert.deepEqual(Object.keys(endpoints).sort(), ['control', 'exit', 'refused', 'resolver', 'stub']);
  assert.equal(new Set(Object.values(endpoints).map((e) => `${e.address}/${e.port}`)).size, 5);
  const streams = new Map(), bytes = {}, endpointPackets = {}, exposed = {}, packets = output.replace(/\n$/, '').split('\n');
  assert.ok(output.length > 0 && output.length <= 16 * 1024 * 1024 && packets.length < 20000);
  for (const name of Object.keys(endpoints)) {
    bytes[name] = { request: 0, response: 0 }; endpointPackets[name] = { request: 0, response: 0 };
  }
  function inspect(name, direction, data) {
    bytes[name][direction] += data.length;
    if (data.includes(Buffer.from(marker))) (exposed[name] ??= new Set()).add(direction);
  }
  for (const row of packets) {
    const f = row.split('\t'); assert.equal(f.length, ADAPTER_PCAP_FIELDS.length);
    assert.ok(Number(f[0]) > 0); assert.equal(f[0], f[1], 'truncated packet');
    assert.ok((f[2] && f[3] && !f[4] && !f[5]) || (!f[2] && !f[3] && f[4] && f[5]), 'ambiguous IP header');
    const srcAddress = f[2] || f[4], dstAddress = f[3] || f[5], tcp = f[6] !== '';
    const src = Number(tcp ? f[7] : f[11]), dst = Number(tcp ? f[8] : f[12]);
    assert.ok(src > 0 && src <= 65535 && dst > 0 && dst <= 65535, 'non TCP/UDP packet');
    const matches = Object.entries(endpoints).flatMap(([name, e]) => [
      ...(e.address === dstAddress && e.port === dst ? [{ name, direction: 'request' }] : []),
      ...(e.address === srcAddress && e.port === src ? [{ name, direction: 'response' }] : []),
    ]);
    assert.equal(matches.length, 1, 'unexpected/ambiguous endpoint');
    const { name, direction } = matches[0];
    endpointPackets[name][direction]++;
    // Source routing on isolated lo picks the local destination address. No
    // arbitrary peer, DNS53, proxy, or additional local TLS listener is allowed.
    assert.equal(srcAddress, dstAddress, 'unexpected peer');
    if (!tcp) assert.ok(name === 'stub' || name === 'control', 'unexpected UDP');
    const hex = tcp ? f[10] : f[13]; assert.match(hex, /^(?:[a-fA-F0-9]{2})*$/);
    const data = Buffer.from(hex, 'hex');
    if (name === 'refused') assert.equal(data.length, 0, 'payload on refused candidate');
    if (!data.length) continue;
    if (!tcp) { inspect(name, direction, data); continue; }
    assert.match(f[6], /^\d+$/); assert.match(f[9], /^\d+$/);
    const key = `${f[6]}:${srcAddress}:${src}:${dstAddress}:${dst}`;
    const stream = streams.get(key) ?? { name, direction, segments: [] };
    stream.segments.push({ seq: Number(f[9]), data }); streams.set(key, stream);
  }
  for (const { name, direction, segments } of streams.values()) {
    segments.sort((a, b) => a.seq - b.seq); assert.equal(segments[0].seq, 1, 'missing TCP prefix');
    let data = Buffer.alloc(0);
    for (const segment of segments) {
      const offset = segment.seq - 1; assert.ok(offset <= data.length, 'TCP capture gap');
      const overlap = Math.min(data.length - offset, segment.data.length);
      assert.ok(data.subarray(offset, offset + overlap).equals(segment.data.subarray(0, overlap)), 'conflicting retransmit');
      data = Buffer.concat([data, segment.data.subarray(overlap)]); assert.ok(data.length <= 1024 * 1024, 'stream budget');
    }
    inspect(name, direction, data);
  }
  for (const name of Object.keys(endpoints)) for (const direction of ['request', 'response']) {
    assert.ok(endpointPackets[name][direction] > 0, 'missing endpoint/direction');
    if (name === 'refused') continue;
    assert.ok(bytes[name][direction] > 0, 'empty capture direction');
    assert.equal(exposed[name]?.has(direction) ?? false, name === 'stub' || name === 'control', 'plaintext/control mismatch');
  }
  return { packets: packets.length, positiveControl: true, localStubPlaintext: true, protectedPlaintext: false,
    unexpectedEndpoints: 0, bytes, endpointPackets };
}
