/** Independent tshark output matching for the bounded TLS 1.3 browser matrix. */
import assert from 'node:assert/strict';

export const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';
export const PCAP_FIELDS = ['frame.number', 'tcp.stream', 'tcp.srcport', 'tcp.dstport',
  'tls.handshake.type', 'tls.handshake.random', 'tls.handshake.extensions_server_name',
  'tls.handshake.ja3', 'tls.handshake.ja4', 'tls.handshake.extension.type'];

export function parseBrowserPcap(output, ports) {
  const byPort = new Map(Object.entries(ports).map(([stage, port]) => [port, stage]));
  assert.equal(byPort.size, 3, 'three distinct lab ports required');
  const streams = new Map();
  let previousFrame = 0;
  for (const line of output.split('\n').filter(Boolean)) {
    const fields = line.split('\t');
    assert.equal(fields.length, PCAP_FIELDS.length, 'unexpected tshark field count');
    const [frameText, streamText, srcText, dstText, type, randomText, sni, ja3, ja4, extensions] = fields;
    for (const value of [frameText, streamText, srcText, dstText]) assert.match(value, /^\d+$/);
    const frame = Number(frameText), streamId = Number(streamText), src = Number(srcText), dst = Number(dstText);
    assert.ok(frame > previousFrame, 'pcap frames must be unique and ordered'); previousFrame = frame;
    assert.ok(type === '1' || type === '2', 'ambiguous/coalesced handshake fields unsupported');
    const stage = byPort.get(type === '1' ? dst : src);
    const peerPort = type === '1' ? src : dst;
    assert.ok(stage && !byPort.has(peerPort), 'unexpected hello direction/port');
    const random = randomText.replaceAll(':', '').toLowerCase();
    assert.match(random, /^[0-9a-f]{64}$/);
    let stream = streams.get(streamId);
    if (!stream) {
      stream = { streamId, stage, peerPort, hellos: [], replies: [], events: [] };
      streams.set(streamId, stream);
    }
    assert.equal(stream.stage, stage, 'stream stage changed');
    assert.equal(stream.peerPort, peerPort, 'stream peer changed');
    const ext = extensions ? extensions.split(',').map((value) => {
      assert.match(value, /^\d+$/); return Number(value);
    }) : [];
    const record = { frame, random, sni, ja3, ja4, psk: ext.includes(41) };
    if (type === '1') {
      assert.match(ja3, /^[0-9a-f]{32}$/); assert.ok(ja4);
      record.flight = stream.hellos.length + 1;
      stream.hellos.push(record); stream.events.push(`CH${record.flight}`);
    } else {
      record.hrr = random === HRR_RANDOM;
      stream.replies.push(record); stream.events.push(record.hrr ? 'HRR' : 'SH');
    }
  }
  assert.ok(streams.size, 'no TLS hellos in pcap');
  return [...streams.values()];
}

export function assertBrowserPcap(streams, captures, expectations) {
  const used = new Set();
  assert.ok(captures.length >= 3);
  for (const hello of captures) {
    const candidates = streams.filter((stream) => stream.stage === hello.stage && stream.peerPort === hello.peerPort &&
      stream.hellos[hello.flight - 1]?.random === hello.id);
    assert.equal(candidates.length, 1, 'capture must match exactly one stream/peer/random/flight');
    const stream = candidates[0], actual = stream.hellos[hello.flight - 1];
    const key = `${stream.streamId}:${hello.flight}`;
    assert.ok(!used.has(key), 'duplicate passive capture'); used.add(key);
    assert.equal(actual.sni, hello.sni, `${hello.stage} CH${hello.flight} independent SNI`);
    assert.equal(actual.ja3, hello.ja3, `${hello.stage} CH${hello.flight} independent JA3`);
    assert.equal(actual.ja4, hello.ja4, `${hello.stage} CH${hello.flight} independent JA4`);
  }
  const seen = new Map();
  for (const stream of streams) {
    const id = stream.hellos[0]?.random, expected = expectations.get(id);
    assert.ok(expected, 'unexpected pcap connection');
    const stages = seen.get(id) ?? new Set();
    assert.ok(!stages.has(stream.stage), 'duplicate stream for one hello/stage');
    stages.add(stream.stage); seen.set(id, stages);
    assert.deepEqual(stream.events, expected.hrr ? ['CH1', 'HRR', 'CH2', 'SH'] : ['CH1', 'SH'], 'TLS flight order');
    for (const hello of stream.hellos) {
      assert.equal(hello.random, id, 'CH2 random preserved');
      assert.equal(hello.psk, expected.offered, 'independent PSK offer');
      assert.ok(used.has(`${stream.streamId}:${hello.flight}`), 'unmatched pcap ClientHello');
    }
    assert.equal(stream.replies.at(-1).psk, expected.resumed, 'independent ServerHello PSK selection');
  }
  assert.equal(seen.size, expectations.size, 'missing expected connection');
  for (const stages of seen.values()) assert.deepEqual(stages, new Set(['client', 'exit', 'origin']));
  return used.size;
}
