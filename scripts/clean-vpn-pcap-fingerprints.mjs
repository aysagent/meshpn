#!/usr/bin/env node
// Offline observer. Reads tcpdump's classic Ethernet/IPv4 pcap, never engine logs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIPv4 } from 'node:net';
import { createHash } from 'node:crypto';
import { parseFirstTlsClientHelloFromTcpBuf, ja3ComponentsFromClientHelloBody } from './lib/tls-clienthello-ja3.mjs';
import { observeTlsProfile } from './lib/native-tls-profile-observer.mjs';
import { ja4FromClientHelloBody } from './lib/tls-clienthello-ja4.mjs';

const MAX_FILE = 64 * 1024 * 1024, PREFIX = 65536, MAX_STREAMS = 128;
const check = (ok, code) => { if (!ok) throw Error(code); };
export function inspectPcap(bytes, { destination, port = 443, profile = null }) {
  check(isIPv4(destination) && Number.isInteger(port) && port > 0 && port < 65536, 'invalid_endpoint');
  check(bytes.length >= 24 && bytes.length <= MAX_FILE, 'pcap_size');
  const magic = bytes.subarray(0, 4).toString('hex');
  check(['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d'].includes(magic), 'classic_pcap_required');
  const le = ['d4c3b2a1', '4d3cb2a1'].includes(magic);
  const precision = ['4d3cb2a1', 'a1b23c4d'].includes(magic) ? 9 : 6;
  const u32 = (b, o) => le ? b.readUInt32LE(o) : b.readUInt32BE(o);
  const u16 = (b, o) => le ? b.readUInt16LE(o) : b.readUInt16BE(o);
  check(u16(bytes, 4) === 2 && u16(bytes, 6) === 4 && u32(bytes, 20) === 1, 'ethernet_pcap_v24_required');
  const streams = [], current = new Map();
  const counts = { packets: 0, selected: 0, withoutSyn: 0, fragmented: 0, truncated: 0 };
  const address = (b, o) => [...b.subarray(o, o + 4)].join('.');
  for (let o = 24; o < bytes.length;) {
    check(o + 16 <= bytes.length, 'incomplete_pcap_header');
    const seconds = u32(bytes, o), fraction = u32(bytes, o + 4);
    check(fraction < 10 ** precision, 'invalid_pcap_timestamp');
    const timestamp = `${seconds}.${String(fraction).padStart(precision, '0')}`;
    const n = u32(bytes, o + 8), original = u32(bytes, o + 12);
    check(n <= original && o + 16 + n <= bytes.length, 'incomplete_pcap_packet');
    const b = bytes.subarray(o + 16, o + 16 + n); o += 16 + n; counts.packets++;
    if (n < original) { counts.truncated++; continue; }
    if (b.length < 14) continue;
    let ip = 14, ether = b.readUInt16BE(12);
    // At most two VLAN headers. Other encapsulations are explicitly outside scope.
    for (let v = 0; v < 2 && [0x8100, 0x88a8].includes(ether); v++) {
      check(b.length >= ip + 4, 'short_vlan'); ether = b.readUInt16BE(ip + 2); ip += 4;
    }
    if (ether !== 0x0800) continue;
    check(b.length >= ip + 20 && b[ip] >>> 4 === 4, 'short_ipv4');
    const ihl = (b[ip] & 15) * 4, total = b.readUInt16BE(ip + 2);
    check(ihl >= 20 && total >= ihl && ip + total <= b.length, 'invalid_ipv4_length');
    if (b[ip + 9] !== 6 || address(b, ip + 16) !== destination) continue;
    if (b.readUInt16BE(ip + 6) & 0x3fff) { counts.fragmented++; continue; }
    const tcp = ip + ihl;
    check(total >= ihl + 20, 'short_tcp');
    if (b.readUInt16BE(tcp + 2) !== port) continue;
    counts.selected++;
    const thl = (b[tcp + 12] >>> 4) * 4;
    check(thl >= 20 && ihl + thl <= total, 'invalid_tcp_length');
    const source = address(b, ip + 12), sourcePort = b.readUInt16BE(tcp);
    const key = `${source}:${sourcePort}`, seq = b.readUInt32BE(tcp + 4), flags = b[tcp + 13];
    let stream = current.get(key);
    if ((flags & 0x12) === 2) {
      if (!stream || stream.syn !== seq || stream.closed) {
        check(streams.length < MAX_STREAMS, 'stream_limit');
        stream = { source, sourcePort, syn: seq, firstPacket: counts.packets, timestamp,
          data: Buffer.alloc(PREFIX), seen: Buffer.alloc(PREFIX), conflict: false, closed: false };
        streams.push(stream); current.set(key, stream);
      }
    }
    if (!stream) { counts.withoutSyn++; continue; }
    if (flags & 5) stream.closed = true;
    const payload = b.subarray(tcp + thl, ip + total);
    const offset = (seq + ((flags & 2) ? 1 : 0) - ((stream.syn + 1) >>> 0)) >>> 0;
    // Only a bounded initial prefix is needed. Modulo arithmetic handles ISN wrap.
    for (let j = 0; j < payload.length && offset + j < PREFIX; j++) {
      const at = offset + j;
      if (stream.seen[at] && stream.data[at] !== payload[j]) stream.conflict = true;
      stream.data[at] = payload[j]; stream.seen[at] = 1;
    }
  }
  const connections = streams.map(stream => {
    const result = { source: stream.source, sourcePort: stream.sourcePort, firstPacket: stream.firstPacket,
      synUnixSeconds: stream.timestamp };
    if (stream.conflict) return { ...result, status: 'conflicting_tcp_overlap' };
    let n = 0; while (n < PREFIX && stream.seen[n]) n++;
    try {
      const hello = parseFirstTlsClientHelloFromTcpBuf(stream.data.subarray(0, n));
      if (!hello.ok) return { ...result, status: hello.needMore ? 'incomplete_clienthello' : 'not_valid_clienthello' };
      const ja3 = ja3ComponentsFromClientHelloBody(hello.clientHelloBody);
      return { ...result, status: 'observed', sni: hello.sni, alpn: hello.alpn,
        clientHelloBytes: hello.clientHelloBody.length, ja3: ja3.ja3Digest, ja3String: ja3.ja3String,
        ja4: ja4FromClientHelloBody(hello.clientHelloBody).fingerprint,
        ...(profile ? { profile: observeTlsProfile(stream.data.subarray(0, hello.bytesConsumed), profile) } : {}) };
    } catch { return { ...result, status: 'not_valid_clienthello' }; }
  });
  return { schema: 1, kind: 'clean-vpn-pcap-fingerprints', source: 'offline-tcpdump-pcap',
    pcapSha256: createHash('sha256').update(bytes).digest('hex'), destination, port, counts, connections,
    limitations: ['ethernet-ipv4-tcp-only', 'first-clienthello-only-no-HRR', 'requires-captured-SYN',
      'prefix-limit-64KiB', 'no-checksum-verification', 'no-capture-drop-proof',
      'shared-JA3-JA4-parser-with-project-sniffer-not-independent-algorithm',
      'no-browser-equivalence-or-leak-verdict'] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    check((args.length === 2 || (args.length === 3 && args[2].startsWith('--profile='))) && args[0].startsWith('--pcap=') && args[1].startsWith('--destination='), 'usage_pcap_then_destination');
    const file = args[0].slice(7), stat = fs.statSync(file);
    check(stat.isFile() && stat.size <= MAX_FILE, 'pcap_size');
    let profile = null;
    if (args[2]) {
      const profileFile = args[2].slice('--profile='.length), info = fs.lstatSync(profileFile);
      check(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 16384, 'invalid_profile_file');
      profile = JSON.parse(fs.readFileSync(profileFile));
    }
    const report = inspectPcap(fs.readFileSync(file), { destination: args[1].slice(14), profile });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = !report.connections.some(c => c.status === 'observed') ? 1
      : profile && report.connections.some(c => c.profile?.status !== 'matched') ? 2 : 0;
  } catch (e) { console.error(JSON.stringify({ status: 'failed', code: /^[a-z0-9_]+$/.test(e.message) ? e.message : 'pcap_read_failed' })); process.exitCode = 1; }
}
