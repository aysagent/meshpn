/** Synthetic wire fixtures only, no resolver/network access. */
import { parseDnsQuery, fixtureDnsAnswer, dnsFailure, validateDnsResponse } from './lab-dns-wire.mjs';

export function sizedTxtAnswer(query, size) {
  const base = fixtureDnsAnswer(query, { rdata: Buffer.alloc(0) });
  const rdata = Buffer.alloc(size - base.length, 0x78);
  for (let at = 0; at < rdata.length;) {
    const length = Math.min(255, rdata.length - at - 1); rdata[at] = length; at += length + 1;
  }
  return fixtureDnsAnswer(query, { rdata });
}

export function paddedDnsQuery(query, size) {
  const opt = parseDnsQuery(query).records.find((rr) => rr.type === 41);
  if (!opt || opt.length !== 0 || opt.offset !== query.length) throw new Error('fixture expects empty trailing OPT');
  const packet = Buffer.alloc(size); query.copy(packet);
  packet.writeUInt16BE(size - query.length, opt.offset - 2);
  packet.writeUInt16BE(12, opt.offset); // EDNS padding
  packet.writeUInt16BE(size - query.length - 4, opt.offset + 2);
  parseDnsQuery(packet); return packet;
}

export function negativeSoaAnswer(query, { ttl = 600, minimum = 60, rcode = 3 } = {}) {
  const q = parseDnsQuery(query), base = dnsFailure(query, rcode);
  const record = Buffer.alloc(36);
  record.writeUInt16BE(0xc00c); record.writeUInt16BE(6, 2); record.writeUInt16BE(1, 4);
  record.writeUInt32BE(ttl, 6); record.writeUInt16BE(24, 10);
  record.writeUInt16BE(0xc00c, 12); record.writeUInt16BE(0xc00c, 14);
  record.writeUInt32BE(minimum, 32);
  base.writeUInt16BE(1, 8);
  const packet = Buffer.concat([base.subarray(0, q.questionEnd), record, base.subarray(q.questionEnd)]);
  validateDnsResponse(packet, query); return packet;
}
