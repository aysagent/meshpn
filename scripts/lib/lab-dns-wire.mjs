/** Bounded DNS forwarding envelope, not a recursive resolver or RDATA validator. */
export const DNS_MAX_BYTES = 4096;
export const dnsError = (code) => Object.assign(new Error(code), { code });
const need = (condition) => { if (!condition) throw dnsError('DNS_WIRE'); };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
// Pilot policy: ordinary IN queries only, no meta/transfer/ANY operations.
const excludedTypes = new Set([0, 41, 249, 250, 251, 252, 253, 254, 255, 65535]);

function nameAt(packet, start) {
  let at = start, end, size = 1, compressed = false;
  const labels = [], visited = new Set();
  for (let steps = 0; steps < 128; steps++) {
    need(at < packet.length && !visited.has(at)); visited.add(at);
    const n = packet[at++];
    if ((n & 0xc0) === 0xc0) {
      need(at < packet.length);
      const target = ((n & 63) << 8) | packet[at++];
      need(target >= 12 && target < at - 2);
      compressed = true; end ??= at; at = target; continue;
    }
    need(n <= 63 && at + n <= packet.length);
    if (!n) return { name: labels.map((label) => label.toString('latin1')).join('.'),
      nameKey: labels.map((label) => label.toString('hex')).join('.'), end: end ?? at, compressed };
    // DNS labels are binary. Only ASCII A-Z fold for comparison (RFC 4343);
    // hex label boundaries prevent collisions between embedded dots and labels.
    const label = Buffer.from(packet.subarray(at, at + n));
    for (let i = 0; i < label.length; i++) if (label[i] >= 65 && label[i] <= 90) label[i] += 32;
    size += n + 1; need(size <= 255); labels.push(label); at += n;
  }
  throw dnsError('DNS_WIRE');
}

export function parseDns(packet) {
  need(Buffer.isBuffer(packet) && packet.length >= 12 && packet.length <= DNS_MAX_BYTES);
  const flags = packet.readUInt16BE(2);
  need((flags & 0x7840) === 0 && packet.readUInt16BE(4) === 1);
  const question = nameAt(packet, 12);
  need(question.end + 4 <= packet.length);
  const type = packet.readUInt16BE(question.end), klass = packet.readUInt16BE(question.end + 2);
  need(!excludedTypes.has(type) && klass === 1);
  const questionEnd = question.end + 4;
  const counts = [6, 8, 10].map((at) => packet.readUInt16BE(at));
  need(counts.reduce((a, b) => a + b, 0) <= 128);
  const records = [];
  let at = questionEnd, udpSize = 512, edns = null;
  for (const [section, count] of counts.entries()) for (let i = 0; i < count; i++) {
    const name = nameAt(packet, at); at = name.end;
    need(at + 10 <= packet.length);
    const rrtype = packet.readUInt16BE(at), rrclass = packet.readUInt16BE(at + 2);
    const ttl = packet.readUInt32BE(at + 4), length = packet.readUInt16BE(at + 8);
    at += 10; need(at + length <= packet.length);
    if (rrtype === 1) need(length === 4);
    if (rrtype === 28) need(length === 16);
    if (rrtype === 41) {
      need(section === 2 && !edns && name.nameKey === '' && !name.compressed);
      edns = { extendedRcode: ttl >>> 24, version: (ttl >>> 16) & 255, flags: ttl & 65535 };
      udpSize = Math.min(DNS_MAX_BYTES, Math.max(512, rrclass));
      let option = at;
      while (option < at + length) {
        need(option + 4 <= at + length);
        option += 4 + packet.readUInt16BE(option + 2); need(option <= at + length);
      }
    }
    records.push({ section, type: rrtype, klass: rrclass, ttl, offset: at, length });
    at += length;
  }
  need(at === packet.length);
  return { id: packet.readUInt16BE(0), flags, name: question.name, nameKey: question.nameKey,
    questionCompressed: question.compressed, type, klass, questionEnd, counts, records, udpSize, edns,
    rcode: (flags & 15) | ((edns?.extendedRcode ?? 0) << 4) };
}

export function parseDnsQuery(packet) {
  const q = parseDns(packet);
  need((q.flags & ~0x0130) === 0 && q.counts[0] === 0 && q.counts[1] === 0);
  need(q.records.every((rr) => rr.type === 41));
  // Rebuilt errors/truncation copy the question; external compression pointers
  // in a question would become invalid after removing records.
  need(!q.questionCompressed && (!q.edns || (q.edns.version === 0 && q.edns.extendedRcode === 0)));
  return q;
}

export function validateDnsResponse(packet, query) {
  const q = parseDnsQuery(query), r = parseDns(packet);
  need((r.flags & 0x8000) !== 0 && r.id === q.id && r.nameKey === q.nameKey && r.type === q.type && r.klass === q.klass);
  need(!r.edns || (q.edns && r.edns.version === 0));
  return r;
}

export function dnsFailure(query, rcode = 2, truncated = false) {
  const q = parseDnsQuery(query), reply = Buffer.from(query.subarray(0, q.questionEnd));
  need(Number.isInteger(rcode) && rcode >= 0 && rcode <= 4095 && (rcode <= 15 || q.edns));
  reply.writeUInt16BE(0x8080 | (q.flags & 0x0110) | (rcode & 15) | (truncated ? 0x0200 : 0), 2);
  reply.fill(0, 6, 12);
  const opt = q.records.find((rr) => rr.type === 41);
  if (!opt) return reply;
  const edns = Buffer.concat([Buffer.from([0]), u16(41), u16(q.udpSize), Buffer.alloc(6)]);
  edns.writeUInt32BE(((rcode >>> 4) * 0x1000000) + (opt.ttl & 0x8000), 5); reply.writeUInt16BE(1, 10);
  return Buffer.concat([reply, edns]);
}

/** Entire RRs are omitted, never sliced: no dangling compression pointers.
 * Preserve the upstream RCODE/RA/RD/CD, but do not assert AA/AD for a rebuilt answer.
 * Upstream options are not copied into the synthesized OPT (RFC 6891).
 */
export function truncateDnsResponse(query, response) {
  const r = validateDnsResponse(response, query), reply = dnsFailure(query, r.rcode, true);
  reply.writeUInt16BE(0x8200 | (r.flags & 0x019f), 2);
  return reply;
}

export function makeDnsQuery(name, type = 1, id = 123, udpSize) {
  const labels = (name === '.' ? [] : name.replace(/\.$/, '').split('.')).map((label) => { need(/^[a-z0-9_-]{1,63}$/i.test(label)); return Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]); });
  const header = Buffer.alloc(12); header.writeUInt16BE(id); header.writeUInt16BE(0x100, 2); header.writeUInt16BE(1, 4);
  const opt = udpSize === undefined ? Buffer.alloc(0) : Buffer.concat([Buffer.from([0]), u16(41), u16(udpSize), Buffer.alloc(6)]);
  if (opt.length) header.writeUInt16BE(1, 10);
  const packet = Buffer.concat([header, ...labels, Buffer.from([0]), u16(type), u16(1), opt]);
  parseDnsQuery(packet); return packet;
}

/** Static documentation IPs only; no network resolution by the test origin. */
export function fixtureDnsAnswer(query, { count = 1, ttl = 30, rcode = 0 } = {}) {
  const q = parseDnsQuery(query), reply = dnsFailure(query, rcode);
  if (rcode) return reply;
  const target = Buffer.from('066f726967696e047465737400', 'hex'); // origin.test.
  const data = new Map([
    [1, Buffer.from([192, 0, 2, 123])], [28, Buffer.from('20010db8000000000000000000000012', 'hex')],
    [2, target], [5, target], [12, target], [39, target],
    [15, Buffer.concat([u16(10), target])], [16, Buffer.from([3, 0, 255, 65])],
    [33, Buffer.concat([u16(0), u16(1), u16(443), target])],
    // priority=1, root target, alpn=h2, unknown parameter=opaque bytes.
    [64, Buffer.from('00010000010003026832fde8000300c0ff', 'hex')],
    [65, Buffer.from('00010000010003026832fde8000300c0ff', 'hex')],
  ]);
  const address = data.get(q.type) ?? Buffer.from('00c0ff41', 'hex');
  const record = Buffer.concat([Buffer.from([0xc0, 0x0c]), u16(q.type), u16(1), Buffer.alloc(4), u16(address.length), address]);
  record.writeUInt32BE(ttl, 6); reply.writeUInt16BE(count, 6);
  const packet = Buffer.concat([reply.subarray(0, q.questionEnd), ...Array.from({ length: count }, () => record), reply.subarray(q.questionEnd)]);
  validateDnsResponse(packet, query); return packet;
}
