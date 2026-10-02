import test from 'node:test';
import assert from 'node:assert/strict';
import { PcapHeaders, classifyPacket, captureTrafficNeedsReview, captureUnit, consumers, gateText } from './lib/host-boot-capture.mjs';

function packet({ ip = [1, 1, 1, 1], port = 53, source = 1234, protocol = 17, fragment = 0 } = {}) {
  const b = Buffer.alloc(48); b.writeUInt16BE(0x0800); b.writeUInt32BE(3, 4); b[10] = 4;
  b[20] = 0x45; b[29] = protocol; b.writeUInt16BE(fragment, 26);
  Buffer.from(ip).copy(b, 36); b.writeUInt16BE(source, 40); b.writeUInt16BE(port, 42); return b;
}
test('headers classify DNS, DHCP, exit TLS, other public traffic and fragments', () => {
  const classify = p => classifyPacket(p, '154.62.226.216').category;
  assert.equal(classify(packet()), 'direct-dns-or-dot');
  assert.equal(classify(packet({ ip: [192,168,1,1] })), 'direct-dns-or-dot');
  assert.equal(classify(packet({ source: 68, port: 67 })), 'dhcp4');
  assert.equal(classify(packet({ ip: [154,62,226,216], protocol: 6, port: 443 })), 'exit-tls');
  assert.equal(classify(packet({ ip: [154,62,226,216], protocol: 17, port: 443 })), 'unexpected-egress');
  assert.equal(classify(packet({ port: 443 })), 'unexpected-egress');
  assert.equal(classify(packet({ fragment: 1 })), 'fragment-review');
});
test('stream parser handles every byte boundary, refuses wrong link type and truncation', () => {
  const header = Buffer.alloc(24); header.writeUInt32LE(0xa1b2c3d4); header.writeUInt32LE(276, 20);
  const record = Buffer.alloc(16); record.writeUInt32LE(48, 8);
  const seen = []; const parser = new PcapHeaders(p => seen.push(Buffer.from(p)));
  for (const byte of Buffer.concat([header, record, packet()])) parser.push(Buffer.from([byte]));
  parser.finish(); assert.deepEqual(seen, [packet()]);
  header.writeUInt32LE(1, 20); assert.throws(() => new PcapHeaders(() => {}).push(header));
  assert.throws(() => new PcapHeaders(() => {}).finish());
});
test('gates include socket and WiFi activators; readiness is notify, not simple', () => {
  assert.ok(consumers.includes('netplan-wpa-wlan0.service'));
  assert.ok(consumers.includes('systemd-networkd.socket'));
  assert.match(gateText, /Requires=clean-vpn-boot-capture.service/);
  assert.match(captureUnit('/usr/bin/node'), /Type=notify/);
  assert.match(captureUnit('/usr/bin/node'), /RemainAfterExit=yes/);
  assert.throws(() => captureUnit('/root/a b/node'));
});
test('IPv6 transport and extension headers are not silently whitelisted', () => {
  const p = Buffer.alloc(68); p.writeUInt16BE(0x86dd); p.writeUInt32BE(3,4); p[10] = 4;
  p[20] = 0x60; p[26] = 17; p[44] = 0x20; p[45] = 1; p.writeUInt16BE(53,62);
  assert.equal(classifyPacket(p, '').category, 'direct-dns-or-dot');
  p[26] = 44; assert.equal(classifyPacket(p, '').category, 'ipv6-extension-review');
  p[26] = 58; p[60] = 128; assert.equal(classifyPacket(p, '').category, 'unexpected-egress');
});
test('only the narrow Linux link-local MLDv2 header form is allowed', () => {
  const p = Buffer.alloc(76); p.writeUInt16BE(0x86dd); p.writeUInt32BE(3,4); p[10] = 4;
  p[20] = 0x60; p[27] = 1; p[44] = 0xff; p[45] = 2; p[59] = 0x16;
  Buffer.from('3a00050200000100','hex').copy(p,60); p[68] = 143;
  assert.equal(classifyPacket(p,'').category,'mldv2-link-control');
  p[59] = 0x17; assert.equal(classifyPacket(p,'').category,'ipv6-extension-review');
  p[59] = 0x16; p[64] = 1; assert.equal(classifyPacket(p,'').category,'ipv6-extension-review');
});

test('SLL2 protocol is retained, including unknown values, without packet bodies', () => {
  for (const ether of [0x0004, 0x0806, 0x888e, 0x88cc, 0xffff]) {
    const p = Buffer.alloc(64, 0x61);
    p.writeUInt16BE(ether); p.writeUInt32BE(3, 4); p[10] = 4;
    const category = ether === 0x0806 ? 'arp' : 'other-link-protocol';
    assert.deepEqual(classifyPacket(p, ''), {
      ifindex: 3, outbound: true, etherType: `0x${ether.toString(16).padStart(4, '0')}`, category,
    });
    assert.equal(captureTrafficNeedsReview({ [category]: 1 }), ether !== 0x0806);
  }
  assert.equal(classifyPacket(packet(), '').etherType, '0x0800');
  assert.deepEqual(classifyPacket(Buffer.alloc(19), ''), { category: 'unparsed' });
});

test('only exact IPv4/IPv6 multicast UDP5353 endpoints get mDNS review category', () => {
  const v4 = packet({ ip: [224, 0, 0, 251], port: 5353 });
  const v6 = Buffer.alloc(68); v6.writeUInt16BE(0x86dd); v6.writeUInt32BE(3, 4); v6[10] = 4;
  v6[20] = 0x60; v6[26] = 17; v6[27] = 255; v6[44] = 0xff; v6[45] = 2;
  v6[59] = 0xfb; v6.writeUInt16BE(5353, 62);
  for (const [p, protocolOffset, portOffset, destinationLastByte] of [
    [v4, 29, 42, 39], [v6, 26, 62, 59],
  ]) {
    assert.equal(classifyPacket(p, '').category, 'mdns-local-review');
    const tcp = Buffer.from(p); tcp[protocolOffset] = 6;
    assert.equal(classifyPacket(tcp, '').category, 'unexpected-egress');
    const port = Buffer.from(p); port.writeUInt16BE(5354, portOffset);
    assert.equal(classifyPacket(port, '').category, 'unexpected-egress');
    const destination = Buffer.from(p); destination[destinationLastByte] = 0xfc;
    assert.equal(classifyPacket(destination, '').category, 'unexpected-egress');
    assert.equal(classifyPacket(p.subarray(0, portOffset + 1), '').category, 'unparsed');
  }
  assert.equal(classifyPacket(v6, '').etherType, '0x86dd');
  assert.equal(classifyPacket(packet({ port: 5353 }), '').category, 'unexpected-egress');
  v4.writeUInt16BE(1, 26);
  assert.equal(classifyPacket(v4, '').category, 'fragment-review');
  v6[26] = 0;
  assert.equal(classifyPacket(v6, '').category, 'ipv6-extension-review');
});

test('mDNS and unknown link protocols still require review, including Radxa boot counts', () => {
  const baseline = { 'mldv2-link-control': 11, 'icmpv6-link-control': 3, dhcp4: 3, dhcp6: 7, arp: 1, 'exit-tls': 55 };
  assert.equal(captureTrafficNeedsReview(baseline), false);
  for (const category of ['mdns-local-review', 'other-link-protocol', 'unexpected-egress',
    'direct-dns-or-dot', 'local-destination-review', 'unparsed', 'future-unknown-category']) {
    assert.equal(captureTrafficNeedsReview({ ...baseline, [category]: 1 }), true);
  }
  assert.equal(captureTrafficNeedsReview({ ...baseline, 'mdns-local-review': 6, 'other-link-protocol': 2 }), true);
});

test('big-endian pcap retains the network-order SLL2 protocol', () => {
  const header = Buffer.alloc(24); header.writeUInt32BE(0xa1b2c3d4); header.writeUInt32BE(276, 20);
  const record = Buffer.alloc(16); record.writeUInt32BE(48, 8);
  const p = packet(); p.writeUInt16BE(0x888e);
  const seen = []; const parser = new PcapHeaders(p => seen.push(classifyPacket(p, '')));
  for (const byte of Buffer.concat([header, record, p])) parser.push(Buffer.from([byte]));
  parser.finish();
  assert.deepEqual(seen, [{ ifindex: 3, outbound: true, etherType: '0x888e', category: 'other-link-protocol' }]);
});
