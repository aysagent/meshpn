/** RFC 2131/2132 subset for a single isolated Ethernet DHCP test client, NOT an OS client. */
import assert from 'node:assert/strict';

export const USB_LAB_MAC = Buffer.from([2, 0, 0, 7, 0, 2]);
const cookie = Buffer.from([99, 130, 83, 99]);
const ip = (value) => {
  assert.match(value, /^(?:\d{1,3}\.){3}\d{1,3}$/);
  const bytes = value.split('.').map(Number); assert.ok(bytes.every((b) => b <= 255)); return Buffer.from(bytes);
};
const option = (code, bytes) => Buffer.concat([Buffer.from([code, bytes.length]), bytes]);

export function makeDhcpLabRequest({ xid, requested, server } = {}) {
  assert.ok(Number.isInteger(xid) && xid >= 0 && xid <= 0xffffffff);
  assert.equal(requested === undefined, server === undefined);
  const header = Buffer.alloc(240);
  header[0] = 1; header[1] = 1; header[2] = 6;
  header.writeUInt32BE(xid, 4); header.writeUInt16BE(0x8000, 10);
  USB_LAB_MAC.copy(header, 28); cookie.copy(header, 236);
  const fields = [option(53, Buffer.from([requested ? 3 : 1])),
    option(61, Buffer.concat([Buffer.from([1]), USB_LAB_MAC])), option(12, Buffer.from('usb-client')),
    option(55, Buffer.from([1, 3, 6, 51, 54]))];
  if (requested) fields.push(option(50, ip(requested)), option(54, ip(server)));
  const packet = Buffer.concat([header, ...fields, Buffer.from([255])]);
  return Buffer.concat([packet, Buffer.alloc(Math.max(0, 300 - packet.length))]);
}

export function parseDhcpLabReply(packet, xid) {
  assert.ok(Buffer.isBuffer(packet) && packet.length >= 241 && packet.length <= 1500, 'DHCP size');
  assert.equal(packet[0], 2); assert.equal(packet[1], 1); assert.equal(packet[2], 6);
  assert.equal(packet.readUInt32BE(4), xid, 'DHCP xid');
  assert.ok(packet.subarray(28, 34).equals(USB_LAB_MAC), 'DHCP chaddr');
  assert.ok(packet.subarray(236, 240).equals(cookie), 'DHCP cookie');
  const options = new Map(); let ended = false;
  for (let at = 240; at < packet.length;) {
    const code = packet[at++];
    if (code === 0) continue;
    if (code === 255) { ended = true; break; }
    assert.ok(at < packet.length); const size = packet[at++];
    assert.ok(at + size <= packet.length, 'truncated DHCP option');
    assert.ok(!options.has(code), 'duplicate DHCP option outside fixture subset');
    assert.notEqual(code, 52, 'option overload outside fixture subset');
    options.set(code, Buffer.from(packet.subarray(at, at + size))); at += size;
  }
  assert.ok(ended, 'DHCP end required');
  assert.equal(options.get(53)?.length, 1); const type = options.get(53)[0];
  assert.ok([2, 5, 6].includes(type), 'offer/ack/nak only');
  const addressList = (code) => {
    const data = options.get(code); assert.ok(data?.length && data.length <= 32 && data.length % 4 === 0);
    return Array.from({ length: data.length / 4 }, (_, i) => [...data.subarray(i * 4, i * 4 + 4)].join('.'));
  };
  assert.equal(options.get(54)?.length, 4);
  const server = addressList(54)[0]; assert.equal(server, '192.168.7.1', 'fixture DHCP server');
  if (type === 6) return { type, server };
  const address = [...packet.subarray(16, 20)].join('.');
  assert.equal(packet[16], 192); assert.equal(packet[17], 168); assert.equal(packet[18], 7);
  assert.ok(packet[19] >= 10 && packet[19] <= 50, 'fixture lease range');
  assert.equal(options.get(1)?.length, 4);
  const mask = addressList(1)[0], routers = addressList(3), dns = addressList(6);
  assert.equal(mask, '255.255.255.0'); assert.deepEqual(routers, ['192.168.7.1']);
  assert.equal(options.get(51)?.length, 4); const leaseSeconds = options.get(51).readUInt32BE();
  assert.ok(leaseSeconds > 0 && leaseSeconds <= 43200);
  return { type, server, address, mask, routers, dns, leaseSeconds };
}
