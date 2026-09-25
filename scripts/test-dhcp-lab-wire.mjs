import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { makeDhcpLabRequest, parseDhcpLabReply, USB_LAB_MAC } from './lib/dhcp-lab-wire.mjs';

const xid = 0x12345678;
const option = (id, bytes) => Buffer.from([id, bytes.length, ...bytes]);
function response(type = 2, extras = []) {
  const header = Buffer.from(makeDhcpLabRequest({ xid }).subarray(0, 240));
  header[0] = 2; Buffer.from([192, 168, 7, 14]).copy(header, 16);
  return Buffer.concat([header, option(53, [type]), option(54, [192, 168, 7, 1]),
    option(1, [255, 255, 255, 0]), option(3, [192, 168, 7, 1]), option(6, [192, 168, 7, 1]),
    option(51, [0, 0, 168, 192]), ...extras, Buffer.from([255])]);
}
test('bounded DISCOVER/REQUEST fixture packets contain Ethernet identity, broadcast flag and requested options', () => {
  const discover = makeDhcpLabRequest({ xid });
  assert.equal(discover.length, 300); assert.equal(discover[0], 1);
  assert.equal(discover.readUInt32BE(4), xid); assert.equal(discover.readUInt16BE(10), 0x8000);
  assert.ok(discover.subarray(28, 34).equals(USB_LAB_MAC));
  assert.deepEqual([...discover.subarray(236, 243)], [99, 130, 83, 99, 53, 1, 1]);
  const request = makeDhcpLabRequest({ xid, requested: '192.168.7.14', server: '192.168.7.1' });
  assert.equal(request[242], 3);
  assert.ok(request.includes(option(50, [192, 168, 7, 14])));
  assert.ok(request.includes(option(54, [192, 168, 7, 1])));
  for (const options of [{ xid: -1 }, { xid: 2 ** 32 }, { xid: '1' }, { xid, requested: '192.168.7.14' },
    { xid, requested: '999.1.1.1', server: '192.168.7.1' }]) assert.throws(() => makeDhcpLabRequest(options));
});
test('OFFER/ACK decode addresses, gateway, DNS and a bounded lease; NAK is distinct', () => {
  for (const type of [2, 5]) assert.deepEqual(parseDhcpLabReply(response(type), xid), {
    type, server: '192.168.7.1', address: '192.168.7.14', mask: '255.255.255.0',
    routers: ['192.168.7.1'], dns: ['192.168.7.1'], leaseSeconds: 43200 });
  assert.deepEqual(parseDhcpLabReply(response(6), xid), { type: 6, server: '192.168.7.1' });
});
test('wrong transaction/client/cookie, invalid envelope and outside-subnet lease are rejected', () => {
  for (const [at, value] of [[0, 1], [1, 2], [2, 0], [4, 0], [28, 3], [236, 0], [16, 10], [19, 51], [19, 9]]) {
    const packet = response(); packet[at] = value; assert.throws(() => parseDhcpLabReply(packet, xid));
  }
  for (const packet of [Buffer.alloc(0), Buffer.alloc(1501), response().subarray(0, 240), response().subarray(0, -1)]) {
    assert.throws(() => parseDhcpLabReply(packet, xid));
  }
});
test('truncated, repeated, overloaded and malformed critical options are rejected', () => {
  for (const extra of [option(6, [1, 1, 1, 1]), option(52, [1]), Buffer.from([200, 10, 1])]) {
    assert.throws(() => parseDhcpLabReply(response(2, [extra]), xid));
  }
  for (const code of [1, 3, 6, 51, 54]) {
    const packet = response();
    for (let at = 240; packet[at] !== 255; at += packet[at + 1] + 2) if (packet[at] === code) {
      packet[at + 1] = 0; break;
    }
    assert.throws(() => parseDhcpLabReply(packet, xid));
  }
});
test('USB peer worker refuses ordinary host invocation before creating sockets or changing links', () => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('MESHPN_PARENT_') || key === 'MESHPN_DNSMASQ_GATEWAY_NETNS') delete env[key];
  const result = spawnSync(process.execPath, ['scripts/lib/dnsmasq-usb-peer-worker.mjs'], { env, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.match(result.stderr, /USB_PEER_FAILED/);
});
