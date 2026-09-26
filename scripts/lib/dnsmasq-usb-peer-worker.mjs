/** Private child network namespace only. Fixed DHCP/DNS test RPC, no host resolver edits. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { readlink } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { exec } from './browser-lab-driver.mjs';
import { makeDhcpLabRequest, parseDhcpLabReply } from './dhcp-lab-wire.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { assertDnsmasqVm } from './dnsmasq-vm-safety.mjs';

const gateway = '192.168.7.1';
const report = (id, result) => process.stdout.write(`USB_PEER ${id} ${JSON.stringify(result)}\n`);
let configured = false, lease;
const upstream = process.argv[2] === '--upstream';
const observers = [];

async function acquire() {
  assert.ok(configured);
  // No generic addresses/routes accepted from RPC or DHCP packets.
  await exec('ip', ['-4', 'addr', 'flush', 'dev', 'usbpeer']);
  // Permit reverse-path validation of the server's reply before a lease exists.
  await exec('ip', ['route', 'replace', 'default', 'dev', 'usbpeer']);
  await exec('ip', ['route', 'replace', '255.255.255.255/32', 'dev', 'usbpeer']);
  const socket = dgram.createSocket('udp4');
  const xid = randomBytes(4).readUInt32BE();
  try {
    socket.bind(68, '0.0.0.0'); await once(socket, 'listening'); socket.setBroadcast(true);
    const exchange = (packet, type) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error('DHCP deadline')), 5000);
      const finish = (error, result) => {
        clearTimeout(timer); socket.off('message', message); socket.off('error', failure);
        error ? reject(error) : resolve(result);
      };
      const failure = (error) => finish(error);
      const message = (bytes, sender) => {
        if (sender.port !== 67 || sender.address !== gateway) return;
        if (bytes.length < 8 || bytes.readUInt32BE(4) !== xid) return;
        try {
          const result = parseDhcpLabReply(bytes, xid);
          assert.notEqual(result.type, 6, 'unexpected DHCP NAK');
          if (result.type === type) finish(null, result);
        } catch (error) { finish(error); }
      };
      socket.on('message', message); socket.once('error', failure);
      socket.send(packet, 67, '255.255.255.255', (error) => { if (error) finish(error); });
    });
    const offer = await exchange(makeDhcpLabRequest({ xid }), 2);
    const ack = await exchange(makeDhcpLabRequest({ xid, requested: offer.address, server: offer.server }), 5);
    assert.equal(ack.address, offer.address);
    await exec('ip', ['addr', 'add', `${ack.address}/24`, 'dev', 'usbpeer']);
    await exec('ip', ['route', 'replace', 'default', 'via', gateway, 'dev', 'usbpeer']);
    await exec('ip', ['route', 'del', '255.255.255.255/32', 'dev', 'usbpeer']);
    lease = ack;
    return { offer, ack, stages: ['DISCOVER', 'OFFER', 'REQUEST', 'ACK'] };
  } finally { socket.close(); }
}

async function lookup({ sequence, tcp, type, local = false, direct = false, forwarded = false, family = 4 }) {
  assert.ok(lease && Number.isSafeInteger(sequence) && sequence > 0 && sequence <= 100);
  assert.equal(typeof tcp, 'boolean'); assert.ok([1, 28].includes(type));
  assert.equal(typeof local, 'boolean'); assert.equal(typeof direct, 'boolean');
  assert.equal(typeof forwarded, 'boolean'); assert.ok(!forwarded || direct);
  assert.ok(family === 4 || family === 6 && direct);
  const host = forwarded ? family === 6 ? '2001:db8:54::53' : '203.0.113.53'
    : direct ? family === 6 ? '2001:db8:53::1' : '1.1.1.1' : lease.dns[0];
  assert.ok(['192.168.7.1', '1.1.1.1', '8.8.8.8', '2001:db8:53::1', '203.0.113.53', '2001:db8:54::53'].includes(host));
  const query = makeDnsQuery(local ? 'usb-client' : `usb-peer-${sequence}.test`, type);
  const socket = tcp ? net.connect({ host, port: 53 }) : dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
  let timer;
  try {
    const response = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('DNS deadline'), { code: 'DNS_CLIENT_TIMEOUT' })),
        process.env.MESHPN_DNSMASQ_VM === '1' ? 10000 : 1800);
      socket.once('error', reject);
      if (tcp) {
        let buffer = Buffer.alloc(0);
        socket.once('connect', () => {
          const size = Buffer.alloc(2); size.writeUInt16BE(query.length); socket.write(Buffer.concat([size, query]));
        });
        socket.on('end', () => reject(new Error('DNS EOF')));
        socket.on('data', (part) => {
          if (buffer.length + part.length > 65537) { reject(new Error('DNS size')); return; }
          buffer = Buffer.concat([buffer, part]);
          if (buffer.length >= 2 && buffer.length === buffer.readUInt16BE(0) + 2) resolve(buffer.subarray(2));
        });
      } else {
        socket.connect(53, host, () => { socket.once('message', resolve); socket.send(query); });
      }
    });
    const parsed = validateDnsResponse(response, query);
    const rr = parsed.records.find((r) => r.section === 0 && r.type === type);
    return { outcome: 'dns-response', rcode: parsed.rcode,
      answer: rr ? response.subarray(rr.offset, rr.offset + rr.length).toString('hex') : null };
  } catch (error) {
    if (error.code === 'DNS_CLIENT_TIMEOUT') return { outcome: 'client-deadline' };
    if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH'].includes(error.code)) return { outcome: 'transport-error', code: error.code };
    throw error;
  } finally { clearTimeout(timer); if (tcp) socket.destroy(); else socket.close(); }
}

try {
  assert.ok(process.argv.length === 2 || process.argv.length === 3 && upstream, 'unknown worker arguments');
  if (process.env.MESHPN_DNSMASQ_VM === '1') { await assertDnsmasqVm({ peer: true }); assert.equal(upstream, false); }
  else for (const [kind, original] of [['net', process.env.MESHPN_PARENT_NETNS], ['pid', process.env.MESHPN_PARENT_PIDNS],
    ['mnt', process.env.MESHPN_PARENT_MNTNS], ['net', process.env.MESHPN_DNSMASQ_GATEWAY_NETNS]]) {
    assert.ok(original); assert.notEqual(await readlink(`/proc/self/ns/${kind}`), original, 'isolated USB peer required');
  }
  assert.ok(process.pid > 1);
  assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout).map((l) => l.ifname), ['lo']);
  report(0, { ready: true });
  let pending = '', busy = false;
  process.stdin.setEncoding('utf8');
  process.stdin.on('end', () => process.exit(0));
  process.stdin.on('data', (chunk) => {
    pending += chunk;
    if (pending.length > 4096) process.exit(1);
    if (!pending.endsWith('\n')) return;
    const raw = pending; pending = '';
    if (busy) process.exit(1);
    busy = true;
    (async () => {
      const { id, operation, options } = JSON.parse(raw);
      assert.ok(Number.isInteger(id) && id >= 1 && id <= 100);
      let result;
      if (operation === 'configure') {
        assert.equal(configured, false);
        const links = JSON.parse((await exec('ip', ['-j', 'link', 'show'])).stdout);
        assert.deepEqual(links.map((l) => l.ifname).sort(), ['lo', upstream ? 'wanpeer' : 'usbpeer']);
        await exec('ip', ['link', 'set', 'lo', 'up']);
        if (upstream) {
          await exec('ip', ['link', 'set', 'wanpeer', 'up']);
          await exec('ip', ['addr', 'add', '198.18.0.2/30', 'dev', 'wanpeer']);
          await exec('ip', ['-6', 'addr', 'add', '2001:db8:8::2/64', 'dev', 'wanpeer', 'nodad']);
          await exec('ip', ['addr', 'add', '203.0.113.53/32', 'dev', 'lo']);
          await exec('ip', ['-6', 'addr', 'add', '2001:db8:54::53/128', 'dev', 'lo', 'nodad']);
          await exec('ip', ['route', 'add', '192.168.7.0/24', 'via', '198.18.0.1']);
          await exec('ip', ['-6', 'route', 'add', '2001:db8:7::/64', 'via', '2001:db8:8::1']);
          for (const address of ['203.0.113.53', '2001:db8:54::53']) observers.push(await sentinel(address));
          configured = true; result = { configured: true };
        } else {
          await exec('ip', ['link', 'set', 'usbpeer', 'address', '02:00:00:07:00:02']);
          await exec('ip', ['link', 'set', 'usbpeer', 'up']);
          await exec('ip', ['-6', 'addr', 'add', '2001:db8:7::2/64', 'dev', 'usbpeer', 'nodad']);
          await exec('ip', ['-6', 'route', 'add', 'default', 'via', '2001:db8:7::1', 'dev', 'usbpeer']);
          configured = true; result = { configured: true };
        }
      } else if (operation === 'hits' && upstream && configured) result = observers.map((s) => s.hits());
      else if (operation === 'acquire' && !upstream) result = await acquire();
      else if (operation === 'lookup' && !upstream) result = await lookup(options);
      else throw new Error('unknown USB peer operation');
      report(id, { ok: true, result });
    })().catch((error) => { process.stderr.write(`USB_PEER_FAILED ${error.message}\n`); process.exitCode = 1; process.stdin.destroy(); })
      .finally(() => { busy = false; });
  });
} catch (error) { process.stderr.write(`USB_PEER_FAILED ${error.message}\n`); process.exitCode = 1; }
