import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { readlink } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { assessDnsAdapterSockets, inspectDnsAdapterSockets } from './lib/dns-adapter-sockets.mjs';

const header = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
const row = (inode, protocol, address = '0100007F', uid = 1234, state = protocol === 'tcp' ? '0A' : '07') =>
  `0: ${address}:0805 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 ${uid} 0 ${inode} 1 0\n`;
const evidence = () => ({ port: 2053, uid: 1234, endian: 'LE', before: ['101', '102'], after: ['101', '102'],
  tables: { tcp: header + row('101', 'tcp'), udp: header + row('102', 'udp'), tcp6: header, udp6: header } });
test('socket data needs distinct loopback UDP/TCP listeners, selected UID and FDs before/after', () => {
  const e = evidence(), before = structuredClone(e);
  assert.deepEqual(assessDnsAdapterSockets(e), { udp: '102', tcp: '101' }); assert.deepEqual(e, before);
  e.endian = 'BE'; e.tables.tcp = header + row('101', 'tcp', '7F000001'); e.tables.udp = header + row('102', 'udp', '7F000001');
  assert.deepEqual(assessDnsAdapterSockets(e), { udp: '102', tcp: '101' });
});
for (const [name, change] of [
  ['missing TCP', (e) => { e.tables.tcp = header; }], ['missing UDP', (e) => { e.tables.udp = header; }],
  ['wildcard', (e) => { e.tables.udp = header + row('102', 'udp', '00000000'); }],
  ['foreign UID', (e) => { e.tables.tcp = header + row('101', 'tcp', '0100007F', 1000); }],
  ['unowned FD', (e) => { e.before = ['102']; }], ['closed FD', (e) => { e.after = ['101']; }],
  ['reused inode', (e) => { e.tables.udp = header + row('101', 'udp'); }],
  ['duplicate UDP', (e) => { e.tables.udp += row('103', 'udp'); }],
  ['duplicate TCP', (e) => { e.tables.tcp += row('103', 'tcp'); }],
  ['connected UDP', (e) => { e.tables.udp = e.tables.udp.replace('00000000:0000', '08080808:0035'); }],
  ['wrong UDP state', (e) => { e.tables.udp = header + row('102', 'udp', '0100007F', 1234, '01'); }],
  ['IPv6 listener', (e) => { e.tables.tcp6 += row('103', 'tcp', '0'.repeat(32)).replace('00000000:0000', `${'0'.repeat(32)}:0000`); }],
  ['truncated row', (e) => { e.tables.tcp += '0: invalid\n'; }],
  ['too many FDs', (e) => { e.before = Array(257).fill('101'); }],
  ['oversized table', (e) => { e.tables.udp = ' '.repeat(524289); }],
]) test(`socket data refuses ${name}`, () => { const e = evidence(); change(e); assert.throws(() => assessDnsAdapterSockets(e)); });
test('TCP accepted streams and unrelated ports do not replace the owned listener', () => {
  const e = evidence(); e.tables.tcp += row('999', 'tcp', '0100007F', 999, '01');
  e.tables.udp += row('999', 'udp').replace(':0805', ':0806');
  assert.deepEqual(assessDnsAdapterSockets(e), { udp: '102', tcp: '101' });
});
test('real /proc inspection binds both loopback socket inodes and notices listener closure without sending DNS', { timeout: 10000 }, async (t) => {
  const tcp = net.createServer(), udp = dgram.createSocket('udp4');
  t.after(async () => { if (tcp.listening) await new Promise((r) => tcp.close(r)); try { udp.close(); } catch {} });
  tcp.listen(0, '127.0.0.1'); await once(tcp, 'listening'); const port = tcp.address().port;
  udp.bind(port, '127.0.0.1'); await once(udp, 'listening');
  const options = { pid: process.pid, uid: process.getuid(), port, netns: await readlink('/proc/self/ns/net') };
  const result = await inspectDnsAdapterSockets(options);
  assert.match(result.tcp, /^[1-9][0-9]*$/); assert.match(result.udp, /^[1-9][0-9]*$/); assert.notEqual(result.tcp, result.udp);
  await new Promise((r) => udp.close(r)); await assert.rejects(inspectDnsAdapterSockets(options), /both adapter listeners required/);
});
test('real sockets of another process in the same netns are not adopted', { timeout: 10000 }, async (t) => {
  const code = `const net=require('node:net'), dgram=require('node:dgram');
    const tcp=net.createServer(), udp=dgram.createSocket('udp4');
    tcp.listen(0,'127.0.0.1',()=>{const port=tcp.address().port; udp.bind(port,'127.0.0.1',()=>process.send({port}));});`;
  const child = spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const exited = once(child, 'exit'); t.after(async () => { child.kill('SIGKILL'); await exited; });
  const [{ port }] = await once(child, 'message');
  await assert.rejects(inspectDnsAdapterSockets({ pid: process.pid, uid: process.getuid(), port,
    netns: await readlink('/proc/self/ns/net') }), /listener not held by selected process/);
});
