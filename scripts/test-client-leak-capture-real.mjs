// Run only inside a new network namespace: sudo unshare --net node --test THIS_FILE.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { startLeakCapture, captureSummary } from './lib/client-leak-check.mjs';

test('real tcpdump: DNS UDP/TCP decoding, drain, clean stop and abort in isolated namespace', { timeout: 20000 }, async t => {
  assert.equal(process.getuid(), 0, 'run with sudo unshare --net');
  assert.notEqual(await readlink('/proc/self/ns/net'), await readlink('/proc/1/ns/net'), 'never modify host networking');
  execFileSync('ip', ['link', 'set', 'lo', 'up']);
  const name = 'cv-local-capture-check.example.com';
  const header = Buffer.alloc(12); header.writeUInt16BE(42, 0); header.writeUInt16BE(0x100, 2); header.writeUInt16BE(1, 4);
  const query = Buffer.concat([header, ...name.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0, 0, 1, 0, 1])]);
  const udp = createSocket('udp4'); udp.bind(53, '127.0.0.1'); await once(udp, 'listening');
  t.after(() => udp.close());
  const tcp = createServer(s => { s.on('data', () => s.end()); });
  tcp.listen(53, '127.0.0.1'); await once(tcp, 'listening');
  t.after(() => new Promise(resolve => tcp.close(resolve)));
  // Linux loopback is presented as incoming by libpcap; production physical/TUN captures use out.
  const cap = await startLeakCapture('lo', '(udp or tcp) and dst port 53', undefined, 'inout');
  t.after(() => cap.finish());
  const sender = createSocket('udp4');
  await new Promise((resolve, reject) => sender.send(query, 53, '127.0.0.1', e => e ? reject(e) : resolve())); sender.close();
  const socket = connect(53, '127.0.0.1'); await once(socket, 'connect');
  const length = Buffer.alloc(2); length.writeUInt16BE(query.length);
  socket.end(Buffer.concat([length, query])); await once(socket, 'close');
  await delay(1200);
  const raw = await cap.finish(), summary = captureSummary(raw, [name]);
  assert.equal(summary.healthy, true, JSON.stringify(summary));
  assert.deepEqual(summary.observedNames, [name], JSON.stringify(raw)); assert.ok(summary.dnsOutboundPackets >= 2);
  assert.ok(raw.stdout.split(name).length >= 3, 'both UDP and TCP decoded');
  const controller = new AbortController(), aborted = await startLeakCapture('lo', 'udp port 53', controller.signal);
  controller.abort();
  const result = captureSummary(await aborted.finish(), []);
  assert.equal(result.healthy, false); assert.equal(result.reason, 'aborted');
});
