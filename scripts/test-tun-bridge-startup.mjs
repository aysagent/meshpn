import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { ipv6PacketAllowed } from './lib/vpn-ipv6.mjs';

// Evaluate the actual CLI bridge functions without running main(), opening a TUN,
// loading native transports, or changing the host. Only endpoint IO is replaced.
const source = readFileSync(new URL('./clean-vpn.js', import.meta.url), 'utf8');
const start = source.indexOf('function attachTunBridge(tun,');
const end = source.indexOf('\n/**\n * Exit/inbound', start);
assert.ok(start > 0 && end > start);
const framerStart = source.indexOf('class StreamFramer {');
const framerEnd = source.indexOf('\n/** Uint32 BE', framerStart);
assert.ok(framerStart > 0 && framerEnd > framerStart);
const timers = [];
const { attachOutboundTunBridge: attach, attachTunBridge } = runInNewContext(
  `${source.slice(framerStart, framerEnd)}\n${source.slice(start, end)}\n({attachOutboundTunBridge, attachTunBridge});`, {
  Buffer, process: { env: {} }, randomBytes, ipv6PacketAllowed,
  setTimeout: fn => { const timer = { fn, unref() {} }; timers.push(timer); return timer; },
  clearTimeout: timer => { if (timer) timer.cancelled = true; }, setInterval, clearInterval,
  setImmediate, console: { log() {}, error() {}, warn() {} }, MAX_PKT: 65535, KEEPALIVE_TUN_QUEUE_MAX: 256,
  STREAM_FRAMER_CHUNK_MERGE_AFTER: 24, RECONNECT_BRIDGE_TRANSPORTS: new Set(['tcp']),
  createVpnPacketTracer: () => () => {}, gracefulCloseTcpEndpoint: async () => {},
  isTcpWireResetError: () => false,
  resetTcpEndpoint() { throw new Error('unexpected endpoint reset'); },
  isIpv4Bridgeable: (packet) => packet[0] >> 4 === 4,
  createTcpFramedBatchedWriter: (endpoint, onError) => {
    endpoint.reportWriteError = onError;
    return (packet) => endpoint.sent.push(packet);
  },
});

function fixture({ keepAlive = 0, eager = false, failFirst = false, ipv6Role = null, networkReady } = {}) {
  let read, calls = 0, resolve, reject;
  const endpoint = new EventEmitter(); endpoint.sent = [];
  const received = [];
  const api = attach({ startRead(callback) { read = callback; }, write(b) { received.push(b); } }, 'tcp', { ipv6Role, networkReady }, () => {
    calls++;
    return new Promise((yes, no) => { resolve = yes; reject = no; });
  }, keepAlive, 0, eager);
  const packet = Buffer.alloc(20); packet[0] = 0x45;
  return { api, endpoint, packet, received, read: (b = packet) => read([b]), calls: () => calls,
    finish: async (connectedEndpoint = endpoint) => {
      if (failFirst && calls === 1) reject(new Error('injected connection failure'));
      else resolve(connectedEndpoint);
      await new Promise(setImmediate);
    } };
}

test('eager and packet-triggered TLS wait for network startup without opening sockets', async () => {
  let ready;
  const f = fixture({ networkReady: new Promise(resolve => { ready = resolve; }) });
  f.read(); f.read(); await new Promise(setImmediate); assert.equal(f.calls(), 0);
  ready(true); await new Promise(setImmediate); assert.equal(f.calls(), 1);
  await f.finish(); assert.equal(f.endpoint.sent.length, 2);
});
test('failed network startup never dials even when TUN has queued packets', async () => {
  let ready;
  const f = fixture({ networkReady: new Promise(resolve => { ready = resolve; }) });
  f.read(); ready(false); await new Promise(setImmediate);
  assert.equal(f.calls(), 0); await f.api.ensureWire(); assert.equal(f.calls(), 0);
});

test('IPv6 alone wakes lazy bridge; multicast cannot; inbound address validation enforced', async () => {
  const f = fixture({ keepAlive: 30, ipv6Role: 'client' });
  const packet = Buffer.alloc(48); packet[0] = 0x60; packet.writeUInt16BE(8, 4); packet[6] = 17;
  const client = Buffer.from('fd426376706e00000000000000000002', 'hex'), remote = Buffer.from('26064700470000000000000000001111', 'hex');
  client.copy(packet, 8); remote.copy(packet, 24);
  const multicast = Buffer.from(packet); multicast[24] = 255;
  f.read(multicast); assert.equal(f.calls(), 0);
  f.read(packet); assert.equal(f.calls(), 1); await f.finish(); assert.equal(f.endpoint.sent.length, 1);
  const reply = Buffer.from(packet); remote.copy(reply, 8); client.copy(reply, 24);
  const frame = b => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); };
  f.endpoint.emit('data', frame(reply)); assert.equal(f.received.length, 1);
  f.endpoint.emit('data', frame(packet)); assert.equal(f.received.length, 1);
});

test('eager startup and concurrent TUN packets share one outbound connection', async () => {
  const f = fixture(); assert.equal(f.calls(), 1);
  for (let n = 0; n < 20; n++) f.read();
  assert.equal(f.calls(), 1);
  await f.finish();
  assert.equal(f.endpoint.sent.length, 20);
  assert.equal(f.endpoint.listenerCount('data'), 1);
  f.read(); await f.api.ensureWire();
  assert.equal(f.calls(), 1); assert.equal(f.endpoint.sent.length, 21);
});

test('failed eager startup releases the gate for the next TUN packet', async () => {
  const f = fixture({ failFirst: true }); f.read(); await f.finish();
  assert.equal(f.calls(), 1);
  f.read(); f.read(); assert.equal(f.calls(), 2);
  await f.finish(); assert.equal(f.endpoint.sent.length, 3);
  assert.equal(f.endpoint.listenerCount('data'), 1);
});

test('keep-alive remains lazy unless eager startup is explicitly requested', async () => {
  for (const eager of [false, true]) {
    const f = fixture({ keepAlive: 30, eager });
    assert.equal(f.calls(), eager ? 1 : 0);
    f.read(); f.read(); assert.equal(f.calls(), 1);
    await f.finish(); assert.equal(f.endpoint.sent.length, 2);
  }
});

test('idle reconnect before old close event replaces the cached framed writer', async () => {
  const f = fixture({ keepAlive: 30 });
  f.read(); await f.finish(); assert.equal(f.endpoint.sent.length, 1);
  // Idle-disarm keeps the writer for possible reuse. Node marks the old stream
  // destroyed before its asynchronous close event; TUN may wake in between.
  timers.findLast(t => !t.cancelled).fn();
  f.endpoint.destroyed = true;
  const second = new EventEmitter(); second.sent = [];
  f.read(); assert.equal(f.calls(), 2); await f.finish(second);
  assert.equal(second.sent.length, 1, 'queued wake-up packet must use the new endpoint');
  assert.equal(f.endpoint.sent.length, 1, 'old endpoint must receive no new packets');
  f.endpoint.emit('close');
  f.read(); assert.equal(second.sent.length, 2);
  assert.equal(second.listenerCount('data'), 1);
});

test('a truncated frame from the old inbound connection cannot corrupt the next session', () => {
  const received = [], first = new EventEmitter(), second = new EventEmitter();
  const api = attachTunBridge({ startRead() {}, write(packet) { received.push(packet); } }, 'tcp', first, {});
  const packet = Buffer.alloc(20, 0x45), framed = Buffer.alloc(24);
  framed.writeUInt32BE(packet.length); packet.copy(framed, 4);
  first.emit('data', framed.subarray(0, 9)); assert.equal(received.length, 0);
  api.reconnectWire(second);
  second.emit('data', framed);
  assert.equal(received.length, 1); assert.deepEqual(received[0], packet);
});

test('a delayed write error from an old connection cannot tear down its replacement', () => {
  let read;
  const first = new EventEmitter(), second = new EventEmitter(); first.sent = []; second.sent = [];
  const api = attachTunBridge({ startRead(callback) { read = callback; }, write() {} }, 'tcp', first, {});
  const packet = Buffer.alloc(20); packet[0] = 0x45;
  read([packet]); api.reconnectWire(second);
  first.reportWriteError(new Error('late old-stream write failure'));
  read([packet]); assert.equal(second.sent.length, 1);
});
