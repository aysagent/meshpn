import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';

// Evaluate the actual CLI bridge functions without running main(), opening a TUN,
// loading native transports, or changing the host. Only endpoint IO is replaced.
const source = readFileSync(new URL('./clean-vpn.js', import.meta.url), 'utf8');
const start = source.indexOf('function attachTunBridge(tun,');
const end = source.indexOf('\n/**\n * Exit/inbound', start);
assert.ok(start > 0 && end > start);
const framerStart = source.indexOf('class StreamFramer {');
const framerEnd = source.indexOf('\n/** Uint32 BE', framerStart);
assert.ok(framerStart > 0 && framerEnd > framerStart);
const { attachOutboundTunBridge: attach, attachTunBridge } = runInNewContext(
  `${source.slice(framerStart, framerEnd)}\n${source.slice(start, end)}\n({attachOutboundTunBridge, attachTunBridge});`, {
  Buffer, process: { env: {} }, randomBytes,
  setTimeout: () => ({ unref() {} }), clearTimeout() {}, setInterval, clearInterval,
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

function fixture({ keepAlive = 0, eager = false, failFirst = false } = {}) {
  let read, calls = 0, resolve, reject;
  const endpoint = new EventEmitter(); endpoint.sent = [];
  const api = attach({ startRead(callback) { read = callback; }, write() {} }, 'tcp', {}, () => {
    calls++;
    return new Promise((yes, no) => { resolve = yes; reject = no; });
  }, keepAlive, 0, eager);
  const packet = Buffer.alloc(20); packet[0] = 0x45;
  return { api, endpoint, packet, read: () => read([packet]), calls: () => calls,
    finish: async () => {
      if (failFirst && calls === 1) reject(new Error('injected connection failure'));
      else resolve(endpoint);
      await new Promise(setImmediate);
    } };
}

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
