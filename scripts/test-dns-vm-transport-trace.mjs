import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { traceVmTransport } from './lib/dns-vm-transport-trace.mjs';
test('VM transport trace preserves receiver, arguments, return value and errors; records no content', () => {
  let ms = 0; const calls = [], sockets = [];
  const make = (method) => { const object = { [method](...args) { assert.equal(this, object); calls.push(args); ms += 10;
    if (args[0] === 'fail') throw new Error('PRIVATE'); const socket = new EventEmitter(); sockets.push(socket); return socket; } }; return object; };
  const tls = make('connect'), net = make('connect'), https = make('request'), original = tls.connect;
  const trace = traceVmTransport({ tls, net, https, now: () => ms, cpu: () => ({ user: ms * 1000, system: 0 }) });
  const socket = tls.connect({ secret: 'PRIVATE', servername: 'PRIVATE' });
  assert.equal(socket, sockets[0]); assert.equal(socket.listenerCount('error'), 0);
  ms += 7; socket.emit('secureConnect'); socket.emit('close');
  net.connect('PRIVATE').emit('connect'); https.request('PRIVATE').emit('response', { secret: 'PRIVATE' });
  assert.throws(() => tls.connect('fail'), /PRIVATE/);
  const result = trace.snapshot(); assert.equal(result[1].ms - result[0].ms, 10);
  assert.equal(result[1].cpuMs - result[0].cpuMs, 10);
  assert.ok(result.some((e) => e.phase === 'tls:secureConnect'));
  assert.ok(!JSON.stringify(result).includes('PRIVATE')); assert.equal(calls.length, 4);
  result[0].phase = 'changed'; assert.notEqual(trace.snapshot()[0].phase, 'changed');
  trace.close(); assert.equal(tls.connect, original);
});
test('VM trace ring stays bounded and does not overwrite subsequent wrappers', () => {
  const base = () => new EventEmitter(), tls = { connect: base }, net = { connect: base }, https = { request: base };
  let ms = 0; const trace = traceVmTransport({ tls, net, https, now: () => ms++, cpu: () => ({ user: 0, system: 0 }) });
  for (let n = 0; n < 100; n++) tls.connect().emit('close');
  assert.equal(trace.snapshot().length, 24);
  const changed = () => {}; tls.connect = changed; trace.close(); assert.equal(tls.connect, changed); assert.equal(net.connect, base);
});
