import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { traceVmTransport, traceVmHttpsServer } from './lib/dns-vm-transport-trace.mjs';
test('VM transport trace preserves receiver, arguments, return value and errors; records no content', () => {
  let ms = 0; const calls = [], sockets = [];
  const make = (method) => { const object = { [method](...args) { assert.equal(this, object); calls.push(args); ms += 10;
    if (args[0] === 'fail') throw new Error('PRIVATE'); const socket = new EventEmitter(); sockets.push(socket); return socket; } }; return object; };
  const tls = make('connect'), net = make('connect'), https = make('request'), original = tls.connect;
  const trace = traceVmTransport({ tls, net, https, now: () => ms, cpu: () => ({ user: ms * 1000, system: 0 }), wall: () => 1000 + ms });
  const socket = tls.connect({ secret: 'PRIVATE', servername: 'PRIVATE' });
  assert.equal(socket, sockets[0]); assert.equal(socket.listenerCount('error'), 0);
  ms += 7; socket.emit('secureConnect'); socket.emit('close');
  net.connect('PRIVATE').emit('connect'); const req = https.request('PRIVATE'); req.emit('finish'); req.emit('response', { secret: 'PRIVATE' });
  assert.throws(() => tls.connect('fail'), /PRIVATE/);
  const result = trace.snapshot(); assert.equal(result[1].ms - result[0].ms, 10);
  assert.equal(result[1].cpuMs - result[0].cpuMs, 10);
  assert.ok(result.some((e) => e.phase === 'tls:secureConnect'));
  assert.ok(result.some((e) => e.phase === 'http:finish')); assert.ok(result.every((e) => e.wallMs === 1000 + e.ms));
  assert.ok(!JSON.stringify(result).includes('PRIVATE')); assert.equal(calls.length, 4);
  result[0].phase = 'changed'; assert.notEqual(trace.snapshot()[0].phase, 'changed');
  trace.close(); assert.equal(tls.connect, original);
});
test('VM origin trace correlates request phases without consuming data or collecting contents', () => {
  const server = new EventEmitter(), socket = new EventEmitter(), req = new EventEmitter(), res = new EventEmitter();
  req.socket = socket; req.url = 'PRIVATE'; req.headers = { secret: 'PRIVATE' };
  let ms = 0; const trace = traceVmHttpsServer(server, { now: () => ms++, wall: () => 12345, cpu: () => ({ user: 100, system: 0 }) });
  req.on('end', () => { ms += 500; }); // Existing handler's work must follow the receipt timestamp.
  server.emit('connection', socket); server.emit('secureConnection', socket); server.emit('request', req, res);
  assert.equal(req.listenerCount('data'), 0); assert.equal(req.listenerCount('error'), 0);
  req.emit('end'); res.emit('finish'); res.emit('close');
  const events = trace.snapshot();
  assert.ok(events[3].ms < 500); assert.ok(events[4].ms >= 500);
  assert.deepEqual(events.map((e) => e.phase), ['origin:connection', 'origin:secureConnection', 'origin:request',
    'origin:requestEnd', 'origin:responseFinish', 'origin:responseClose']);
  assert.ok(events.every((e) => e.id === 1 && e.wallMs === 12345)); assert.ok(!JSON.stringify(events).includes('PRIVATE'));
  for (let i = 0; i < 100; i++) server.emit('connection', new EventEmitter());
  assert.equal(trace.snapshot().length, 24); trace.close();
  for (const name of ['connection', 'secureConnection', 'request']) assert.equal(server.listenerCount(name), 0);
});
test('VM trace ring stays bounded and does not overwrite subsequent wrappers', () => {
  const base = () => new EventEmitter(), tls = { connect: base }, net = { connect: base }, https = { request: base };
  let ms = 0; const trace = traceVmTransport({ tls, net, https, now: () => ms++, cpu: () => ({ user: 0, system: 0 }) });
  for (let n = 0; n < 100; n++) tls.connect().emit('close');
  assert.equal(trace.snapshot().length, 24);
  const changed = () => {}; tls.connect = changed; trace.close(); assert.equal(tls.connect, changed); assert.equal(net.connect, base);
});
