/** One real verified TLS/H1 stream stalled after handshake, alongside healthy H1/H2. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { STREAM_BYTES, STREAM_HASH, writeStream } from './lab-slow-streams.mjs';

export async function slowReaderCase({ lab, tunnel, own, healthy, until, signal, direction, outcome, onBlocked = () => {} }) {
  assert.ok(['forward', 'reverse'].includes(direction));
  assert.ok(['resume', 'timeout'].includes(outcome));
  const metrics = { direction, outcome, bytes: 0, pressureSamples: 0, maxReadable: 0, maxWritable: 0 };
  const socket = own(tls.connect({ socket: await tunnel(), servername: 'localhost', ca: lab.cert,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], rejectUnauthorized: true }));
  let sampler, writing, writeFailed = false, responseError;
  const sample = () => {
    const point = lab.relayPressure(direction);
    if (point.blocked) metrics.pressureSamples++;
    metrics.maxReadable = Math.max(metrics.maxReadable, point.readable);
    metrics.maxWritable = Math.max(metrics.maxWritable, point.writable);
    if (point.overBudget) metrics.overBudget = true;
    return point;
  };
  try {
    await once(socket, 'secureConnect');
    assert.equal(socket.authorized, true); assert.equal(socket.getProtocol(), 'TLSv1.3');
    assert.equal(socket.alpnProtocol, 'http/1.1');
    let header = Buffer.alloc(0), parsed = false, bytes = 0, declared, uploadReply = '';
    const digest = createHash('sha256');
    socket.on('data', (chunk) => {
      if (!parsed) {
        header = Buffer.concat([header, chunk]);
        const split = header.indexOf('\r\n\r\n');
        if (split < 0) {
          if (header.length > 8192) { responseError = 'header-limit'; socket.destroy(); }
          return;
        }
        const text = header.subarray(0, split).toString('latin1');
        if (!/^HTTP\/1\.1 200 /.test(text)) responseError = 'http-status';
        declared = Number(/\r\ncontent-length: (\d+)/i.exec(text)?.[1]);
        chunk = header.subarray(split + 4); header = Buffer.alloc(0); parsed = true;
      }
      bytes += chunk.length;
      if (direction === 'reverse') digest.update(chunk);
      else if (bytes <= 1024) uploadReply += chunk.toString();
      else responseError = 'upload-reply-limit';
    });
    const ended = new Promise((resolve) => {
      const finish = (ok) => { socket.off('end', onEnd); socket.off('error', onError); socket.off('close', onError); resolve(ok); };
      const onEnd = () => finish(true), onError = () => finish(false);
      socket.once('end', onEnd); socket.once('error', onError); socket.once('close', onError);
    });
    if (direction === 'forward') {
      socket.write(`POST /slow-upload HTTP/1.1\r\nHost: localhost:${lab.originPort}\r\nContent-Length: ${STREAM_BYTES}\r\nConnection: close\r\n\r\n`);
      writing = writeStream(socket).catch(() => { writeFailed = true; });
    } else {
      socket.pause();
      socket.write(`GET /slow-download HTTP/1.1\r\nHost: localhost:${lab.originPort}\r\nConnection: close\r\n\r\n`);
    }
    sampler = setInterval(sample, 5);
    await until(() => sample().blocked > 0, 5000);
    await delay(100, undefined, { signal });
    await until(() => sample().blocked > 0, 1000);
    // Healthy requests must finish while the slow stream remains blocked, not after its timeout.
    await healthy();
    assert.ok(sample().blocked > 0, 'slow stream no longer blocked during healthy traffic');
    assert.equal(lab.runtimeErrors.length, 0, 'slow stream failed before healthy traffic completed');
    onBlocked({ type: 'pressure', direction, outcome });
    if (outcome === 'resume') {
      if (direction === 'forward') lab.resumeSlowUploads();
      else socket.resume();
      assert.equal(await ended, true, 'TLS response did not end cleanly');
      await writing; assert.equal(writeFailed, false);
      assert.equal(responseError, undefined); assert.equal(parsed, true); assert.equal(bytes, declared);
      if (direction === 'forward') assert.deepEqual(JSON.parse(uploadReply), { bytes: STREAM_BYTES, sha256: STREAM_HASH });
      else { assert.equal(bytes, STREAM_BYTES); assert.equal(digest.digest('hex'), STREAM_HASH); }
      metrics.bytes = STREAM_BYTES;
    } else {
      await until(() => lab.runtimeErrors.some((e) => e.code === 'TLS_RELAY_WRITE_TIMEOUT'), 5000);
      metrics.timeout = 'TLS_RELAY_WRITE_TIMEOUT';
      // A paused HTTP/TLS receiver cannot observe buffered EOF. Release the fixture
      // only AFTER proving the runtime write deadline, never to make it time out.
      if (direction === 'forward') lab.resumeSlowUploads();
      socket.resume(); // Drain queued TLS bytes so the paused reader can observe remote close.
    }
    sample();
    assert.ok(metrics.pressureSamples > 0); assert.ok(!metrics.overBudget, 'sampled relay queues exceeded HWM + 64 KiB');
    return metrics;
  } finally {
    clearInterval(sampler); socket.destroy(); await writing;
  }
}
