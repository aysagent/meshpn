/** Four stream-flow cases on ONE verified TLS/H2 connection; no socket-level pause. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import http2 from 'node:http2';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { H2_BYTES, H2_HASH, writeH2Body } from './lab-h2-flow.mjs';

export function assertFlowBlocked(point) {
  assert.equal(point.localWindow, 0, 'receiving stream window must be exhausted');
  assert.equal(point.needDrain, true, 'sending stream must be backpressured');
  assert.ok(point.connectionWindow > 0, 'connection window must still permit sibling traffic');
}
export function flowBlocked(point) {
  return point.localWindow === 0 && point.needDrain === true && point.connectionWindow > 0;
}
export async function waitFlowBlocked(until, sample) {
  let observed;
  await until(() => flowBlocked(observed = sample()));
  // Validate the snapshot which satisfied readiness. A later snapshot may already
  // reflect another asynchronous WINDOW_UPDATE or drain notification.
  assertFlowBlocked(observed);
  return observed;
}

export async function h2FlowMatrix({ lab, proxy, tunnel, own, until, concurrency, signal, emit = () => {} }) {
  const before = { tls: lab.stats().tlsConnections, origins: lab.stats().originConnections, tunnels: proxy.stats().tunnels };
  const socket = own(tls.connect({ socket: await tunnel(), servername: 'localhost', ca: lab.cert,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['h2'], rejectUnauthorized: true }));
  let session, sessionClosed, sampler, writing;
  let currentCase = 'setup', step = 'setup', latestPoint;
  const streams = new Set(), cases = {};
  let goaways = 0, sessionErrors = 0;
  function request(path, { body, method = 'POST', maxBytes = H2_BYTES, captureText = false, length } = {}) {
    const headers = { ':method': method, ':path': path };
    if (length !== undefined) headers['content-length'] = String(length);
    const stream = session.request(headers);
    streams.add(stream); stream.once('close', () => streams.delete(stream));
    stream.on('error', () => {});
    let status, bytes = 0, text = '', overflow = false;
    const digest = createHash('sha256');
    stream.on('response', (headers) => { status = headers[':status']; });
    stream.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) { overflow = true; stream.close(http2.constants.NGHTTP2_CANCEL); return; }
      digest.update(chunk);
      if (captureText) text += chunk.toString();
    });
    const response = new Promise((resolve) => {
      const finish = (ended) => {
        stream.off('end', onEnd); stream.off('error', onClose); stream.off('close', onClose);
        resolve({ ended, status, bytes, text, overflow, sha256: digest.digest('hex') });
      };
      const onEnd = () => finish(true), onClose = () => finish(false);
      stream.once('end', onEnd); stream.once('close', onClose); stream.once('error', onClose);
    });
    if (body !== undefined) stream.end(body);
    return { stream, response };
  }
  const checkConnection = () => {
    assert.equal(session.closed || session.destroyed, false);
    assert.equal(goaways + sessionErrors, 0);
    assert.equal(lab.stats().tlsConnections - before.tls, 1);
    assert.equal(lab.stats().originConnections - before.origins, 1);
    assert.equal(proxy.stats().tunnels - before.tunnels, 1);
    assert.equal(lab.runtimeErrors.length, 0);
    assert.equal(lab.stats().h2FlowDeadlines, 0, 'fixture deadline is not a successful cancellation');
  };
  async function echo() {
    const body = Buffer.alloc(128 * 1024, 0x3d);
    const { response } = request('/echo', { body, maxBytes: body.length });
    const result = await response;
    assert.equal(result.ended, true); assert.equal(result.status, 200); assert.equal(result.overflow, false);
    assert.equal(result.bytes, body.length);
    assert.equal(result.sha256, createHash('sha256').update(body).digest('hex'));
  }
  try {
    await once(socket, 'secureConnect');
    assert.equal(socket.authorized, true); assert.equal(socket.alpnProtocol, 'h2'); assert.equal(socket.getProtocol(), 'TLSv1.3');
    session = http2.connect(`https://localhost:${lab.originPort}`, { createConnection: () => socket });
    session.on('error', () => { sessionErrors++; }); session.on('goaway', () => { goaways++; });
    sessionClosed = new Promise((resolve) => session.once('close', resolve));
    await once(session, 'connect');
    await echo(); await until(() => streams.size === 0);
    for (const direction of ['forward', 'reverse']) for (const outcome of ['resume', 'cancel']) {
      const key = `${direction}-${outcome}`, upload = direction === 'forward';
      currentCase = key; step = 'initial-window';
      const cancelsBefore = lab.stats().h2FlowCancels;
      const slow = request(upload ? '/h2-flow-upload' : '/h2-flow-download', {
        method: upload ? 'POST' : 'GET', length: upload ? H2_BYTES : undefined,
        maxBytes: upload ? 1024 : H2_BYTES, captureText: upload,
      });
      let writeFailed = false;
      if (upload) writing = writeH2Body(slow.stream).catch(() => { writeFailed = true; });
      else { slow.stream.pause(); slow.stream.end(); }
      const metrics = { cases: 1, bytes: 0, zeroWindowSamples: 0, maxReadable: 0, maxWritable: 0,
        healthyWhileBlocked: 0, healthyAfter: 0, heldSurvived: 0 };
      const point = () => {
        const origin = lab.h2FlowSnapshots().find((s) => s.id === slow.stream.id);
        return upload ? { localWindow: origin?.localWindow, needDrain: slow.stream.writableNeedDrain,
          connectionWindow: session.state.remoteWindowSize, readable: origin?.readable ?? 0, writable: slow.stream.writableLength }
          : { localWindow: slow.stream.state.localWindowSize, needDrain: origin?.needDrain,
            connectionWindow: origin?.connectionWindow, readable: slow.stream.readableLength, writable: origin?.writable ?? 0 };
      };
      const sample = () => {
        const state = point();
        latestPoint = state;
        if (state.localWindow === 0 && state.needDrain) metrics.zeroWindowSamples++;
        metrics.maxReadable = Math.max(metrics.maxReadable, state.readable);
        metrics.maxWritable = Math.max(metrics.maxWritable, state.writable);
        return state;
      };
      sampler = setInterval(sample, 5);
      // Stream and connection WINDOW_UPDATE are observed asynchronously at opposite
      // endpoints. Wait for the whole required state, not just two of its fields.
      await waitFlowBlocked(until, sample);
      await delay(100, undefined, { signal });
      step = 'healthy-while-blocked';
      await Promise.all(Array.from({ length: concurrency }, echo));
      await waitFlowBlocked(until, sample); checkConnection();
      metrics.healthyWhileBlocked = concurrency;
      emit({ type: 'h2-flow', direction, outcome });
      if (outcome === 'resume') {
        step = 'resume';
        if (upload) lab.resumeH2Uploads(); else slow.stream.resume();
        const received = await slow.response;
        await writing; writing = undefined;
        assert.equal(writeFailed, false); assert.equal(received.ended, true); assert.equal(received.status, 200);
        assert.equal(received.overflow, false);
        if (upload) assert.deepEqual(JSON.parse(received.text), { bytes: H2_BYTES, sha256: H2_HASH });
        else { assert.equal(received.bytes, H2_BYTES); assert.equal(received.sha256, H2_HASH); }
        metrics.bytes = H2_BYTES;
      } else {
        step = 'hold-siblings';
        // Keep siblings actually pending at origin during RST_STREAM, not just before/after it.
        const held = Array.from({ length: concurrency }, () => request('/hold', { body: Buffer.alloc(0), maxBytes: 64, captureText: true }));
        await until(() => lab.stats().heldResponses === concurrency);
        await waitFlowBlocked(until, sample);
        step = 'cancel';
        slow.stream.close(http2.constants.NGHTTP2_CANCEL); slow.stream.resume();
        await until(() => slow.stream.destroyed && lab.stats().h2FlowStreams === 0);
        await writing; writing = undefined;
        assert.equal(slow.stream.rstCode, http2.constants.NGHTTP2_CANCEL);
        assert.equal(lab.stats().h2FlowCancels, cancelsBefore + 1);
        lab.releaseHeldResponses();
        step = 'held-survivors';
        for (const item of held) {
          const received = await item.response;
          assert.equal(received.ended, true); assert.equal(received.status, 200); assert.equal(received.text, 'released');
          assert.equal(item.stream.rstCode, 0);
        }
        metrics.heldSurvived = concurrency; metrics.rstCode = http2.constants.NGHTTP2_CANCEL;
      }
      clearInterval(sampler); sampler = undefined;
      step = 'recovery';
      await until(() => streams.size === 0 && lab.stats().h2FlowStreams + lab.stats().heldResponses === 0);
      await Promise.all(Array.from({ length: concurrency }, echo));
      await until(() => streams.size === 0);
      metrics.healthyAfter = concurrency;
      checkConnection();
      assert.ok(metrics.zeroWindowSamples > 0);
      assert.ok(metrics.maxReadable <= 256 * 1024 && metrics.maxWritable <= 256 * 1024, 'sampled H2 queues exceeded fixture budget');
      cases[key] = metrics;
    }
    return { cases, tlsConnections: 1, healthyEchoes: 1 + 8 * concurrency };
  } catch (error) {
    error.h2Flow = { case: currentCase, step, point: latestPoint,
      ...(typeof error.actual === 'number' || typeof error.actual === 'boolean' ? { actual: error.actual } : {}),
      ...(typeof error.expected === 'number' || typeof error.expected === 'boolean' ? { expected: error.expected } : {}) };
    throw error;
  } finally {
    clearInterval(sampler);
    for (const stream of streams) stream.destroy();
    session?.destroy(); socket.destroy();
    await writing; await sessionClosed;
  }
}
