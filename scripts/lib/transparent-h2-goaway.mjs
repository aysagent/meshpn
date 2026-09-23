/** Origin-initiated graceful drain through the real opaque TLS relay. Lab only. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import http2 from 'node:http2';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { H2_BYTES, H2_HASH, writeH2Body } from './lab-h2-flow.mjs';
import { waitFlowBlocked } from './transparent-h2-flow.mjs';

export function assertGoaways(events, lastAcceptedID) {
  assert.ok(events.length > 0 && events.length <= 8, 'bounded GOAWAY evidence required');
  let previous = 0x7fffffff;
  for (const event of events) {
    assert.equal(event.code, http2.constants.NGHTTP2_NO_ERROR);
    assert.ok(Number.isInteger(event.lastStreamID) && event.lastStreamID >= lastAcceptedID && event.lastStreamID <= previous,
      'GOAWAY boundary must cover accepted streams and never increase');
    previous = event.lastStreamID;
  }
  // This fixture has no in-flight admission race: all requests reached origin first.
  assert.equal(events.at(-1).lastStreamID, lastAcceptedID);
}

export async function h2GoawayCase({ lab, proxy, tunnel, own, until, concurrency, direction, signal, emit = () => {} }) {
  assert.ok(['forward', 'reverse'].includes(direction));
  const before = { lab: lab.stats(), tunnels: proxy.stats().tunnels };
  const socket = own(tls.connect({ socket: await tunnel(), servername: 'localhost', ca: lab.cert,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['h2'], rejectUnauthorized: true }));
  let session, sessionClosed, writing, draining, drainError, drainDone = false, closed = false;
  let step = 'setup', latestPoint, sessionErrors = 0, goawayOverflow = false;
  const streams = new Set(), events = [];
  function request(path, { upload = false, held = false } = {}) {
    const stream = session.request({ ':method': upload || held ? 'POST' : 'GET', ':path': path,
      ...(upload ? { 'content-length': String(H2_BYTES) } : {}) });
    streams.add(stream); stream.once('close', () => streams.delete(stream));
    stream.on('error', () => {});
    const result = { ended: false, status: undefined, bytes: 0, text: '', errors: 0 };
    const hash = createHash('sha256'), textResponse = upload || held;
    stream.on('response', (headers) => { result.status = headers[':status']; });
    stream.on('error', () => { result.errors++; });
    stream.on('data', (chunk) => {
      result.bytes += chunk.length;
      if (result.bytes > (textResponse ? 1024 : H2_BYTES)) { stream.destroy(); return; }
      hash.update(chunk); if (textResponse) result.text += chunk.toString();
    });
    stream.once('end', () => { result.ended = true; });
    const response = new Promise((resolve) => stream.once('close', () => resolve({ ...result,
      sha256: hash.digest('hex'), rstCode: stream.rstCode })));
    if (held) stream.end('one admitted POST');
    else if (!upload) { stream.pause(); stream.end(); }
    return { stream, response, result };
  }
  const assertNoReplay = () => {
    assert.equal(lab.stats().requests - before.lab.requests, concurrency + 1);
    assert.equal(lab.stats().originConnections - before.lab.originConnections, 1);
    assert.equal(lab.stats().tlsConnections - before.lab.tlsConnections, 1);
    assert.equal(proxy.stats().tunnels - before.tunnels, 1);
  };
  const assertResponse = (result) => {
    assert.equal(result.ended, true); assert.equal(result.status, 200);
    assert.equal(result.errors, 0); assert.equal(result.rstCode, 0);
  };
  try {
    await once(socket, 'secureConnect');
    assert.equal(socket.authorized, true); assert.equal(socket.alpnProtocol, 'h2'); assert.equal(socket.getProtocol(), 'TLSv1.3');
    session = http2.connect(`https://localhost:${lab.originPort}`, { createConnection: () => socket });
    session.on('error', () => { sessionErrors++; });
    session.on('goaway', (code, lastStreamID) => {
      if (events.length < 8) events.push({ code, lastStreamID }); else goawayOverflow = true;
    });
    sessionClosed = new Promise((resolve) => session.once('close', () => { closed = true; resolve(); }));
    await once(session, 'connect');
    const upload = direction === 'forward';
    const slow = request(upload ? '/h2-flow-upload' : '/h2-flow-download', { upload });
    let writeFailed = false;
    if (upload) writing = writeH2Body(slow.stream).catch(() => { writeFailed = true; });
    const sample = () => {
      const origin = lab.h2FlowSnapshots().find((s) => s.id === slow.stream.id);
      latestPoint = upload ? { localWindow: origin?.localWindow, needDrain: slow.stream.writableNeedDrain,
        connectionWindow: session.state.remoteWindowSize }
        : { localWindow: slow.stream.state.localWindowSize, needDrain: origin?.needDrain, connectionWindow: origin?.connectionWindow };
      return latestPoint;
    };
    step = 'blocked'; await waitFlowBlocked(until, sample);
    const held = Array.from({ length: concurrency }, () => request('/hold', { held: true }));
    await until(() => lab.stats().heldResponses === concurrency);
    await waitFlowBlocked(until, sample);
    const lastAcceptedID = Math.max(slow.stream.id, ...held.map((item) => item.stream.id));
    assertNoReplay();
    step = 'goaway';
    // Observe rejection immediately, even if a later assertion fails first.
    draining = lab.drainOriginHttp2().then(() => { drainDone = true; }, (error) => { drainError = error; });
    await until(() => events.length > 0);
    assertGoaways(events, lastAcceptedID);
    assert.equal(session.closed, true); assert.equal(session.destroyed, false);
    assert.equal(lab.stats().h2DrainTimers, 1);
    step = 'new-request-refused';
    assert.throws(() => {
      const unexpected = session.request({ ':method': 'POST', ':path': '/must-not-replay' });
      unexpected.on('error', () => {}); unexpected.destroy();
    }, { code: 'ERR_HTTP2_GOAWAY_SESSION' });
    // A real observation interval with active streams, not just flags in the GOAWAY callback.
    emit({ type: 'h2-goaway', direction, phase: 'draining' });
    await delay(100, undefined, { signal });
    await waitFlowBlocked(until, sample);
    assert.equal(closed || drainDone || Boolean(drainError), false);
    assert.equal(lab.stats().heldResponses, concurrency); assert.equal(lab.stats().h2Sessions, 1);
    assert.equal(slow.result.ended, false);
    for (const item of held) assert.equal(item.result.ended, false);
    assertNoReplay();
    step = 'release'; lab.releaseHeldResponses();
    if (upload) lab.resumeH2Uploads(); else slow.stream.resume();
    const received = await slow.response;
    await writing; writing = undefined;
    assert.equal(writeFailed, false); assertResponse(received);
    if (upload) assert.deepEqual(JSON.parse(received.text), { bytes: H2_BYTES, sha256: H2_HASH });
    else { assert.equal(received.bytes, H2_BYTES); assert.equal(received.sha256, H2_HASH); }
    for (const item of held) { const response = await item.response; assertResponse(response); assert.equal(response.text, 'released'); }
    step = 'natural-close';
    // No destroy/close by the workload on the success path before both endpoints close.
    await until(() => closed && (drainDone || Boolean(drainError)));
    if (drainError) throw drainError;
    assert.equal(drainDone, true); assert.equal(streams.size, 0); assert.equal(sessionErrors, 0);
    assert.equal(goawayOverflow, false); assertGoaways(events, lastAcceptedID); assertNoReplay();
    assert.equal(lab.stats().h2FlowDeadlines, before.lab.h2FlowDeadlines);
    assert.equal(lab.stats().h2FlowCancels, before.lab.h2FlowCancels);
    assert.equal(lab.stats().h2DrainTimers + lab.stats().h2Sessions + lab.stats().heldResponses + lab.stats().h2FlowStreams, 0);
    assert.equal(lab.runtimeErrors.length, 0);
    return { cases: 1, bytes: H2_BYTES, heldSurvived: concurrency, refused: 1, tlsConnections: 1,
      naturalCloses: 1, goaways: events.length, lastAcceptedID, lastStreamID: events.at(-1).lastStreamID };
  } catch (error) {
    error.h2Goaway = { direction, step, point: latestPoint, events, drainDone, closed,
      ...(typeof error.actual === 'number' || typeof error.actual === 'boolean' ? { actual: error.actual } : {}),
      ...(typeof error.expected === 'number' || typeof error.expected === 'boolean' ? { expected: error.expected } : {}) };
    throw error;
  } finally {
    for (const stream of streams) stream.destroy();
    session?.destroy(); socket.destroy();
    await writing; await sessionClosed; await draining;
  }
}
