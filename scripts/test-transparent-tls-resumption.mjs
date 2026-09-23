/** Real ticket-based TLS resumption, never early data or certificate bypass. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import tls from 'node:tls';
import http2 from 'node:http2';
import { once } from 'node:events';
import test from 'node:test';
import { startTransparentTlsLab, requestThroughLab, assertRelayTrace } from './lib/transparent-tls-lab.mjs';

const TEST_OPTS = { timeout: 15_000 };
async function labFor(t, options = {}) {
  const lab = await startTransparentTlsLab({ sessionTimeoutMs: 0, ...options });
  t.after(async () => {
    await lab.close();
    assert.equal(lab.stats().sockets, 0);
  });
  return lab;
}

test('lab GOAWAY drains persistent HTTP/2 without closing listeners or discarding tickets', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const socket = tls.connect({ host: lab.host, port: lab.clientPort, servername: lab.originName,
    ca: lab.cert, ALPNProtocols: ['h2'], minVersion: 'TLSv1.3' });
  t.after(() => socket.destroy());
  const ticket = once(socket, 'session');
  const session = http2.connect(`https://localhost:${lab.originPort}`, { createConnection: () => socket });
  session.on('error', () => {});
  t.after(() => session.destroy());
  const req = session.request({ ':path': '/' });
  const data = []; req.on('data', (chunk) => data.push(chunk));
  const ended = once(req, 'end'); req.end(); await ended;
  assert.equal(JSON.parse(Buffer.concat(data)).sessionReused, false);
  const [state] = await ticket;
  const goaway = once(session, 'goaway'), closed = once(session, 'close');
  await lab.drainOriginHttp2();
  await goaway; await closed;
  // Idempotent when there are no active sessions; no new HTTP endpoint was added.
  await lab.drainOriginHttp2();
  const resumed = await requestThroughLab(lab, { httpVersion: '2', tlsOptions: { session: state } });
  assert.equal(resumed.sessionReused, true);
  assert.equal(lab.stats().tlsConnections, 2);
  assert.equal(lab.stats().resumedTlsConnections, 1);
});

test('lab GOAWAY control has a deadline for an unfinished HTTP/2 request', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const socket = tls.connect({ host: lab.host, port: lab.clientPort, servername: lab.originName,
    ca: lab.cert, ALPNProtocols: ['h2'] });
  socket.on('error', () => {});
  t.after(() => socket.destroy());
  const session = http2.connect(`https://localhost:${lab.originPort}`, { createConnection: () => socket });
  session.on('error', () => {});
  t.after(() => session.destroy());
  const req = session.request({ ':path': '/echo', ':method': 'POST' });
  req.on('error', () => {}); req.write('unfinished');
  const deadline = Date.now() + 2000;
  while (lab.stats().requests !== 1) {
    if (Date.now() > deadline) throw new Error('origin request observation deadline');
    await new Promise((resolve) => setImmediate(resolve));
  }
  await assert.rejects(lab.drainOriginHttp2(), { name: 'AbortError' });
  assert.equal(lab.stats().h2DrainTimers, 0, 'expired drain deadline must release its timer');
  assert.equal(session.destroyed, false, 'deadline is a reported failure, not a forced successful close');
});

for (const httpVersion of ['1.1', '2']) {
  test(`TLS 1.2 HTTP/${httpVersion}: ticket resumption also preserves the raw relay path`, TEST_OPTS, async (t) => {
    const lab = await labFor(t);
    const tlsOptions = { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' };
    const first = await requestThroughLab(lab, { httpVersion, tlsOptions, captureSession: true });
    const second = await requestThroughLab(lab, {
      httpVersion, tlsOptions: { ...tlsOptions, session: requireTicket(first) },
    });
    assert.equal(first.sessionReused, false);
    assert.equal(second.tlsVersion, 'TLSv1.2');
    assert.equal(second.sessionReused, true);
    assert.equal(JSON.parse(second.body).sessionReused, true);
    assert.equal(lab.stats().resumedTlsConnections, 1);
    assertRelayTrace(lab, second.clientHelloId);
    const client = lab.captures.find((c) => c.stage === 'client' && c.id === second.clientHelloId);
    const ext = extensions(client.body);
    assert.ok(ext.get(35)?.length > 0, 'session_ticket is offered on the wire');
    assert.equal(ext.has(41), false, 'TLS 1.2 ticket is not a TLS 1.3 PSK extension');
  });
}

for (const failure of ['untrusted CA', 'wrong hostname']) {
  test(`rejected ticket fallback does not bypass ${failure} validation`, TEST_OPTS, async (t) => {
    const lab = await labFor(t);
    const first = await requestThroughLab(lab, { captureSession: true });
    lab.rotateTicketKeys();
    const options = failure === 'untrusted CA' ? { ca: [] } : {
      tlsOptions: { checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity('wrong.invalid', cert) },
    };
    await assert.rejects(requestThroughLab(lab, {
      ...options, tlsOptions: { ...options.tlsOptions, session: requireTicket(first) },
    }), failure === 'untrusted CA' ? /self.signed|issuer|verify/i : /hostname|altnames/i);
    assert.equal(lab.stats().requests, 1, 'failed fallback never sends HTTP');
    assert.equal(lab.stats().resumedTlsConnections, 0);
    const attempted = lab.captures.findLast((c) => c.stage === 'client');
    assert.notEqual(attempted.id, first.clientHelloId);
    assertPskTrace(lab, attempted.id);
  });
}

test('parallel ticket sessions remain independently matched and really resume', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const versions = ['1.1', '2', '1.1', '2'];
  const cold = await Promise.all(versions.map((httpVersion) =>
    requestThroughLab(lab, { httpVersion, captureSession: true })));
  assert.ok(cold.every((result) => result.sessionReused === false));
  const resumed = await Promise.all(cold.map((first, i) => requestThroughLab(lab, {
    httpVersion: versions[i], tlsOptions: { session: requireTicket(first) },
    path: '/echo', body: Buffer.alloc(64 * 1024, i),
  })));
  for (let i = 0; i < resumed.length; i++) {
    assert.equal(resumed[i].sessionReused, true);
    assert.deepEqual(resumed[i].body, Buffer.alloc(64 * 1024, i));
    assertPskTrace(lab, resumed[i].clientHelloId);
  }
  assert.equal(new Set([...cold, ...resumed].map((r) => r.clientHelloId)).size, 8);
  assert.equal(lab.stats().originConnections, 8);
  assert.equal(lab.stats().resumedTlsConnections, 4);
});

test('resumable session state is opt-in, bounded and absent from JSON results', TEST_OPTS, async (t) => {
  const lab = await labFor(t);
  const ordinary = await requestThroughLab(lab);
  assert.equal(Object.hasOwn(ordinary, 'session'), false);
  const captured = await requestThroughLab(lab, { captureSession: true });
  const state = requireTicket(captured);
  assert.ok(state.length <= 64 * 1024);
  assert.equal(Object.getOwnPropertyDescriptor(captured, 'session').enumerable, false);
  assert.equal(Object.hasOwn(JSON.parse(JSON.stringify(captured)), 'session'), false);
  // The caller can still use the explicitly requested in-memory state.
  assert.equal((await requestThroughLab(lab, { tlsOptions: { session: state } })).sessionReused, true);
  await lab.close();
  assert.throws(() => lab.rotateTicketKeys(), /closing/);
  assert.throws(() => lab.setOriginGroups('P-256'), /closing/);
  await assert.rejects(lab.drainOriginHttp2(), /closing/);
});

function requireTicket(response) {
  assert.match(response.clientHelloId, /^[0-9a-f]{64}$/);
  assert.ok(Buffer.isBuffer(response.session) && response.session.length > 0,
    'a real session event must supply resumable state');
  return response.session;
}

/** Inspect the actual captured extension bytes, not a synthesized profile. */
function extensions(body) {
  let at = 34;
  at += 1 + body[at];
  at += 2 + body.readUInt16BE(at);
  at += 1 + body[at];
  const end = at + 2 + body.readUInt16BE(at);
  at += 2;
  assert.equal(end, body.length);
  const result = new Map();
  while (at < end) {
    assert.ok(at + 4 <= end);
    const type = body.readUInt16BE(at);
    const size = body.readUInt16BE(at + 2);
    at += 4;
    assert.ok(at + size <= end && !result.has(type));
    result.set(type, body.subarray(at, at + size));
    at += size;
  }
  return result;
}

function pskFields(bytes) {
  assert.ok(bytes && bytes.length >= 2, 'offered pre_shared_key extension');
  const identitiesEnd = 2 + bytes.readUInt16BE(0);
  assert.ok(identitiesEnd + 2 <= bytes.length);
  const identities = [];
  for (let at = 2; at < identitiesEnd;) {
    assert.ok(at + 2 <= identitiesEnd);
    const size = bytes.readUInt16BE(at);
    at += 2;
    assert.ok(size > 0 && at + size + 4 <= identitiesEnd);
    identities.push(bytes.subarray(at, at + size));
    at += size + 4; // skip obfuscated ticket age
  }
  const binders = [];
  let at = identitiesEnd + 2;
  assert.equal(at + bytes.readUInt16BE(identitiesEnd), bytes.length);
  while (at < bytes.length) {
    const size = bytes[at++];
    assert.ok(size >= 32 && at + size <= bytes.length);
    binders.push(bytes.subarray(at, at + size));
    at += size;
  }
  assert.ok(identities.length > 0);
  assert.equal(binders.length, identities.length);
  return { identities, binders };
}

function assertPskTrace(lab, id, flight = 1) {
  assert.match(id, /^[0-9a-f]{64}$/);
  assertRelayTrace(lab, id, flight);
  const captures = ['client', 'exit', 'origin'].map((stage) =>
    lab.captures.find((c) => c.stage === stage && c.id === id && c.flight === flight));
  const ext = captures.map((capture) => extensions(capture.body));
  for (const entry of ext) {
    assert.equal(entry.has(42), false, 'no early_data in this test');
    assert.equal([...entry.keys()].at(-1), 41, 'PSK remains the last extension');
    assert.ok(entry.get(41).equals(ext[0].get(41)), 'PSK identities and binders are not rewritten');
  }
  return pskFields(ext[0].get(41));
}

for (const httpVersion of ['1.1', '2']) {
  test(`TLS 1.3 HTTP/${httpVersion}: a new TCP connection really resumes a ticket session`, TEST_OPTS, async (t) => {
    const lab = await labFor(t);
    const first = await requestThroughLab(lab, { httpVersion, captureSession: true });
    assert.equal(first.sessionReused, false);
    const session = requireTicket(first);
    const body = randomBytes(128 * 1024);
    const second = await requestThroughLab(lab, { httpVersion, path: '/echo', body, tlsOptions: { session } });
    assert.equal(second.sessionReused, true, 'not a successful full-handshake fallback');
    assert.deepEqual(second.body, body);
    assert.notEqual(first.clientHelloId, second.clientHelloId);
    assert.equal(lab.stats().originConnections, 2);
    assert.equal(lab.stats().resumedTlsConnections, 1, 'origin also confirms resumption');
    assertRelayTrace(lab, first.clientHelloId);
    assertPskTrace(lab, second.clientHelloId);
    const cold = lab.captures.find((c) => c.stage === 'client' && c.id === first.clientHelloId);
    assert.equal(extensions(cold.body).has(41), false);
  });

  test(`TLS 1.3 HTTP/${httpVersion}: rejected ticket falls back and issues a usable replacement`, TEST_OPTS, async (t) => {
    const lab = await labFor(t);
    const first = await requestThroughLab(lab, { httpVersion, captureSession: true });
    const oldSession = requireTicket(first);
    lab.rotateTicketKeys();
    const fallback = await requestThroughLab(lab, {
      httpVersion, captureSession: true, tlsOptions: { session: oldSession },
    });
    assert.equal(fallback.sessionReused, false);
    assert.equal(JSON.parse(fallback.body).sessionReused, false);
    assert.equal(lab.stats().resumedTlsConnections, 0);
    assertPskTrace(lab, fallback.clientHelloId); // client really offered the rejected ticket
    const resumed = await requestThroughLab(lab, {
      httpVersion, tlsOptions: { session: requireTicket(fallback) },
    });
    assert.equal(resumed.sessionReused, true);
    assert.equal(JSON.parse(resumed.body).sessionReused, true);
    assert.equal(lab.stats().originConnections, 3);
    assert.equal(lab.stats().resumedTlsConnections, 1);
    assertPskTrace(lab, resumed.clientHelloId);
  });

  test(`TLS 1.3 HTTP/${httpVersion}: resumed PSK handshake survives HRR with intact CH2 binder`, TEST_OPTS, async (t) => {
    const lab = await labFor(t, { originTls: { ecdhCurve: 'X25519', ciphers: 'TLS_AES_128_GCM_SHA256' } });
    const tlsOptions = { ecdhCurve: 'X25519:P-256', ciphers: 'TLS_AES_128_GCM_SHA256' };
    const first = await requestThroughLab(lab, { httpVersion, tlsOptions, captureSession: true });
    assert.equal(first.sessionReused, false);
    lab.setOriginGroups('P-256'); // retain ticket keys, force a new key share via HRR
    const second = await requestThroughLab(lab, {
      httpVersion, tlsOptions: { ...tlsOptions, session: requireTicket(first) },
    });
    assert.equal(second.sessionReused, true, 'HRR must not silently turn this into a full handshake');
    assert.equal(JSON.parse(second.body).sessionReused, true);
    const flights = lab.captures.filter((c) => c.stage === 'client' && c.id === second.clientHelloId);
    assert.equal(flights.length, 2, 'a real HRR produced CH2');
    const one = assertPskTrace(lab, second.clientHelloId, 1);
    const two = assertPskTrace(lab, second.clientHelloId, 2);
    assert.ok(one.identities[0].equals(two.identities[0]), 'same ticket in both hellos');
    assert.ok(!one.binders[0].equals(two.binders[0]), 'TLS client recomputed the binder for the HRR transcript');
    const wire = lab.captures.filter((c) => c.stage === 'exit' && c.id === second.clientHelloId);
    assert.equal(wire[0].sni, wire[1].sni);
    assert.ok(!wire[1].prefix.includes(Buffer.from(lab.originName)));
    assert.equal(lab.stats().originConnections, 2);
    assert.equal(lab.stats().resumedTlsConnections, 1);
  });
}
