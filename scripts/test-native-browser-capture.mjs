import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http2 from 'node:http2';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { BrowserCapture, helloLayout, validateCaptureMetadata } from './lib/native-browser-capture.mjs';
import { startBrowserCapture } from './lib/native-browser-capture-server.mjs';
import { readCaptureFile } from './clean-vpn-native-browser-capture.mjs';
import { browserOrigin } from './lib/browser-lab-origin.mjs';

const metadata = { schema: 1, id: 'unit-capture', identity: { browser: 'test-fixture', version: '0',
  versionSource: 'operator-declared', platform: 'fixture', architecture: 'fixture' }, context: {
  scenario: 'cold', isolation: 'operator-declared', certificateValidation: 'enabled', http: 'h2', proxy: 'none',
  echMode: 'disabled', extensionOrder: 'permuted', padding: 'optional' } };
const negotiated = { alpn: 'h2', tlsVersion: 'TLSv1.3', sessionReused: false };
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const vector = b => Buffer.concat([u16(b.length), b]);
function wire({ reverse = false, cipher = 4865, signature = 1027, unsupported = false, compression = null, padding = false, fragmented = false } = {}) {
  const ext = (id, bytes) => Buffer.concat([u16(id), vector(bytes)]);
  const name = Buffer.from('secret.capture.invalid');
  let extensions = [ext(0, vector(Buffer.concat([Buffer.from([0]), vector(name)]))),
    ext(10, vector(u16(29))), ext(16, vector(Buffer.from([2, 104, 50]))), ext(13, vector(u16(signature))),
    ext(51, vector(Buffer.concat([u16(29), vector(Buffer.alloc(32, 0x77))]))),
    ext(45, Buffer.from([1, 1])), ext(43, Buffer.from([2, 3, 4])), ext(0x1a1a, Buffer.from([0]))];
  if (reverse) extensions.reverse();
  if (unsupported || compression !== null) extensions.push(ext(27, Buffer.concat([Buffer.from([2]), u16(compression ?? 2)])));
  if (unsupported) extensions.push(ext(50, Buffer.from([0, 2, 4, 3])));
  if (padding) extensions.push(ext(21, Buffer.alloc(7)));
  const body = Buffer.concat([u16(771), Buffer.alloc(32, 0x33), Buffer.from([0]),
    vector(Buffer.concat([u16(0x2a2a), u16(cipher)])), Buffer.from([1, 0]), vector(Buffer.concat(extensions))]);
  const handshake = Buffer.alloc(4); handshake[0] = 1; handshake.writeUIntBE(body.length, 1, 3);
  const full = Buffer.concat([handshake, body]);
  const record = b => Buffer.concat([Buffer.from([22, 3, 1]), vector(b)]);
  return fragmented ? Buffer.concat([record(full.subarray(0, 17)), record(full.subarray(17))]) : record(full);
}

test('capture metadata is explicit, bounded and immutable', () => {
  for (const mutate of [m => m.identity.versionSource = 'guessed-from-ja3', m => m.context.scenario = 'resumed',
    m => m.context.certificateValidation = 'ignored', m => m.identity.version = 'x'.repeat(129),
    m => m.id = '../profile', m => m.context.padding = 'guess', m => m.extra = true]) {
    const m = structuredClone(metadata); mutate(m); assert.throws(() => validateCaptureMetadata(m));
  }
  const m = structuredClone(metadata), c = new BrowserCapture(m);
  m.identity.version = 'changed'; assert.equal(c.snapshot().metadata.identity.version, '0');
});

test('bundle preserves structural differences, filters secrets, limits samples and is not an applied profile', () => {
  const c = new BrowserCapture(metadata, { maxSamples: 3 });
  assert.equal(c.snapshot().assessment.status, 'insufficient-samples');
  c.add(wire(), negotiated); c.add(wire({ reverse: true, fragmented: true }), negotiated);
  assert.equal(c.snapshot().assessment.candidateProfile, null);
  c.add(wire({ padding: true }), negotiated);
  const b = c.snapshot(), { contentSha256, ...content } = b;
  assert.equal(b.assessment.status, 'candidate'); assert.equal(b.assessment.nativeValidated, false);
  assert.equal(b.assessment.browserEquivalent, false); assert.equal(b.assessment.distinctJa3, 3);
  assert.equal(b.samples[1].layout.records.length, 2); assert.deepEqual(b.samples[0].layout.cipherGreaseSlots, [0]);
  assert.ok(b.samples[0].layout.extensions.some(e => e.grease && e.type === null));
  assert.ok(b.samples[2].measurement.actual.extension_types.includes(21));
  assert.equal(contentSha256, createHash('sha256').update(JSON.stringify(content)).digest('hex'));
  assert.doesNotMatch(JSON.stringify(b), /secret\.capture|3333333333333333|7777777777777777|clientHelloBody|ticket_hex/);
  b.samples.length = 0; assert.equal(c.size, 3);
  assert.throws(() => c.add(wire(), negotiated), /sample_limit/);
  assert.throws(() => new BrowserCapture(metadata).add(wire(), { ...negotiated, sessionReused: true }));
});

test('unsupported extensions and inconsistent fields cannot become a candidate', () => {
  const unsupported = new BrowserCapture(metadata), inconsistent = new BrowserCapture(metadata);
  for (let i = 0; i < 3; i++) {
    unsupported.add(wire({ unsupported: true }), negotiated);
    inconsistent.add(wire({ cipher: i === 1 ? 4866 : 4865 }), negotiated);
  }
  const b = unsupported.snapshot(); assert.equal(b.assessment.status, 'unsupported');
  assert.deepEqual(b.assessment.unsupported, ['extension:50']); assert.equal(b.assessment.candidateProfile, null);
  assert.deepEqual(b.samples[0].layout.certificateCompression, [2]);
  const signatures = new BrowserCapture(metadata); signatures.add(wire({ signature: 0x0904 }), negotiated);
  assert.deepEqual(signatures.snapshot().assessment.unsupported, ['signature:2308']);
  assert.equal(inconsistent.snapshot().assessment.status, 'inconsistent');
  assert.deepEqual(inconsistent.snapshot().assessment.variations, ['cipher_suites']);
  const fixed = structuredClone(metadata); fixed.context.extensionOrder = 'fixed';
  const c = new BrowserCapture(fixed); c.add(wire(), negotiated); c.add(wire({ reverse: true }), negotiated);
  assert.ok(c.snapshot().assessment.variations.includes('extension_types'));
});

test('capture carries supported Brotli algorithms and refuses unsupported compression', () => {
  const good = new BrowserCapture(metadata), bad = new BrowserCapture(metadata);
  for (let i = 0; i < 3; i++) {
    good.add(wire({ compression: 2 }), negotiated);
    bad.add(wire({ compression: 1 }), negotiated);
  }
  assert.equal(good.snapshot().assessment.status, 'candidate');
  assert.deepEqual(good.snapshot().assessment.candidateProfile.tls.certificate_compression, [2]);
  assert.equal(bad.snapshot().assessment.status, 'unsupported');
  assert.deepEqual(bad.snapshot().assessment.unsupported, ['certificate-compression-algorithms']);
});

test('bounded parser and file reader refuse truncation, symlinks and oversized inputs', async t => {
  const bytes = wire();
  for (let i = 0; i < bytes.length; i++) assert.throws(() => helloLayout(bytes.subarray(0, i)));
  assert.throws(() => helloLayout(Buffer.alloc(65537)));
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cvpn-capture-file-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  await fs.writeFile(path.join(dir, 'data'), '12345'); await fs.symlink(path.join(dir, 'data'), path.join(dir, 'link'));
  assert.throws(() => readCaptureFile(path.join(dir, 'link'), 10));
  assert.throws(() => readCaptureFile(path.join(dir, 'data'), 4));
  assert.throws(() => readCaptureFile(dir, 10));
  assert.equal(readCaptureFile(path.join(dir, 'data'), 5).toString(), '12345');
});

test('real Chromium baseline preserves all samples, fingerprints and explicit incompatibilities', async () => {
  const report = JSON.parse(await fs.readFile(new URL('../fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47.json', import.meta.url)));
  const { contentSha256, ...content } = report.bundle;
  assert.equal(createHash('sha256').update(JSON.stringify(content)).digest('hex'), contentSha256);
  assert.equal(content.samples.length, 20); assert.equal(content.assessment.status, 'unsupported');
  assert.equal(content.assessment.candidateProfile, null); assert.equal(content.assessment.nativeValidated, false);
  assert.equal(content.metadata.identity.version, 'Chrome/156.0.8078.47');
  assert.equal(report.validation.untrustedCertificateRejected, true);
  for (const sample of content.samples) {
    const m = sample.measurement;
    assert.equal(createHash('md5').update(m.ja3String).digest('hex'), m.ja3);
    const [a, ciphers, ...extensionsAndSigs] = m.ja4.raw_r.split('_');
    const hash = value => createHash('sha256').update(value).digest('hex').slice(0, 12);
    assert.equal(`${a}_${hash(ciphers)}_${hash(extensionsAndSigs.join('_'))}`, m.ja4.fingerprint);
    for (const id of [27, 35, 17613, 51764]) assert.ok(m.actual.extension_types.includes(id));
    for (const id of [2308, 2309, 2310]) assert.ok(sample.unsupported.includes(`signature:${id}`));
    assert.equal(sample.negotiated.sessionReused, false);
  }
  assert.equal(new Set(content.samples.map(s => s.measurement.ja3)).size, 20);
  assert.equal(new Set(content.samples.map(s => s.measurement.ja4.fingerprint)).size, 1);
  assert.doesNotMatch(JSON.stringify(report), /\/Users\/|\/tmp\/|\/capture\/|BEGIN.*KEY|clientHelloBody|ticket_hex/);
});

async function setup(t, options = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cvpn-capture-server-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const origin = await browserOrigin(dir);
  const server = await startBrowserCapture({ ...origin.originTls, metadata, ...options });
  t.after(() => server.close());
  return { server, ca: await fs.readFile(origin.caPath) };
}
async function connect(t, server, ca) {
  const u = new URL(server.url);
  const session = http2.connect(`https://127.0.0.1:${u.port}`, { servername: 'localhost', ca });
  t.after(() => session.destroy());
  await once(session, 'connect');
  return session;
}
async function request(session, url, headers = {}) {
  const u = new URL(url), req = session.request({ ':path': u.pathname, ':authority': u.host, ...headers });
  let body = '', response; req.on('response', h => response = h);
  req.on('data', b => { body += b; if (body.length > 1048576) req.destroy(Error('test_response_limit')); });
  req.end(); await once(req, 'end'); return { status: response[':status'], headers: response, body };
}
test('real TLS/H2 capture binds token and authority, deduplicates connections and exports exact bundle', { timeout: 15000 }, async t => {
  const { server, ca } = await setup(t, { maxSamples: 3 });
  const u = new URL(server.url), rejected = http2.connect(`https://127.0.0.1:${u.port}`, { servername: 'localhost' });
  await assert.rejects(once(rejected, 'connect'), /certificate/i); rejected.destroy();
  assert.equal(server.snapshot().samples.length, 0);
  const session = await connect(t, server, ca);
  for (const headers of [{ ':authority': 'wrong.localhost' }, { ':path': '/capture/wrong' },
    { ':method': 'POST' }, { origin: 'https://elsewhere.invalid' }]) {
    assert.equal((await request(session, server.url, headers)).status, 404);
    assert.equal(server.snapshot().samples.length, 0);
  }
  assert.equal((await request(session, server.url)).status, 200);
  assert.equal((await request(session, server.url)).status, 200); assert.equal(server.snapshot().samples.length, 1);
  const download = await request(session, server.bundleUrl);
  assert.equal(download.headers['cache-control'], 'no-store');
  assert.deepEqual(JSON.parse(download.body), server.snapshot());
  for (let i = 0; i < 2; i++) assert.equal((await request(await connect(t, server, ca), server.url)).status, 200);
  assert.equal((await request(await connect(t, server, ca), server.url)).status, 429);
  assert.equal(server.snapshot().samples.length, 3);
});

test('capture expiry closes pending partial TLS connections and releases listeners', { timeout: 5000 }, async t => {
  const { server } = await setup(t, { lifetimeMs: 1000 });
  const socket = net.connect(Number(new URL(server.url).port), '127.0.0.1');
  t.after(() => socket.destroy()); await once(socket, 'connect'); socket.write(Buffer.from([22, 3]));
  await once(socket, 'close'); await server.close();
  assert.equal(server.snapshot().samples.length, 0);
});
