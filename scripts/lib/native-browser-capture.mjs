/** Measurement bundles are evidence, never executable browser profiles. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compileTlsProfileCandidate } from './native-tls-profile-observer.mjs';
import { parseFirstTlsClientHelloFromTcpBuf, TLS_GREASE_VALUES } from './tls-clienthello-ja3.mjs';

const exact = (value, keys) => assert.ok(value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'capture_fields');
export function validateCaptureMetadata(metadata) {
  exact(metadata, ['schema', 'id', 'identity', 'context']);
  assert.equal(metadata.schema, 1);
  assert.match(metadata.id, /^[A-Za-z0-9_.-]{1,64}$/);
  exact(metadata.identity, ['browser', 'version', 'versionSource', 'platform', 'architecture']);
  for (const value of Object.values(metadata.identity)) assert.ok(typeof value === 'string' && /^[\x20-\x7e]{1,128}$/.test(value), 'identity_text');
  assert.ok(['operator-declared', 'browser-protocol'].includes(metadata.identity.versionSource));
  const c = metadata.context;
  exact(c, ['scenario', 'isolation', 'certificateValidation', 'http', 'proxy', 'echMode', 'extensionOrder', 'padding']);
  assert.equal(c.scenario, 'cold');
  assert.ok(['operator-declared', 'fresh-process-per-sample'].includes(c.isolation));
  assert.equal(c.certificateValidation, 'enabled');
  assert.equal(c.http, 'h2');
  assert.equal(c.proxy, 'none');
  assert.ok(['disabled', 'grease'].includes(c.echMode));
  assert.ok(['fixed', 'permuted'].includes(c.extensionOrder));
  assert.ok(['exact', 'optional'].includes(c.padding));
  return structuredClone(metadata);
}

// Preserve structural facts JA hashes omit. Never export extension payloads,
// random, SNI text, key-share bytes, session ID bytes or PSK binders.
export function helloLayout(wire) {
  assert.ok(wire.length <= 65536);
  const hello = parseFirstTlsClientHelloFromTcpBuf(wire);
  assert.equal(hello.ok, true, 'complete_clienthello_required');
  const b = hello.clientHelloBody;
  let offset = 35 + b[34], length = b.readUInt16BE(offset); offset += 2;
  const cipherGreaseSlots = [];
  for (let i = 0; i < length / 2; i++) if (TLS_GREASE_VALUES.has(b.readUInt16BE(offset + 2 * i))) cipherGreaseSlots.push(i);
  offset += length; offset += 1 + b[offset];
  const end = offset + 2 + b.readUInt16BE(offset); offset += 2;
  const extensions = [], certificateCompression = [];
  while (offset < end) {
    const type = b.readUInt16BE(offset), size = b.readUInt16BE(offset + 2); offset += 4;
    assert.ok(offset + size <= end);
    const grease = TLS_GREASE_VALUES.has(type);
    extensions.push({ type: grease ? null : type, grease, bytes: size });
    if (type === 27) {
      assert.ok(size >= 1 && b[offset] === size - 1 && (size - 1) % 2 === 0, 'compression_vector');
      for (let p = offset + 1; p < offset + size; p += 2) certificateCompression.push(b.readUInt16BE(p));
    }
    offset += size;
  }
  assert.equal(offset, end);
  const records = [];
  for (let p = 0; p < hello.bytesConsumed;) {
    const bytes = wire.readUInt16BE(p + 3);
    records.push({ type: wire[p], version: wire.readUInt16BE(p + 1), bytes }); p += 5 + bytes;
  }
  return { records, clientHelloBytes: b.length + 4, cipherGreaseSlots, extensions, certificateCompression };
}

export class BrowserCapture {
  #metadata; #samples = [];
  constructor(metadata, { maxSamples = 32 } = {}) {
    this.#metadata = validateCaptureMetadata(metadata);
    assert.ok(Number.isInteger(maxSamples) && maxSamples >= 3 && maxSamples <= 32);
    this.maxSamples = maxSamples;
  }
  get size() { return this.#samples.length; }
  add(wire, { alpn, tlsVersion, sessionReused }) {
    assert.ok(this.size < this.maxSamples, 'sample_limit');
    assert.equal(alpn, 'h2'); assert.equal(tlsVersion, 'TLSv1.3'); assert.equal(sessionReused, false);
    const c = this.#metadata.context;
    const candidate = compileTlsProfileCandidate(wire, { id: this.#metadata.id, ...c });
    const sample = { index: this.size + 1, observedAt: new Date().toISOString(),
      negotiated: { alpn, tlsVersion, sessionReused }, measurement: candidate.measurement,
      layout: helloLayout(wire), candidateStatus: candidate.status, unsupported: candidate.unsupported };
    this.#samples.push({ sample, profile: candidate.profile });
    return structuredClone(sample);
  }
  snapshot() {
    const c = this.#metadata.context, samples = this.#samples.map(x => x.sample);
    const unsupported = [...new Set(samples.flatMap(s => s.unsupported))].sort();
    const variations = [];
    for (const field of ['cipher_suites', 'supported_groups', 'key_share_groups', 'signature_algorithms', 'alpn', 'supported_versions', 'extension_types', 'grease', 'certificate_compression']) {
      const values = samples.map(s => {
        let value = s.measurement.actual[field];
        if (field === 'extension_types') {
          value = value.filter(n => c.padding !== 'optional' || n !== 21);
          if (c.extensionOrder === 'permuted') value = [...value].sort((a, b) => a - b);
        }
        return JSON.stringify(value);
      });
      if (new Set(values).size > 1) variations.push(field);
    }
    const status = unsupported.length ? 'unsupported' : variations.length ? 'inconsistent'
      : samples.length < 3 ? 'insufficient-samples' : 'candidate';
    const candidateProfile = status === 'candidate' ? this.#samples[0].profile : null;
    const content = { schema: 1, kind: 'clean-vpn-browser-capture-bundle', metadata: this.#metadata,
      samples, assessment: { status, sampleCount: samples.length, unsupported, variations,
        distinctJa3: new Set(samples.map(s => s.measurement.ja3)).size,
        distinctJa4: new Set(samples.map(s => s.measurement.ja4.fingerprint)).size,
        candidateProfile, nativeValidated: false, browserEquivalent: false },
      limitations: ['metadata-is-declared-not-attested', 'cold-first-ClientHello-only',
        'no-HTTP2-frame-or-HTTP-header-fidelity', 'three-samples-is-only-a-minimum-not-statistical-proof',
        'candidate-requires-native-check-config-and-independent-wire-comparison'] };
    // Integrity checksum of this JSON serialization, not publisher authentication.
    return structuredClone({ ...content, contentSha256: createHash('sha256').update(JSON.stringify(content)).digest('hex') });
  }
}
