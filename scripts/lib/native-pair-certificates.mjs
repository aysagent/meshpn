/** Public certificate evidence and bounded offline chain verification. */
import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');

export function certificateEvidence(bytes) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);
  const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  assert.ok(pems.length > 0 && pems.length <= 32, 'bounded PEM certificate bundle required');
  return pems.map(pem => {
    const cert = new X509Certificate(pem);
    return { der: cert.raw.toString('base64'), sha256: hash(cert.raw), fingerprint256: cert.fingerprint256,
      subject: cert.subject, issuer: cert.issuer, ca: cert.ca, validFrom: cert.validFrom, validTo: cert.validTo };
  });
}

function material(item) {
  assert.ok(item && typeof item === 'object' && /^[A-Za-z0-9+/]+={0,2}$/.test(item.der ?? ''), 'invalid certificate evidence');
  const raw = Buffer.from(item.der, 'base64');
  assert.ok(raw.length > 0 && raw.length <= 1024 * 1024 && raw.toString('base64') === item.der, 'invalid certificate DER');
  const cert = new X509Certificate(raw);
  assert.equal(hash(cert.raw), item.sha256, 'certificate evidence hash mismatch');
  return cert;
}

function validAt(cert, now) {
  const from = Date.parse(cert.validFrom), to = Date.parse(cert.validTo);
  return Number.isFinite(from) && Number.isFinite(to) && from <= now && now <= to;
}

export function verifyCertificatePair({ serverName, exitChain, clientTrust, now = Date.now() }) {
  try {
    assert.match(serverName ?? '', /^(?=.{1,253}$)[A-Za-z0-9.-]+$/, 'invalid server name');
    assert.ok(Array.isArray(exitChain) && exitChain.length > 0 && exitChain.length <= 16, 'invalid exit chain');
    assert.ok(Array.isArray(clientTrust) && clientTrust.length > 0 && clientTrust.length <= 32, 'invalid client trust');
    const chain = exitChain.map(material), trust = clientTrust.map(material), leaf = chain[0];
    assert.ok(leaf.checkHost(serverName, { subject: 'default' }), 'server name mismatch');
    assert.ok(validAt(leaf, now), 'leaf validity mismatch');
    const trusted = new Set(trust.map(cert => cert.fingerprint256));
    const candidates = [...chain.slice(1), ...trust];
    let current = leaf; const path = [leaf.fingerprint256];
    for (let depth = 0; depth < 16; depth++) {
      if (trusted.has(current.fingerprint256)) return { status: 'verified', serverName,
        leafSha256: hash(leaf.raw), trustAnchorSha256: hash(current.raw), depth, path };
      const issuer = candidates.find(cert => !path.includes(cert.fingerprint256) && cert.subject === current.issuer
        && cert.ca === true && validAt(cert, now) && current.verify(cert.publicKey));
      assert.ok(issuer, 'trusted issuer not found');
      current = issuer; path.push(current.fingerprint256);
    }
    throw Error('certificate path too deep');
  } catch (error) {
    return { status: 'failed', reason: /^[a-zA-Z0-9 _-]{1,100}$/.test(error?.message ?? '')
      ? error.message.replaceAll(' ', '-') : 'certificate-verification-failed' };
  }
}
