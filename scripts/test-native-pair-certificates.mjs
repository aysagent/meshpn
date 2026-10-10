import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { certificateEvidence, verifyCertificatePair } from './lib/native-pair-certificates.mjs';

const cert = fs.readFileSync(new URL('./fixtures/boring-tls-local.cert.pem', import.meta.url));

test('public certificate evidence is bounded and internally hashed', () => {
  const evidence = certificateEvidence(cert);
  assert.equal(evidence.length, 1); assert.equal(evidence[0].ca, true);
  assert.match(evidence[0].der, /^[A-Za-z0-9+/]+={0,2}$/); assert.match(evidence[0].sha256, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(evidence).includes('PRIVATE KEY'), false);
});

test('directly trusted certificate verifies name, time and DER', () => {
  const evidence = certificateEvidence(cert), now = Date.parse('2026-10-11T12:00:00Z');
  const result = verifyCertificatePair({ serverName: 'localhost', exitChain: evidence, clientTrust: evidence, now });
  assert.equal(result.status, 'verified'); assert.equal(result.depth, 0);
  for (const bad of [
    { serverName: 'wrong.example', exitChain: evidence, clientTrust: evidence, now },
    { serverName: 'localhost', exitChain: evidence, clientTrust: evidence, now: Date.parse('2040-01-01T00:00:00Z') },
    { serverName: 'localhost', exitChain: evidence, clientTrust: [{ ...evidence[0], sha256: '00'.repeat(32) }], now },
  ]) assert.equal(verifyCertificatePair(bad).status, 'failed');
});

test('malformed and untrusted evidence fails closed', () => {
  const evidence = certificateEvidence(cert), now = Date.parse('2026-10-11T12:00:00Z');
  assert.equal(verifyCertificatePair({ serverName: 'localhost', exitChain: evidence, clientTrust: [], now }).status, 'failed');
  assert.equal(verifyCertificatePair({ serverName: 'localhost', exitChain: [{ ...evidence[0], der: 'AAAA' }], clientTrust: evidence, now }).status, 'failed');
});
