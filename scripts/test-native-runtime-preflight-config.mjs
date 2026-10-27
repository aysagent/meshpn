import test from 'node:test';
import assert from 'node:assert/strict';
import { validatePreflightConfig } from './lib/native-runtime-preflight-config.mjs';

const client = { version: 1, role: 'client', address: '192.0.2.1', port: 443, tun: 'tun0', dns: true };
test('existing host inventory accepts an existing TUN without generating a network plan', () => {
  assert.equal(validatePreflightConfig(client, 'existing-host'), null);
  assert.equal(validatePreflightConfig({ ...client, role: 'exit' }, 'existing-host'), null);
});
test('default runtime ownership constraints remain strict', () => {
  assert.throws(() => validatePreflightConfig(client), /runtime_owns_cvpn0/);
  assert.equal(validatePreflightConfig({ ...client, tun: 'cvpn0' }).tun, 'cvpn0');
});
test('inventory scope rejects other transports and malformed summaries', () => {
  for (const change of [{ transport: 'combo-tls' }, { role: 'unknown' }, { port: 0 },
    { address: 'example.net' }, { tun: '../tun0' }, { version: 2 }]) {
    assert.throws(() => validatePreflightConfig({ ...client, ...change }, 'existing-host'));
  }
  assert.throws(() => validatePreflightConfig(client, 'auto'));
});
