import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseRuntimeConfig, createRuntimeConfig } from './clean-vpn-native-runtime-config.mjs';
const base = fs.realpathSync(os.tmpdir());
const args = dir => ['create', '--directory=' + dir, '--mode=container', '--endpoint=192.0.2.10', '--exit-address=172.30.77.2', '--server-name=runtime.test', '--clients=2'];
test('offline bundle isolates credentials, verifies server identity and refuses overwrites', () => {
  const root = fs.mkdtempSync(path.join(base, 'native-config-test-'));
  try {
    const dir = path.join(root, 'bundle'), options = parseRuntimeConfig(args(dir));
    createRuntimeConfig(options);
    const get = f => fs.readFileSync(path.join(dir, f));
    const c = JSON.parse(get('client-1/engine.json')), exit = JSON.parse(get('exit/engine.json'));
    assert.equal(c.ca, '/config/ca.pem'); assert.equal(c.peer_ipv4, '10.99.0.2');
    assert.equal(exit.peers.length, 2); assert.equal(exit.peers[1].ipv4, '10.99.0.3');
    assert.deepEqual(get('client-1/psk'), get('exit/peer-1.psk')); assert.equal(get('client-1/psk').length, 32);
    assert.notDeepEqual(get('client-1/psk'), get('client-2/psk'));
    assert.deepEqual(fs.readdirSync(path.join(dir, 'client-1')).sort(), ['ca.pem', 'engine.json', 'profile.json', 'psk']);
    for (const role of ['authority', 'exit', 'client-1', 'client-2']) {
      assert.equal(fs.statSync(path.join(dir, role)).mode & 0o777, 0o700);
      for (const file of fs.readdirSync(path.join(dir, role))) assert.equal(fs.statSync(path.join(dir, role, file)).mode & 0o777, 0o600);
    }
    execFileSync('openssl', ['verify', '-CAfile', dir + '/client-1/ca.pem', '-verify_hostname', 'runtime.test', dir + '/exit/cert.pem']);
    assert.throws(() => execFileSync('openssl', ['verify', '-CAfile', dir + '/client-1/ca.pem', '-verify_hostname', 'wrong.test', dir + '/exit/cert.pem'], { stdio: 'pipe' }));
    const before = get('client-1/psk'); assert.throws(() => createRuntimeConfig(options), /EEXIST/); assert.deepEqual(get('client-1/psk'), before);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('invalid addresses, modes, counts and duplicate options are rejected before writes', () => {
  for (const tail of [['--clients=33'], ['--mode=host'], ['--endpoint=127.0.0.1'], ['--days=0'], ['--server-name=x\nsubjectAltName=DNS:evil']]) {
    const option = tail[0].split('=')[0];
    assert.throws(() => parseRuntimeConfig([...args('/nonexistent/new').filter(a => !a.startsWith(option + '=')), ...tail]));
  }
  assert.throws(() => parseRuntimeConfig([...args('/nonexistent/new'), '--mode=standalone']), /duplicate_option/);
});
