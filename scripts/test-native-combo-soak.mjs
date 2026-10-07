// Native-only sustained packet traffic plus TLS connection churn. Loopback
// namespace + fixture packet FDs; not real TUN, WAN, DNS or a speed benchmark.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { assertComboSoakEvidence } from './lib/native-combo-soak-evidence.mjs';

const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
const seconds = Number(process.env.CVPN_COMBO_SOAK_SECONDS ?? 180);
assert.ok(Number.isInteger(seconds) && seconds >= 10 && seconds <= 600);
test('combo soak rejects malformed/out-of-range duration before configuration or network access', () => {
  for (const value of ['', '9', '601', '-1', '10x', '4294967306']) {
    const r = spawnSync(build + '/transparent-socket-test', ['unused-cert', 'unused-key', 'unused-engine',
      fs.readlinkSync('/proc/self/ns/net'), '--combo-soak', value], { encoding: 'utf8', timeout: 3000 });
    assert.equal(r.status, 1); assert.equal(r.stdout, ''); assert.ok(!r.error);
  }
});
test('native combo sustained bidirectional packets and TLS12/TLS13-HRR churn', { timeout: (seconds + 40) * 1000 }, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-combo-soak-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = dir + '/cert.pem', key = dir + '/key.pem';
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  const env = { ...process.env }; delete env.NOTIFY_SOCKET;
  const result = spawnSync('unshare', ['--user', '--map-root-user', '--net',
    build + '/transparent-socket-test', cert, key, build + '/clean-vpn-engine-fixture',
    fs.readlinkSync('/proc/self/ns/net'), '--combo-soak', String(seconds)],
  { encoding: 'utf8', timeout: (seconds + 30) * 1000, maxBuffer: 65536, env, detached: true });
  if (Number.isInteger(result.pid) && result.pid > 1) {
    try { process.kill(-result.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
  }
  assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  const match = /^combo soak (.+) PASS$/m.exec(result.stdout); assert.ok(match, result.stdout);
  const report = JSON.parse(match[1]); assertComboSoakEvidence(report, seconds);
  t.diagnostic(JSON.stringify(report));
});
