import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

// Node provisions fixture certificates and collects verdicts only. Every
// ClientHello, TLS record and application byte is generated/handled by C++.
test('native transparent codec and end-to-end TLS transcript restoration', { timeout: 30000 }, t => {
  const binary = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build', 'transparent-test');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-transparent-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  for (const [exe, args] of [[binary, []], [binary, [cert, key]], [path.join(path.dirname(binary), 'transparent-socket-test'), [cert, key]]]) {
    const result = spawnSync(exe, args, { encoding: 'utf8', timeout: 20000, maxBuffer: 65536 });
    assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
    if (!args.length) assert.match(result.stdout, /10000 mutations, HRR gates/);
    else if (exe === binary) assert.equal((result.stdout.match(/native transparent TLS PASS/g) ?? []).length, 9);
    else assert.match(result.stdout, /native transparent sockets PASS/);
    console.log(result.stdout.trim());
  }
});

test('native transparent engine with real REDIRECT in isolated network namespace', { timeout: 30000 }, t => {
  const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-transparent-engine-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  const env = { ...process.env }; delete env.NOTIFY_SOCKET;
  // No namespace fallback: unavailable unshare/netfilter is a failed lab, never
  // permission to install rules in the host namespace. C++ checks ns identity.
  const result = spawnSync('unshare', ['--user', '--map-root-user', '--net',
    path.join(build, 'transparent-socket-test'), cert, key, path.join(build, 'clean-vpn-engine'),
    fs.readlinkSync('/proc/self/ns/net')], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536, env });
  assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /native transparent engine REDIRECT PASS/);
  console.log(result.stdout.trim());
});
