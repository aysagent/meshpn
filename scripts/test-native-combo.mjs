import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';

const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-combo-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = dir + '/cert.pem', key = dir + '/key.pem';
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  return { dir, cert, key };
}
test('native combo classifier leaves fragmented ClientHello and coalesced tail untouched', () => {
  assert.match(execFileSync(build + '/combo-test', [], { encoding: 'utf8', timeout: 5000 }), /timeout\/cancel PASS/);
});
test('combo config binds roles, one endpoint, SNI and separate keys; checking has no replay writes', t => {
  const { dir, cert, key } = fixture(t);
  const tunnelKey = dir + '/tunnel.key', relayKey = dir + '/relay.key';
  for (const file of [tunnelKey, relayKey]) fs.writeFileSync(file, randomBytes(32), { mode: 0o600 });
  const engine = build + '/clean-vpn-engine', file = dir + '/config.json';
  const endpoint = { ipv4: '127.0.0.1', port: 33443 };
  const config = { version: 1, transport: 'combo-tls', role: 'client',
    boring: { version: 1, role: 'client', address: endpoint.ipv4, port: endpoint.port,
      tun: 'cvtest0', server_name: 'localhost', sni: 'relay.example', ca: cert, secret_path: tunnelKey },
    transparent: { version: 1, transport: 'transparent-tls', role: 'client', public_name: 'relay.example',
      secret_path: relayKey, listen: { ipv4: '127.0.0.1', port: 33444 }, exit: endpoint,
      destinations: [{ ipv4: '127.0.0.1', port: 33445 }] } };
  const check = j => { fs.writeFileSync(file, JSON.stringify(j), { mode: 0o600 }); return spawnSync(engine, ['--check-config', file], { encoding: 'utf8', timeout: 3000 }); };
  assert.equal(check(config).status, 0);
  const server = structuredClone(config); server.role = server.boring.role = server.transparent.role = 'exit';
  server.boring.cert = cert; server.boring.key = key;
  delete server.boring.ca; delete server.boring.server_name; delete server.boring.sni;
  delete server.transparent.exit; server.transparent.listen = endpoint; server.transparent.replay_directory = dir + '/state';
  assert.equal(check(server).status, 0); assert.equal(fs.existsSync(dir + '/state'), false);
  for (const mutate of [j => { j.role = 'exit'; }, j => { j.boring.port++; },
    j => { j.boring.sni = 'wrong.example'; }, j => { j.boring.secret_path = relayKey; },
    j => { j.transparent.role = 'exit'; }, j => { j.unknown = true; },
    j => { j.transparent.destination_policy = { mode: 'public-https', deny_ipv4: [] }; },
    j => { j.boring.unknown = true; }]) {
    const bad = structuredClone(config); mutate(bad); const result = check(bad);
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'clean-vpn-engine: configuration or startup refused\n');
  }
});
test('both combo engines: one exit port, concurrent packets/TLS and durable replay after SIGKILL', { timeout: 45000 }, t => {
  const { cert, key } = fixture(t);
  const env = { ...process.env }; delete env.NOTIFY_SOCKET;
  // Network writes only after C++ verifies the new empty namespace. TUN packets
  // use the dedicated fixture FD; all TLS, packet generation and assertions are C++.
  const result = spawnSync('unshare', ['--user', '--map-root-user', '--net',
    build + '/transparent-socket-test', cert, key, build + '/clean-vpn-engine-fixture',
    fs.readlinkSync('/proc/self/ns/net'), '--combo'],
  { encoding: 'utf8', timeout: 35000, maxBuffer: 65536, env, detached: true });
  if (Number.isInteger(result.pid) && result.pid > 1) {
    try { process.kill(-result.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
  }
  assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /native combo engine REDIRECT PASS/);
});
