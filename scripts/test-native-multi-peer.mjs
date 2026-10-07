import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';

// Node creates fixture PKI/config only. C++ generates and verifies all packets.
test('native exit multiplexes authenticated peers despite stalled TLS, duplicate identity and spoofing', { timeout: 45000 }, async t => {
  const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-native-multi-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  const listener = net.createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
  const port = listener.address().port; await new Promise(resolve => listener.close(resolve));
  const common = { version: 1, address: '127.0.0.1', port, tun: 'cvtest0' };
  const peers = [2, 3, 4].map(last => {
    const secret_path = path.join(dir, `psk-${last}`); fs.writeFileSync(secret_path, randomBytes(32), { mode: 0o600 });
    return { ipv4: `10.99.0.${last}`, secret_path };
  });
  const configs = {};
  for (const [name, fields] of Object.entries({ exit: { role: 'exit', peers, cert, key },
    a: { role: 'client', peer_ipv4: peers[0].ipv4, secret_path: peers[0].secret_path, ca: cert, server_name: 'localhost' },
    b: { role: 'client', peer_ipv4: peers[1].ipv4, secret_path: peers[1].secret_path, ca: cert, server_name: 'localhost' },
    spoof: { role: 'client', peer_ipv4: peers[1].ipv4, secret_path: peers[2].secret_path, ca: cert, server_name: 'localhost' } })) {
    configs[name] = path.join(dir, `${name}.json`); fs.writeFileSync(configs[name], JSON.stringify({ ...common, ...fields }));
  }
  for (const name of ['a', 'b', 'exit']) {
    const checked = JSON.parse(execFileSync(path.join(build, 'clean-vpn-engine'), ['--check-config', configs[name]], { encoding: 'utf8' }));
    assert.equal(checked.valid, true); assert.equal(checked.peers, name === 'exit' ? 3 : 1);
  }
  for (const patch of [{ peers: [] }, { peers: Array(33).fill(peers[0]) }, { peers: [peers[0], peers[0]] },
    { peers: [peers[0], { ...peers[1], secret_path: peers[0].secret_path }] },
    { peers: [{ ...peers[0], ipv4: '10.99.0.1' }] }, { peer_ipv4: peers[0].ipv4 },
    { secret_path: peers[0].secret_path }, { peers: [{ ...peers[0], unknown: true }] }]) {
    const invalid = path.join(dir, 'invalid.json');
    fs.writeFileSync(invalid, JSON.stringify({ ...common, role: 'exit', cert, key, peers, ...patch }));
    const r = spawnSync(path.join(build, 'clean-vpn-engine'), ['--check-config', invalid], { encoding: 'utf8', timeout: 2000 });
    assert.equal(r.status, 1); assert.equal(r.stdout, '');
    assert.equal(r.stderr, 'clean-vpn-engine: configuration or startup refused\n');
  }
  const child = spawn(path.join(build, 'integration-test'), [path.join(build, 'clean-vpn-engine-fixture'),
    configs.a, configs.exit, 'multi', configs.b, configs.spoof]);
  let output = ''; for (const stream of [child.stdout, child.stderr]) stream.on('data', b => { output += b; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 22000);
  t.after(() => { clearTimeout(timer); child.kill('SIGKILL'); });
  const [status] = await once(child, 'close'); clearTimeout(timer);
  assert.equal(status, 0, output);
  for (const message of ['400 isolated packets PASS', 'duplicate credential cannot evict active owner PASS',
    'authenticated wrong-source peer isolated without disrupting others PASS', 'bounded RSS/FDs, stop PASS',
    'client-to-client forwarding denied by native exit PASS', 'slow authenticated recipient cannot block other peer PASS'])
    assert.ok(output.includes(message), output);
  const many = Array.from({ length: 32 }, (_, i) => {
    const secret_path = path.join(dir, `many-${i}`), ipv4 = `10.99.0.${i + 2}`;
    fs.writeFileSync(secret_path, randomBytes(32), { mode: 0o600 });
    fs.writeFileSync(path.join(dir, `client-${i}.json`), JSON.stringify({ ...common, role: 'client',
      peer_ipv4: ipv4, secret_path, ca: cert, server_name: 'localhost' }));
    return { ipv4, secret_path };
  });
  fs.writeFileSync(configs.exit, JSON.stringify({ ...common, role: 'exit', peers: many, cert, key }));
  const maximum = spawnSync(path.join(build, 'integration-test'), [path.join(build, 'clean-vpn-engine-fixture'),
    dir, configs.exit, 'many'], { encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(maximum.status, 0, maximum.stdout + maximum.stderr);
  assert.match(maximum.stdout, /32 authenticated peers, 256 addressed packets, bounded FD\/RSS PASS/);
});
