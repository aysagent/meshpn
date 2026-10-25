// Run on Linux with the native engine/fixture build. No TUN/firewall changes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { once } from 'node:events';
import { execFileSync, spawn } from 'node:child_process';
import { prepareNativeClients } from './clean-vpn-native-clients.mjs';

test('generated combo bundles connect 32 clients to one exit with isolated bidirectional packets', { timeout: 90000 }, async t => {
  assert.equal(process.platform, 'linux', 'run in Linux lab');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'native-clients-real-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root + '/key.pem',
    '-out', root + '/cert.pem', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  fs.chmodSync(root + '/key.pem', 0o600);
  const source = { version: 1, transport: 'combo-tls', endpoint: '198.51.100.2', port: 443,
    server_name: 'localhost', public_name: 'relay.example', cert: root + '/cert.pem', key: root + '/key.pem', ca: root + '/cert.pem',
    deploy_root: '/etc/clean-vpn-clients', exit: { uplink: 'eth0', link_unit: 'links.service' },
    clients: Array.from({ length: 32 }, (_, i) => ({ name: 'client-' + i, ipv4: `10.99.0.${i + 2}`,
      uplink: 'wan0', link_unit: 'links.service', lan: { interface: 'lan0', subnet: '192.168.7.0/24' } })) };
  prepareNativeClients(source, root + '/bundle');
  const listener = net.createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
  const port = listener.address().port; await new Promise(resolve => listener.close(resolve));
  const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
  const engine = build + '/clean-vpn-engine';
  const config = (dir, role, index = 0) => {
    const c = JSON.parse(fs.readFileSync(dir + '/config.json'));
    const relocate = value => typeof value === 'string' && value.startsWith(source.deploy_root + '/') ? dir + value.slice(source.deploy_root.length) : value;
    for (const key of ['cert', 'key', 'ca', 'secret_path']) if (c.boring[key]) c.boring[key] = relocate(c.boring[key]);
    if (c.boring.peers) for (const p of c.boring.peers) p.secret_path = relocate(p.secret_path);
    c.transparent.secret_path = relocate(c.transparent.secret_path);
    if (c.transparent.replay_directory) c.transparent.replay_directory = relocate(c.transparent.replay_directory);
    c.boring.address = '127.0.0.1'; c.boring.port = port;
    // All clients share a host only in this fixture: separate loopback addresses
    // avoid listener collisions; production clients run on different machines.
    c.transparent.listen = { ipv4: role === 'exit' ? '127.0.0.1' : `127.0.0.${index + 2}`, port };
    if (role === 'client') { c.transparent.exit = { ipv4: '127.0.0.1', port }; c.boring.dns = false; }
    const file = root + (role === 'exit' ? '/exit.json' : `/client-${index}.json`);
    fs.writeFileSync(file, JSON.stringify(c), { mode: 0o600 });
    const checked = JSON.parse(execFileSync(engine, ['--check-config', file], { encoding: 'utf8', timeout: 5000 }));
    assert.equal(checked.peers, role === 'exit' ? 32 : 1); return file;
  };
  const exit = config(root + '/bundle/exit', 'exit');
  for (let i = 0; i < 32; i++) config(root + '/bundle/clients/client-' + i, 'client', i);
  fs.mkdirSync(root + '/bundle/exit/replay', { mode: 0o700 });
  execFileSync(engine, ['--init-transparent-replay', exit], { stdio: 'pipe', timeout: 5000 });
  const env = { ...process.env }; delete env.NOTIFY_SOCKET;
  const child = spawn(build + '/integration-test', [build + '/clean-vpn-engine-fixture', root, exit, 'many-service'], { env });
  let output = ''; for (const stream of [child.stdout, child.stderr]) stream.on('data', b => output += b);
  const timer = setTimeout(() => child.kill('SIGKILL'), 60000);
  t.after(() => { clearTimeout(timer); child.kill('SIGKILL'); });
  const [code] = await once(child, 'close'); clearTimeout(timer);
  assert.equal(code, 0, output);
  assert.match(output, /32 authenticated peers, 256 addressed packets, bounded FD\/RSS PASS/);
});
