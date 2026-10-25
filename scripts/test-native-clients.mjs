import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { planNativeClients, prepareNativeClients } from './clean-vpn-native-clients.mjs';
import { nativeNetworkPlan } from './lib/native-network-profile.mjs';
import { nativeSitePlan } from './lib/native-site-plan.mjs';

const capability = { dns_socket_mark: '0x43564e', experimental_transports: {
  'combo-tls': { single_exit_listener: true, packet_ipc: false, site_provisioning: true },
  'transparent-tls': { durable_replay: true, client_interception: 'SO_ORIGINAL_DST', destination_policies: ['public-https'] },
} };

export function clientManifest(root, count = 2, transport = 'combo-tls') {
  return { version: 1, transport, endpoint: '198.51.100.2', port: 443, server_name: 'localhost',
    ...(transport === 'combo-tls' ? { public_name: 'relay.example' } : {}),
    cert: root + '/cert.pem', key: root + '/key.pem', ca: root + '/cert.pem', deploy_root: '/etc/clean-vpn-clients',
    exit: { uplink: 'eth0', link_unit: 'links.service' },
    clients: Array.from({ length: count }, (_, i) => ({ name: 'client-' + i, ipv4: `10.99.0.${i + 2}`,
      uplink: 'wlan0', link_unit: 'links.service', lan: { interface: 'usb0', subnet: '192.168.7.0/24' } })) };
}
for (const transport of ['boring-tls', 'combo-tls']) test(`${transport}: distinct peers, DNS/SNAT and shared exit subnet agree`, () => {
  const p = planNativeClients(clientManifest('/tmp/cert', 32, transport));
  const packet = c => c.boring ?? c;
  assert.equal(packet(p.exit.config).peers.length, 32);
  for (const host of [p.exit, ...p.clients]) {
    nativeSitePlan({ name: 'multi', target: '/opt/clean-vpn-native/multi', site: host.site, engine: host.config, capability });
  }
  for (const c of p.clients) {
    assert.equal(packet(c.config).peer_ipv4, c.ipv4);
    const rules = nativeNetworkPlan(c.site.profile);
    assert.ok(rules.nat.includes(`--to-source ${c.ipv4}`));
    assert.ok(rules.nat.includes(`--to-destination ${c.ipv4}:1053`));
  }
  assert.ok(nativeNetworkPlan(p.exit.site.profile).nat.includes('-s 10.99.0.0/24'));
  if (transport === 'boring-tls') {
    const source = clientManifest('/tmp/cert', 2, transport); source.clients[1].lan = null;
    const host = planNativeClients(source).clients[1];
    nativeSitePlan({ name: 'multi', target: '/opt/clean-vpn-native/multi', site: host.site, engine: host.config, capability });
  }
});
test('invalid peer inventories are rejected before output publication', () => {
  for (const mutate of [s => s.clients = [], s => s.clients = clientManifest('/tmp/cert', 33).clients,
    s => s.clients[1].ipv4 = s.clients[0].ipv4, s => s.clients[1].name = s.clients[0].name,
    s => s.clients[0].ipv4 = '10.99.0.1', s => s.clients[0].ipv4 = '10.99.0.255',
    s => s.clients[0].ipv4 = '10.99.0.02', s => s.clients[0].name = '../exit',
    s => s.clients[0].lan = null, s => s.clients[0].secret_path = '/tmp/shared',
    s => s.deploy_root = '/etc/../etc/test', s => s.exit.uplink = 'lo', s => s.port = 0,
    s => s.unknown = true, s => s.exit.link_unit = 'bad\n.service']) {
    const s = clientManifest('/tmp/cert'); mutate(s); assert.throws(() => planNativeClients(s));
  }
});
test('bundles isolate credentials, refuse overwrite, retain no server key in clients', t => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-clients-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root + '/key.pem',
    '-out', root + '/cert.pem', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  fs.chmodSync(root + '/key.pem', 0o600);
  const source = clientManifest(root), directory = root + '/bundle';
  const report = prepareNativeClients(source, directory);
  assert.equal(report.clients.length, 2); assert.equal(report.systemSettingsChanged, false);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  const secrets = [];
  for (const c of source.clients) {
    const sub = directory + '/clients/' + c.name;
    assert.deepEqual(fs.readdirSync(sub).sort(), ['ca.pem', 'config.json', 'packet.psk', 'relay.psk', 'site.json']);
    const key = fs.readFileSync(sub + '/packet.psk'); secrets.push(key);
    assert.equal(key.length, 32); assert.equal(fs.statSync(sub + '/packet.psk').mode & 0o777, 0o600);
    assert.deepEqual(key, fs.readFileSync(`${directory}/exit/peers/${c.name}.psk`));
    assert.deepEqual(fs.readFileSync(sub + '/relay.psk'), fs.readFileSync(directory + '/exit/relay.psk'));
  }
  assert.notDeepEqual(secrets[0], secrets[1]);
  assert.notDeepEqual(secrets[0], fs.readFileSync(directory + '/exit/relay.psk'));
  assert.equal(fs.existsSync(directory + '/exit/replay'), false);
  assert.throws(() => prepareNativeClients(source, directory), /EEXIST/);
  assert.deepEqual(fs.readFileSync(directory + '/clients/client-0/packet.psk'), secrets[0]);
  const invalid = structuredClone(source); invalid.clients[1].ipv4 = invalid.clients[0].ipv4;
  assert.throws(() => prepareNativeClients(invalid, root + '/invalid'));
  assert.equal(fs.existsSync(root + '/invalid'), false);
  fs.chmodSync(root + '/key.pem', 0o644);
  assert.throws(() => prepareNativeClients(source, root + '/unsafe'), /owner-only/);
  assert.equal(fs.existsSync(root + '/unsafe'), false);
});
