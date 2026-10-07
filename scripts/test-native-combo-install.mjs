import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { installNative } from './lib/native-install.mjs';

function fixture(t) {
  const base = fs.mkdtempSync('/tmp/native-combo-install-');
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', base + '/key.pem',
    '-out', base + '/cert.pem', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  for (const [key, value] of [['boring', 1], ['relay', 2], ['second', 3]]) fs.writeFileSync(base + '/' + key + '.psk', Buffer.alloc(32, value), { mode: 0o600 });
  return (name, role = 'exit') => {
    const root = base + '/' + name; fs.mkdirSync(root, { mode: 0o700 });
    fs.mkdirSync(root + '/etc/systemd/system', { recursive: true }); fs.mkdirSync(root + '/opt');
    fs.writeFileSync(root + '/etc/systemd/system/links.service', '[Service]\nType=oneshot\nExecStart=/bin/true\n');
    const profile = { version: 1, transport: 'combo-tls', role, tun: 'tun0', tun_address: role === 'client' ? '10.99.0.2/32' : '10.99.0.1/24',
      mtu: 1400, uplink: 'wan0', endpoint: '198.18.0.3', port: 33001, listen_port: role === 'client' ? 33002 : 33001,
      lan: role === 'client' ? { interface: 'lan0', subnet: '192.168.7.0/24' } : null, deny_ipv4: [] };
    const boring = { version: 1, role, tun: 'tun0', address: profile.endpoint, port: profile.port,
      ...(role === 'client' ? { secret_path: base + '/boring.psk', ca: base + '/cert.pem', server_name: 'localhost', sni: 'relay.example', dns: true } :
        { cert: base + '/cert.pem', key: base + '/key.pem', peers: [{ ipv4: '10.99.0.2', secret_path: base + '/boring.psk' }, { ipv4: '10.99.0.3', secret_path: base + '/second.psk' }] }) };
    const transparent = { version: 1, transport: 'transparent-tls', role, public_name: 'relay.example', secret_path: base + '/relay.psk',
      destination_policy: { mode: 'public-https', deny_ipv4: [] }, listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: profile.listen_port },
      ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: profile.port } } : { replay_directory: base + '/unused-' + name }) };
    const config = root + '/source.json', siteProfile = root + '/site.json';
    fs.writeFileSync(config, JSON.stringify({ version: 1, transport: 'combo-tls', role, boring, transparent }), { mode: 0o600 });
    fs.writeFileSync(siteProfile, JSON.stringify({ link_unit: 'links.service', profile }), { mode: 0o600 });
    return { root, name, config, siteProfile, binary: path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build', 'clean-vpn-engine') };
  };
}
test('combo installer relocates both key sets/PKI, creates replay once and keeps direct services disabled', t => {
  const make = fixture(t);
  for (const role of ['client', 'exit']) {
    const o = make(role, role), target = '/opt/clean-vpn-native/' + role, bundle = o.root + target;
    assert.equal(installNative(o).status, 'eligible'); assert.ok(!fs.existsSync(bundle));
    assert.equal(installNative({ ...o, apply: true }).status, 'installed-disabled');
    const c = JSON.parse(fs.readFileSync(bundle + '/config.json')), m = JSON.parse(fs.readFileSync(bundle + '/installed.json'));
    assert.equal(m.transport, 'combo-tls'); assert.equal(m.units.length, role === 'client' ? 5 : 4);
    assert.equal(c.transparent.secret_path, target + '/relay.psk');
    assert.equal(m.mutableDirectories.length, role === 'exit' ? 1 : 0);
    assert.equal(fs.existsSync(bundle + '/routes.json'), role === 'client');
    assert.ok(!fs.existsSync(o.root + '/etc/systemd/system/multi-user.target.wants'));
    const unit = fs.readFileSync(o.root + '/etc/systemd/system/native-' + role + '.service', 'utf8');
    assert.match(unit, /Type=notify/); assert.match(unit, /DeviceAllow=\/dev\/net\/tun rw/); assert.ok(!unit.includes('node'));
    assert.equal(unit.includes('ReadWritePaths=' + target + '/replay'), role === 'exit');
    // Installed files, not original inputs, must pass engine validation under an alternate staging root.
    for (const key of ['ca', 'cert', 'key', 'secret_path']) if (c.boring[key]) c.boring[key] = o.root + c.boring[key];
    if (c.boring.peers) c.boring.peers = c.boring.peers.map(p => ({ ...p, secret_path: o.root + p.secret_path }));
    c.transparent.secret_path = o.root + c.transparent.secret_path;
    if (role === 'exit') c.transparent.replay_directory = o.root + c.transparent.replay_directory;
    const actual = o.root + '/actual.json'; fs.writeFileSync(actual, JSON.stringify(c), { mode: 0o600 });
    execFileSync(o.binary, ['--check-config', actual]);
    if (role === 'exit') {
      assert.equal(fs.statSync(bundle + '/replay').mode & 0o777, 0o700);
      const before = fs.readFileSync(bundle + '/replay/state');
      assert.throws(() => execFileSync(o.binary, ['--init-transparent-replay', actual], { stdio: 'pipe' }));
      assert.deepEqual(fs.readFileSync(bundle + '/replay/state'), before);
    }
    assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
  }
});
for (const stage of ['prepared', 'files', 'replay-prepared', 'replay-initialized', 'unit:native-cut-network.service', 'published'])
  test(`combo partial install at ${stage} is never adopted or reset`, t => {
    const o = fixture(t)('cut');
    assert.throws(() => installNative({ ...o, apply: true }, { fault: s => { if (s === stage) throw Error('cut'); } }), /cut/);
    assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
    assert.equal(fs.existsSync(o.root + '/etc/systemd/system/native-cut.target'), stage === 'published');
  });
test('combo replay initialization also relocates the single-peer exit schema under a staging root', t => {
  const o = fixture(t)('single'), c = JSON.parse(fs.readFileSync(o.config));
  c.boring.secret_path = c.boring.peers[0].secret_path; delete c.boring.peers;
  fs.writeFileSync(o.config, JSON.stringify(c));
  assert.equal(installNative({ ...o, apply: true }).status, 'installed-disabled');
  assert.ok(fs.existsSync(o.root + '/opt/clean-vpn-native/single/replay/state'));
});
test('combo refuses unbound installation, mixed profile, DNS off, shared keys and existing replay before writes', t => {
  const make = fixture(t);
  for (const fault of ['unbound', 'profile', 'dns', 'keys', 'replay', 'endpoint', 'policy']) {
    const o = make(fault, fault === 'replay' ? 'exit' : 'client'), c = JSON.parse(fs.readFileSync(o.config)), s = JSON.parse(fs.readFileSync(o.siteProfile));
    if (fault === 'unbound') delete o.siteProfile;
    if (fault === 'profile') { delete s.profile.transport; delete s.profile.listen_port; delete s.profile.deny_ipv4; }
    if (fault === 'dns') c.boring.dns = false;
    if (fault === 'keys') c.transparent.secret_path = c.boring.secret_path;
    if (fault === 'replay') fs.mkdirSync(c.transparent.replay_directory, { mode: 0o700 });
    if (fault === 'endpoint') s.profile.endpoint = '198.18.0.4';
    if (fault === 'policy') s.profile.deny_ipv4 = ['8.8.8.0/24'];
    fs.writeFileSync(o.config, JSON.stringify(c)); if (o.siteProfile) fs.writeFileSync(o.siteProfile, JSON.stringify(s));
    assert.throws(() => installNative({ ...o, apply: true })); assert.ok(!fs.existsSync(o.root + '/opt/clean-vpn-native'));
  }
});
