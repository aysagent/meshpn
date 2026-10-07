import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { installNative } from './lib/native-install.mjs';

function fixture(t) {
  const base = fs.mkdtempSync('/tmp/native-transparent-install-');
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const binary = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build', 'clean-vpn-engine');
  const psk = base + '/source.psk'; fs.writeFileSync(psk, Buffer.alloc(32, 0x42), { mode: 0o600 });
  return (name, role = 'exit') => {
    const root = base + '/' + name; fs.mkdirSync(root, { mode: 0o700 });
    fs.mkdirSync(root + '/etc/systemd/system', { recursive: true }); fs.mkdirSync(root + '/opt');
    fs.writeFileSync(root + '/etc/systemd/system/links.service', '[Service]\nType=oneshot\nExecStart=/bin/true\n');
    const profile = { version: 1, transport: 'transparent-tls', role, uplink: 'wan0', endpoint: '198.18.0.3', port: 33001,
      listen_port: role === 'client' ? 33002 : 33001, lan: role === 'client' ? { interface: 'lan0', subnet: '192.168.7.0/24' } : null, deny_ipv4: [] };
    const input = { version: 1, transport: 'transparent-tls', role, public_name: 'relay.example', secret_path: psk,
      destination_policy: { mode: 'public-https', deny_ipv4: [] },
      listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: profile.listen_port },
      ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: profile.port } } : { replay_directory: base + '/unused-source-' + name }) };
    const config = root + '/source.json', siteProfile = root + '/site.json';
    fs.writeFileSync(config, JSON.stringify(input), { mode: 0o600 });
    fs.writeFileSync(siteProfile, JSON.stringify({ link_unit: 'links.service', profile }), { mode: 0o600 });
    return { root, binary, config, siteProfile, name };
  };
}
test('fresh transparent installs bind profiles, relocate PSK, initialize durable replay once, stay disabled', t => {
  const make = fixture(t);
  for (const role of ['client', 'exit']) {
    const o = make(role, role), bundle = o.root + '/opt/clean-vpn-native/' + role;
    assert.equal(installNative(o).status, 'eligible'); assert.equal(fs.existsSync(bundle), false);
    assert.equal(installNative({ ...o, apply: true }).status, 'installed-disabled');
    const config = JSON.parse(fs.readFileSync(bundle + '/config.json'));
    const manifest = JSON.parse(fs.readFileSync(bundle + '/installed.json'));
    assert.equal(config.secret_path, '/opt/clean-vpn-native/' + role + '/peer.psk');
    assert.equal(manifest.transport, 'transparent-tls'); assert.equal(manifest.units.length, 4);
    assert.equal(manifest.mutableDirectories.length, role === 'exit' ? 1 : 0);
    for (const f of ['ca.pem', 'cert.pem', 'private.pem', 'routes.json', 'replay-init.json']) assert.equal(fs.existsSync(bundle + '/' + f), false);
    assert.equal(fs.existsSync(o.root + '/etc/systemd/system/multi-user.target.wants'), false);
    const unit = fs.readFileSync(o.root + `/etc/systemd/system/native-${role}.service`, 'utf8');
    assert.match(unit, /Type=notify/); assert.ok(!unit.includes('node')); assert.ok(!unit.includes('/dev/net/tun'));
    if (role === 'exit') {
      assert.equal(config.replay_directory, '/opt/clean-vpn-native/exit/replay');
      assert.equal(fs.statSync(bundle + '/replay').mode & 0o777, 0o700);
      const names = fs.readdirSync(bundle + '/replay'); assert.ok(names.length >= 2);
      for (const file of names) assert.equal(fs.statSync(bundle + '/replay/' + file).mode & 0o777, 0o600);
      const actual = o.root + '/actual.json';
      fs.writeFileSync(actual, JSON.stringify({ ...config, secret_path: bundle + '/peer.psk', replay_directory: bundle + '/replay' }), { mode: 0o600 });
      execFileSync(o.binary, ['--check-config', actual]);
      const before = names.map(f => fs.readFileSync(bundle + '/replay/' + f));
      assert.throws(() => execFileSync(o.binary, ['--init-transparent-replay', actual], { stdio: 'pipe' }));
      assert.deepEqual(names.map(f => fs.readFileSync(bundle + '/replay/' + f)), before);
    }
    assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
  }
});
for (const stage of ['prepared', 'files', 'replay-prepared', 'replay-initialized', 'unit:native-cut-network.service', 'published'])
  test(`transparent install interrupted at ${stage}: refuses adoption and never reinitializes`, t => {
    const o = fixture(t)('cut');
    assert.throws(() => installNative({ ...o, apply: true }, { fault: s => { if (s === stage) throw Error('cut'); } }), /cut/);
    assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
    assert.equal(fs.existsSync(o.root + '/etc/systemd/system/native-cut.target'), stage === 'published');
  });
test('transparent rejects policy mismatch, unbound external units and adoption of source replay state before writes', t => {
  const make = fixture(t);
  const unbound = make('unbound');
  assert.throws(() => installNative({ ...unbound, siteProfile: undefined, networkUnit: 'links.service', guardUnit: 'guard.service', apply: true }), /transparent_requires_bound_site_profile/);
  const mismatch = make('mismatch');
  const site = JSON.parse(fs.readFileSync(mismatch.siteProfile)); site.profile.deny_ipv4 = ['8.8.8.0/24'];
  fs.writeFileSync(mismatch.siteProfile, JSON.stringify(site));
  assert.throws(() => installNative({ ...mismatch, apply: true }), /destination_policy_mismatch/);
  const old = make('old'); const cfg = JSON.parse(fs.readFileSync(old.config));
  fs.mkdirSync(cfg.replay_directory, { mode: 0o700 });
  assert.throws(() => installNative({ ...old, apply: true }), /fresh_replay_source_must_not_exist/);
  for (const o of [unbound, mismatch, old]) assert.equal(fs.existsSync(o.root + '/opt/clean-vpn-native'), false);
});
