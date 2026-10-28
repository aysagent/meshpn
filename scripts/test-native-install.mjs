import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { installNative } from './lib/native-install.mjs';
test('native fresh installer: dry run, secret relocation, collision and crash publication', t => {
  // Default '/' must pass path syntax (without writing to or depending on host units).
  assert.throws(() => installNative({ root: '/', name: '../invalid' }), /invalid_instance/);
  const base = fs.mkdtempSync('/tmp/native-install-');
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const cert = base + '/cert.pem', key = base + '/key.pem', psk = base + '/psk';
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'pipe' });
  fs.writeFileSync(psk, randomBytes(32), { mode: 0o600 });
  const binary = path.resolve('native/clean_vpn/build/clean-vpn-engine');
  const make = name => {
    const root = base + '/' + name; fs.mkdirSync(root, { mode: 0o700 });
    fs.mkdirSync(root + '/etc/systemd/system', { recursive: true }); fs.mkdirSync(root + '/opt');
    for (const name of ['guard', 'network']) fs.writeFileSync(root + `/etc/systemd/system/${name}.service`, '[Service]\nType=oneshot\nExecStart=/bin/true\n');
    const config = root + '/source.json';
    fs.writeFileSync(config, JSON.stringify({ version: 1, role: 'client', address: '127.0.0.1', port: 443,
      tun: 'tun0', ca: cert, server_name: 'localhost', secret_path: psk }), { mode: 0o600 });
    return { root, name, config, binary, networkUnit: 'network.service', guardUnit: 'guard.service' };
  };
  const profiled = make('profiled');
  const profileSource = profiled.root + '/profile.json';
  const profileBytes = fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json');
  fs.writeFileSync(profileSource, profileBytes, { mode: 0o600 });
  const profileConfig = JSON.parse(fs.readFileSync(profiled.config));
  profileConfig.tls_profile_path = profileSource;
  fs.writeFileSync(profiled.config, JSON.stringify(profileConfig));
  assert.equal(installNative({ ...profiled, apply: true }).status, 'installed-disabled');
  const profileTarget = profiled.root + '/opt/clean-vpn-native/profiled';
  const relocated = JSON.parse(fs.readFileSync(profileTarget + '/config.json'));
  assert.equal(relocated.tls_profile_path, '/opt/clean-vpn-native/profiled/tls-profile.json');
  fs.unlinkSync(profileSource);
  assert.deepEqual(fs.readFileSync(profileTarget + '/tls-profile.json'), profileBytes);
  const profileManifest = JSON.parse(fs.readFileSync(profileTarget + '/installed.json'));
  assert.equal(profileManifest.files.find(f => f.name === 'tls-profile.json').mode, 0o600);
  const relocatedCheck = { ...relocated, ca: profileTarget + '/ca.pem', secret_path: profileTarget + '/peer.psk',
    tls_profile_path: profileTarget + '/tls-profile.json' };
  fs.writeFileSync(profiled.config, JSON.stringify(relocatedCheck));
  execFileSync(binary, ['--check-config', profiled.config], { stdio: 'pipe' });
  const options = make('a'), target = options.root + '/opt/clean-vpn-native/a';
  assert.throws(() => installNative({ ...options, apply: 'false' }), /invalid_apply/);
  assert.equal(installNative(options).status, 'eligible'); assert.equal(fs.existsSync(target), false);
  assert.equal(installNative({ ...options, apply: true }).status, 'installed-disabled');
  const config = JSON.parse(fs.readFileSync(target + '/config.json'));
  assert.equal(config.secret_path, '/opt/clean-vpn-native/a/peer.psk');
  assert.ok(fs.readFileSync(target + '/peer.psk').equals(fs.readFileSync(psk)));
  assert.equal(fs.statSync(target + '/peer.psk').mode & 0o777, 0o600);
  assert.equal(fs.existsSync(options.root + '/etc/systemd/system/multi-user.target.wants'), false);
  assert.throws(() => installNative({ ...options, apply: true }), /instance_already_present/);
  for (const stage of ['prepared', 'files', 'published']) {
    const o = make(stage); const unit = o.root + '/etc/systemd/system/native-' + stage + '.service';
    assert.throws(() => installNative({ ...o, apply: true }, { fault: s => { if (s === stage) throw Error('cut'); } }), /cut/);
    assert.equal(fs.existsSync(unit), stage === 'published');
    if (stage === 'published') assert.match(fs.readFileSync(unit, 'utf8'), /--service/);
    assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
  }
  const linked = make('linked'); fs.symlinkSync('/dev/null', linked.root + '/etc/systemd/system/native-linked.service');
  assert.throws(() => installNative({ ...linked, apply: true }), /instance_already_present/);
  const vendor = make('vendor');
  fs.mkdirSync(vendor.root + '/usr/lib/systemd/system', { recursive: true });
  fs.writeFileSync(vendor.root + '/usr/lib/systemd/system/native-vendor.service', '[Service]\nExecStart=/bin/true\n');
  assert.throws(() => installNative({ ...vendor, apply: true }), /instance_already_present/);
  assert.equal(fs.existsSync(vendor.root + '/opt/clean-vpn-native'), false);
  const redirected = make('redirected');
  fs.renameSync(redirected.root + '/opt', redirected.root + '/other');
  fs.symlinkSync(redirected.root + '/other', redirected.root + '/opt');
  assert.throws(() => installNative({ ...redirected, apply: true }), /unsafe_destination/);
  assert.deepEqual(fs.readdirSync(redirected.root + '/other'), []);
  const credentialLink = make('credlink');
  fs.symlinkSync(psk, credentialLink.root + '/linked-key');
  const input = JSON.parse(fs.readFileSync(credentialLink.config)); input.secret_path = credentialLink.root + '/linked-key';
  fs.writeFileSync(credentialLink.config, JSON.stringify(input));
  assert.throws(() => installNative({ ...credentialLink, apply: true }));
  assert.equal(fs.existsSync(credentialLink.root + '/opt/clean-vpn-native'), false);
  const bad = make('bad'); fs.chmodSync(psk, 0o644);
  assert.throws(() => installNative({ ...bad, apply: true }));
  assert.equal(fs.existsSync(bad.root + '/opt/clean-vpn-native'), false);
  fs.chmodSync(psk, 0o600);
  const unsafeParent = make('parent');
  fs.chmodSync(base, 0o777);
  try {
    assert.throws(() => installNative({ ...unsafeParent, apply: true }), /unsafe_parent/);
    assert.equal(fs.existsSync(unsafeParent.root + '/opt/clean-vpn-native'), false);
  } finally { fs.chmodSync(base, 0o700); }
  const exit = make('exit');
  fs.writeFileSync(exit.config, JSON.stringify({ version: 1, role: 'exit', address: '127.0.0.1', port: 443,
    tun: 'tun0', cert, key, peers: [{ ipv4: '10.99.0.2', secret_path: psk }] }));
  assert.equal(installNative({ ...exit, apply: true }).status, 'installed-disabled');
  assert.equal(JSON.parse(fs.readFileSync(exit.root + '/opt/clean-vpn-native/exit/config.json')).peers[0].secret_path,
    '/opt/clean-vpn-native/exit/peer-0.psk');
  const scoped = make('scopedexit');
  fs.writeFileSync(scoped.config, JSON.stringify({version:1,role:'exit',address:'192.0.2.1',port:443,
    tun:'cvexit0',cert,key,peers:[{ipv4:'10.99.0.2',secret_path:psk}]}));
  scoped.exitProfile=scoped.root+'/exit-host.json';fs.writeFileSync(scoped.exitProfile,JSON.stringify({version:1,uplink:'eth0'}),{mode:0o600});
  assert.throws(()=>installNative(scoped),/conflicting_host_dependencies/);
  delete scoped.networkUnit;delete scoped.guardUnit;
  assert.equal(installNative(scoped).status,'eligible');
  assert.ok(!fs.existsSync(scoped.root+'/opt/clean-vpn-native'));
  assert.equal(installNative({...scoped,apply:true}).activation,'native-scopedexit-network.service');
  const scopedBundle=scoped.root+'/opt/clean-vpn-native/scopedexit';
  const scopedManifest=JSON.parse(fs.readFileSync(scopedBundle+'/installed.json'));
  assert.deepEqual(scopedManifest.dependencies,{});assert.equal(scopedManifest.networkUnit,scopedManifest.guardUnit);
  assert.ok(fs.existsSync(scopedBundle+'/control/clean-vpn-native-exit-host.mjs'));
  const scopedUnit=fs.readFileSync(scoped.root+'/etc/systemd/system/native-scopedexit.service','utf8');
  assert.match(scopedUnit,/BindsTo=native-scopedexit-network.service\n/);assert.ok(!scopedUnit.includes('WantedBy='));
  assert.throws(()=>installNative({...scoped,apply:true}),/instance_already_present/);
  for (const cut of [null, 'unit:native-sitecut-network.service', 'unit:native-sitecut.service']) {
    const name = cut ? 'sitecut' + (cut.endsWith('-network.service') ? '' : 'two') : 'site';
    const o = make(name); delete o.networkUnit; delete o.guardUnit;
    const engine = JSON.parse(fs.readFileSync(o.config)); engine.dns = true; fs.writeFileSync(o.config, JSON.stringify(engine));
    o.siteProfile = o.root + '/site.json';
    fs.writeFileSync(o.siteProfile, JSON.stringify({ link_unit: 'network.service', profile: { version: 1, role: 'client', tun: 'tun0',
      tun_address: '10.99.0.2/32', mtu: 1400, uplink: 'wan0', endpoint: '127.0.0.1', port: 443, lan: { interface: 'lan0', subnet: '192.168.7.0/24' } } }), { mode: 0o600 });
    assert.equal(installNative(o).status, 'eligible');
    if (cut) {
      const stage = cut.replace('sitecut', name);
      assert.throws(() => installNative({ ...o, apply: true }, { fault: s => { if (s === stage) throw Error('cut'); } }), /cut/);
      assert.ok(!fs.existsSync(o.root + `/etc/systemd/system/native-${name}.target`));
      assert.throws(() => installNative({ ...o, apply: true }), /instance_already_present/);
      continue;
    }
    assert.equal(installNative({ ...o, apply: true }).activation, 'native-site.target');
    const bundle = o.root + '/opt/clean-vpn-native/site';
    const manifest = JSON.parse(fs.readFileSync(bundle + '/installed.json'));
    assert.equal(manifest.units.length, 5);
    assert.deepEqual(Object.keys(manifest.dependencies), ['network.service']);
    assert.match(fs.readFileSync(o.root + '/etc/systemd/system/native-site-uplink.service', 'utf8'), /--activate-links/);
    assert.match(fs.readFileSync(o.root + '/etc/systemd/system/native-site.service', 'utf8'), /PartOf=native-site.target/);
    assert.ok(!fs.readFileSync(o.root + '/etc/systemd/system/native-site.service', 'utf8').includes('WantedBy='));
    assert.ok(fs.existsSync(bundle + '/control/lib/vpn-host-routes.mjs'));
    assert.ok(!fs.existsSync(o.root + '/etc/systemd/system/multi-user.target.wants'));
  }
});
