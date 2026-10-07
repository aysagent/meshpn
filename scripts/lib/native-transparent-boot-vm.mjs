// Disposable, NIC-less QEMU only. Node owns provisioning and metadata, never
// TLS/application bytes. Invoked by init before systemd, or fixture units.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { installNative } from './native-install.mjs';
import { copyVmTree } from './native-vm-copy-tree.mjs';
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-transparent-boot=1\b/);
assert.match(fs.readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
const action = process.argv[2], parent = fs.readlinkSync('/proc/self/ns/net');
const root = '/opt/clean-vpn-native', names = ['trclient', 'trexit'];
const stateFile = root + '/trexit/replay/state';
const hash = b => createHash('sha256').update(b).digest('hex');
const run = (bin, args) => execFileSync(bin, args, { encoding: 'utf8', timeout: 90000, maxBuffer: 1024 * 1024 });
const ip = (...args) => run('/usr/bin/ip', args);
const ctl = (...args) => run('/usr/bin/systemctl', args).trim();
const prop = (name, property) => ctl('show', `native-${name}.service`, '-p', property, '--value');
const ns = name => name === 'trclient' ? 'trgw' : 'trex';
const gate = key => console.log('NATIVE_TRANSPARENT_' + key + '_PASS');
const fixture = '/native/transparent-socket-test';
const args = mode => [fixture, mode, '/native/cert.pem', '/native/key.pem', parent];
const probe = mode => ip('netns', 'exec', 'trapp', ...args(mode));
const originLines = () => fs.readFileSync('/run/transparent-origin.log', 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
async function until(predicate, seconds = 45) {
  const deadline = Date.now() + seconds * 1000;
  while (!predicate()) { assert.ok(Date.now() < deadline, 'vm_deadline'); await delay(100); }
}
function inventory() {
  const result = {};
  function walk(p) {
    const s = fs.lstatSync(p);
    if (s.isDirectory()) {
      result[p] = { mode: s.mode & 0o7777, directory: true };
      for (const n of fs.readdirSync(p).sort()) walk(p + '/' + n); return;
    }
    result[p] = { mode: s.mode & 0o777, digest: s.isSymbolicLink() ? 'link:' + fs.readlinkSync(p) : hash(fs.readFileSync(p)) };
  }
  walk(root);
  for (const name of names) {
    const manifest = JSON.parse(fs.readFileSync(`${root}/${name}/installed.json`));
    for (const unit of manifest.units) { walk('/etc/systemd/system/' + unit); walk('/etc/systemd/system/' + unit + '.d'); }
    walk(`/etc/systemd/system/multi-user.target.wants/native-${name}.target`);
  }
  return result;
}
function override(name, restart) {
  const p = `/etc/systemd/system/native-${name}.service.d/fault.conf`;
  if (restart === null) fs.unlinkSync(p);
  else fs.writeFileSync(p, `[Service]\nRestart=${restart}\n`);
  ctl('daemon-reload');
}
if (action === 'prepare') {
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  const phase = fs.existsSync('/state/inventory.json') ? 1 : 0;
  if (phase) {
    for (const p of ['opt/clean-vpn-native', 'etc/systemd/system']) copyVmTree('/state/installed/' + p, '/' + p);
    assert.deepEqual(inventory(), JSON.parse(fs.readFileSync('/state/inventory.json')));
    assert.equal(hash(fs.readFileSync(stateFile)), fs.readFileSync('/state/replay.sha256', 'utf8'));
    assert.ok(fs.readFileSync(stateFile).readBigUInt64BE(48) > 0n, 'replay_must_contain_records');
    fs.mkdirSync('/etc/systemd/system/native-tr-driver.service.d', { recursive: true });
    fs.writeFileSync('/etc/systemd/system/native-tr-driver.service.d/order.conf', '[Unit]\nAfter=native-trclient.target native-trexit.target\nWants=native-trclient.target native-trexit.target\n');
    fs.writeFileSync('/run/transparent-reboot', '1'); gate('REBOOT_REPLAY_BYTES');
  }
  console.log('NATIVE_TRANSPARENT_BOOT ' + JSON.stringify({ phase, bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() }));
} else if (action === 'network') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  for (const name of ['trgw', 'trex', 'trapp', 'trorigin']) ip('netns', 'add', name);
  ip('link', 'add', 'trwire', 'type', 'bridge'); ip('link', 'set', 'trwire', 'up');
  const out = fs.openSync('/run/transparent-origin.log', 'wx', 0o600);
  const err = fs.openSync('/run/transparent-origin.err', 'wx', 0o600);
  const origin = spawn('/usr/bin/ip', ['netns', 'exec', 'trorigin', ...args('--public-network-origin')], { stdio: ['ignore', out, err] });
  origin.unref(); fs.closeSync(out); fs.closeSync(err);
  await until(() => originLines().some(l => l.stage === 'namespace-ready'));
  // Connect origin immediately: the C++ fixture has a bounded setup deadline.
  for (const [net, dev, port] of [['trorigin', 'cvpublic1', 'orig'], ['trgw', 'wan0', 'gw'], ['trex', 'wan0', 'ex']]) {
    ip('link', 'add', 'left' + port, 'type', 'veth', 'peer', 'name', 'right' + port);
    ip('link', 'set', 'right' + port, 'netns', net); ip('-n', net, 'link', 'set', 'right' + port, 'name', dev);
    ip('link', 'set', 'left' + port, 'master', 'trwire'); ip('link', 'set', 'left' + port, 'up');
  }
  ip('link', 'add', 'leftlan', 'type', 'veth', 'peer', 'name', 'rightlan');
  ip('link', 'set', 'leftlan', 'netns', 'trgw'); ip('-n', 'trgw', 'link', 'set', 'leftlan', 'name', 'lan0');
  ip('link', 'set', 'rightlan', 'netns', 'trapp'); ip('-n', 'trapp', 'link', 'set', 'rightlan', 'name', 'cvpublic0');
  for (const net of ['trgw', 'trex', 'trapp']) ip('-n', net, 'link', 'set', 'lo', 'up');
  for (const [net, dev, address] of [['trgw', 'wan0', '198.18.0.1/24'], ['trex', 'wan0', '198.18.0.3/24'],
    ['trgw', 'lan0', '192.168.7.1/24'], ['trapp', 'cvpublic0', '192.168.7.2/24']]) ip('-n', net, 'addr', 'add', address, 'dev', dev);
  ip('-n', 'trapp', 'link', 'set', 'cvpublic0', 'up'); ip('-n', 'trapp', 'route', 'add', 'default', 'via', '192.168.7.1');
  await until(() => originLines().some(l => l.stage === 'origin-ready'));
} else if (action === 'defaults') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  for (const net of ['trgw', 'trex']) {
    const routes = JSON.parse(ip('-n', net, '-j', 'route', 'show', '1.1.1.1/32'));
    if (routes.length === 0) ip('-n', net, 'route', 'add', '1.1.1.1/32', 'via', '198.18.0.2', 'dev', 'wan0');
    else assert.ok(routes.length === 1 && routes[0].gateway === '198.18.0.2' && routes[0].dev === 'wan0');
  }
} else if (action === 'run') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  const reboot = fs.existsSync('/run/transparent-reboot'); let passed = false;
  try {
    ctl('start', 'native-tr-links.service');
    if (!reboot) {
      fs.mkdirSync('/opt', { recursive: true });
      for (const name of names) {
        assert.equal(installNative({ name, binary: '/native/clean-vpn-engine', config: `/native/${name}.json`, siteProfile: `/native/${name}-site.json`, apply: true }).status, 'installed-disabled');
        const manifest = JSON.parse(fs.readFileSync(`${root}/${name}/installed.json`));
        for (const unit of manifest.units) {
          assert.ok(!fs.existsSync('/etc/systemd/system/multi-user.target.wants/' + unit));
          fs.mkdirSync(`/etc/systemd/system/${unit}.d`);
          fs.writeFileSync(`/etc/systemd/system/${unit}.d/lab.conf`, '[Unit]\nDefaultDependencies=no\n' +
            (unit === `native-${name}.service` ? 'Requires=native-tr-defaults.service\nAfter=native-tr-defaults.service\n' : '') +
            (unit.endsWith('.service') ? `[Service]\nNetworkNamespacePath=/run/netns/${ns(name)}\nStandardOutput=append:/run/${unit}.log\nStandardError=append:/run/${unit}.log\n` : ''));
        }
      }
      gate('INSTALLED_DISABLED'); ctl('daemon-reload');
      for (const name of names) {
        ctl('start', `native-${name}-network.service`);
        assert.ok(!JSON.parse(ip('-n', ns(name), '-j', 'link', 'show', 'wan0'))[0].flags.includes('UP'));
        assert.equal(prop(name, 'MainPID'), '0');
      }
      gate('GUARD_BEFORE_LINK'); ctl('start', 'native-trexit.target', 'native-trclient.target');
    }
    for (const name of names) {
      await until(() => prop(name, 'ActiveState') === 'active' && Number(prop(name, 'MainPID')) > 0);
      assert.equal(prop(name, 'ActiveState'), 'active');
      assert.equal(fs.realpathSync(`/proc/${prop(name, 'MainPID')}/exe`), `${root}/${name}/engine`);
      const guard = Number(ctl('show', `native-${name}-network.service`, '-p', 'ActiveEnterTimestampMonotonic', '--value'));
      const link = Number(ctl('show', `native-${name}-uplink.service`, '-p', 'ExecMainStartTimestampMonotonic', '--value'));
      assert.ok(guard > 0 && link >= guard);
    }
    gate(reboot ? 'REBOOT_AUTOSTART_ORDER' : 'DIRECT_CPP_NOTIFY');
    assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate(reboot ? 'REBOOT_TLS' : 'TLS');
    assert.match(probe('--public-network-negative'), /blocked PASS/); gate('UNSUPPORTED_BLOCKED');
    if (!reboot) {
      for (const name of names) {
        // First prove normal Restart=on-failure, not a fixture restart loop.
        const pid = prop(name, 'MainPID'); ctl('kill', '--kill-whom=main', '--signal=SIGKILL', `native-${name}.service`);
        await until(() => prop(name, 'ActiveState') === 'active' && prop(name, 'MainPID') !== pid);
        assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate(name === 'trclient' ? 'CLIENT_AUTORESTART' : 'EXIT_AUTORESTART');
        // A separate disabled-restart fault window proves blocking, then restore
        // the installed policy. No firewall modification accompanies the kill.
        override(name, 'no'); ctl('kill', '--kill-whom=main', '--signal=SIGKILL', `native-${name}.service`);
        await until(() => prop(name, 'MainPID') === '0');
        assert.match(probe(name === 'trclient' ? '--public-network-crash' : '--public-client-blocked'), /(?:blocked|no fallback) PASS/);
        override(name, null); ctl('reset-failed', `native-${name}.service`); ctl('start', `native-${name}.target`, `native-${name}.service`);
        assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate(name === 'trclient' ? 'CLIENT_CRASH_BLOCKED' : 'EXIT_CRASH_BLOCKED');
      }
    } else {
      // Owner-driven corruption for the fixture only. Preserve the exact good
      // bytes; runtime must neither replace invalid state nor create missing state.
      ctl('stop', 'native-trexit.service'); override('trexit', 'no');
      const good = fs.readFileSync(stateFile);
      for (const fault of ['missing', 'corrupt']) {
        if (fault === 'missing') fs.renameSync(stateFile, stateFile + '.fixture-backup');
        else fs.writeFileSync(stateFile, Buffer.from('corrupt'), { mode: 0o600 });
        ctl('reset-failed', 'native-trexit.service');
        assert.throws(() => ctl('start', 'native-trexit.service'));
        assert.equal(prop('trexit', 'MainPID'), '0');
        // Explicitly stopping the exit also stops its target/guards; the shared
        // fixture route-owner dependency then stops the client. Bring only the
        // client back so this probe exercises a live gateway with a refused exit,
        // rather than failing at TCP connect to an intentionally stopped gateway.
        ctl('start', 'native-trclient.target', 'native-trclient.service');
        assert.equal(prop('trclient', 'ActiveState'), 'active');
        assert.equal(prop('trexit', 'MainPID'), '0');
        if (fault === 'missing') { assert.equal(fs.existsSync(stateFile), false); fs.renameSync(stateFile + '.fixture-backup', stateFile); }
        else { assert.equal(fs.readFileSync(stateFile, 'utf8'), 'corrupt'); fs.writeFileSync(stateFile, good); }
        assert.match(probe('--public-client-blocked'), /no fallback PASS/);
        gate(fault === 'missing' ? 'MISSING_REPLAY_REFUSED' : 'CORRUPT_REPLAY_REFUSED');
      }
      override('trexit', null); ctl('reset-failed', 'native-trexit.service'); ctl('start', 'native-trexit.target', 'native-trexit.service');
      assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate('REPLAY_RESTORED_TLS');
    }
    ctl('stop', 'native-trclient.target', 'native-trexit.target');
    for (const name of names) {
      assert.equal(prop(name, 'MainPID'), '0');
      assert.match(ip('netns', 'exec', ns(name), 'iptables', '-S', 'OUTPUT'), /-P OUTPUT DROP/);
    }
    assert.match(probe('--public-network-crash'), /blocked PASS/); gate('TARGET_STOP_BLOCKED');
    if (!reboot) {
      ctl('enable', 'native-trclient.target', 'native-trexit.target');
      assert.ok(fs.readFileSync(stateFile).readBigUInt64BE(48) > 0n);
      fs.mkdirSync('/state/installed/opt', { recursive: true }); fs.mkdirSync('/state/installed/etc', { recursive: true });
      copyVmTree(root, '/state/installed/opt/clean-vpn-native');
      copyVmTree('/etc/systemd/system', '/state/installed/etc/systemd/system');
      fs.writeFileSync('/state/inventory.json', JSON.stringify(inventory()));
      fs.writeFileSync('/state/replay.sha256', hash(fs.readFileSync(stateFile))); gate('REPLAY_PERSISTED');
      run('/bin/busybox', ['sync']); run('/bin/busybox', ['mount', '-o', 'remount,ro', '/state']);
    }
    passed = true; console.log('NATIVE_TRANSPARENT_BOOT_OK');
  } catch (e) {
    console.error(e.stack);
    try { console.error(ctl('--no-pager', 'status', 'native-trclient', 'native-trexit', 'native-trclient-network', 'native-trexit-network')); } catch (error) { console.error(error.stdout?.toString()); }
    console.error(run('/usr/bin/journalctl', ['--no-pager', '-n', '120']));
    if (fs.existsSync('/run/transparent-origin.err')) console.error(fs.readFileSync('/run/transparent-origin.err', 'utf8'));
    for (const file of fs.readdirSync('/run').filter(n => n.endsWith('.log') && (n.startsWith('native-tr') || n === 'transparent-network.log'))) console.error(file + '\n' + fs.readFileSync('/run/' + file, 'utf8').slice(-10000));
    console.log('NATIVE_TRANSPARENT_BOOT_FAILED');
  } finally {
    run('/bin/busybox', ['sync']); run('/bin/busybox', [passed && !reboot ? 'reboot' : 'poweroff', '-f']);
  }
} else throw Error('unknown_vm_action');
