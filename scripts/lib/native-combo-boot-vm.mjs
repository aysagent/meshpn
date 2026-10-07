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
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-combo-boot=1\b/);
assert.match(fs.readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
const action = process.argv[2], parent = fs.readlinkSync('/proc/self/ns/net');
const root = '/opt/clean-vpn-native', names = ['coclient', 'coexit'];
const stateFile = root + '/coexit/replay/state';
const hash = b => createHash('sha256').update(b).digest('hex');
const run = (bin, args) => execFileSync(bin, args, { encoding: 'utf8', timeout: 90000, maxBuffer: 1024 * 1024 });
const ip = (...args) => run('/usr/bin/ip', args);
const ctl = (...args) => run('/usr/bin/systemctl', args).trim();
const prop = (name, property) => ctl('show', `native-${name}.service`, '-p', property, '--value');
const ns = name => name === 'coclient' ? 'cogw' : 'coex';
const gate = key => console.log('NATIVE_COMBO_' + key + '_PASS');
const fixture = '/native/transparent-socket-test';
const args = mode => [fixture, mode, '/native/cert.pem', '/native/key.pem', parent];
const probe = mode => ip('netns', 'exec', 'coapp', ...args(mode));
const data = () => {
  assert.match(ip('netns', 'exec', 'coapp', '/native/socket-test', 'probe'), /NATIVE_TUN_PROBE_PASS/);
  for (const net of ['coapp', 'cogw']) assert.match(ip('netns', 'exec', net, '/native/socket-test', 'dns', '203.0.113.53'), /DNS TCP PASS/);
};
const blockedData = () => {
  for (const mode of ['data', 'dns']) assert.throws(() => ip('netns', 'exec', 'coapp', '/native/socket-test', mode));
};
const originLines = () => fs.readFileSync('/run/combo-origin.log', 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
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
    fs.mkdirSync('/etc/systemd/system/native-co-driver.service.d', { recursive: true });
    fs.writeFileSync('/etc/systemd/system/native-co-driver.service.d/order.conf', '[Unit]\nAfter=native-coclient.target native-coexit.target\nWants=native-coclient.target native-coexit.target\n');
    fs.writeFileSync('/run/combo-reboot', '1'); gate('REBOOT_REPLAY_BYTES');
  }
  console.log('NATIVE_COMBO_BOOT ' + JSON.stringify({ phase, bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() }));
} else if (action === 'network') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
  for (const name of ['cogw', 'coex', 'coapp', 'coorigin']) ip('netns', 'add', name);
  ip('link', 'add', 'cowire', 'type', 'bridge'); ip('link', 'set', 'cowire', 'up');
  const out = fs.openSync('/run/combo-origin.log', 'wx', 0o600);
  const err = fs.openSync('/run/combo-origin.err', 'wx', 0o600);
  const origin = spawn('/usr/bin/ip', ['netns', 'exec', 'coorigin', ...args('--combo-network-origin')], { stdio: ['ignore', out, err] });
  origin.unref(); fs.closeSync(out); fs.closeSync(err);
  await until(() => originLines().some(l => l.stage === 'namespace-ready'));
  // Connect origin immediately: the C++ fixture has a bounded setup deadline.
  for (const [net, dev, port] of [['coorigin', 'cvpublic1', 'orig'], ['cogw', 'wan0', 'gw'], ['coex', 'wan0', 'ex']]) {
    ip('link', 'add', 'left' + port, 'type', 'veth', 'peer', 'name', 'right' + port);
    ip('link', 'set', 'right' + port, 'netns', net); ip('-n', net, 'link', 'set', 'right' + port, 'name', dev);
    ip('link', 'set', 'left' + port, 'master', 'cowire'); ip('link', 'set', 'left' + port, 'up');
  }
  ip('link', 'add', 'leftlan', 'type', 'veth', 'peer', 'name', 'rightlan');
  ip('link', 'set', 'leftlan', 'netns', 'cogw'); ip('-n', 'cogw', 'link', 'set', 'leftlan', 'name', 'lan0');
  ip('link', 'set', 'rightlan', 'netns', 'coapp'); ip('-n', 'coapp', 'link', 'set', 'rightlan', 'name', 'cvpublic0');
  for (const net of ['cogw', 'coex', 'coapp']) ip('-n', net, 'link', 'set', 'lo', 'up');
  for (const [net, dev, address] of [['cogw', 'wan0', '198.18.0.1/24'], ['coex', 'wan0', '198.18.0.3/24'],
    ['cogw', 'lan0', '192.168.7.1/24'], ['coapp', 'cvpublic0', '192.168.7.2/24']]) ip('-n', net, 'addr', 'add', address, 'dev', dev);
  ip('-n', 'coapp', 'link', 'set', 'cvpublic0', 'up'); ip('-n', 'coapp', 'route', 'add', 'default', 'via', '192.168.7.1');
  await until(() => originLines().some(l => l.stage === 'origin-ready'));
  const dataLog = fs.openSync('/run/combo-data-origin.log', 'wx', 0o600);
  const server = spawn('/usr/bin/ip', ['netns', 'exec', 'coorigin', '/native/socket-test', 'serve'], { stdio: ['ignore', dataLog, dataLog] });
  server.unref(); fs.closeSync(dataLog);
  await until(() => fs.readFileSync('/run/combo-data-origin.log', 'utf8').includes('origin ready'));
} else if (action === 'defaults') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  const name = process.argv[3]; assert.ok(names.includes(name));
  const net = ns(name), gateway = name === 'coclient' ? '198.18.0.3' : '198.18.0.2';
  const routes = JSON.parse(ip('-n', net, '-j', 'route', 'show', 'default'));
  if (routes.length === 0) ip('-n', net, 'route', 'add', 'default', 'via', gateway, 'dev', 'wan0');
  else assert.ok(routes.length === 1 && routes[0].gateway === gateway && routes[0].dev === 'wan0');
} else if (action === 'run') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  const reboot = fs.existsSync('/run/combo-reboot'); let passed = false;
  try {
    ctl('start', 'native-co-links.service');
    if (!reboot) {
      fs.mkdirSync('/opt', { recursive: true });
      for (const name of names) {
        assert.equal(installNative({ name, binary: '/native/clean-vpn-engine', config: `/native/${name}.json`, siteProfile: `/native/${name}-site.json`, apply: true }).status, 'installed-disabled');
        const manifest = JSON.parse(fs.readFileSync(`${root}/${name}/installed.json`));
        for (const unit of manifest.units) {
          assert.ok(!fs.existsSync('/etc/systemd/system/multi-user.target.wants/' + unit));
          fs.mkdirSync(`/etc/systemd/system/${unit}.d`);
          fs.writeFileSync(`/etc/systemd/system/${unit}.d/lab.conf`, '[Unit]\nDefaultDependencies=no\n' +
            (unit === `native-${name}.service` || unit === `native-${name}-routes.service` ? `Requires=native-${name}-defaults.service\nAfter=native-${name}-defaults.service\n` : '') +
            (unit.endsWith('.service') ? `[Service]\nNetworkNamespacePath=/run/netns/${ns(name)}\nStandardOutput=append:/run/${unit}.log\nStandardError=append:/run/${unit}.log\n` : ''));
        }
      }
      gate('INSTALLED_DISABLED'); ctl('daemon-reload');
      for (const name of names) {
        ctl('start', `native-${name}-network.service`);
        assert.ok(!JSON.parse(ip('-n', ns(name), '-j', 'link', 'show', 'wan0'))[0].flags.includes('UP'));
        assert.equal(prop(name, 'MainPID'), '0');
      }
      gate('GUARD_BEFORE_LINK'); ctl('start', 'native-coexit.target', 'native-coclient.target');
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
    data(); gate(reboot ? 'REBOOT_TUN_DNS' : 'TUN_DNS');
    assert.equal(ctl('show', 'native-coclient-routes.service', '-p', 'ActiveState', '--value'), 'active');
    for (const route of ['0.0.0.0/1', '128.0.0.0/1', '198.18.0.3/32'])
      assert.ok(JSON.parse(ip('-n', 'cogw', '-N', '-j', 'route', 'show', route)).some(r => Number(r.protocol) === 186));
    gate('ROUTE_COORDINATOR');
    assert.match(probe('--combo-network-negative'), /no fallback PASS/); gate('UNSUPPORTED_BLOCKED');
    if (!reboot) {
      for (const name of names) {
        // First prove normal Restart=on-failure, not a fixture restart loop.
        const pid = prop(name, 'MainPID'); ctl('kill', '--kill-whom=main', '--signal=SIGKILL', `native-${name}.service`);
        await until(() => prop(name, 'ActiveState') === 'active' && prop(name, 'MainPID') !== pid);
        assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); data(); gate(name === 'coclient' ? 'CLIENT_AUTORESTART' : 'EXIT_AUTORESTART');
        // A separate disabled-restart fault window proves blocking, then restore
        // the installed policy. No firewall modification accompanies the kill.
        override(name, 'no'); ctl('kill', '--kill-whom=main', '--signal=SIGKILL', `native-${name}.service`);
        await until(() => prop(name, 'MainPID') === '0');
        assert.match(probe(name === 'coclient' ? '--public-network-crash' : '--public-client-blocked'), /(?:blocked|no fallback) PASS/);
        blockedData();
        override(name, null); ctl('reset-failed', `native-${name}.service`); ctl('start', `native-${name}.target`, `native-${name}.service`);
        assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); data(); gate(name === 'coclient' ? 'CLIENT_CRASH_BLOCKED' : 'EXIT_CRASH_BLOCKED');
      }
    } else {
      // Owner-driven corruption for the fixture only. Preserve the exact good
      // bytes; runtime must neither replace invalid state nor create missing state.
      ctl('stop', 'native-coexit.service'); override('coexit', 'no');
      const good = fs.readFileSync(stateFile);
      for (const fault of ['missing', 'corrupt']) {
        if (fault === 'missing') fs.renameSync(stateFile, stateFile + '.fixture-backup');
        else fs.writeFileSync(stateFile, Buffer.from('corrupt'), { mode: 0o600 });
        ctl('reset-failed', 'native-coexit.service');
        assert.throws(() => ctl('start', 'native-coexit.service'));
        assert.equal(prop('coexit', 'MainPID'), '0');
        // Per-role fixture defaults have no shared exit/client dependency.
        // Keep the already-running client alive while exit refuses replay state.
        assert.equal(prop('coclient', 'ActiveState'), 'active');
        assert.equal(prop('coexit', 'MainPID'), '0');
        if (fault === 'missing') { assert.equal(fs.existsSync(stateFile), false); fs.renameSync(stateFile + '.fixture-backup', stateFile); }
        else { assert.equal(fs.readFileSync(stateFile, 'utf8'), 'corrupt'); fs.writeFileSync(stateFile, good); }
        assert.match(probe('--public-client-blocked'), /no fallback PASS/);
        blockedData();
        gate(fault === 'missing' ? 'MISSING_REPLAY_REFUSED' : 'CORRUPT_REPLAY_REFUSED');
      }
      override('coexit', null); ctl('reset-failed', 'native-coexit.service'); ctl('start', 'native-coexit.target', 'native-coexit.service');
      assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); data(); gate('REPLAY_RESTORED_TLS');
    }
    ctl('stop', 'native-coclient.target', 'native-coexit.target');
    for (const name of names) {
      assert.equal(prop(name, 'MainPID'), '0');
      assert.match(ip('netns', 'exec', ns(name), 'iptables', '-S', 'OUTPUT'), /-P OUTPUT DROP/);
    }
    assert.match(probe('--public-network-crash'), /blocked PASS/); blockedData(); gate('TARGET_STOP_BLOCKED');
    if (!reboot) {
      ctl('enable', 'native-coclient.target', 'native-coexit.target');
      assert.ok(fs.readFileSync(stateFile).readBigUInt64BE(48) > 0n);
      fs.mkdirSync('/state/installed/opt', { recursive: true }); fs.mkdirSync('/state/installed/etc', { recursive: true });
      copyVmTree(root, '/state/installed/opt/clean-vpn-native');
      copyVmTree('/etc/systemd/system', '/state/installed/etc/systemd/system');
      fs.writeFileSync('/state/inventory.json', JSON.stringify(inventory()));
      fs.writeFileSync('/state/replay.sha256', hash(fs.readFileSync(stateFile))); gate('REPLAY_PERSISTED');
      run('/bin/busybox', ['sync']); run('/bin/busybox', ['mount', '-o', 'remount,ro', '/state']);
    }
    passed = true; console.log('NATIVE_COMBO_BOOT_OK');
  } catch (e) {
    console.error(e.stack);
    try { console.error(ctl('--no-pager', 'status', 'native-coclient', 'native-coexit', 'native-coclient-network', 'native-coexit-network')); } catch (error) { console.error(error.stdout?.toString()); }
    console.error(run('/usr/bin/journalctl', ['--no-pager', '-n', '120']));
    if (fs.existsSync('/run/combo-origin.err')) console.error(fs.readFileSync('/run/combo-origin.err', 'utf8'));
    for (const file of fs.readdirSync('/run').filter(n => n.endsWith('.log') && (n.startsWith('native-co') || n === 'combo-network.log'))) console.error(file + '\n' + fs.readFileSync('/run/' + file, 'utf8').slice(-10000));
    console.log('NATIVE_COMBO_BOOT_FAILED');
  } finally {
    run('/bin/busybox', ['sync']); run('/bin/busybox', [passed && !reboot ? 'reboot' : 'poweroff', '-f']);
  }
} else throw Error('unknown_vm_action');
