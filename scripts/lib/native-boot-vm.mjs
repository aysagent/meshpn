// Destructive fixture operations ONLY inside a marked NIC-less QEMU guest.
// All application packet generation/verification is in socket-test (C++).
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
const mode = process.argv[2];
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-boot=1\b/);
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.equal(process.getuid(), 0);
assert.match(fs.readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
const exec = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 90000, maxBuffer: 1024 * 1024 }).trim();
const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args]);
const prop = (name, key) => ctl('show', name + '.service', '-p', key, '--value');
const phase = fs.existsSync('/state/phase') ? Number(fs.readFileSync('/state/phase')) : 0;
assert.ok([0, 1, 2].includes(phase));
const event = data => console.log('NATIVE_BOOT_EVENT ' + JSON.stringify({ phase, ...data }));
const check = (name, value) => { assert.ok(value, name); event({ event: 'check', name }); };
const put = (p, text) => { fs.mkdirSync(p.slice(0, p.lastIndexOf('/')), { recursive: true }); fs.writeFileSync(p, text, { mode: p.endsWith('.conf') ? 0o644 : 0o600 }); };
const names = ['c2', 'c3', 'exit'];
const inventory = () => {
  const files = {};
  const walk = p => {
    const stat = fs.lstatSync(p);
    if (stat.isDirectory()) { for (const n of fs.readdirSync(p).sort()) walk(p + '/' + n); return; }
    files[p] = { mode: stat.mode & 0o777, digest: stat.isSymbolicLink() ? 'link:' + fs.readlinkSync(p) :
      createHash('sha256').update(fs.readFileSync(p)).digest('hex') };
  };
  walk('/opt/clean-vpn-native');
  for (const n of names) {
    walk(`/etc/systemd/system/native-${n}.service`);
    walk(`/etc/systemd/system/native-${n}.service.d`);
    walk(`/etc/systemd/system/multi-user.target.wants/native-${n}.service`);
  }
  return files;
};
if (mode === 'prepare') {
  // Pre-PID1 restore of the saved installed artifacts into disposable initramfs.
  assert.deepEqual(fs.readdirSync('/sys/class/net'), ['lo']);
  fs.mkdirSync('/opt', { recursive: true });
  if (phase) {
    for (const dir of ['opt/clean-vpn-native', 'etc/systemd/system'])
      fs.cpSync('/state/installed/' + dir, '/' + dir, { recursive: true, verbatimSymlinks: true });
    assert.deepEqual(inventory(), JSON.parse(fs.readFileSync('/state/inventory.json')));
    put('/etc/systemd/system/native-lab-driver.service.d/order.conf', '[Unit]\nAfter=native-c2.service native-c3.service native-exit.service\n');
  }
  if (phase === 2) put('/run/native-fail-guard', 'fixture fault\n');
  event({ event: 'prepared', bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() });
} else {
  assert.equal(mode, 'run'); assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  let origin;
  try {
    if (!phase) {
      ctl('start', 'native-lab-network.service');
      for (const n of names) {
        const result = JSON.parse(exec('/usr/bin/node', ['/project/scripts/clean-vpn-native-install.mjs', '--apply',
          `--name=${n}`, '--binary=/native/clean-vpn-engine', `--config=/native/${n}.json`,
          '--network-unit=native-lab-uplink.service', '--guard-unit=native-lab-guard.service']));
        check('installed-disabled-' + n, result.status === 'installed-disabled');
        put(`/etc/systemd/system/native-${n}.service.d/lab.conf`, `[Unit]\nDefaultDependencies=no\n[Service]\nNetworkNamespacePath=/run/netns/${n === 'exit' ? 'nexit' : 'n' + n}\n`);
      }
      ctl('daemon-reload');
      for (const n of names) check('not-started-by-installer-' + n, prop('native-' + n, 'MainPID') === '0');
      ctl('enable', ...names.map(n => 'native-' + n + '.service'));
      ctl('start', ...names.map(n => 'native-' + n + '.service'));
    }
    if (phase < 2) {
      for (const n of names) {
        check('active-' + n, prop('native-' + n, 'ActiveState') === 'active');
        check('native-mainpid-' + n, fs.readlinkSync('/proc/' + prop('native-' + n, 'MainPID') + '/exe') === `/opt/clean-vpn-native/${n}/engine`);
      }
      origin = spawn('/usr/bin/ip', ['netns', 'exec', 'nexit', '/native/socket-test', 'serve'], { stdio: 'ignore' });
      await delay(800);
      for (const n of [2, 3]) {
        check('tun-data-' + n, exec('/usr/bin/ip', ['netns', 'exec', 'nc' + n, '/native/socket-test', 'probe']).includes('NATIVE_TUN_PROBE_PASS'));
        check('native-dns-' + n, exec('/usr/bin/ip', ['netns', 'exec', 'nc' + n, '/native/socket-test', 'dns', `10.99.0.${n}`, '1053']).includes('DNS TCP PASS'));
      }
      check('guard-active', prop('native-lab-guard', 'ActiveState') === 'active');
      const guardAt = Number(prop('native-lab-guard', 'ActiveEnterTimestampMonotonic'));
      check('guard-before-uplink', guardAt > 0 && guardAt <= Number(prop('native-lab-uplink', 'ActiveEnterTimestampMonotonic')));
      if (!phase) {
        fs.mkdirSync('/state/installed/opt', { recursive: true });
        fs.mkdirSync('/state/installed/etc/systemd/system/multi-user.target.wants', { recursive: true });
        fs.cpSync('/opt/clean-vpn-native', '/state/installed/opt/clean-vpn-native', { recursive: true });
        for (const n of names) for (const p of [`native-${n}.service`, `native-${n}.service.d`, `multi-user.target.wants/native-${n}.service`])
          fs.cpSync('/etc/systemd/system/' + p, '/state/installed/etc/systemd/system/' + p, { recursive: true, verbatimSymlinks: true });
        put('/state/inventory.json', JSON.stringify(inventory()));
      } else check('installed-bytes-survived-reboot', JSON.stringify(inventory()) === fs.readFileSync('/state/inventory.json', 'utf8'));
      ctl('stop', ...names.map(n => 'native-' + n + '.service'), 'native-lab-uplink.service');
      origin.kill('SIGTERM');
      put('/state/phase', String(phase + 1));
      exec('/bin/busybox', ['sync']); exec('/bin/busybox', ['mount', '-o', 'remount,ro', '/state']);
      event({ event: 'reboot-ready' }); exec('/bin/busybox', ['reboot', '-f']);
    } else {
      check('guard-failed', prop('native-lab-guard', 'ActiveState') === 'failed');
      check('uplink-not-active', prop('native-lab-uplink', 'ActiveState') !== 'active');
      for (const n of names) check('engine-not-started-' + n, prop('native-' + n, 'MainPID') === '0');
      for (const n of [2, 3]) {
        const link = JSON.parse(exec('/usr/bin/ip', ['-n', 'nc' + n, '-j', 'link', 'show', 'wlan0']))[0];
        check('uplink-stays-down-' + n, !link.flags.includes('UP'));
        check('no-default-' + n, exec('/usr/bin/ip', ['-n', 'nc' + n, 'route', 'show', 'default']) === '');
      }
      check('installed-bytes-preserved-on-failure', JSON.stringify(inventory()) === fs.readFileSync('/state/inventory.json', 'utf8'));
      event({ event: 'passed' }); exec('/bin/busybox', ['sync']); exec('/bin/busybox', ['poweroff', '-f']);
    }
  } catch (e) {
    event({ event: 'failed', message: e.message });
    try { console.log(ctl('status', ...names.map(n => 'native-' + n + '.service'))); } catch {}
    origin?.kill('SIGTERM'); exec('/bin/busybox', ['poweroff', '-f']);
  }
}
