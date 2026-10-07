// Persist installed site artifacts over a real VM reboot, never the host.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-site-boot=1\b/);
assert.match(fs.readFileSync('/proc/mounts', 'utf8'), /^\/dev\/vda \/state ext4 /m);
const mode = process.argv[2];
const inventory = () => {
  const out = {}, walk = p => {
    const s = fs.lstatSync(p);
    if (s.isDirectory()) { for (const n of fs.readdirSync(p).sort()) walk(p + '/' + n); return; }
    out[p] = { mode: s.mode & 0o777, digest: s.isSymbolicLink() ? 'link:' + fs.readlinkSync(p) : createHash('sha256').update(fs.readFileSync(p)).digest('hex') };
  };
  walk('/opt/clean-vpn-native');
  for (const name of ['c2', 'exit']) {
    const manifest = JSON.parse(fs.readFileSync(`/opt/clean-vpn-native/${name}/installed.json`));
    for (const unit of manifest.units) { walk('/etc/systemd/system/' + unit); walk('/etc/systemd/system/' + unit + '.d'); }
    walk(`/etc/systemd/system/multi-user.target.wants/native-${name}.target`);
  }
  return out;
};
const ctl = (...args) => execFileSync('/usr/bin/systemctl', args, { encoding: 'utf8', timeout: 20000 }).trim();
if (mode === 'prepare') {
  assert.deepEqual(fs.readdirSync('/sys/class/net'), ['lo']);
  const phase = fs.existsSync('/state/inventory.json') ? 1 : 0;
  if (phase) {
    for (const dir of ['opt/clean-vpn-native', 'etc/systemd/system']) fs.cpSync('/state/installed/' + dir, '/' + dir, { recursive: true, verbatimSymlinks: true });
    assert.deepEqual(inventory(), JSON.parse(fs.readFileSync('/state/inventory.json')));
    fs.mkdirSync('/etc/systemd/system/native-lab-driver.service.d', { recursive: true });
    // The observer must outlive the target/default units it deliberately stops.
    fs.writeFileSync('/etc/systemd/system/native-lab-driver.service.d/order.conf', '[Unit]\nAfter=native-c2.target native-exit.target native-lab-defaults.service\nWants=native-lab-defaults.service\n');
    fs.writeFileSync('/run/native-site-reboot', '1');
  }
  console.log('NATIVE_SITE_BOOT ' + JSON.stringify({ phase, bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() }));
} else if (mode === 'save') {
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  ctl('enable', 'native-c2.target', 'native-exit.target');
  fs.mkdirSync('/state/installed/opt', { recursive: true });
  fs.mkdirSync('/state/installed/etc/systemd/system', { recursive: true });
  fs.cpSync('/opt/clean-vpn-native', '/state/installed/opt/clean-vpn-native', { recursive: true });
  // Fixture units contain only fixed topology and namespace overrides.
  fs.cpSync('/etc/systemd/system', '/state/installed/etc/systemd/system', { recursive: true, verbatimSymlinks: true });
  fs.writeFileSync('/state/inventory.json', JSON.stringify(inventory()));
  execFileSync('/bin/busybox', ['sync']); execFileSync('/bin/busybox', ['mount', '-o', 'remount,ro', '/state']);
} else if (mode === 'verify') {
  assert.deepEqual(inventory(), JSON.parse(fs.readFileSync('/state/inventory.json')));
  for (const name of ['c2', 'exit']) {
    const guard = Number(ctl('show', `native-${name}-network.service`, '-p', 'ActiveEnterTimestampMonotonic', '--value'));
    const gate = Number(ctl('show', `native-${name}-uplink.service`, '-p', 'ExecMainStartTimestampMonotonic', '--value'));
    assert.ok(guard > 0 && gate >= guard, 'guard_before_link_activation');
  }
  console.log('NATIVE_NETWORK_REBOOT_INVENTORY_AND_ORDER_PASS');
} else throw Error('mode');
