#!/usr/bin/env node
/** Reuses a passed NIC-less host-boot image. All networking changes are in QEMU. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { addUsbMssVmImage } from './lib/usb-mss-vm-image.mjs';
const base = resolve(process.argv[2] ?? '');
const gateway = process.argv[4] === '--gateway';
assert.ok([3, 4].includes(process.argv.length) || process.argv.length === 5 && gateway, 'usage: BASE [TOOLS [--gateway]]');
assert.ok(process.argv[2]?.startsWith('/'), 'absolute passed host boot artifact directory required');
const previous = JSON.parse(fs.readFileSync(join(base, 'report.json')));
assert.equal(previous.status, 'passed'); assert.equal(previous.nic, 'none');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(hash(fs.readFileSync(join(base, 'guest-kernel'))), previous.image.kernelSha256);
const space = fs.statfsSync('/var/tmp');
assert.ok(space.bavail * space.bsize >= 768 * 1024 * 1024, 'at least 768 MiB free in /var/tmp required');
const root = fs.mkdtempSync(gateway ? '/var/tmp/meshpn-usb-gateway-lab-' : '/var/tmp/meshpn-usb-rescue-lab-');
console.error('USB rescue VM artifacts: ' + root);
const guest = join(root, 'guest'); fs.cpSync(join(base, 'guest'), guest, { recursive: true, verbatimSymlinks: true });
const put = (path, value, mode = 0o644) => {
  const dst = join(guest, path); fs.mkdirSync(dst.slice(0, dst.lastIndexOf('/')), { recursive: true });
  fs.writeFileSync(dst, value, { mode });
};
const sources = ['scripts/clean-vpn-usb-rescue.mjs', 'scripts/lib/host-usb-rescue.mjs', 'scripts/lib/host-usb-rescue-vm.mjs', 'scripts/autostart/killswitch.sh'];
if (gateway) sources.push('scripts/lib/host-usb-gateway.mjs', 'scripts/lib/host-usb-gateway-vm.mjs', 'scripts/clean-vpn-usb-snat.mjs',
  'scripts/lib/host-update.mjs', 'scripts/lib/host-uninstall.mjs', 'scripts/fixtures/usb-gateway-pre-mss.txt', 'scripts/lib/usb-mss-vm-image.mjs');
for (const path of sources) put('/project/' + path, fs.readFileSync(path));
if (gateway) fs.symlinkSync('/usr/bin/ip', join(guest, 'usr/sbin/ip')); // Debian Radxa executable layout
// Host OS executables only, never host keys or SSH/PAM configuration.
const binaries = ['/usr/sbin/sshd', '/usr/bin/ssh', '/usr/bin/ssh-keygen', '/usr/bin/systemd-analyze', '/usr/bin/ss'];
for (const path of binaries) {
  put(path, fs.readFileSync(path), 0o755);
  const libs = execFileSync('ldd', [path], { encoding: 'utf8' }).match(/\/[^\s()]+/g) ?? [];
  for (const lib of libs) put(lib, fs.readFileSync(lib), 0o755);
}
fs.symlinkSync('/bin/busybox', join(guest, 'usr/bin/awk'));
put('/etc/systemd/system/default.target', '[Unit]\nDefaultDependencies=no\nWants=usb-rescue-test.service systemd-udev-trigger.service multi-user.target\n');
put('/etc/systemd/system/usb-rescue-test.service', '[Unit]\nAfter=systemd-udev-trigger.service dbus.service\nRequires=systemd-udev-trigger.service\nWants=dbus.service\n[Service]\nType=oneshot\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin\nEnvironmentFile=/etc/usb-rescue-lab.env\nExecStart=/usr/bin/node /project/scripts/lib/host-usb-rescue-vm.mjs test\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=240\n');
put('/etc/systemd/system/clean-vpn-killswitch.service', '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/false\n');
for (const unit of ['systemd-networkd.service', 'systemd-networkd.socket']) put(`/etc/systemd/system/${unit}.d/90-rescue-test.conf`, '[Unit]\nRequires=clean-vpn-killswitch.service\nAfter=clean-vpn-killswitch.service\n');
put('/etc/systemd/system/primary-ssh.service', '[Service]\nExecStart=/usr/sbin/sshd -D -e\nRuntimeDirectory=sshd\nRuntimeDirectoryPreserve=yes\nStandardError=append:/run/primary-ssh.log\n');
const addon = gateway ? addUsbMssVmImage(fs.readFileSync(join(guest, 'init'), 'utf8'), put) : null;
const oldInit = addon?.init ?? fs.readFileSync(join(guest, 'init'), 'utf8');
assert.ok(oldInit.includes('mount -t ext4'));
const init = oldInit.slice(0, oldInit.indexOf('mount -t ext4'));
const report = { kind: 'clean-vpn-usb-rescue-lab', status: 'failed', nic: 'none', hostSharedFilesystem: false,
  base, baseReportSha256: hash(fs.readFileSync(join(base, 'report.json'))),
  sourceHashes: Object.fromEntries(sources.map(p => [p, hash(fs.readFileSync(p))])), boots: [] };
if (gateway) {
  report.mssImageHashes = addon.hashes;
  report.kind = 'clean-vpn-usb-gateway-lab';
  report.limitations = ['VPN-service-readiness-fixture-not-real-TLS', 'veth-not-physical-USB',
    'second-boot-recreates-installed-files-not-persistent-disk', 'no-full-shell-installer-in-this-VM'];
}
// Use the same already-verified QEMU tools as the base test.
const manifest = JSON.parse(fs.readFileSync(previous.packageTrust.previousReport));
const toolCandidate = previous.packages.find(p => p.package === 'qemu-system-x86');
assert.ok(toolCandidate && manifest.status === 'passed');
const toolRoot = resolve(manifest.toolsRoot ?? '/var/tmp/meshpn-dns-vm-tools/root');
// Optional explicit tools root (location is not an authority to change networking).
const tools = process.argv[3] ? resolve(process.argv[3]) : toolRoot;
assert.ok(fs.existsSync(join(tools, 'usr/bin/qemu-system-x86_64')), 'supply extracted verified QEMU tools root as third argument');
try {
  for (const phase of ['install', 'installed']) {
    put('/etc/usb-rescue-lab.env', `USB_RESCUE_BOOT=${phase}\nUSB_GATEWAY_LAB=${gateway ? 1 : 0}\n`);
    put('/init', init + `export USB_RESCUE_BOOT=${phase}\nexport USB_GATEWAY_LAB=${gateway ? 1 : 0}\nnode scripts/lib/host-usb-rescue-vm.mjs prepare\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no\n`, 0o755);
    const files = ['.'];
    const walk = path => { for (const name of fs.readdirSync(join(guest, path))) { const p = path ? path + '/' + name : name; files.push(p); if (fs.lstatSync(join(guest, p)).isDirectory()) walk(p); } }; walk('');
    const archive = execFileSync('cpio', ['-o', '-H', 'newc', '--owner=0:0', '--quiet'], { cwd: guest, input: files.join('\n') + '\n', maxBuffer: 256 * 1024 * 1024 });
    const initrd = join(root, `${phase}.gz`); fs.writeFileSync(initrd, gzipSync(archive, { level: 1 }));
    const env = { ...process.env, LD_LIBRARY_PATH: `${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`, QEMU_MODULE_DIR: `${tools}/usr/lib/x86_64-linux-gnu/qemu` };
    delete env.LD_PRELOAD; delete env.LD_AUDIT;
    const p = spawn(join(tools, 'usr/bin/qemu-system-x86_64'), ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1', '-bios', `${tools}/usr/share/seabios/bios-256k.bin`, '-L', `${tools}/usr/share/qemu`, '-kernel', join(base, 'guest-kernel'), '-initrd', initrd, '-append', 'console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.usb-rescue-lab=1'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; const timer = setTimeout(() => p.kill('SIGKILL'), 300000);
    const logFd = fs.openSync(join(root, `${phase}.log`), 'wx');
    for (const stream of [p.stdout, p.stderr]) stream.on('data', b => {
      fs.writeSync(logFd, b); output += b;
      if (output.length > 1024 * 1024 || output.includes('Kernel panic')) p.kill('SIGKILL');
    });
    let code; try { code = await new Promise((res, rej) => { p.once('error', rej); p.once('close', res); }); } finally { clearTimeout(timer); fs.closeSync(logFd); }
    const checks = output.split('\n').filter(l => l.includes('USB_RESCUE_CHECK'));
    report.boots.push({ phase, code, checks }); console.error(JSON.stringify(report.boots.at(-1)));
    assert.equal(code, 0); assert.ok(output.includes('USB_RESCUE_PASS') && !output.includes('USB_RESCUE_FAIL'), `VM failed; inspect ${root}/${phase}.log`);
  }
  report.status = 'passed';
} finally {
  fs.writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2));
  // Only this invocation's reproducible image copies; keep all logs/reports.
  fs.rmSync(guest, { recursive: true, force: true });
  for (const phase of ['install', 'installed']) fs.rmSync(join(root, `${phase}.gz`), { force: true });
  console.error('Report: ' + join(root, 'report.json'));
}
