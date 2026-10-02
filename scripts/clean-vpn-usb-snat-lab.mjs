#!/usr/bin/env node
/** Builds a disposable NIC-less VM. Never changes host networking. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
const [base, tools] = process.argv.slice(2);
assert.ok(base?.startsWith('/') && tools?.startsWith('/'), 'absolute verified base and QEMU tools required');
const previous = JSON.parse(fs.readFileSync(join(base, 'report.json')));
assert.equal(previous.status, 'passed'); assert.equal(previous.nic, 'none'); assert.equal(previous.hostSharedFilesystem, false);
const hash = b => createHash('sha256').update(b).digest('hex');
assert.equal(hash(fs.readFileSync(join(base, 'guest-kernel'))), previous.image.kernelSha256);
const space = fs.statfsSync('/var/tmp'); assert.ok(space.bavail * space.bsize > 768 * 1024 * 1024);
const root = fs.mkdtempSync('/var/tmp/meshpn-usb-snat-lab-'); console.error(root);
const guest = join(root, 'guest'), initrd = join(root, 'initrd.gz');
const sources = ['scripts/clean-vpn-usb-snat.mjs', 'scripts/lib/usb-snat-vm.mjs', 'scripts/autostart/killswitch.sh',
  'scripts/lib/vpn-host-routes.mjs', 'scripts/lib/dns-tunnel-command.mjs'];
const report = { kind: 'clean-vpn-usb-snat-lab', status: 'failed', nic: 'none', hostSharedFilesystem: false,
  sourceHashes: Object.fromEntries(sources.map(p => [p, hash(fs.readFileSync(p))])),
  limitations: ['veth-model-not-VPN-TLS', 'Linux-peer-not-macOS', 'unit-readiness-fixtures', 'synthetic-UDP53-not-DNS-resolution', 'not-boot-persistence'] };
const put = (p, data, mode = 0o644) => { const dst = join(guest, p); fs.mkdirSync(dst.slice(0, dst.lastIndexOf('/')), { recursive: true }); fs.writeFileSync(dst, data, { mode }); };
try {
  fs.cpSync(join(base, 'guest'), guest, { recursive: true, verbatimSymlinks: true });
  for (const p of sources) put('/project/' + p, fs.readFileSync(p));
  const old = fs.readFileSync(join(guest, 'init'), 'utf8'); assert.ok(old.includes('mount -t ext4'));
  put('/init', old.slice(0, old.indexOf('mount -t ext4')) + 'node /project/scripts/lib/usb-snat-vm.mjs\npoweroff -f\n', 0o755);
  const files = ['.'];
  const walk = p => { for (const n of fs.readdirSync(join(guest, p))) { const q = p ? p + '/' + n : n; files.push(q); if (fs.lstatSync(join(guest, q)).isDirectory()) walk(q); } }; walk('');
  const archive = execFileSync('cpio', ['-o', '-H', 'newc', '--owner=0:0', '--quiet'], { cwd: guest, input: files.join('\n') + '\n', maxBuffer: 256 * 1024 * 1024 });
  fs.writeFileSync(initrd, gzipSync(archive, { level: 1 }));
  const env = { ...process.env, LD_LIBRARY_PATH: `${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`, QEMU_MODULE_DIR: `${tools}/usr/lib/x86_64-linux-gnu/qemu` };
  delete env.LD_PRELOAD; delete env.LD_AUDIT;
  const child = spawn(join(tools, 'usr/bin/qemu-system-x86_64'), ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1', '-bios', `${tools}/usr/share/seabios/bios-256k.bin`, '-L', `${tools}/usr/share/qemu`, '-kernel', join(base, 'guest-kernel'), '-initrd', initrd, '-append', 'console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.usb-snat-lab=1'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; const fd = fs.openSync(join(root, 'boot.log'), 'wx');
  const timer = setTimeout(() => child.kill('SIGKILL'), 150000);
  for (const s of [child.stdout, child.stderr]) s.on('data', b => { fs.writeSync(fd, b); output += b; if (output.length > 1024 * 1024 || output.includes('Kernel panic')) child.kill('SIGKILL'); });
  try { report.code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); }); }
  finally { clearTimeout(timer); fs.closeSync(fd); }
  report.checks = output.split('\n').filter(line => line.includes('USB_SNAT_CHECK'));
  assert.equal(report.code, 0); assert.ok(output.includes('USB_SNAT_PASS') && !output.includes('USB_SNAT_FAIL'), `inspect ${root}/boot.log`);
  report.status = 'passed';
} finally {
  fs.writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2));
  // Only disposable images allocated above. Keep report and log.
  fs.rmSync(guest, { recursive: true, force: true }); fs.rmSync(initrd, { force: true });
  console.error('Report: ' + join(root, 'report.json'));
}
