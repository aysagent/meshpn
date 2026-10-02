#!/usr/bin/env node
/** Host runner: no host clock/network writes. Only a disposable, NIC-less QEMU VM. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
const [base, tools] = process.argv.slice(2);
assert.ok(base?.startsWith('/') && tools?.startsWith('/'), 'absolute passed host-boot artifacts and extracted QEMU tools required');
const previous = JSON.parse(fs.readFileSync(join(base, 'report.json')));
assert.equal(previous.status, 'passed'); assert.equal(previous.nic, 'none'); assert.equal(previous.hostSharedFilesystem, false);
const hash = b => createHash('sha256').update(b).digest('hex');
assert.equal(hash(fs.readFileSync(join(base, 'guest-kernel'))), previous.image.kernelSha256);
const space = fs.statfsSync('/var/tmp'); assert.ok(space.bavail * space.bsize > 768 * 1024 * 1024);
const root = fs.mkdtempSync('/var/tmp/meshpn-http-date-lab-'); console.error(root);
const guest = join(root, 'guest'), initrd = join(root, 'initrd.gz');
const sources = ['scripts/clean-vpn.js', 'scripts/lib/vpn-http-date.mjs', 'scripts/lib/vpn-http-date-fixture.mjs',
  'scripts/lib/vpn-http-date-vm.mjs', 'scripts/fixtures/boring-tls-local.cert.pem', 'scripts/fixtures/boring-tls-local.key.pem'];
const report = { kind: 'clean-vpn-http-date-lab', status: 'failed', nic: 'none', hostSharedFilesystem: false, base,
  sourceHashes: Object.fromEntries(sources.map(p => [p, hash(fs.readFileSync(p))])) };
const put = (p, data, mode = 0o644) => { const dst = join(guest, p); fs.mkdirSync(dst.slice(0, dst.lastIndexOf('/')), { recursive: true }); fs.writeFileSync(dst, data, { mode }); };
try {
  fs.cpSync(join(base, 'guest'), guest, { recursive: true, verbatimSymlinks: true });
  for (const path of sources) put('/project/' + path, fs.readFileSync(path));
  put('/usr/bin/date', fs.readFileSync('/usr/bin/date'), 0o755);
  for (const lib of execFileSync('ldd', ['/usr/bin/date'], { encoding: 'utf8' }).match(/\/[^\s()]+/g) ?? []) put(lib, fs.readFileSync(lib), 0o755);
  const old = fs.readFileSync(join(guest, 'init'), 'utf8'); assert.ok(old.includes('mount -t ext4'));
  put('/init', old.slice(0, old.indexOf('mount -t ext4')) + 'node /project/scripts/lib/vpn-http-date-vm.mjs\npoweroff -f\n', 0o755);
  const files = ['.'];
  const walk = p => { for (const n of fs.readdirSync(join(guest, p))) { const q = p ? p + '/' + n : n; files.push(q); if (fs.lstatSync(join(guest, q)).isDirectory()) walk(q); } }; walk('');
  const archive = execFileSync('cpio', ['-o', '-H', 'newc', '--owner=0:0', '--quiet'], { cwd: guest, input: files.join('\n') + '\n', maxBuffer: 256 * 1024 * 1024 });
  fs.writeFileSync(initrd, gzipSync(archive, { level: 1 }));
  const env = { ...process.env, LD_LIBRARY_PATH: `${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`, QEMU_MODULE_DIR: `${tools}/usr/lib/x86_64-linux-gnu/qemu` };
  delete env.LD_PRELOAD; delete env.LD_AUDIT;
  const child = spawn(join(tools, 'usr/bin/qemu-system-x86_64'), ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1', '-bios', `${tools}/usr/share/seabios/bios-256k.bin`, '-L', `${tools}/usr/share/qemu`, '-kernel', join(base, 'guest-kernel'), '-initrd', initrd, '-append', 'console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.http-date-lab=1'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; const fd = fs.openSync(join(root, 'boot.log'), 'wx');
  const timer = setTimeout(() => child.kill('SIGKILL'), 240000);
  for (const stream of [child.stdout, child.stderr]) stream.on('data', b => { fs.writeSync(fd, b); output += b; if (output.length > 1024 * 1024 || output.includes('Kernel panic')) child.kill('SIGKILL'); });
  try { report.code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); }); }
  finally { clearTimeout(timer); fs.closeSync(fd); }
  report.checks = output.split('\n').filter(line => line.includes('HTTP_DATE_CHECK'));
  assert.equal(report.code, 0); assert.ok(output.includes('HTTP_DATE_PASS') && !output.includes('HTTP_DATE_FAIL'), `inspect ${root}/boot.log`);
  report.status = 'passed';
} finally {
  fs.writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2));
  // Exact paths inside this runner's newly allocated directory; keep logs/report.
  fs.rmSync(guest, { recursive: true, force: true }); fs.rmSync(initrd, { force: true });
  console.error('Report: ' + join(root, 'report.json'));
}
