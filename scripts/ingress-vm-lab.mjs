#!/usr/bin/env node
/** Opt-in CLI/TUN acceptance in a NIC-less VM. Reuses the trusted initramfs packer, not DNS lifecycle. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, readdir } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildDnsVmImage, verifyVmPackages, sha256 } from './lib/dns-vm-image.mjs';

const flags = new Map();
for (const arg of process.argv.slice(2)) {
  const match = /^--(tools|kernel|resolved|verified-report)=(\/[^\n\r,]+)$/.exec(arg);
  assert.ok(match && !flags.has(match[1]), 'absolute --tools=DIR --kernel=FILE --resolved=FILE required');
  flags.set(match[1], match[2]);
}
for (const key of ['tools', 'kernel', 'resolved']) assert.ok(flags.has(key), `missing --${key}`);
process.umask(0o077);
const directory = await mkdtemp(join(tmpdir(), 'meshpn-ingress-vm-'));
console.error(`Ingress VM artifacts: ${directory}`);
const root = join(flags.get('tools'), 'root');
const report = { schema: 1, status: 'failed', nic: 'none', hostSharedFilesystem: false, transports: [] };
try {
  if (flags.has('verified-report')) {
    // Explicit trust in a previous, locally retained successful lab report; never an automatic fallback.
    const bytes = await readFile(flags.get('verified-report')), previous = JSON.parse(bytes);
    assert.equal(previous.status, 'passed'); assert.ok(Array.isArray(previous.packages));
    const packages = [];
    for (const name of (await readdir(flags.get('tools'))).filter((n) => n.endsWith('.deb')).sort()) {
      const digest = sha256(await readFile(join(flags.get('tools'), name)));
      const matches = previous.packages.filter((p) => p.sha256 === digest);
      assert.equal(matches.length, 1, `package not in trusted previous report: ${name}`); packages.push(matches[0]);
    }
    assert.equal(packages.length, previous.packages.length);
    assert.ok(packages.some((p) => p.package === 'qemu-system-x86'));
    assert.ok(packages.some((p) => p.package === 'busybox-static'));
    report.packages = packages; report.packageTrust = { previousReport: flags.get('verified-report'), sha256: sha256(bytes) };
  } else report.packages = await verifyVmPackages(flags.get('tools'));
  const image = await buildDnsVmImage({ directory, toolsRoot: root, kernel: flags.get('kernel'), resolved: flags.get('resolved'), ingress: true });
  report.image = image.manifest;
  const env = { ...process.env, LD_LIBRARY_PATH: `${root}/usr/lib/x86_64-linux-gnu:${root}/lib/x86_64-linux-gnu`,
    QEMU_MODULE_DIR: `${root}/usr/lib/x86_64-linux-gnu/qemu` };
  for (const key of ['LD_PRELOAD', 'LD_AUDIT', 'QEMU_AUDIO_DRV']) delete env[key];
  const child = spawn(join(root, 'usr/bin/qemu-system-x86_64'), [
    '-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot',
    '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1', '-machine', 'pc,dump-guest-core=off',
    '-bios', `${root}/usr/share/seabios/bios-256k.bin`, '-L', `${root}/usr/share/qemu`,
    '-kernel', image.kernel, '-initrd', image.initrd, '-append', 'console=ttyS0 loglevel=7 panic=-1 reboot=t random.trust_cpu=on',
  ], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = createWriteStream(join(directory, 'serial.log'), { flags: 'wx', mode: 0o600 });
  let bytes = 0, pending = '', passed = false, failure;
  const abort = (reason) => { failure ??= reason; child.kill('SIGKILL'); };
  const interrupt = () => abort('interrupted');
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const timer = setTimeout(() => abort('VM deadline exceeded'), 900000);
  log.on('error', (error) => abort(error.message));
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (b) => {
    bytes += b.length;
    if (bytes > 512 * 1024) { abort('serial output limit'); return; }
    log.write(b);
    if (stream !== child.stdout) return;
    pending += b;
    for (;;) {
      const end = pending.indexOf('\n'); if (end < 0) break;
      const line = pending.slice(0, end).trim(); pending = pending.slice(end + 1);
      if (line === 'INGRESS_VM_PASS') passed = true;
      if (/INGRESS_VM_FAIL|Kernel panic/.test(line)) abort('guest failed');
      if (line.startsWith('# {"status":"passed"') || line.startsWith('{"status":"passed"')) {
        try { const evidence = JSON.parse(line.replace(/^# /, '')); report.transports.push(evidence); console.error(`VM ${evidence.actualTransportTested}: ${evidence.checks.length} checks passed`); }
        catch (error) { abort(error.message); }
      }
    }
  });
  let exit;
  try { exit = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve(code)); }); }
  finally { clearTimeout(timer); process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt); await new Promise((resolve) => log.end(resolve)); }
  assert.equal(failure, undefined, failure); assert.equal(exit, 0); assert.equal(passed, true);
  assert.deepEqual(report.transports.map((v) => v.actualTransportTested), ['tls', 'boring-tls', 'transparent-tls', 'combo-tls']);
  assert.ok(report.transports.every((v) => v.hostNetworkChanged === false && v.checks.length >= 12));
  report.status = 'passed';
} catch (error) { report.error = error.message; process.exitCode = 1; console.error(error.stack); }
finally {
  await writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.error(`Report: ${directory}/report.json`);
}
