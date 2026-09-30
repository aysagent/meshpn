#!/usr/bin/env node
/** NIC-less QEMU only: actual installation, persistent disk and three kernel boots. */
import assert from 'node:assert/strict';
import { mkdtemp, open, readFile, writeFile, readdir } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildDnsVmImage, sha256 } from './lib/dns-vm-image.mjs';
import { assertHostBootEvidence } from './lib/vpn-host-boot-evidence.mjs';

const args = new Map();
for (const arg of process.argv.slice(2)) {
  const m = /^--(tools|kernel|resolved|dns-conntrack|dnsmasq|verified-report)=(\/[^\r\n,]+)$/.exec(arg);
  assert.ok(m && !args.has(m[1]), 'six unique absolute tool/report paths required'); args.set(m[1], m[2]);
}
for (const key of ['tools', 'kernel', 'resolved', 'dns-conntrack', 'dnsmasq', 'verified-report']) assert.ok(args.has(key), `missing --${key}`);
process.umask(0o077);
const directory = await mkdtemp(join(tmpdir(), 'meshpn-host-boot-'));
console.error(`Host boot VM artifacts: ${directory}`);
const report = { schema: 1, kind: 'clean-vpn-host-boot-lab', status: 'failed', nic: 'none', hostSharedFilesystem: false, boots: [], acceptance: 'not-ready-for-deployment' };
try {
  const previousBytes = await readFile(args.get('verified-report')), previous = JSON.parse(previousBytes);
  assert.equal(previous.status, 'passed'); assert.ok(Array.isArray(previous.packages));
  const packages = [];
  for (const name of (await readdir(args.get('tools'))).filter(n => n.endsWith('.deb')).sort()) {
    const digest = sha256(await readFile(join(args.get('tools'), name)));
    const entries = previous.packages.filter(p => p.sha256 === digest); assert.equal(entries.length, 1); packages.push(entries[0]);
  }
  assert.equal(packages.length, previous.packages.length); assert.ok(packages.some(p => p.package === 'qemu-system-x86')); assert.ok(packages.some(p => p.package === 'busybox-static'));
  report.packages = packages; report.packageTrust = { previousReport: args.get('verified-report'), sha256: sha256(previousBytes) };
  const root = join(args.get('tools'), 'root');
  const image = await buildDnsVmImage({ directory, toolsRoot: root, kernel: args.get('kernel'), resolved: args.get('resolved'), dnsConntrack: args.get('dns-conntrack'), bootDnsmasq: args.get('dnsmasq'), ingress: true, ipv6: true, hostSystemd: true, hostNetworkd: true, hostColdBoot: true });
  report.image = image.manifest;
  const disk = join(directory, 'state.raw'), fd = await open(disk, 'wx', 0o600);
  try { await fd.truncate(256 * 1024 * 1024); } finally { await fd.close(); }
  await promisify(execFile)('/usr/sbin/mke2fs', ['-q', '-F', '-t', 'ext4', '-O', '^metadata_csum_seed,^orphan_file', disk], { timeout: 30000 });
  for (let phase = 0; phase < 3; phase++) {
    console.error(`Host boot VM: phase ${phase} (${phase === 0 ? 'install' : phase === 1 ? 'cold boot / late DHCP' : 'reboot / guard failure'})`);
    const env = { ...process.env, LD_LIBRARY_PATH: `${root}/usr/lib/x86_64-linux-gnu:${root}/lib/x86_64-linux-gnu`, QEMU_MODULE_DIR: `${root}/usr/lib/x86_64-linux-gnu/qemu` };
    for (const key of ['LD_PRELOAD', 'LD_AUDIT', 'QEMU_AUDIO_DRV']) delete env[key];
    const proc = spawn(join(root, 'usr/bin/qemu-system-x86_64'), ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1024', '-smp', '1', '-machine', 'pc,dump-guest-core=off', '-bios', `${root}/usr/share/seabios/bios-256k.bin`, '-L', `${root}/usr/share/qemu`, '-kernel', image.kernel, '-initrd', image.initrd, '-append', 'console=ttyS0 loglevel=7 panic=-1 reboot=t random.trust_cpu=on meshpn.host-cold-boot=1', '-drive', `file=${disk},format=raw,if=virtio,cache=writeback`], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const output = createWriteStream(join(directory, `boot-${phase}.log`), { flags: 'wx', mode: 0o600 });
    const boot = { phase, events: [], kernelRestart: false, powerDown: false, synced: false, unmounted: false }; report.boots.push(boot);
    let pending = '', bytes = 0, failure;
    const abort = why => { failure ??= why; proc.kill('SIGKILL'); };
    const interrupt = () => abort('interrupted'); process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
    const timer = setTimeout(() => abort('boot deadline exceeded'), 20 * 60 * 1000);
    output.on('error', e => abort(e.message));
    for (const stream of [proc.stdout, proc.stderr]) stream.on('data', b => {
      bytes += b.length; if (bytes > 512 * 1024) { abort('serial output limit'); return; } output.write(b);
      if (stream !== proc.stdout) return; pending += b;
      for (;;) {
        const at = pending.indexOf('\n'); if (at < 0) break; const line = pending.slice(0, at).trim(); pending = pending.slice(at + 1);
        boot.kernelRestart ||= /reboot: Restarting system/.test(line); boot.powerDown ||= /reboot: Power down/.test(line);
        boot.synced ||= /Syncing filesystems and block devices/.test(line); boot.unmounted ||= /All filesystems unmounted/.test(line);
        if (/Kernel panic/.test(line)) abort('kernel panic');
        const marker = line.indexOf('HOST_BOOT_EVENT ');
        if (marker >= 0) try {
          const e = JSON.parse(line.slice(marker + 16)); boot.events.push(e);
          if (e.event === 'failed') abort(e.message);
          if (e.event === 'check') console.error(`boot ${phase}: ${e.name}`);
        } catch (e) { abort(e.message); }
        if (/host-boot-driver.service: Failed with result/.test(line) && !boot.events.some(e => ['reboot-ready', 'passed'].includes(e.event))) abort('boot driver failed');
      }
    });
    try { boot.exitCode = await new Promise((resolve, reject) => { proc.once('error', reject); proc.once('close', code => resolve(code)); }); }
    finally { clearTimeout(timer); process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt); await new Promise(resolve => output.end(resolve)); }
    assert.equal(failure, undefined, failure); assert.equal(boot.exitCode, 0);
    assert.equal(boot.kernelRestart, phase < 2); assert.equal(boot.powerDown, phase === 2); assert.equal(boot.synced, true); assert.equal(boot.unmounted, true);
  }
  assertHostBootEvidence({ ...report, acceptance: 'lab-ready-for-host-review' });
  report.acceptance = 'lab-ready-for-host-review'; report.status = 'passed';
} catch (e) { report.error = e.message; process.exitCode = 1; console.error(e.stack); }
finally { await writeFile(join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); console.error(`Report: ${directory}/report.json`); }
