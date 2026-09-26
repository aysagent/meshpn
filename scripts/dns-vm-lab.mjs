#!/usr/bin/env node
/** Explicit opt-in, disposable, NIC-less QEMU TCG lab. Never installs host services. */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { openSync, writeSync, closeSync } from 'node:fs';
import { promisify } from 'node:util';
import { mkdtemp, open, writeFile, readFile, lstat, readlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { buildDnsVmImage, verifyVmPackages, sha256 } from './lib/dns-vm-image.mjs';
import { qemuDnsArgs, VM_FAULTS, vmCases, assertVmFaultEvidence, assertVmSystemdEvidence, assertVmDnsmasqEvidence, vmSerialEvent } from './lib/dns-vm-protocol.mjs';

const exec = promisify(execFile);
async function main() {
  const flags = new Map();
  for (const arg of process.argv.slice(2)) {
    const match = /^--(tools|kernel|resolved|case|dnsmasq)=(.+)$/.exec(arg);
    assert.ok(match && !flags.has(match[1]), 'expected --tools=DIR --kernel=FILE --resolved=FILE [--case=all|faults|systemd|dnsmasq|cycle|CASE] [--dnsmasq=FILE]');
    flags.set(match[1], match[2]);
  }
  for (const key of ['tools', 'kernel', 'resolved']) assert.ok(flags.get(key)?.startsWith('/'), `absolute --${key} required`);
  const cases = vmCases(flags.get('case'));
  const dnsmasq = flags.get('case') === 'dnsmasq';
  assert.ok(dnsmasq ? flags.get('dnsmasq')?.startsWith('/') : !flags.has('dnsmasq'), 'absolute --dnsmasq required only for --case=dnsmasq');
  const systemd = dnsmasq || flags.get('case') === 'systemd';
  const tools = resolve(flags.get('tools')), root = join(tools, 'root');
  const packages = await verifyVmPackages(tools);
  const env = { ...process.env, LD_LIBRARY_PATH: `${root}/usr/lib/x86_64-linux-gnu:${root}/lib/x86_64-linux-gnu`,
    QEMU_MODULE_DIR: `${root}/usr/lib/x86_64-linux-gnu/qemu` };
  for (const key of ['LD_PRELOAD', 'LD_AUDIT', 'QEMU_AUDIO_DRV']) delete env[key];
  const qemu = join(root, 'usr/bin/qemu-system-x86_64');
  const version = (await exec(qemu, ['--version'], { env, timeout: 10000 })).stdout.split('\n')[0];
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-vm-')); process.umask(0o077);
  console.error(`VM artifacts: ${directory}`);
  const hostSnapshot = async () => Object.fromEntries(await Promise.all(['/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group'].map(async (path) => {
    const stat = await lstat(path);
    return [path, { dev: stat.dev, ino: stat.ino, mode: stat.mode, target: stat.isSymbolicLink() ? await readlink(path) : null,
      hash: await readFile(path).then(sha256).catch((e) => { if (e.code === 'ENOENT') return null; throw e; }) }];
  })));
  const before = await hostSnapshot();
  const report = { schema: 1, kind: 'clean-vpn-dns-vm-lab', status: 'failed', version, packages,
    nic: 'none', accelerator: 'tcg', diskCache: 'writeback', hostSharedFilesystem: false,
    systemdPid1: systemd, ...(dnsmasq ? { backend: 'dnsmasq' } : {}), physicalPowerLossTested: false, inProcessHotResetTested: false, cases: [] };
  try {
    const image = await buildDnsVmImage({ directory, toolsRoot: root, kernel: flags.get('kernel'), resolved: flags.get('resolved'), systemd,
      dnsmasq: dnsmasq ? flags.get('dnsmasq') : null });
    report.image = { kernelSha256: image.manifest.kernelSha256, initrdSha256: image.manifest.initrdSha256 };
    let launchNumber = 0;
    async function launch(disk, phase, point, expectReboot = false) {
      const args = qemuDnsArgs({ root, ...image, disk, phase, point });
      const events = []; let pending = '', failure, killedAtCheckpoint = false, logBytes = 0, kernelRestart = false, shutdownSynced = false, shutdownUnmounted = false;
      const log = join(directory, `serial-${++launchNumber}.log`);
      const logFd = openSync(log, 'wx', 0o600);
      const proc = spawn(qemu, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
      const abort = (error) => { failure ??= error; proc.kill('SIGKILL'); };
      const capture = (data) => {
        logBytes += data.length;
        if (logBytes > 256 * 1024) { abort(new Error('VM serial output limit')); return; }
        try { assert.equal(writeSync(logFd, data), data.length, 'incomplete serial log write'); } catch (error) { abort(error); }
      };
      const onSignal = () => abort(new Error('VM lab interrupted'));
      process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal);
      const deadlineMs = systemd ? 900000 : 240000;
      const timer = setTimeout(() => abort(new Error(`VM deadline exceeded (${deadlineMs / 1000} seconds)`)), deadlineMs);
      proc.on('error', (error) => { failure ??= error; });
      proc.stderr.on('data', capture);
      proc.stdout.on('data', (data) => {
        capture(data); pending += data;
        if (pending.length > 65536) return abort(new Error('oversized serial line'));
        for (;;) {
          const end = pending.indexOf('\n'); if (end < 0) break;
          const line = pending.slice(0, end).replace(/\x1b\[[0-9;]*m/g, '').trim(); pending = pending.slice(end + 1);
          if (/Freezing execution\.|Kernel panic - not syncing/.test(line)) abort(new Error('guest init/kernel failed'));
          if (/dns-vm-driver\.service: Failed with result/.test(line)) abort(new Error('systemd acceptance driver failed'));
          if (/\.mount: Mount process exited,.*status=203\/EXEC/.test(line)) abort(new Error('guest mount helper missing'));
          if (/reboot: Restarting system$/.test(line)) kernelRestart = true;
          if (/^(?:.*systemd-shutdown[^:]*: )?Syncing filesystems and block devices\.$/.test(line)) shutdownSynced = true;
          if (/^(?:.*systemd-shutdown[^:]*: )?All filesystems unmounted\.$/.test(line)) shutdownUnmounted = true;
          if (line === 'DNS_VM_GUEST_FAILURE') abort(new Error('guest init failed'));
          try {
            const event = vmSerialEvent(line); if (!event) continue;
            assert.ok(events.length < 32); events.push(event);
            console.error(`VM ${phase}/${point}: ${event.event}`);
            if (event.event === 'failed') abort(new Error(event.message));
            if (event.event === 'cut-ready') {
              assert.equal(phase, 'cut'); assert.equal(event.point, point); assert.equal(killedAtCheckpoint, false);
              killedAtCheckpoint = true; proc.kill('SIGKILL');
            }
          } catch (error) { abort(error); }
        }
      });
      let exit;
      try { exit = await new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal }))); }
      finally { clearTimeout(timer); process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal); closeSync(logFd); }
      if (failure) throw new Error(`${failure.message}\nSerial log: ${log}`);
      if (phase === 'cut') { assert.equal(killedAtCheckpoint, true); assert.equal(exit.signal, 'SIGKILL'); }
      else {
        assert.equal(exit.code, 0, `QEMU exit; serial log: ${log}`);
        assert.equal(events.filter((e) => e.event === 'passed').length, expectReboot ? 0 : 1, `guest result missing; serial log: ${log}`);
        assert.equal(events.filter((e) => e.event === 'reboot-ready').length, expectReboot ? 1 : 0, `unexpected reboot; serial log: ${log}`);
        assert.equal(events.filter((e) => e.event === 'reboot-committed').length, expectReboot && !systemd ? 1 : 0, `missing sync/remount-ro; serial log: ${log}`);
        if (systemd) { assert.equal(shutdownSynced, true, `systemd shutdown sync missing: ${log}`); assert.equal(shutdownUnmounted, true, `systemd unmount missing: ${log}`); }
        assert.equal(kernelRestart, expectReboot, `guest reboot request not observed; serial log: ${log}`);
      }
      return events;
    }
    for (const point of cases) {
      const fault = VM_FAULTS.includes(point);
      const disk = join(directory, `state-${report.cases.length}.raw`);
      const fd = await open(disk, 'wx', 0o600); try { await fd.truncate(256 * 1024 * 1024); } finally { await fd.close(); }
      await exec('mke2fs', ['-q', '-F', '-t', 'ext4', '-O', '^metadata_csum_seed,^orphan_file', disk], { timeout: 30000 });
      let events;
      if (systemd) events = [...await launch(disk, dnsmasq ? 'dnsmasq' : 'systemd', point, true), ...await launch(disk, dnsmasq ? 'dnsmasq' : 'systemd', point)];
      else if (fault) events = await launch(disk, 'fault', point);
      else if (point === 'none') events = [...await launch(disk, 'cycle', point, true), ...await launch(disk, 'cycle', point)];
      else events = [...await launch(disk, 'cut', point), ...await launch(disk, 'inspect', point)];
      const boots = events.filter((e) => e.event === 'boot-guard').map((e) => e.bootId);
      assert.equal(boots.length, fault ? 1 : 2);
      if (!fault) assert.notEqual(boots[0], boots[1]);
      const passed = events.find((e) => e.event === 'passed');
      if (fault) assertVmFaultEvidence(point, passed.fault);
      else assert.equal(passed.previousBootId, boots[0]);
      if (systemd) { (dnsmasq ? assertVmDnsmasqEvidence : assertVmSystemdEvidence)(passed); assert.ok(events.filter((e) => e.event === 'boot-guard').every((e) => e.pid1 === 'systemd')); }
      assert.equal(passed.bootId, boots.at(-1));
      report.cases.push({ point, gracefulReboot: point === 'none' || systemd, qemuRelaunched: !fault, guestPowerCut: !fault && point !== 'none' && !systemd, ...passed });
    }
    report.status = 'passed';
  } catch (error) { report.error = error.message; throw error; }
  finally {
    report.hostDnsFilesUnchanged = JSON.stringify(await hostSnapshot()) === JSON.stringify(before);
    if (!report.hostDnsFilesUnchanged) report.status = 'failed';
    await writeFile(join(directory, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    console.error(`Report: ${directory}/report.json`);
  }
  assert.equal(report.status, 'passed'); console.log(JSON.stringify(report, null, 2));
}
main().catch((error) => { console.error(error.stack); process.exitCode = 1; });
