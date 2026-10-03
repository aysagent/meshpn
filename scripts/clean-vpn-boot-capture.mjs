#!/usr/bin/env node
/** Fixed Radxa profile: publish next-boot capture, report, or remove ONLY its gates. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isIPv4 } from 'node:net';
import { captureDir, captureName, consumers, gateText, gatePath, captureUnit } from './lib/host-boot-capture.mjs';

const run = (f, a) => execFileSync(f, a, { encoding: 'utf8', timeout: 20000, maxBuffer: 512 * 1024 });
const ctl = (...a) => run('systemctl', a).trim();
const bootId = () => fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const trusted = path => {
  for (let p = path; ; p = dirname(p)) {
    const s = fs.lstatSync(p);
    assert.ok(!s.isSymbolicLink() && s.uid === 0 && !(s.mode & 0o022), `unsafe root-owned path: ${p}`);
    if (p === '/') break;
  }
};
const absent = p => { try { fs.lstatSync(p); } catch (e) { if (e.code === 'ENOENT') return; throw e; } throw Error(`already exists: ${p}`); };
const publish = (p, value) => {
  fs.mkdirSync(dirname(p), { recursive: true, mode: 0o755 }); trusted(dirname(p));
  const stage = fs.mkdtempSync(dirname(p) + '/.boot-capture-');
  const temporary = stage + '/new';
  try {
    const fd = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.linkSync(temporary, p);
    const dir = fs.openSync(dirname(p), 'r'); try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); fs.rmdirSync(stage); }
};
const args = process.argv.slice(2);
const mode = args.find(a => ['--install', '--report', '--remove'].includes(a));
try {
  assert.equal(process.getuid(), 0, 'run with sudo');
  assert.ok(mode && args.filter(a => ['--install', '--report', '--remove'].includes(a)).length === 1,
    'Usage: --install --exit-ip=IPv4 [--apply] | --report | --remove --apply');
  assert.ok(args.every(a => [mode, '--apply'].includes(a) || (mode === '--install' && a.startsWith('--exit-ip='))), 'unknown option');
  if (mode === '--report') {
    trusted(captureDir);
    const report = JSON.parse(fs.readFileSync(`${captureDir}/report.json`, 'utf8'));
    report.currentBoot = report.bootId === bootId();
    if (!report.currentBoot) report.status = 'stale-report';
    console.log('=== CLEAN-VPN BOOT CAPTURE BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN BOOT CAPTURE END ===');
  } else {
    assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
    assert.equal(fs.readlinkSync('/proc/self/ns/net'), fs.readlinkSync('/proc/1/ns/net'));
    if (mode === '--remove') {
      trusted(captureDir); trusted(`${captureDir}/config.json`);
      const config = JSON.parse(fs.readFileSync(`${captureDir}/config.json`, 'utf8'));
      const paths = consumers.map(gatePath).filter(p => {
        try { fs.lstatSync(p); return true; } catch (e) { if(e.code === 'ENOENT') return false; throw e; }
      });
      for (const p of paths) { trusted(p); assert.equal(fs.readFileSync(p, 'utf8'), gateText, `modified gate: ${p}`); }
      const unit = `/etc/systemd/system/${captureName}.service`;
      let unitPresent = true;
      try { fs.lstatSync(unit); } catch(e) { if(e.code === 'ENOENT') unitPresent = false; else throw e; }
      if (unitPresent) { trusted(unit); assert.equal(fs.readFileSync(unit, 'utf8'), captureUnit(config.node)); }
      if (args.includes('--apply')) {
        // Removing dependency files, NOT stopping their units. Existing guard gates stay.
        for (const p of paths) fs.unlinkSync(p);
        if (unitPresent) fs.unlinkSync(unit); run('systemctl', ['daemon-reload']);
      }
      console.log(JSON.stringify({ status: args.includes('--apply') ? 'capture-gates-removed' : 'remove-plan',
        networkRestarted: false, guardAndRescueChanged: false, reportsAndHelperRetained: true }));
    } else {
      const exitIp = args.find(a => a.startsWith('--exit-ip='))?.slice(10);
      assert.ok(isIPv4(exitIp), '--exit-ip must be a literal IPv4 address');
      assert.equal(ctl('is-active', 'clean-vpn-usb-rescue.socket'), 'active', 'USB rescue must already be active');
      assert.equal(ctl('is-active', 'clean-vpn-usb-rescue-address.service'), 'active');
      const usb = JSON.parse(run('ip', ['-j', 'address', 'show', 'dev', 'usb0']))[0];
      assert.ok(usb?.flags.includes('UP') && usb.address === '02:00:00:00:00:02'
        && usb.addr_info.some(a => a.family === 'inet' && a.local === '192.168.7.1' && a.prefixlen === 24), 'known live USB rescue interface required');
      assert.equal(ctl('is-active', 'systemd-networkd.service'), 'active');
      assert.equal(ctl('is-active', 'clean-vpn-killswitch.service'), 'active');
      const guard = run('/usr/local/bin/clean-vpn-killswitch.sh', ['status']);
      for (const family of ['IPv4', 'IPv6']) assert.ok([2, 3, 4].some(v => guard.includes(`${family}: cvks${v}:both:block:tun0:${exitIp}:22`)), 'known persistent guard profile required');
      for (const u of ['NetworkManager.service', 'connman.service', 'wicked.service', 'networking.service'])
        assert.notEqual(ctl('show', u, '--property=ActiveState', '--value'), 'active', `unsupported network manager: ${u}`);
      for (const f of ['tcpdump', 'ip', 'systemd-notify']) run('which', [f]);
      const node = fs.realpathSync(process.execPath); trusted(node);
      for (const p of ['/etc/systemd/system', '/usr/local/lib', '/var/lib']) trusted(p);
      assert.equal(ctl('show', `${captureName}.service`, '--property=LoadState', '--value'), 'not-found');
      assert.equal(ctl('show', `${captureName}.service`, '--property=DropInPaths', '--value'), '');
      const config = { schema: 1, exitIp, node, installedBootId: bootId() };
      const files = {
        [`${captureDir}/config.json`]: JSON.stringify(config),
        '/usr/local/lib/clean-vpn-boot-capture.mjs': fs.readFileSync(new URL('./lib/host-boot-capture.mjs', import.meta.url), 'utf8'),
        [`/etc/systemd/system/${captureName}.service`]: captureUnit(node),
        ...Object.fromEntries(consumers.map(u => [gatePath(u), gateText])),
      };
      absent(captureDir);
      for (const p of Object.keys(files)) {
        absent(p); let parent = dirname(p);
        while (!fs.existsSync(parent)) parent = dirname(parent);
        trusted(parent);
      }
      console.log(JSON.stringify({ status: args.includes('--apply') ? 'publishing' : 'plan', files: Object.keys(files),
        activates: 'next boot only', windowSeconds: 90, networkRestarted: false,
        failurePolicy: 'capture startup failure blocks gated WiFi/networkd; use USB rescue to remove capture gates',
        rescueCommand: 'node scripts/clean-vpn-boot-capture.mjs --remove --apply',
        untouched: ['guard rules and gates', 'USB gadget', 'USB rescue', 'SSH', 'VPN process'],
        limitation: 'Other boot scripts or initramfs can raise wlan0 earlier; early-UP is refused, not counted as a pass.' }));
      if (args.includes('--apply')) {
        // Exclusive creation; no concurrent administrators. On failure retain evidence.
        for (const [p, value] of Object.entries(files)) publish(p, value);
        run('systemd-analyze', ['verify', '--man=no', `/etc/systemd/system/${captureName}.service`,
          ...consumers.filter(u => ctl('show', u, '--property=LoadState', '--value') === 'loaded')]);
        run('systemctl', ['daemon-reload']);
        for (const u of consumers) {
          if (ctl('show', u, '--property=LoadState', '--value') !== 'loaded') continue;
          for (const prop of ['After', 'Requires']) assert.ok(ctl('show', u, `--property=${prop}`, '--value').split(/\s+/).includes(`${captureName}.service`));
        }
        console.log(JSON.stringify({ status: 'armed-for-next-boot', servicesRestarted: false,
          next: 'Keep USB rescue available. After reboot wait 90 seconds, then run --report. No reboot performed.' }));
      }
    }
  }
} catch (e) { console.error(JSON.stringify({ status: 'refused-or-incomplete', error: e.message,
  note: 'No automatic service restart/rollback. Review partial files if publication started.' })); process.exitCode = 1; }
