#!/usr/bin/env node
/** Persistent two-boot test. No host network, systemd, clock or shared filesystem. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { usbE2eUnits } from './lib/usb-e2e-vm.mjs';
import { assertUsbE2eEvidence, assertUsbFaultEvidence } from './lib/usb-e2e-evidence.mjs';
import { legacyUsbGuardHash, legacyUsbSnatHash } from './lib/host-usb-dns-upgrade.mjs';
import { assertUsbSoakEvidence } from './lib/usb-soak-evidence.mjs';
import { addUsbMssVmImage } from './lib/usb-mss-vm-image.mjs';
import { assertUsbPmtuEvidence } from './lib/usb-pmtu-vm.mjs';

const [base, tools, option] = process.argv.slice(2);
const networkOnly = option === '--network-faults';
const soak = option === '--soak';
const pmtu = option === '--pmtu';
const faults = option === '--faults' || networkOnly || soak || pmtu;
assert.ok(process.argv.length === 4 || process.argv.length === 5 && faults, 'usage: absolute verified HOST_BOOT_BASE QEMU_TOOLS_ROOT [--faults|--network-faults|--soak|--pmtu]');
for (const path of [base, tools]) assert.ok(path?.startsWith('/') && resolve(path) === path && !/[\r\n,]/.test(path));
const hash = b => createHash('sha256').update(b).digest('hex');
const previous = JSON.parse(fs.readFileSync(join(base, 'report.json')));
assert.equal(previous.status, 'passed'); assert.equal(previous.nic, 'none'); assert.equal(previous.hostSharedFilesystem, false);
assert.equal(hash(fs.readFileSync(join(base, 'guest-kernel'))), previous.image.kernelSha256);
const free = fs.statfsSync('/var/tmp'); assert.ok(free.bavail * free.bsize > 1024 * 1024 * 1024);
const root = fs.mkdtempSync('/var/tmp/meshpn-usb-e2e-'), guest = join(root, 'guest');
const disk = join(root, 'state.raw'), initrd = join(root, 'initrd.gz');
console.error('USB E2E artifacts: ' + root);
const report = { kind: 'clean-vpn-usb-e2e', status: 'failed', nic: 'none', hostSharedFilesystem: false,
  scenario: pmtu ? 'usb-pmtu' : soak ? 'usb-soak' : networkOnly ? 'usb-network-faults' : faults ? 'usb-faults' : 'two-boot-installation',
  realTls: true, realTun: true, persistentInstalledFiles: true, boots: [], sourceHashes: {},
  limitations: ['Linux-peer-not-macOS', 'veth-not-WiFi-or-physical-USB', 'initramfs-restores-owned-installation-from-ext4',
    'fixture-PKI-and-origins', 'no-power-cut', 'IPv6-static-neighbours-not-NDP-RA-acceptance',
    'host-LAN-exceptions-and-local-proxies-not-application-isolated', 'not-all-IP-protocols-tested'] };
const put = (p, bytes, mode = 0o644) => { const out = join(guest, p); fs.mkdirSync(out.slice(0, out.lastIndexOf('/')), { recursive: true }); fs.writeFileSync(out, bytes, { mode }); fs.chmodSync(out, mode); };
try {
  fs.cpSync(join(base, 'guest'), guest, { recursive: true, verbatimSymlinks: true });
  // Current production code, not the historical copy in the base image. Native
  // addon/dependencies and kernel come from that already verified x86_64 image.
  const walkSource = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walkSource(path);
      else if (entry.isFile() && /\.(?:m?js|sh)$/.test(path)) {
        const bytes = fs.readFileSync(path); report.sourceHashes[path] = hash(bytes); put('/project/' + path, bytes, path.endsWith('.sh') ? 0o755 : 0o644);
      }
    }
  }; walkSource('scripts');
  if (soak) {
    const source = fs.readFileSync('scripts/clean-vpn.js', 'utf8');
    assert.ok(source.startsWith('#!/usr/bin/env node\n'));
    const instrumented = source.replace('#!/usr/bin/env node\n', '#!/usr/bin/env node\nimport "./lib/usb-memory-vm.mjs";\n');
    put('/project/scripts/clean-vpn.js', instrumented);
    report.memoryInstrumentation = { labOnly: true, forcedGcAfterWorkloadOnly: true, originalSha256: hash(source), instrumentedSha256: hash(instrumented) };
  }
  if (pmtu) {
    const path = 'scripts/lib/usb-pmtu-probe.c';
    report.sourceHashes[path] = hash(fs.readFileSync(path));
    const binary = join(guest, 'usr/bin/usb-pmtu-probe');
    execFileSync('gcc', ['-static', '-O2', '-Wall', '-Wextra', '-Werror', path, '-o', binary]);
    report.pmtuProbeSha256 = hash(fs.readFileSync(binary));
  }
  for (const [name, expected] of [['guard', legacyUsbGuardHash], ['snat', legacyUsbSnatHash], ['installer', '4ac97633449ac56573b87b79e6bccd5faecbc2a4118b22224fd715120c1be592']]) {
    const path = `scripts/fixtures/usb-dns-v2-${name}.txt`, bytes = fs.readFileSync(path);
    assert.equal(hash(bytes), expected); report.sourceHashes[path] = expected;
    put(`/legacy/${name}`, bytes);
  }
  for (const binary of ['/usr/sbin/sshd', '/usr/bin/ssh', '/usr/bin/ssh-keygen', '/usr/bin/ss', '/usr/bin/systemd-analyze', '/usr/bin/journalctl', '/usr/lib/systemd/systemd-journald']) {
    put(binary, fs.readFileSync(binary), 0o755);
    for (const lib of execFileSync('ldd', [binary], { encoding: 'utf8' }).match(/\/[^\s()]+/g) ?? []) put(lib, fs.readFileSync(lib), 0o755);
  }
  for (const [path, target] of [['usr/sbin/ip', '/usr/bin/ip'], ['usr/bin/awk', '/bin/busybox']])
    if (!fs.existsSync(join(guest, path))) fs.symlinkSync(target, join(guest, path));
  for (const [name, contents] of Object.entries(usbE2eUnits())) put('/etc/systemd/system/' + name,
    soak && name === 'usb-e2e-driver.service' ? contents.replace('TimeoutStartSec=24min', 'TimeoutStartSec=54min') :
      pmtu && name === 'usb-e2e-exit.service' ? contents.replace(' --ext=eth0', ' --keep-alive=5 --ext=eth0') : contents);
  const addon = addUsbMssVmImage(fs.readFileSync(join(guest, 'init'), 'utf8'), put);
  report.mssImageHashes = addon.hashes;
  const original = addon.init; assert.ok(original.includes('mount -t ext4'));
  put('/init', original.slice(0, original.indexOf('mount -t ext4')) + 'mount -t ext4 -o rw /dev/vda /state\nnode scripts/lib/usb-e2e-vm.mjs prepare\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no\n', 0o755);
  const paths = ['.']; const walk = p => { for (const name of fs.readdirSync(join(guest, p))) { const q = p ? p + '/' + name : name; paths.push(q); if (fs.lstatSync(join(guest, q)).isDirectory()) walk(q); } }; walk('');
  fs.writeFileSync(initrd, gzipSync(execFileSync('cpio', ['-o', '-H', 'newc', '--owner=0:0', '--quiet'], { cwd: guest,
    input: paths.join('\n') + '\n', maxBuffer: 320 * 1024 * 1024 }), { level: 1 }));
  const fd = fs.openSync(disk, 'wx', 0o600); try { fs.ftruncateSync(fd, 128 * 1024 * 1024); } finally { fs.closeSync(fd); }
  execFileSync('/usr/sbin/mke2fs', ['-q', '-F', '-t', 'ext4', '-O', '^metadata_csum_seed,^orphan_file', disk]);
  for (let phase = 0; phase < (faults ? 1 : 2); phase++) {
    const boot = { phase, events: [] }; report.boots.push(boot);
    const env = { ...process.env, LD_LIBRARY_PATH: `${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`, QEMU_MODULE_DIR: `${tools}/usr/lib/x86_64-linux-gnu/qemu` };
    delete env.LD_PRELOAD; delete env.LD_AUDIT;
    const kernelArgs = 'console=ttyS0 loglevel=4 panic=-1 reboot=t random.trust_cpu=on meshpn.usb-e2e=1' + (faults ? ' meshpn.usb-faults=1' : '') + (networkOnly ? ' meshpn.usb-network-faults=1' : '') + (soak ? ' meshpn.usb-soak=1' : '') + (pmtu ? ' meshpn.usb-pmtu=1' : '');
    const child = spawn(join(tools, 'usr/bin/qemu-system-x86_64'), ['-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-no-reboot', '-serial', 'stdio', '-accel', 'tcg', '-cpu', 'max', '-m', '1536', '-smp', '1', '-bios', `${tools}/usr/share/seabios/bios-256k.bin`, '-L', `${tools}/usr/share/qemu`, '-kernel', join(base, 'guest-kernel'), '-initrd', initrd, '-append', kernelArgs, '-drive', `file=${disk},format=raw,if=virtio,cache=writeback`], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', pending = '', failure;
    const log = fs.openSync(join(root, `boot-${phase}.log`), 'wx', 0o600);
    const abort = reason => { failure ??= reason; child.kill('SIGKILL'); };
    const timer = setTimeout(() => abort('boot deadline'), (soak ? 55 : 25) * 60 * 1000);
    const interrupt = () => abort('interrupted'); process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
    for (const stream of [child.stdout, child.stderr]) stream.on('data', b => {
      fs.writeSync(log, b); output += b; pending += b;
      if (output.length > 2 * 1024 * 1024 || output.includes('Kernel panic')) abort('serial limit or panic');
      for (;;) {
        const at = pending.indexOf('\n'); if (at < 0) break;
        const line = pending.slice(0, at).trim(); pending = pending.slice(at + 1);
        const marker = line.indexOf('USB_E2E_EVENT '); if (marker < 0) continue;
        try { const e = JSON.parse(line.slice(marker + 14)); boot.events.push(e);
          if (e.event === 'check') console.error(`boot ${phase}: ${e.name}`);
          if (e.event === 'failed') abort(e.message);
        } catch (e) { abort(e.message); }
      }
    });
    try { boot.code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); }); }
    finally { clearTimeout(timer); process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt); fs.closeSync(log); }
    assert.equal(failure, undefined, failure); assert.equal(boot.code, 0);
    boot.synced = output.includes('Syncing filesystems and block devices'); boot.unmounted = output.includes('All filesystems unmounted');
    assert.ok(boot.synced && boot.unmounted);
    boot.kernelRestart = output.includes('reboot: Restarting system'); boot.powerDown = output.includes('reboot: Power down');
    const end = boot.events.filter(e => e.event === 'completed'); assert.equal(end.length, 1); boot.bootId = end[0].bootId;
  }
  if (pmtu) assertUsbPmtuEvidence(report); else if (soak) assertUsbSoakEvidence(report); else if (faults) assertUsbFaultEvidence(report); else assertUsbE2eEvidence(report);
  report.status = 'passed'; report.acceptance = soak ? 'lab-only-three-repeated-exit-carrier-DHCP-cycles-and-long-TCP; bounded-resource-observation; physical-WiFi-pending' : networkOnly ? 'lab-only-USB-network-faults; SIGKILL-not-tested-in-this-run; physical-WiFi-pending' : faults ? 'lab-only-USB-SIGKILL-exit-blackhole-carrier-DHCP-recovery; physical-WiFi-pending' : 'lab-only-USB-tunnel-only-and-DNS-interception; real-Radxa-and-Mac-pending';
  if (pmtu) report.acceptance = 'lab-only-IPv4-UDP-fragments-and-PMTU; Linux-peer-not-macOS; fixed-TLS-profile';
} catch (e) { report.error = e.message; process.exitCode = 1; console.error(e.stack); }
finally {
  fs.writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2));
  // Only copies/images allocated by this invocation; retain diagnostic logs.
  fs.rmSync(guest, { recursive: true, force: true }); fs.rmSync(initrd, { force: true });
  if (report.status === 'passed') fs.rmSync(disk);
  console.error('Report: ' + join(root, 'report.json'));
}
