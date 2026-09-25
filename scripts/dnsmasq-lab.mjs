#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { runDnsmasqLab } from './lib/dnsmasq-lab.mjs';

const args = process.argv.slice(2), entry = fileURLToPath(import.meta.url);
const usb = args.includes('--usb');
if (usb) args.splice(args.indexOf('--usb'), 1);
let directory;
const controller = new AbortController(), abort = () => controller.abort();
process.once('SIGINT', abort); process.once('SIGTERM', abort);
try {
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Usage: MESHPN_DNSMASQ=/absolute/path/dnsmasq node scripts/dnsmasq-lab.mjs [--usb]\nPrivate namespace only; --usb adds DHCP peer and namespace-only DNS guards. No installation or host DNS/firewall/TUN changes.\n');
  } else if (args.length === 1 && args[0] === '--isolated') {
    console.log = console.warn = console.error = () => {};
    const report = await runDnsmasqLab(process.env.MESHPN_DNSMASQ_LAB_DIR, process.env.MESHPN_DNSMASQ, { usb });
    process.stdout.write(`DNSMASQ_LAB_RESULT ${JSON.stringify(report)}\n`);
  } else {
    assert.equal(args.length, 0, 'unknown arguments');
    assert.ok(process.env.MESHPN_DNSMASQ?.startsWith('/'), 'set absolute MESHPN_DNSMASQ; no automatic installation');
    process.umask(0o077);
    const hash = async () => createHash('sha256').update(await readFile('/etc/resolv.conf')).digest('hex');
    const before = await hash();
    const hostForwarding = () => Promise.all(['/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding']
      .map((path) => readFile(path, 'utf8')));
    const forwardingBefore = usb ? await hostForwarding() : null;
    directory = await mkdtemp(join(tmpdir(), 'meshpn-dnsmasq-lab-'));
    // Namespace-local root is needed for network sysctl ownership, not host sudo.
    const isolation = namespaceArgs.map((arg) => usb && arg === '--map-current-user' ? '--map-root-user' : arg);
    const result = await runCommand('unshare', [...isolation, '--propagation', 'private',
      process.execPath, entry, '--isolated', ...(usb ? ['--usb'] : [])], { timeoutMs: usb ? 90000 : 60000, signal: controller.signal,
      env: { ...cleanEnvironment(process.env), MESHPN_DNSMASQ_LAB_DIR: directory,
        MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid'),
        MESHPN_PARENT_MNTNS: await readlink('/proc/self/ns/mnt') } });
    assert.equal(await hash(), before, 'host resolver changed');
    if (usb) assert.deepEqual(await hostForwarding(), forwardingBefore, 'host forwarding changed');
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
    assert.ok(lines[0].startsWith('DNSMASQ_LAB_RESULT '));
    const report = JSON.parse(lines[0].slice('DNSMASQ_LAB_RESULT '.length));
    if (usb) report.hostForwardingUnchanged = true;
    assert.equal(report.status, 'passed'); process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
} catch (error) { process.stderr.write(`DNSMASQ_LAB_FAILED ${error.message}\n`); process.exitCode = 1; }
finally {
  process.off('SIGINT', abort); process.off('SIGTERM', abort);
  if (directory) await rm(directory, { recursive: true, force: true });
}
