#!/usr/bin/env node
/** Explicit, bounded namespace experiment; never starts host services. */
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { networkdLabOptions, runNetworkdLab, assertNetworkdEvidence } from './lib/dns-networkd-lab.mjs';

const entry = fileURLToPath(import.meta.url);
let directory;
const controller = new AbortController(), abort = () => controller.abort();
process.once('SIGINT', abort); process.once('SIGTERM', abort);
try {
  const options = networkdLabOptions(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/dns-networkd-lab.mjs --systemd-dir=/path/to/systemd249/lib/systemd --dnsmasq=/path/to/dnsmasq\nPrivate namespaces only; real networkd DHCP renew + resolved 249. No downloads, host services, SSH, TUN or host DNS/firewall changes.');
  else if (options.isolated) {
    console.log = console.warn = console.error = () => {};
    const report = await runNetworkdLab(process.env.MESHPN_NETWORKD_LAB_DIR, options);
    process.stdout.write(`NETWORKD_LAB_RESULT ${JSON.stringify(report)}\n`);
  } else {
    process.umask(0o077);
    const snapshot = () => Promise.all(['/etc/resolv.conf', '/etc/passwd', '/etc/group', '/etc/nsswitch.conf',
      '/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding'].map(async (p) =>
      createHash('sha256').update(await readFile(p)).digest('hex')));
    const before = await snapshot();
    directory = await mkdtemp(join(tmpdir(), 'meshpn-networkd-lab-'));
    const result = await runCommand('unshare', [...namespaceArgs, '--uts', '--propagation', 'private',
      process.execPath, entry, '--isolated', `--systemd-dir=${options.systemdDir}`, `--dnsmasq=${options.dnsmasq}`],
    { timeoutMs: 120000, maxBytes: 128 * 1024, signal: controller.signal,
      env: { ...cleanEnvironment(process.env), MESHPN_NETWORKD_LAB_DIR: directory,
        MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid'),
        MESHPN_PARENT_MNTNS: await readlink('/proc/self/ns/mnt'), MESHPN_PARENT_UTSNS: await readlink('/proc/self/ns/uts') } });
    assert.deepEqual(await snapshot(), before, 'host configuration changed');
    assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
    const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
    assert.ok(lines[0].startsWith('NETWORKD_LAB_RESULT '));
    const report = JSON.parse(lines[0].slice('NETWORKD_LAB_RESULT '.length));
    Object.assign(report, { hostDnsFilesUnchanged: true, hostForwardingUnchanged: true });
    assertNetworkdEvidence(report); console.log(JSON.stringify(report, null, 2));
  }
} catch (error) { process.stderr.write(`NETWORKD_LAB_FAILED ${error.stack}\n`); process.exitCode = 1; }
finally {
  process.off('SIGINT', abort); process.off('SIGTERM', abort);
  if (directory) await rm(directory, { recursive: true, force: true });
}
