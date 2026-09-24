#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { runDnsLifecycleLab } from './lib/dns-lifecycle-lab.mjs';

const entry = fileURLToPath(import.meta.url), root = dirname(dirname(entry));
const args = process.argv.slice(2), isolated = args[0] === '--isolated';
if (isolated) args.shift();
const crash = args.includes('--crash');
if (crash) args.splice(args.indexOf('--crash'), 1);
const resolvedJournal = args.includes('--resolved-journal');
if (resolvedJournal) args.splice(args.indexOf('--resolved-journal'), 1);
const resolved = args.includes('--resolved') || resolvedJournal;
if (args.includes('--resolved')) args.splice(args.indexOf('--resolved'), 1);
if (args.length === 1 && args[0] === '--help' && !isolated) {
  console.log('Usage: node scripts/dns-lifecycle-lab.mjs [--family=4|6] [--crash | --resolved | --resolved-journal]\nNamespace-only glibc DNS lifecycle fixture. --resolved and --resolved-journal require real systemd-resolved, dbus-daemon and busctl. --resolved-journal adds durable controller SIGKILL recovery. MESHPN_SYSTEMD_RESOLVED selects a local binary. No host DNS/firewall/TUN changes.');
} else {
  let directory;
  const controller = new AbortController(), abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  try {
    assert.ok(!(crash && resolved), 'choose one extended suite');
    assert.ok(args.length === 0 || (args.length === 1 && /^--family=[46]$/.test(args[0])), 'invalid arguments');
    const family = Number(args[0]?.slice(9) ?? 4);
    process.umask(0o077);
    if (isolated) {
      console.log = console.warn = console.error = () => {};
      const result = await runDnsLifecycleLab(process.env.MESHPN_DNS_LIFECYCLE_DIR, family, { crash, resolved, resolvedJournal });
      process.stdout.write(`DNS_LIFECYCLE_RESULT ${JSON.stringify(result)}\n`);
    } else {
      const files = ['/etc/resolv.conf', '/etc/nsswitch.conf', ...(resolved ? ['/etc/passwd', '/etc/group'] : [])];
      const hashes = () => Promise.all(files.map(async (path) => createHash('sha256').update(await readFile(path)).digest('hex')));
      const before = await hashes();
      directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-lifecycle-'));
      const result = await runCommand('unshare', [...namespaceArgs, ...(resolved ? ['--uts'] : []), '--propagation', 'private',
        'sh', '-eu', '-c', 'ulimit -c 0; exec "$@"', 'dns-lifecycle',
        process.execPath, '--max-old-space-size=128', entry, '--isolated', `--family=${family}`,
        ...(crash ? ['--crash'] : []), ...(resolved ? [resolvedJournal ? '--resolved-journal' : '--resolved'] : [])],
      { cwd: root, timeoutMs: resolvedJournal ? 240000 : crash || resolved ? 120000 : 45000,
        signal: controller.signal, env: { ...cleanEnvironment(process.env), MESHPN_DNS_LIFECYCLE_DIR: directory,
          MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid'),
          ...(resolved ? { MESHPN_PARENT_UTSNS: await readlink('/proc/self/ns/uts') } : {}),
          MESHPN_PARENT_MNTNS: await readlink('/proc/self/ns/mnt') } });
      assert.deepEqual(await hashes(), before, 'host resolver files changed during lab');
      assert.equal(result.reason, null); assert.equal(result.code, 0, result.stderr);
      const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
      assert.ok(lines[0].startsWith('DNS_LIFECYCLE_RESULT '));
      const report = JSON.parse(lines[0].slice('DNS_LIFECYCLE_RESULT '.length));
      assert.equal(report.status, 'passed'); assert.equal(report.family, family);
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    }
  } catch (error) { process.stderr.write(`DNS_LIFECYCLE_FAILED ${error.message}\n`); process.exitCode = 1; }
  finally {
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
    if (directory) await rm(directory, { recursive: true, force: true });
  }
}
