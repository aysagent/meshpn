/** Full source publication against real inactivity checks; NIC-less VM only. */
import assert from 'node:assert/strict';
import { mkdir, open, readFile, lstat, chmod } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { DNS_BOOT_LOCK, requireDnsBootGuardLock } from './dns-boot-guard.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { inspectFreshDnsDeployment } from './dns-deployment-inactive.mjs';
import { compileDnsClientDeploymentFiles } from './dns-deployment-files.mjs';
import { dnsDeployment } from './dns-deployment.mjs';
import { exec } from './browser-lab-driver.mjs';

const input = { schema: 1, client: 'vps2', id: 'b'.repeat(32) };
const directory = '/opt/dns-deployment-vm', source = '/source/clean-vpn';
async function gate() { const o = await assertCoupledDnsVm(); assert.equal(o.phase, 'coupled'); assert.equal(o.point, 'publication'); }
async function transaction(operation) {
  await gate(); assert.ok(['install', 'remove'].includes(operation));
  const commands = await createDnsSystemCommands({ assertAuthority: gate, required: ['ip', 'busctl', 'iptables', 'ip6tables'] });
  const bundle = await readFile(`${source}/bundle.json`, 'utf8'), secret = Buffer.alloc(32, 0x42);
  const domainPolicy = { schema: 1, denySuffixes: ['baseline.test'] };
  const files = compileDnsClientDeploymentFiles({ bundle, secret,
    adapter: { schema: 1, exitIp: '93.184.216.36', exitPort: 44443, publicName: 'relay.test', listenPort: 2053,
      readyName: 'systemd-ready.test', domainPolicy, upstream: { schema: 1, transport: 'doh', hostname: 'resolver.test',
        port: 443, path: '/dns-query', bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } } },
    guard: { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'legacy', input },
    config: { schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2', uplink: 'dnsfixture',
      networkFile: { path: '/etc/systemd/network/10-dnsfixture.network', sha256: 'c'.repeat(64) },
      adapterPort: 2053, readyName: 'systemd-ready.test', domainPolicy } });
  let checks = 0; const started = performance.now();
  try {
    if (operation === 'install') for (const f of files) await mkdir(dirname(f.path), { recursive: true, mode: 0o755 });
    const result = await dnsDeployment({ root: '/', directory, operation, source,
      expectedSha256: createHash('sha256').update(bundle).digest('hex'), ...(operation === 'install' ? { files } : {}),
      lockFd: await requireDnsBootGuardLock(), assertInactive: async () => {
        const result = await inspectFreshDnsDeployment({ commands, input, firewallBackend: 'legacy' }); checks++;
        return result.freshInactive === true;
      } });
    return { ...result, inactiveChecks: checks, elapsedMs: Math.round(performance.now() - started), bundleFiles: Object.keys(JSON.parse(bundle).files).length };
  } finally { secret.fill(0); for (const f of files) if (Buffer.isBuffer(f.contents)) f.contents.fill(0); }
}
export async function checkDnsPublicationVm() {
  await gate(); const checks = [];
  await mkdir('/var/lib', { recursive: true, mode: 0o755 }); await mkdir('/opt', { mode: 0o755 }); await chmod('/opt', 0o755);
  await mkdir(directory, { mode: 0o700 }); await mkdir('/run/clean-vpn-dns-guard', { mode: 0o700 });
  const lock = await open(DNS_BOOT_LOCK, 'wx', 0o600); await lock.close();
  await exec('/usr/bin/systemctl', ['start', 'dbus.service'], { timeout: 30000 });
  const firewall = () => Promise.all(['iptables', 'ip6tables'].map(async (tool) => (await exec(tool, ['-S'])).stdout));
  const before = await firewall();
  const run = async (operation) => {
    console.log(`DNS_PUBLICATION_STAGE ${operation} begin`);
    const r = JSON.parse((await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK,
      '/usr/bin/node', '/project/scripts/lib/dns-publication-vm-check.mjs', operation], { timeout: 420000 })).stdout);
    console.log(`DNS_PUBLICATION_STAGE ${operation} passed elapsedMs=${r.elapsedMs} inactiveChecks=${r.inactiveChecks} bundleFiles=${r.bundleFiles}`);
    assert.ok(r.bundleFiles > 100); assert.equal(r.activated, false); return r;
  };
  assert.equal((await run('install')).stage, 'installed'); checks.push('full-code-and-client-files-published');
  // Invalid arguments exercise every entrypoint's real import graph without
  // starting guard/adapter/client or using the synthetic, non-ready baseline.
  for (const [name, marker] of [['dns-client', 'DNS_CLIENT_ARGUMENTS'], ['dns-exit-adapter', 'DNS_EXIT_ADAPTER_INVALID'],
    ['dns-boot-guard', 'DNS_BOOT_GUARD_REFUSED phase=arguments code=ERR_ASSERTION']])
    await assert.rejects(exec('/usr/bin/node', [`/opt/clean-vpn/scripts/${name}.mjs`, '--invalid'], { timeout: 30000 }),
      (e) => e.code === 1 && e.stdout === '' && e.stderr.trim() === marker);
  checks.push('installed-entrypoint-imports');
  assert.equal((await run('remove')).stage, 'removed');
  await assert.rejects(lstat('/opt/clean-vpn'), { code: 'ENOENT' });
  await assert.rejects(lstat('/etc/clean-vpn/dns/client-opt-in.json'), { code: 'ENOENT' });
  await lstat(`${directory}/code/retired/bundle.json`); assert.deepEqual(await firewall(), before);
  checks.push('inactive-config-revoked-code-retained'); return checks;
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  transaction(process.argv[2]).then((v) => console.log(JSON.stringify(v))).catch((e) => { console.error(e.stack); process.exitCode = 1; });
