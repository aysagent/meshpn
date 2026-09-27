/** Paired executor restricted to the NIC-less Radxa systemd guest. */
import assert from 'node:assert/strict';
import { readFile, lstat, mkdir, readlink, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { assertDnsmasqVm } from './dnsmasq-vm-safety.mjs';
import { journal, backendContext, probe, exists, emit } from './dnsmasq-vm-worker.mjs';
import { createResolverObjectFiles } from './dns-resolver-object-files.mjs';
import { RESOLVER_TARGET } from './dns-resolver-object-journal.mjs';
import { pairRadxaBackends, readRadxaJournal } from './dns-radxa-journal.mjs';
import { loadDnsBootGuard } from './dns-boot-guard.mjs';
import { createBootGuardLifecycle } from './dns-boot-guard-lifecycle.mjs';
import { readDnsGuardJournal } from './dns-client-guard-journal.mjs';
import { createDnsClientController } from './dns-client-controller.mjs';
import { exec } from './browser-lab-driver.mjs';
export const guardJournal = '/state/dns-guard';
let lifecycle;
const guard = async (enabled) => {
  assert.ok(lifecycle, 'shared boot/DNS lifecycle required');
  return enabled ? lifecycle.prepare() : lifecycle.release();
};
export async function createRadxaVmGuardLifecycle({ restoring, authorizeRelease, dnsStateExists, client }) {
  await assertRadxaVm(); const boot = await loadDnsBootGuard();
  assert.equal(client, 'radxa'); assert.equal(boot.policy.input.client, client);
  if (!restoring) await boot.guard.ensure();
  try { await mkdir(guardJournal, { recursive: true, mode: 0o700 }); }
  catch (e) { await boot.guard.ensure(); throw e; }
  const backend = boot.createJournalBackend({
    context: async () => {
      await assertRadxaVm(); const dir = await lstat(guardJournal);
      assert.ok(dir.isDirectory() && dir.uid === 0 && (dir.mode & 0o777) === 0o700);
      const [link] = JSON.parse((await exec('ip', ['-j', 'addr', 'show', 'dev', 'usb0'])).stdout);
      assert.ok(link.addr_info.some((a) => a.family === 'inet' && a.local === '192.168.7.1' && a.prefixlen === 24));
      return { bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
        netns: await readlink('/proc/self/ns/net'), directoryIdentity: `${dir.dev}:${dir.ino}`,
        firewall: { ipv4: boot.policy.firewallBackend, ipv6: boot.policy.firewallBackend },
        usb: { name: link.ifname, ifindex: link.ifindex, mac: link.address, address: '192.168.7.1' } };
    },
    authorizeRelease,
  });
  let allowBind;
  try { allowBind = !await dnsStateExists(); }
  catch (e) { await boot.guard.ensure(); throw e; }
  return createBootGuardLifecycle({ directory: guardJournal, boot, backend, restoring, allowBind });
}
export async function assertRadxaVm() {
  const o = await assertDnsmasqVm(); assert.ok(['radxa', 'radxa-cut', 'radxa-inspect'].includes(o.phase)); return o;
}
export const journalBytes = () => Promise.all(['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json'].map((name) => readFile(`${journal}/${name}`, 'utf8')));
export async function journalRecords() {
  const [root, dnsmasq, resolver] = (await journalBytes()).map(JSON.parse); return { root, dnsmasq, resolver };
}
export async function radxaVmContext({ ensureGuard = () => guard(true), releaseGuard = () => guard(false) } = {}) {
  await assertRadxaVm(); const { scope, backend: dnsmasq, verifyRestoredDaemon } = await backendContext({ ensureGuard, removeGuard: releaseGuard });
  const directory = `${journal}/resolver-etc`;
  const resolver = await createResolverObjectFiles({ directory, baseline: 'localhost-file', ensureGuard,
    identity: async () => ({ scope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim() }),
    checkEnvironment: async () => {
      await assertRadxaVm(); const a = await lstat('/etc', { bigint: true }), b = await lstat(directory, { bigint: true });
      assert.equal(a.ino, b.ino); assert.equal(a.dev, b.dev);
      const mounts = (await readFile('/proc/self/mountinfo', 'utf8')).split('\n').map((s) => s.split(' ')[4]);
      for (const path of ['/etc/resolv.conf', ...['resolv.conf', 'managed.conf', 'restored.conf'].map((n) => `${directory}/${n}`)]) assert.ok(!mounts.includes(path));
      await assert.rejects(lstat(RESOLVER_TARGET), { code: 'ENOENT' });
    }, probe: async () => { await probe(); await probe(53); } });
  return { scope, backend: pairRadxaBackends(dnsmasq, resolver), verifyDaemon: verifyRestoredDaemon };
}
async function main(command) {
  const options = await assertRadxaVm(); assert.ok(['activate', 'disable', 'guard-proof-check'].includes(command)); process.umask(0o077);
  const checkpoint = async (point) => {
    if (options.phase !== 'radxa-cut' || options.point !== point) return;
    assert.ok(await exists('/state/radxa-first-boot.json'));
    emit('cut-ready', { point, journals: await journalRecords(), guard: await readDnsGuardJournal(guardJournal) });
    await new Promise(() => { setInterval(() => {}, 1000); });
  };
  const controller = await createDnsClientController({ client: 'radxa', command: command === 'disable' ? 'disable' : 'start',
    directory: journal, createGuard: createRadxaVmGuardLifecycle, createContext: radxaVmContext, checkpoint });
  lifecycle = controller.guard;
  if (command === 'guard-proof-check') {
    const before = await readFile(`${guardJournal}/journal.json`);
    assert.equal((await readRadxaJournal(journal)).phase, 'active'); await assert.rejects(lifecycle.release());
    assert.deepEqual(await readFile(`${guardJournal}/journal.json`), before);
    const saved = `${guardJournal}/missing-journal-fixture.json`;
    assert.equal(await exists(saved), false); await rename(`${guardJournal}/journal.json`, saved);
    try {
      await assert.rejects(lifecycle.prepare(), /explicit new guard binding/);
      assert.equal(await exists(`${guardJournal}/journal.json`), false);
      assert.deepEqual(await (await loadDnsBootGuard()).guard.inspect(), ['present', 'present']);
    } finally {
      assert.deepEqual(await readFile(saved), before); await rename(saved, `${guardJournal}/journal.json`);
    }
    return;
  }
  console.log('DNS_RADXA_TRANSACTION', await controller.run());
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv[2]).catch((e) => { console.error(e.stack); process.exitCode = 1; });
