/** Paired executor restricted to the NIC-less Radxa systemd guest. */
import assert from 'node:assert/strict';
import { readFile, lstat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { assertDnsmasqVm } from './dnsmasq-vm-safety.mjs';
import { journal, guard, backendContext, probe, exists, emit } from './dnsmasq-vm-worker.mjs';
import { createResolverObjectFiles } from './dns-resolver-object-files.mjs';
import { RESOLVER_TARGET } from './dns-resolver-object-journal.mjs';
import { pairRadxaBackends, radxaDnsTransaction, readRadxaJournal } from './dns-radxa-journal.mjs';
export async function assertRadxaVm() {
  const o = await assertDnsmasqVm(); assert.ok(['radxa', 'radxa-cut', 'radxa-inspect'].includes(o.phase)); return o;
}
export const journalBytes = () => Promise.all(['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json'].map((name) => readFile(`${journal}/${name}`, 'utf8')));
export async function journalRecords() {
  const [root, dnsmasq, resolver] = (await journalBytes()).map(JSON.parse); return { root, dnsmasq, resolver };
}
export async function radxaVmContext() {
  await assertRadxaVm(); const { scope, backend: dnsmasq } = await backendContext();
  const directory = `${journal}/resolver-etc`;
  const resolver = await createResolverObjectFiles({ directory, ensureGuard: () => guard(true),
    identity: async () => ({ scope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim() }),
    checkEnvironment: async () => {
      await assertRadxaVm(); const a = await lstat('/etc', { bigint: true }), b = await lstat(directory, { bigint: true });
      assert.equal(a.ino, b.ino); assert.equal(a.dev, b.dev);
      const mounts = (await readFile('/proc/self/mountinfo', 'utf8')).split('\n').map((s) => s.split(' ')[4]);
      for (const path of ['/etc/resolv.conf', ...['resolv.conf', 'managed.conf', 'restored.conf'].map((n) => `${directory}/${n}`)]) assert.ok(!mounts.includes(path));
      await assert.rejects(lstat(RESOLVER_TARGET), { code: 'ENOENT' });
    }, probe: async () => { await probe(); await probe(53); } });
  return { scope, backend: pairRadxaBackends(dnsmasq, resolver) };
}
async function main(command) {
  const options = await assertRadxaVm(); assert.ok(['activate', 'disable'].includes(command)); process.umask(0o077);
  await guard(true); const { scope, backend } = await radxaVmContext();
  const operation = command === 'disable' ? 'disable' : await exists(`${journal}/radxa/journal.json`) ? 'recover' : 'enable';
  if (operation === 'recover') assert.ok(['dnsmasq', 'resolver', 'active'].includes((await readRadxaJournal(journal)).phase), 'restored/restoring journal requires explicit epoch');
  const checkpoint = async (point) => {
    if (options.phase !== 'radxa-cut' || options.point !== point) return;
    assert.ok(await exists('/state/radxa-first-boot.json'));
    emit('cut-ready', { point, journals: await journalRecords() });
    await new Promise(() => { setInterval(() => {}, 1000); });
  };
  console.log('DNS_RADXA_TRANSACTION', await radxaDnsTransaction({ directory: journal, operation, scope, backend, checkpoint }));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv[2]).catch((e) => { console.error(e.stack); process.exitCode = 1; });
