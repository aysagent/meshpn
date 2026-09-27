/** Actual coupled controller, authority restricted to the offline systemd guest. */
import assert from 'node:assert/strict';
import { mkdir, readFile, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { journal, guardJournal, createVmGuardLifecycle, busContext, protectedProbe, exists, emitSystemd as emit } from './dns-systemd-vm-worker.mjs';
import { createVmCoupledBackend } from './dns-coupled-backend.mjs';
import { coupledDnsTransaction, readCoupledJournal } from './dns-coupled-journal.mjs';
import { verifyCoupledGuardRestore } from './dns-boot-guard-lifecycle.mjs';
import { loadDnsBootGuard } from './dns-boot-guard.mjs';
import { readDnsGuardJournal } from './dns-client-guard-journal.mjs';

let lifecycle;
const guard = async (enabled) => {
  assert.ok(lifecycle, 'shared boot/DNS lock and lifecycle required');
  return enabled ? lifecycle.prepare() : lifecycle.release();
};

export async function coupledVmContext() {
  await assertCoupledDnsVm();
  const { bus, scope, ifindex } = await busContext();
  const backend = await createVmCoupledBackend({ bus, ensureGuard: () => guard(true), releaseGuard: () => guard(false),
    port: 2053, probe: protectedProbe });
  return { bus, scope, ifindex, backend };
}
async function main(command) {
  const options = await assertCoupledDnsVm();
  assert.ok(['activate', 'disable', 'guard-proof-check'].includes(command));
  process.umask(0o077);
  lifecycle = await createVmGuardLifecycle({ restoring: command === 'disable',
    dnsStateExists: async () => await exists(`${journal}/journal.json`) || await exists(`${journal}/link/journal.json`),
    authorizeRelease: async () => verifyCoupledGuardRestore({ directory: journal, backend: (await coupledVmContext()).backend }) });
  if (command === 'guard-proof-check') {
    const before = await readFile(`${guardJournal}/journal.json`);
    assert.equal((await readCoupledJournal(journal)).direction, 'apply');
    await assert.rejects(lifecycle.release());
    assert.deepEqual(await readFile(`${guardJournal}/journal.json`), before);
    const saved = `${guardJournal}/missing-journal-fixture.json`;
    assert.equal(await exists(saved), false); await rename(`${guardJournal}/journal.json`, saved);
    try {
      await assert.rejects(lifecycle.prepare(), /explicit new guard binding/);
      assert.equal(await exists(`${guardJournal}/journal.json`), false);
      assert.deepEqual(await (await loadDnsBootGuard()).guard.inspect(), ['present', 'present']);
    } finally {
      assert.equal(await exists(`${guardJournal}/journal.json`), false);
      assert.deepEqual(await readFile(saved), before); await rename(saved, `${guardJournal}/journal.json`);
    }
    return;
  }
  await guard(true);
  const { scope, backend } = await coupledVmContext();
  await mkdir(journal, { recursive: true, mode: 0o700 });
  const operation = command === 'disable' ? 'disable' : await exists(`${journal}/journal.json`) ? 'recover' : 'enable';
  if (operation === 'recover') {
    const r = await readCoupledJournal(journal);
    assert.ok(r.direction === 'apply' && ['link', 'settings'].includes(r.phase), 'released/restoring journal requires explicit new epoch');
  }
  const checkpoint = async (point) => {
    if (options.phase !== 'coupled-cut' || options.point !== point) return;
    assert.equal(await exists('/state/coupled-first-boot.json'), true);
    const root = await readCoupledJournal(journal);
    const child = JSON.parse(await readFile(`${journal}/link/journal.json`, 'utf8'));
    emit('cut-ready', { point, root, child, guard: await readDnsGuardJournal(guardJournal) });
    // Host SIGKILLs QEMU at this event. Do not sync the guest at the cut.
    await new Promise(() => { setInterval(() => {}, 1000); });
  };
  console.log('DNS_COUPLED_TRANSACTION', await coupledDnsTransaction({ directory: journal, operation, scope, backend, checkpoint }));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => { console.error(error.stack); process.exitCode = 1; });
}
