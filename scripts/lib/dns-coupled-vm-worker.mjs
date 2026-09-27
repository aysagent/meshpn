/** Actual coupled controller, authority restricted to the offline systemd guest. */
import assert from 'node:assert/strict';
import { readFile, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { journal, guardJournal, createVmGuardLifecycle, busContext, protectedProbe, exists, emitSystemd as emit } from './dns-systemd-vm-worker.mjs';
import { createVmCoupledBackend, createVmLockedCoupledBackend } from './dns-coupled-backend.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { createDnsSystemBus } from './dns-system-bus.mjs';
import { readCoupledJournal } from './dns-coupled-journal.mjs';
import { createDnsClientController } from './dns-client-controller.mjs';
import { loadDnsBootGuard } from './dns-boot-guard.mjs';
import { readDnsGuardJournal } from './dns-client-guard-journal.mjs';

let lifecycle;
const guard = async (enabled) => {
  assert.ok(lifecycle, 'shared boot/DNS lock and lifecycle required');
  return enabled ? lifecycle.prepare() : lifecycle.release();
};

export async function coupledVmContext({ ensureGuard = () => guard(true), releaseGuard = () => guard(false), locked = false } = {}) {
  await assertCoupledDnsVm();
  const context = await busContext(), { scope, ifindex } = context;
  const commands = locked ? await createDnsSystemCommands({ assertAuthority: assertCoupledDnsVm, required: ['ip', 'busctl'] }) : undefined;
  const bus = locked ? createDnsSystemBus(commands.run) : context.bus;
  const backend = await (locked ? createVmLockedCoupledBackend : createVmCoupledBackend)({ bus, ensureGuard, releaseGuard, commands,
    port: 2053, probe: protectedProbe });
  return { bus, scope, ifindex, backend };
}
async function main(command) {
  const options = await assertCoupledDnsVm();
  assert.ok(['activate', 'disable', 'guard-proof-check'].includes(command));
  process.umask(0o077);
  const checkpoint = async (point) => {
    if (options.phase !== 'coupled-cut' || options.point !== point) return;
    assert.equal(await exists('/state/coupled-first-boot.json'), true);
    const root = await readCoupledJournal(journal);
    const child = JSON.parse(await readFile(`${journal}/link/journal.json`, 'utf8'));
    emit('cut-ready', { point, root, child, guard: await readDnsGuardJournal(guardJournal) });
    await new Promise(() => { setInterval(() => {}, 1000); });
  };
  const controller = await createDnsClientController({ client: 'vps2', command: command === 'disable' ? 'disable' : 'start',
    directory: journal, createGuard: createVmGuardLifecycle, createContext: (hooks) => coupledVmContext({ ...hooks, locked: true }), checkpoint });
  lifecycle = controller.guard;
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
  console.log('DNS_COUPLED_TRANSACTION', await controller.run());
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => { console.error(error.stack); process.exitCode = 1; });
}
