/** Durable guard intent. Caller holds a process-lifetime stable-inode flock.
 * No host CLI/automatic boot adoption; no DNS baseline setters in this module. */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { compileDnsClientGuard, createDnsClientGuard } from './dns-client-guard.mjs';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';

const keys = (value, names) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...names].sort());
};
export function validateDnsGuardContext(context) {
  keys(context, ['bootId', 'netns', 'directoryIdentity', 'firewall', 'usb']);
  assert.match(context.bootId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.match(context.netns, /^net:\[\d+\]$/); assert.match(context.directoryIdentity, /^\d+:\d+$/);
  keys(context.firewall, ['ipv4', 'ipv6']);
  for (const value of Object.values(context.firewall)) assert.ok(['nf_tables', 'legacy'].includes(value));
  assert.equal(context.firewall.ipv4, context.firewall.ipv6, 'mixed firewall backends unsupported');
  if (context.usb !== null) {
    keys(context.usb, ['name', 'ifindex', 'mac', 'address']);
    assert.ok(Number.isSafeInteger(context.usb.ifindex) && context.usb.ifindex > 1);
    assert.match(context.usb.mac, /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/);
    compileDnsClientGuard({ schema: 1, client: 'radxa', id: '0'.repeat(32), usbInterface: context.usb.name, usbAddress: context.usb.address });
  }
  return context;
}
export function validateDnsGuardJournal(record) {
  keys(record, ['schema', 'backend', 'input', 'context', 'stage']);
  assert.equal(record.schema, 1); assert.equal(record.backend, 'client-dns-guard');
  compileDnsClientGuard(record.input); validateDnsGuardContext(record.context);
  assert.ok(['installing', 'active', 'releasing', 'released'].includes(record.stage));
  if (record.input.client === 'vps2') assert.equal(record.context.usb, null);
  else {
    assert.equal(record.context.usb?.name, record.input.usbInterface);
    assert.equal(record.context.usb.address, record.input.usbAddress);
  }
  return record;
}
export const readDnsGuardJournal = (directory) => readPrivateJournal(directory, validateDnsGuardJournal);
export const writeDnsGuardJournal = (directory, record, checkpoint) => writePrivateJournal(directory, record, validateDnsGuardJournal, checkpoint);

/** Production-shaped backend adapter: commands/context/restore proof are injected,
 * never reconstructed from executable paths or commands in the journal. */
export function createDnsGuardJournalBackend({ config, context, read, restore, authorizeRelease, installedInput }) {
  const checkedConfig = () => {
    assert.ok(!Object.hasOwn(config, 'id')); compileDnsClientGuard({ ...config, id: '0'.repeat(32) });
    return structuredClone(config);
  };
  checkedConfig();
  assert.ok(installedInput === undefined || typeof installedInput === 'function');
  const bootInput = async () => {
    if (!installedInput) return null;
    const input = await installedInput(); compileDnsClientGuard(input);
    const { id, ...fromBoot } = input;
    assert.deepEqual(fromBoot, checkedConfig(), 'installed boot policy changed');
    return structuredClone(input);
  };
  const current = async () => validateDnsGuardContext(await context());
  const guard = (record) => {
    validateDnsGuardJournal(record);
    return createDnsClientGuard({ input: record.input, read, restore,
      assertContext: async () => {
        assert.deepEqual(await current(), record.context, 'guard context changed');
        const { id, ...configFromJournal } = record.input;
        assert.deepEqual(checkedConfig(), configFromJournal, 'guard policy changed');
        const installed = await bootInput();
        if (installed) assert.deepEqual(record.input, installed, 'journal does not belong to installed boot policy');
      } });
  };
  return {
    config: async () => checkedConfig(), context: current, installedInput: bootInput,
    inspect: (record) => guard(record).inspect(),
    async authorizeRelease(record) {
      await guard(record).inspect(); assert.equal(typeof authorizeRelease, 'function');
      return authorizeRelease(structuredClone(record));
    },
    async commit(record, family) {
      const instance = guard(record);
      assert.ok(record.stage === 'installing' || record.stage === 'releasing', 'durable intent required');
      if (record.stage === 'installing') return instance.ensureFamily(family);
      return instance.releaseFamily(family, async () => {
        assert.equal(typeof authorizeRelease, 'function'); return authorizeRelease(structuredClone(record));
      });
    },
  };
}

/** enable creates a fresh intent; start only ensures install intent; recover
 * follows the recorded direction; disable alone may switch it to release.
 * bind-boot explicitly records already verified rules from a durable installed
 * policy. It never adopts another journal/epoch or generates a replacement ID. */
export async function dnsGuardTransaction({ directory, operation, backend, checkpoint = async () => {} }) {
  assert.ok(['enable', 'bind-boot', 'start', 'recover', 'disable', 'inspect'].includes(operation));
  let record;
  const save = async (stage) => {
    record = { ...record, stage }; await writeDnsGuardJournal(directory, record, checkpoint); await checkpoint(stage);
  };
  if (operation === 'enable' || operation === 'bind-boot') {
    try { await readDnsGuardJournal(directory); throw new Error('guard journal already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const installed = structuredClone(await backend.installedInput?.() ?? null);
    if (operation === 'bind-boot') assert.ok(installed, 'explicit installed boot policy required');
    else assert.equal(installed, null, 'installed policy requires explicit bind-boot');
    record = { schema: 1, backend: 'client-dns-guard', input: installed ?? { ...await backend.config(), id: randomBytes(16).toString('hex') },
      context: await backend.context(), stage: installed ? 'active' : 'installing' };
    validateDnsGuardJournal(record);
    assert.deepEqual(await backend.inspect(record), installed ? ['present', 'present'] : ['absent', 'absent'],
      installed ? 'both installed boot guard families must be verified' : 'guard exists without durable intent');
    assert.deepEqual(await backend.context(), record.context, 'guard context changed before intent');
    if (installed) assert.deepEqual(await backend.installedInput(), installed, 'installed boot policy changed before binding');
    await save(record.stage);
  } else record = await readDnsGuardJournal(directory);
  const observe = async () => {
    assert.deepEqual(await backend.context(), record.context, 'stale guard context');
    const { id, ...config } = record.input;
    assert.deepEqual(await backend.config(), config, 'guard policy changed');
    const installed = await backend.installedInput?.() ?? null;
    if (installed) assert.deepEqual(record.input, installed, 'journal does not belong to installed boot policy');
    const states = await backend.inspect(record);
    assert.ok(Array.isArray(states) && states.length === 2 && states.every((state) => ['present', 'absent'].includes(state)));
    assert.deepEqual(await backend.context(), record.context, 'guard context changed during read');
    return states;
  };
  let states = await observe();
  const result = () => ({ schema: 1, kind: 'clean-vpn-dns-guard-transaction', id: record.input.id, stage: record.stage, states });
  if (operation === 'inspect') return { ...result(), mode: 'read-only' };
  if (operation === 'start') assert.ok(['installing', 'active'].includes(record.stage), 'release intent requires explicit review, not service start');
  if (operation === 'disable' && ['installing', 'active'].includes(record.stage)) {
    assert.equal(await backend.authorizeRelease(record), true, 'verified restored baseline required');
    await save('releasing');
  }
  if (record.stage === 'released') { assert.deepEqual(states, ['absent', 'absent'], 'released guard reappeared'); return result(); }
  if (record.stage === 'active') {
    // Missing family rules can be reasserted only under the same context, with
    // a durable install intent committed before the first firewall mutation.
    if (states.every((state) => state === 'present')) return result();
    await save('installing');
  }
  const wanted = record.stage === 'installing' ? 'present' : 'absent';
  for (const [index, family] of [4, 6].entries()) {
    states = await observe();
    if (states[index] === wanted) continue;
    if (record.stage === 'releasing') assert.equal(await backend.authorizeRelease(record), true, 'restore proof no longer valid');
    await backend.commit(record, family); await checkpoint(`${record.stage}:${family}:committed`);
    states = await observe(); assert.equal(states[index], wanted, 'guard family readback mismatch');
  }
  states = await observe(); assert.deepEqual(states, [wanted, wanted]);
  if (record.stage === 'releasing') assert.equal(await backend.authorizeRelease(record), true, 'restore proof no longer valid at release completion');
  await save(wanted === 'present' ? 'active' : 'released');
  return result();
}
