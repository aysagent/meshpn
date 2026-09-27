import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, mkdtemp, rm, lstat, symlink, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDnsClientController, dnsClientStateExists } from './lib/dns-client-controller.mjs';

async function fixture(t) {
  const path = await mkdtemp(join(tmpdir(), 'meshpn-client-controller-'));
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
for (const client of ['vps2', 'radxa']) test(`${client}: protection failure precedes storage and context`, async (t) => {
  const directory = join(await fixture(t), 'new-journal'); let contextCalls = 0;
  const c = await createDnsClientController({ client, command: 'start', directory,
    createGuard: async () => ({ prepare: async () => { throw new Error('guard failed'); }, release: async () => assert.fail() }),
    createContext: async () => { contextCalls++; assert.fail(); } });
  await assert.rejects(c.run(), /guard failed/); assert.equal(contextCalls, 0);
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
});
for (const client of ['vps2', 'radxa']) test(`${client}: dangling root/child journal is existing state`, async (t) => {
  const directory = await fixture(t); await mkdir(join(directory, 'link')); await mkdir(join(directory, 'radxa')); await mkdir(join(directory, 'resolver-etc'));
  assert.equal(await dnsClientStateExists(client, directory), false);
  for (const path of client === 'vps2' ? ['journal.json', 'link/journal.json'] : ['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json']) {
    await symlink('/missing-controller-test-journal', join(directory, path));
    assert.equal(await dnsClientStateExists(client, directory), true); await unlink(join(directory, path));
  }
});
for (const [client, command] of [['vps2', 'stop'], ['radxa', 'recover'], ['unknown', 'start'], ['__proto__', 'start']])
  test(`invalid command/profile refuses before factory: ${client}/${command}`, async () => {
    await assert.rejects(createDnsClientController({ client, command, directory: '/must-not-create',
      createGuard: async () => assert.fail('factory invoked'), createContext: async () => assert.fail() }), /unsupported|explicit/);
  });
