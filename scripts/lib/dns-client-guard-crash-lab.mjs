/** Real controller SIGKILL; parent PID1 alone executes namespace-local firewall RPC. */
import assert from 'node:assert/strict';
import { mkdir, readlink, readFile, writeFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { createDnsGuardJournalBackend, readDnsGuardJournal } from './dns-client-guard-journal.mjs';

export const DNS_GUARD_CRASH_POINTS = ['installing:dir-synced', 'installing:4:committed', 'installing:6:committed', 'active:renamed',
  'releasing:dir-synced', 'releasing:4:committed', 'releasing:6:committed', 'released:renamed'];
export async function runDnsGuardCrashLab({ directory, read, restore, run, versions }) {
  await assertDnsMountNamespace();
  const baseline = await Promise.all([4, 6].map(read)), cases = [];
  let lockConflicts = 0;
  for (const client of ['vps2', 'radxa']) for (const point of DNS_GUARD_CRASH_POINTS) {
    const path = join(directory, `case-${cases.length}`); await mkdir(path, { mode: 0o700 });
    await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 });
    const config = { schema: 1, client, ...(client === 'radxa' ? { usbInterface: 'usb0', usbAddress: '192.168.7.1' } : {}) };
    const context = async () => {
      await assertDnsMountNamespace();
      const stat = await lstat(path);
      const usb = client === 'radxa' ? JSON.parse(run('/usr/bin/ip', ['-j', 'link', 'show', 'dev', 'usb0']))[0] : null;
      return { bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(), netns: await readlink('/proc/self/ns/net'),
        directoryIdentity: `${stat.dev}:${stat.ino}`, firewall: { ipv4: /\((nf_tables|legacy)\)/.exec(versions[0])[1], ipv6: /\((nf_tables|legacy)\)/.exec(versions[1])[1] },
        usb: usb ? { name: usb.ifname, ifindex: usb.ifindex, mac: usb.address, address: '192.168.7.1' } : null };
    };
    // No OS DNS was changed in this guard-only fixture; explicit release is
    // authorized only by this scenario. Not a production restore-proof callback.
    const backend = createDnsGuardJournalBackend({ config, context, read, restore, authorizeRelease: async () => true });
    const execute = async (operation) => {
      const result = await controller(path, operation, backend, undefined, 'guard').done;
      assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); return result.result;
    };
    const releasing = /^(releasing|released)/.test(point);
    if (releasing) await execute('enable');
    const childController = controller(path, releasing ? 'disable' : 'enable', backend, point, 'guard');
    try {
      await childController.reached;
      if (point === 'active:renamed') {
        const rival = await controller(path, 'start', backend, undefined, 'guard').done;
        assert.equal(rival.code, 75); assert.equal(rival.result, undefined); lockConflicts++;
      }
    } finally { childController.kill(); }
    assert.equal((await childController.done).signal, 'SIGKILL');
    const record = await readDnsGuardJournal(path), beforeRecovery = await backend.inspect(record);
    const expectedBefore = point === 'installing:dir-synced' || ['releasing:6:committed', 'released:renamed'].includes(point) ? ['absent', 'absent']
      : point === 'installing:4:committed' ? ['present', 'absent']
        : point === 'releasing:4:committed' ? ['absent', 'present'] : ['present', 'present'];
    assert.deepEqual(beforeRecovery, expectedBefore, `unexpected state at ${point}`);
    const result = await execute('recover'); assert.equal(result.id, record.input.id);
    assert.equal(result.stage, releasing ? 'released' : 'active');
    assert.deepEqual(result.states, releasing ? ['absent', 'absent'] : ['present', 'present']);
    if (!releasing) await execute('disable');
    assert.deepEqual(await Promise.all([4, 6].map(read)), baseline, 'foreign baseline rules changed');
    cases.push({ client, point, signal: 'SIGKILL', beforeRecovery, recovered: result.stage });
  }
  assert.equal(cases.length, 16); assert.equal(lockConflicts, 2);
  return { status: 'passed', controllerSigkills: 16, lockConflicts, cases, wholeGuestPowerLossTested: false };
}
