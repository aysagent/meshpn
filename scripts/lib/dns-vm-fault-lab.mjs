/** Failure injection ONLY in a disposable guest namespace. Never a live DNS backend. */
import assert from 'node:assert/strict';
import { mkdir, readdir, readFile, open, rename } from 'node:fs/promises';
import { join } from 'node:path';
import dgram from 'node:dgram';
import net from 'node:net';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { resolvedTransaction, readResolvedJournal } from './dns-resolved-journal.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';
import { assertVmFaultEvidence } from './dns-vm-protocol.mjs';
import { makeDnsQuery } from './lab-dns-wire.mjs';
import { assertSystemdDnsVm } from './dns-systemd-vm-safety.mjs';

export async function assertVmBaselineBlocked(address, tcp) {
  await assertDnsMountNamespace(); return baselineBlocked(address, tcp);
}
export async function assertSystemdVmBaselineBlocked(address, tcp) {
  await assertSystemdDnsVm(); return baselineBlocked(address, tcp);
}
async function baselineBlocked(address, tcp) {
  assert.ok(['127.0.0.55', '::1'].includes(address));
  const query = makeDnsQuery('fault-baseline.test');
  await assert.rejects(new Promise((resolve, reject) => {
    const socket = tcp ? net.createConnection({ host: address, port: 53 }) : dgram.createSocket(address.includes(':') ? 'udp6' : 'udp4');
    let ended = false;
    const finish = (error) => {
      if (ended) return; ended = true; clearTimeout(timer);
      if (tcp) socket.destroy(); else socket.close();
      error ? reject(error) : resolve();
    };
    const timer = setTimeout(() => finish(Object.assign(new Error('baseline deadline'), { code: 'ETIMEDOUT' })), 1500);
    socket.once('error', finish); socket.once(tcp ? 'data' : 'message', () => finish());
    if (tcp) socket.once('connect', () => { const prefix = Buffer.alloc(2); prefix.writeUInt16BE(query.length); socket.write(Buffer.concat([prefix, query])); });
    else socket.connect(53, address, () => socket.send(query, (error) => { if (error) finish(error); }));
  }), (error) => ['ECONNREFUSED', 'EACCES', 'EPERM', 'EHOSTUNREACH', 'ETIMEDOUT'].includes(error.code));
}

export async function failVmGuardBeforeNetwork({ journal, scope }) {
  await assertDnsMountNamespace();
  let touchedBackend = false;
  const rule = ['OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'REJECT'];
  await assert.rejects(resolvedTransaction({ directory: journal, operation: 'enable', scope,
    backend: {
      ensureGuard: () => exec('/usr/bin/setpriv', ['--bounding-set=-net_admin', '--inh-caps=-net_admin', '--ambient-caps=-net_admin',
        '/usr/sbin/iptables', '-w', '2', '-A', ...rule]),
      view: async () => { touchedBackend = true; throw new Error('backend reached without guard'); },
    } }), (error) => Number.isInteger(error.code) && error.code !== 0 && /Permission denied|Operation not permitted|must be root/.test(error.stderr));
  assert.equal(touchedBackend, false);
  await assert.rejects(exec('iptables', ['-w', '2', '-C', ...rule]), (e) => e.code === 1);
  const links = JSON.parse((await exec('ip', ['-j', 'link'])).stdout);
  assert.deepEqual(links.map((link) => link.ifname), ['lo']); assert.ok(!links[0].flags.includes('UP'));
  assert.deepEqual(await readdir(journal), []);
  return { guardClaimedInstalledOnFailure: false, loopbackStayedDown: true, consumersStartedOnFailure: false };
}

export async function runVmStartupFault({ point, journal, scope, backend, lab, guardFailure, blocked, managed, restored }) {
  await assertDnsMountNamespace();
  const baseline = await backend.view(); let setters = 0;
  const instrumented = { ...backend, async set(...args) { setters++; return backend.set(...args); } };
  const transact = (operation, directory = journal) => resolvedTransaction({ directory, operation, scope, backend: instrumented });
  let operation = 'enable', expectedId;
  const evidence = { point, status: 'passed', dnsUnchangedOnFailure: true, noSettersOnFailure: true,
    blockedAfterFailure: true, explicitRecoveryPassed: true };
  if (point === 'guard-unavailable') {
    assert.ok(guardFailure); Object.assign(evidence, guardFailure, { failure: 'permission-denied' });
  } else if (point === 'storage-readonly') {
    const readonly = join(journal, 'readonly'); await mkdir(readonly, { mode: 0o700 });
    await exec('mount', ['--bind', readonly, readonly]);
    await exec('mount', ['-o', 'remount,bind,ro', readonly, readonly]);
    await assert.rejects(transact('enable', readonly), { code: 'EROFS' });
    assert.deepEqual(await readdir(readonly), []);
    Object.assign(evidence, { failure: 'EROFS', guardRetained: true });
  } else if (point === 'corrupt-journal') {
    const bytes = '{"schema":1,'; const fd = await open(join(journal, 'journal.json'), 'wx', 0o600);
    try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    await syncDirectory(journal);
    await assert.rejects(transact('recover'), SyntaxError);
    assert.equal(await readFile(join(journal, 'journal.json'), 'utf8'), bytes);
    // Explicit operator repair in this fixture, not an automatic recovery policy.
    const archived = `${journal}-corrupt`; await rename(journal, archived); await syncDirectory('/state');
    await mkdir(journal, { mode: 0o700 }); await syncDirectory('/state');
    assert.equal(await readFile(join(archived, 'journal.json'), 'utf8'), bytes);
    Object.assign(evidence, { failure: 'SyntaxError', guardRetained: true, corruptBytesPreserved: true });
  } else if (point === 'adapter-unready') {
    await lab.stopExit();
    await assert.rejects(transact('enable'), /protected VM DNS readiness failed/);
    const record = await readResolvedJournal(journal);
    assert.equal(record.cursor, 0); assert.equal(record.pending, false); assert.equal(record.stage, 'running');
    expectedId = record.id; operation = 'recover';
    Object.assign(evidence, { failure: 'readiness-failed', guardRetained: true, sameTransactionRecovered: true });
  } else throw new Error('unknown startup fault');
  assert.equal(setters, 0); assert.deepEqual(await backend.view(), baseline);
  await blocked();
  if (point === 'adapter-unready') await lab.restartExit();
  const result = await transact(operation);
  if (expectedId) assert.equal(result.id, expectedId);
  await managed(); await transact('disable'); await restored();
  assertVmFaultEvidence(point, evidence); return evidence;
}
