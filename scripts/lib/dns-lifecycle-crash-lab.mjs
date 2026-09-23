/** SIGKILL matrix in the existing namespace. NEVER a host DNS executor. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, readFile, writeFile, readlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec } from './browser-lab-driver.mjs';
import { cleanEnvironment } from './transparent-acceptance.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { readDnsJournal, writeDnsJournal, syncDirectory } from './dns-lifecycle-journal.mjs';
import { sameDnsObject } from './dns-lifecycle-transaction.mjs';

async function fingerprint(path, privateSource = false) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | (privateSource ? constants.O_NOFOLLOW : 0));
  try {
    const stat = await fd.stat({ bigint: true }); assert.ok(stat.isFile() && stat.size <= 4096n);
    if (privateSource) {
      assert.equal(stat.mode & 0o777n, 0o600n); assert.equal(stat.uid, BigInt(process.getuid())); assert.equal(stat.nlink, 1n);
    }
    const bytes = await fd.readFile(); assert.ok(bytes.length <= 4096);
    return { identity: `${stat.dev}:${stat.ino}`, sha256: createHash('sha256').update(bytes).digest('hex') };
  } finally { await fd.close(); }
}

function controller(directory, operation, backend, pause) {
  const worker = fileURLToPath(new URL('./dns-lifecycle-crash-worker.mjs', import.meta.url));
  const proc = spawn('flock', ['-n', '-E', '75', '-F', join(directory, 'lock'), process.execPath, worker, directory, operation],
    { env: { ...cleanEnvironment(process.env), MESHPN_DNS_CONTROLLER: 'namespace-rpc' }, stdio: ['pipe', 'pipe', 'pipe'] });
  let result, stderr = '', failure, chain = Promise.resolve(), count = 0, bytes = 0, paused = false;
  let reach, rejectReach;
  const reached = pause ? new Promise((resolve, reject) => { reach = resolve; rejectReach = reject; }) : undefined;
  reached?.catch(() => {});
  const timer = setTimeout(() => { failure = new Error('controller deadline'); proc.kill('SIGKILL'); }, 15000);
  proc.on('error', (error) => { failure = error; }); proc.stdin.on('error', () => {});
  proc.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4096); });
  proc.stdout.on('data', (chunk) => { bytes += chunk.length; if (bytes > 65536) { failure = new Error('controller output limit'); proc.kill('SIGKILL'); } });
  const lines = createInterface({ input: proc.stdout });
  lines.on('line', (line) => {
    chain = chain.then(async () => {
      assert.ok(++count <= 128 && line.length < 16384);
      const message = JSON.parse(line);
      if (message.type === 'result') { assert.equal(result, undefined); result = message.result; return; }
      let value, error;
      if (message.type === 'checkpoint') {
        if (message.point === pause) { assert.equal(paused, false); paused = true; reach(); return; }
      } else {
        assert.equal(message.type, 'backend'); assert.ok(Object.hasOwn(backend, message.method));
        try { value = await backend[message.method](...message.args); } catch { error = true; }
      }
      proc.stdin.write(`${JSON.stringify({ id: message.id, value, error })}\n`);
    }).catch((error) => { failure = error; proc.kill('SIGKILL'); });
  });
  const done = new Promise((resolve, reject) => proc.once('close', async (code, signal) => {
    clearTimeout(timer); lines.close(); await chain;
    if (!paused) rejectReach?.(new Error(`checkpoint not reached: ${pause}; ${stderr}`));
    if (failure) reject(failure); else resolve({ code, signal, result, stderr });
  }));
  done.catch(() => {});
  return { done, reached, kill: () => proc.kill('SIGKILL') };
}

export async function runDnsCrashLab({ directory, baseline, managed, bindText, setGuard, probe, lookup, hits, lab }) {
  await assertDnsMountNamespace();
  const cases = [], scope = {};
  for (const key of ['net', 'mnt', 'pid']) scope[key] = await readlink(`/proc/self/ns/${key}`);
  let serial = 0, killed = 0, lockConflicts = 0;
  async function fixture() {
    await setGuard(false); await bindText('/etc/resolv.conf', baseline);
    const path = join(directory, `crash-${serial++}`); await mkdir(path, { mode: 0o700 });
    await writeFile(join(path, 'lock'), '', { flag: 'wx', mode: 0o600 });
    const sources = { managed: join(path, 'managed.conf'), restored: join(path, 'restored.conf') };
    const current = () => fingerprint('/etc/resolv.conf');
    const backend = {
      ensureGuard: () => setGuard(true), removeGuard: () => setGuard(false), current, probe,
      async prepare() {
        const original = await current(), saved = await readFile('/etc/resolv.conf', 'utf8');
        assert.ok(sameDnsObject(original, await current()), 'snapshot race');
        for (const name of ['managed', 'restored']) {
          const fd = await open(sources[name], 'wx', 0o600);
          try { await fd.writeFile(name === 'managed' ? managed : saved); await fd.sync(); } finally { await fd.close(); }
        }
        await syncDirectory(path);
        return { original, managed: await fingerprint(sources.managed, true), restored: await fingerprint(sources.restored, true) };
      },
      async verifySnapshots(record) {
        for (const name of ['managed', 'restored']) assert.ok(sameDnsObject(await fingerprint(sources[name], true), record[name]), 'snapshot changed');
      },
      async select(name, record, expected) {
        assert.ok(['managed', 'restored'].includes(name)); await backend.verifySnapshots(record);
        const latest = await current();
        assert.ok(expected.some((value) => sameDnsObject(value, latest)), 'compare-and-select conflict');
        await exec('mount', ['--bind', sources[name], '/etc/resolv.conf']);
        assert.ok(sameDnsObject(await current(), record[name]));
      },
    };
    const run = async (operation) => {
      const result = await controller(path, operation, backend).done;
      assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); return result.result;
    };
    return { path, backend, run, current, sources };
  }
  const points = [
    ['enable', 'prepared'], ['enable', 'apply-intent'], ['enable', 'applied'],
    ['enable', 'active:file-synced'], ['enable', 'active:renamed'], ['enable', 'active'],
    ['disable', 'restore-intent'], ['disable', 'restored-dns'], ['disable', 'restored:renamed'],
    ['disable', 'restore-committed'], ['disable', 'guard-removed'], ['disable', 'released'],
  ];
  for (const [operation, point] of points) {
    const fixtureCase = await fixture();
    if (operation === 'disable') await fixtureCase.run('enable');
    const child = controller(fixtureCase.path, operation, fixtureCase.backend, point);
    try {
      await child.reached;
      if (point === 'active') {
        const rival = await controller(fixtureCase.path, 'recover', fixtureCase.backend).done;
        assert.equal(rival.code, 75); assert.equal(rival.result, undefined); lockConflicts++;
      }
    } finally { child.kill(); }
    const death = await child.done; assert.equal(death.signal, 'SIGKILL'); assert.equal(death.result, undefined); killed++;
    const record = await readDnsJournal(fixtureCase.path), before = hits();
    const current = await fixtureCase.current();
    const alreadyReleased = ['guard-removed', 'released'].includes(point);
    await lookup(`crash-${point}-before-recovery`, alreadyReleased ? '203.0.113.8'
      : sameDnsObject(current, record.managed) ? '192.0.2.123' : null);
    if (!alreadyReleased) assert.equal(hits(), before);
    const recovered = await fixtureCase.run('recover'); assert.equal(recovered.id, record.id);
    assert.equal(recovered.status, operation === 'disable' ? 'released' : 'active');
    await lookup(`crash-${point}-after-recovery`, operation === 'disable' ? '203.0.113.8' : '192.0.2.123', true);
    if (operation === 'enable') { assert.equal(hits(), before); await fixtureCase.run('disable'); }
    cases.push({ operation, point, recovered: recovered.status });
  }
  // Missing journal after a crash in the initial guard phase is a hard stop.
  const missing = await fixture(), initial = controller(missing.path, 'enable', missing.backend, 'guard-installed');
  try { await initial.reached; } finally { initial.kill(); }
  assert.equal((await initial.done).signal, 'SIGKILL'); killed++;
  const errors = [];
  async function refused(name, fixtureCase, expectedText) {
    const before = hits(), identity = await fixtureCase.current();
    const result = await controller(fixtureCase.path, 'recover', fixtureCase.backend).done;
    assert.equal(result.code, 2); assert.equal(result.result, undefined);
    assert.deepEqual(await fixtureCase.current(), identity);
    if (expectedText !== undefined) assert.equal(await readFile('/etc/resolv.conf', 'utf8'), expectedText);
    // Check guard is still present for both families and protocols.
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    }
    await lookup(`refused-${name}`, expectedText === managed && name !== 'exit-down' ? '192.0.2.123' : null);
    assert.equal(hits(), before); errors.push(name);
  }
  await refused('missing-journal', missing, baseline);
  const corrupt = await fixture(); await corrupt.run('enable');
  await writeFile(join(corrupt.path, 'journal.json'), '{broken');
  // The adapter is independent: refusing recovery must not restore/unblock baseline.
  await refused('corrupt-journal', corrupt, managed);
  const conflict = await fixture(); await conflict.run('enable');
  await bindText('/etc/resolv.conf', managed); // same bytes, different inode: still foreign.
  await refused('same-content-foreign-inode', conflict, managed);
  const foreign = await fixture(); await foreign.run('enable');
  const foreignText = 'nameserver ::1\noptions timeout:1 attempts:1\n';
  await bindText('/etc/resolv.conf', foreignText); await refused('foreign-config', foreign, foreignText);
  const stale = await fixture(); await stale.run('enable');
  const old = await readDnsJournal(stale.path); old.scope.mnt = 'mnt:[0]'; await writeDnsJournal(stale.path, old);
  await refused('stale-scope', stale, managed);
  const damaged = await fixture(); await damaged.run('enable');
  await writeFile(damaged.sources.restored, 'nameserver 127.0.0.99\n');
  await refused('changed-snapshot', damaged, managed);
  const outage = await fixture(); await outage.run('enable'); await lab.stopExit();
  try { await refused('exit-down', outage, managed); } finally { await lab.restartExit(); }
  assert.equal((await outage.run('recover')).status, 'active'); await outage.run('disable');
  await lookup('crash-final-explicit-disable', '203.0.113.8');
  return { status: 'passed', controllerSigkills: killed, lockConflicts, cases, refused: errors,
    journalRecoveryTested: true, rebootTested: false, adapterSigkillTested: false, backend: 'namespace-rpc-fixture' };
}
