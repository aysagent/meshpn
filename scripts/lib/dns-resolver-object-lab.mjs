/** Namespace-only synthetic /etc. No host resolver inode is edited or followed. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, readlink, symlink, lstat, realpath, rename, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { createResolverObjectFiles } from './dns-resolver-object-files.mjs';
import { RESOLVER_TARGET, RESOLVER_MANAGED, readResolverObjectJournal, inspectResolverObjectTransaction } from './dns-resolver-object-journal.mjs';
import { controller } from './dns-lifecycle-crash-lab.mjs';
import { radxaCrashLab } from './dns-radxa-crash-lab.mjs';

export const RESOLVER_CRASH_POINTS = Object.freeze(['prepared', 'apply-intent', 'apply:set', 'active', 'restore-intent', 'restore:set', 'restored']);
export async function setupResolverObjectLab(parent, { localhostBaseline = false } = {}) {
  await assertDnsMountNamespace();
  const directory = join(parent, 'resolver-etc'), privateRun = join(parent, 'resolver-run');
  await mkdir(directory, { mode: 0o700 }); await mkdir(privateRun, { mode: 0o700 });
  // Debian's tool entrypoints traverse /etc/alternatives. Preserve only these
  // four executable links in the synthetic tree, never copy the host /etc.
  await mkdir(join(directory, 'alternatives'), { mode: 0o700 });
  for (const name of ['iptables', 'ip6tables', 'iptables-save', 'ip6tables-save']) {
    await symlink(await realpath(`/usr/sbin/${name}`), join(directory, 'alternatives', name));
  }
  await writeFile(join(directory, 'passwd'), 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n');
  await writeFile(join(directory, 'group'), 'root:x:0:\nnogroup:x:65534:\n');
  await writeFile(join(directory, 'nsswitch.conf'), 'passwd: files\ngroup: files\nhosts: dns\n');
  await writeFile(join(directory, 'lock'), '', { mode: 0o600, flag: 'wx' });
  if (localhostBaseline) {
    await writeFile(join(directory, 'resolv.conf'), RESOLVER_MANAGED, { flag: 'wx' });
    await chmod(join(directory, 'resolv.conf'), 0o644);
  } else await symlink(RESOLVER_TARGET, join(directory, 'resolv.conf'));
  await exec('mount', ['--bind', privateRun, '/run']); await exec('mount', ['--bind', directory, '/etc']);
  process.env.OPENSSL_CONF = '/dev/null';
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) scope[key] = await readlink(`/proc/self/ns/${key}`);
  let sequence = 0;
  const evidence = { controllerSigkills: 0, lockConflicts: 0, checkpoints: [], checks: [], exactSymlinkTextRestored: false,
    baseline: localhostBaseline ? 'localhost-file' : 'dangling-stub', exactLocalhostFileRestored: false, boundedBlockedLookups: [],
    protectionRetainedAfterRestore: false, refusals: [], fixtureOnly: true, rebootTested: false };
  const checkEnvironment = async () => {
    await assertDnsMountNamespace();
    const mounts = (await readFile('/proc/self/mountinfo', 'utf8')).trim().split('\n')
      .map((line) => line.split(' ')[4].replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8))));
    for (const path of ['/etc/resolv.conf', join(directory, 'resolv.conf'), join(directory, 'managed.conf'), join(directory, 'restored.conf')]) {
      assert.ok(!mounts.includes(path), 'resolver object is a mountpoint');
    }
    const a = await lstat('/etc', { bigint: true }), b = await lstat(directory, { bigint: true });
    assert.equal(a.ino, b.ino); assert.equal(a.dev, b.dev, 'private /etc mount replaced');
    await assert.rejects(lstat(RESOLVER_TARGET), { code: 'ENOENT' }, 'resolved target appeared; explicit review required');
  };
  await checkEnvironment();
  async function systemLookup(label, expected, tcp = false, family = 4, allowBlockedDeadline = false) {
    assert.ok(!allowBlockedDeadline || expected === null, 'deadline is never a successful lookup');
    await checkEnvironment();
    let code = 0, stdout = '';
    try { ({ stdout } = await exec('getent', ['-A', '-s', 'dns', `ahostsv${family}`, `resolver-${++sequence}.test`],
      { timeout: 5000, env: { ...process.env, RES_OPTIONS: `timeout:1 attempts:1${tcp ? ' use-vc' : ''}` } })); }
    catch (e) {
      if (allowBlockedDeadline && e.killed) {
        assert.equal(e.signal, 'SIGTERM', label); assert.equal(e.code, null, label); assert.equal(e.stdout, '', label);
        evidence.boundedBlockedLookups.push(label); code = 2; stdout = '';
      } else { assert.equal(e.killed, false, label); code = e.code; stdout = e.stdout; }
    }
    assert.equal(code, expected ? 0 : 2, label);
    if (expected) assert.ok(stdout.trim().split('\n').every((line) => line.startsWith(`${expected} `)), label);
    else assert.equal(stdout, '', label);
    evidence.checks.push(label);
  }
  let backend, paired, backendError = '';
  const run = async (operation, pause) => {
    const worker = controller(directory, operation, backend, pause, 'resolver-object');
    if (!pause) { const r = await worker.done; assert.equal(r.code, 0, `${r.stderr} ${backendError}`); return r.result; }
    try {
      await worker.reached;
      if (pause === 'prepared') {
        assert.equal((await controller(directory, 'recover', backend, undefined, 'resolver-object').done).code, 75);
        evidence.lockConflicts++;
      }
    } catch (e) { throw new Error(`${e.message}; ${backendError}`); }
    finally { worker.kill(); }
    assert.equal((await worker.done).signal, 'SIGKILL'); evidence.controllerSigkills++; evidence.checkpoints.push(pause);
  };
  return { evidence, systemLookup, recover: () => paired.recover(), recoveryResult: () => paired.raw('recover').done,
    async enable({ ensureGuard, probe, dnsmasq }) {
      const files = await createResolverObjectFiles({ directory, checkEnvironment, ensureGuard, probe,
        baseline: localhostBaseline ? 'localhost-file' : 'dangling-stub',
        identity: async () => ({ scope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim() }) });
      backend = Object.fromEntries(Object.entries(files).map(([name, fn]) => [name, async (...args) => {
        try { return await fn(...args); } catch (e) { backendError = `${name}: ${e.stack}`.slice(0, 4096); throw e; }
      }]));
      if (dnsmasq) {
        paired = await radxaCrashLab(parent, scope, dnsmasq, backend);
        evidence.paired = paired.evidence; await paired.enable();
      } else {
        await run('enable', 'prepared');
        const before = await readFile(join(directory, 'journal.json'));
        assert.equal((await inspectResolverObjectTransaction({ directory, scope, backend })).readinessVerified, false);
        assert.deepEqual(await readFile(join(directory, 'journal.json')), before);
        for (const point of ['apply-intent', 'apply:set', 'active']) await run('recover', point);
        assert.equal((await run('recover')).status, 'active');
      }
      assert.equal(await readFile('/etc/resolv.conf', 'utf8'), RESOLVER_MANAGED);
      assert.equal((await readResolverObjectJournal(directory)).phase, 'active');
      for (const family of [4, 6]) for (const tcp of [false, true]) {
        await systemLookup(`system-managed-${family}-${tcp ? 'tcp' : 'udp'}`, family === 4 ? '192.0.2.123' : '2001:db8::12', tcp, family);
      }
      const refuse = async (label) => {
        const journals = [join(directory, 'journal.json'), ...(paired ? [join(parent, 'journal.json'), join(parent, 'radxa', 'journal.json')] : [])];
        const before = await Promise.all(journals.map((path) => readFile(path)));
        const result = await (paired ? paired.raw('recover') : controller(directory, 'recover', backend, undefined, 'resolver-object')).done;
        assert.notEqual(result.code, 0, label); assert.equal(result.signal, null, label);
        assert.match(result.stderr, /DNS_CONTROLLER_REFUSED/);
        assert.deepEqual(await Promise.all(journals.map((path) => readFile(path))), before);
        for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
          await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
        }
        evidence.refusals.push(label);
      };
      // These are explicit fixture mutations, not automatic recovery actions.
      const path = join(directory, 'resolv.conf'), saved = join(directory, 'owned.saved');
      await rename(path, saved);
      await writeFile(path, RESOLVER_MANAGED, { flag: 'wx', mode: 0o644 }); await chmod(path, 0o644);
      const foreign = await lstat(path);
      await refuse('same-content-foreign-inode'); assert.equal((await lstat(path)).ino, foreign.ino);
      await rename(path, join(directory, 'foreign.saved')); await rename(saved, path);
      await exec('mount', ['--bind', path, '/etc/resolv.conf']);
      try { await refuse('resolver-mountpoint'); } finally { await exec('umount', ['/etc/resolv.conf']); }
      await mkdir('/run/systemd/resolve', { recursive: true });
      await writeFile(RESOLVER_TARGET, 'nameserver 192.0.2.1\n', { flag: 'wx' });
      await refuse('resolved-target-appeared');
      assert.equal(await readFile(RESOLVER_TARGET, 'utf8'), 'nameserver 192.0.2.1\n');
      await rename(RESOLVER_TARGET, `${RESOLVER_TARGET}.saved`);
      assert.equal((await (paired ? paired.recover() : run('recover'))).status, 'active');
    },
    async restore() {
      if (paired) await paired.restore();
      else {
        await run('disable', 'restore-intent'); await run('recover', 'restore:set'); await run('recover', 'restored');
        const r = await run('recover'); assert.equal(r.status, 'restored'); assert.equal(r.protectionRetained, true);
      }
      if (localhostBaseline) {
        assert.equal(await readFile('/etc/resolv.conf', 'utf8'), RESOLVER_MANAGED);
        const stat = await lstat('/etc/resolv.conf'); assert.ok(stat.isFile()); assert.equal(stat.mode & 0o7777, 0o644);
      } else assert.equal(await readlink('/etc/resolv.conf'), RESOLVER_TARGET);
      await checkEnvironment();
      for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
        await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
      }
      evidence.exactSymlinkTextRestored = !localhostBaseline; evidence.exactLocalhostFileRestored = localhostBaseline;
      evidence.protectionRetainedAfterRestore = true;
      if (!paired) assert.deepEqual(evidence.checkpoints, RESOLVER_CRASH_POINTS);
    },
  };
}
