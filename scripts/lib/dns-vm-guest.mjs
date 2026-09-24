/** Executed ONLY as PID 1 in the disposable VM's private user/mount/net namespaces. */
import assert from 'node:assert/strict';
import { readFile, readlink, mkdir, writeFile, rename, open, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { vmBootOptions, assertVmJournalCheckpoint } from './dns-vm-protocol.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { exec } from './browser-lab-driver.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { runResolvedLab } from './dns-resolved-lab.mjs';
import { createResolvedJournalBackend } from './dns-resolved-backend.mjs';
import { resolvedTransaction, readResolvedJournal } from './dns-resolved-journal.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { sha256 } from './dns-vm-image.mjs';
import { failVmGuardBeforeNetwork, runVmStartupFault, assertVmBaselineBlocked } from './dns-vm-fault-lab.mjs';

const emit = (event, data = {}) => console.log(`DNS_VM_EVENT ${JSON.stringify({ event, ...data })}`);
async function main() {
  // All checks precede mutation. This entrypoint is not a host DNS command.
  const options = vmBootOptions(await readFile('/proc/cmdline', 'utf8'));
  assert.match(await readFile('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  await assertDnsMountNamespace();
  assert.equal(process.getuid(), 1000); process.umask(0o077);
  assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const directory = `/state/boot-${bootId}`; await mkdir(directory, { mode: 0o700 });
  // Hide the outer init's root-owned xtables lock and all runtime sockets.
  const privateRun = '/tmp/dns-vm-run'; await mkdir(privateRun, { mode: 0o700 });
  await exec('mount', ['--bind', privateRun, '/run']);
  const journal = '/state/transaction'; await mkdir(journal, { mode: 0o700, recursive: true });
  await syncDirectory('/state');
  const scope = Object.fromEntries(await Promise.all(['net', 'mnt', 'pid'].map(async (key) => [key, await readlink(`/proc/self/ns/${key}`)])));
  const guardFailure = options.phase === 'fault' && options.point === 'guard-unavailable'
    ? await failVmGuardBeforeNetwork({ journal, scope }) : undefined;
  let guard = false, lab, observer, observer6, fileId = 0;
  const hits = () => (observer?.hits() ?? 0) + (observer6?.hits() ?? 0);
  const checks = [];
  const setGuard = async (enabled) => {
    if (guard === enabled) return;
    for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
      const rule = ['OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT'];
      await exec(tool, ['-w', '2', enabled ? '-A' : '-D', ...rule]);
      if (enabled) await exec(tool, ['-w', '2', '-C', ...rule]);
    }
    guard = enabled;
  };
  const bindText = async (target, contents) => {
    const path = join(directory, `mount-${fileId++}`);
    await writeFile(path, contents, { flag: 'wx', mode: 0o600 }); await exec('mount', ['--bind', path, target]);
  };
  const lookup = async (label, expected, tcp = false, family = 4) => {
    const started = performance.now();
    let code = 0, stdout;
    try { ({ stdout } = await exec('getent', ['-A', '-s', 'dns', `ahostsv${family}`, `vm-${checks.length}.test`],
      // TCG emulates TLS and the guest scheduler: a 1s glibc deadline can expire
      // with a healthy protected query still in flight. No retry/fallback added.
      { env: { ...process.env, RES_OPTIONS: `timeout:5 attempts:1${tcp ? ' use-vc' : ''}` }, timeout: 15000 })); }
    catch (e) { assert.equal(e.killed, false, label); code = e.code; stdout = e.stdout; }
    if (code !== (expected ? 0 : 2)) emit('lookup-diagnostic', { label, code, elapsedMs: Math.round(performance.now() - started), stats: lab?.stats() });
    assert.equal(code, expected ? 0 : 2, label);
    if (expected) assert.ok(stdout.split('\n').filter(Boolean).every((line) => line.startsWith(`${expected} `)), label);
    else assert.equal(stdout, '', label);
    checks.push(label);
  };
  const readControl = async () => { try { return JSON.parse(await readFile('/state/control.json', 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; return null; } };
  const saveControl = async () => {
    const fd = await open('/state/control.json', 'wx', 0o600);
    try { await fd.writeFile(JSON.stringify({ bootId, point: options.point })); await fd.sync(); } finally { await fd.close(); }
    await syncDirectory('/state');
  };
  try {
    await setGuard(true); // Before lo, DNS consumers, resolved, or adapter startup.
    await exec('ip', ['link', 'set', 'lo', 'up']);
    observer = await sentinel('127.0.0.55');
    observer6 = await sentinel('::1');
    await bindText('/etc/resolv.conf', 'nameserver ::1\noptions timeout:1 attempts:1\n');
    await lookup('early-ipv6-baseline-udp-blocked', null); await lookup('early-ipv6-baseline-tcp-blocked', null, true);
    await bindText('/etc/resolv.conf', 'nameserver 127.0.0.55\noptions timeout:1 attempts:1\n');
    await lookup('early-baseline-udp-blocked', null); await lookup('early-baseline-tcp-blocked', null, true);
    assert.equal(hits(), 0);
    emit('boot-guard', { bootId, ...options });
    lab = await startAdapterSoakLab({ family: 4, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 5000 }, directory);
    return await runResolvedLab({ directory, lab, bindText, setGuard, lookup, hits,
      async bootRunner({ bus, ifindex, identity, version }) {
        const probe = async () => {
          for (const tcp of [false, true]) {
            const q = makeDnsQuery('vm-ready.test');
            assert.equal(validateDnsResponse(await queryLabDns(lab.adapter.port, q, { tcp, timeoutMs: 10000 }), q).flags & 15, 0, 'protected VM DNS readiness failed');
          }
        };
        const backend = createResolvedJournalBackend({ bus, scope, ifindex, identity, port: lab.adapter.port,
          ensureGuard: () => setGuard(true), removeGuard: () => setGuard(false), probe });
        const transact = (operation, checkpoint) => resolvedTransaction({ directory: journal, operation, scope, backend, checkpoint });
        if (options.phase === 'fault') {
          const fault = await runVmStartupFault({ point: options.point, journal, scope, backend, lab, guardFailure,
            async blocked() {
              assert.equal(guard, true);
              for (const address of ['127.0.0.55', '::1']) {
                for (const tcp of [false, true]) {
                  await assertVmBaselineBlocked(address, tcp); checks.push(`fault-${address}-${tcp ? 'tcp' : 'udp'}-blocked`);
                }
              }
              assert.equal(hits(), 0);
            },
            async managed() {
              await lookup('fault-recovered-managed-a', '192.0.2.123');
              await lookup('fault-recovered-managed-aaaa-tcp', '2001:db8::12', true, 6);
              assert.equal(hits(), 0);
            },
            async restored() {
              await lookup('fault-explicit-disable-baseline-udp', '203.0.113.8');
              await lookup('fault-explicit-disable-baseline-tcp', '203.0.113.8', true);
              assert.ok(observer.hits() >= 2);
              await bindText('/etc/resolv.conf', 'nameserver ::1\noptions timeout:1 attempts:1\n');
              await lookup('fault-explicit-disable-ipv6-udp', '203.0.113.8');
              await lookup('fault-explicit-disable-ipv6-tcp', '203.0.113.8', true);
              assert.ok(observer6.hits() >= 2); assert.equal(lab.stats().dnsCalls, 0);
            } });
          emit('passed', { bootId, ...options, version, checks, fault, baselineQueriesDuringProtection: 0, baselinePositiveControl: true });
          return 0;
        }
        const control = await readControl();
        const afterBoot = options.phase === 'inspect' || control !== null;
        if (afterBoot) {
          assert.ok(control); assert.notEqual(control.bootId, bootId); assert.equal(control.point, options.point);
          const files = await readdir(journal);
          const bytes = files.includes('journal.json') ? await readFile(join(journal, 'journal.json')) : null;
          let oldRecord;
          if (bytes) {
            oldRecord = await readResolvedJournal(journal);
            assertVmJournalCheckpoint(oldRecord, options.point);
            assert.notEqual(oldRecord.context.busId, await bus.id());
            await assert.rejects(transact('recover'), /stale namespace scope|resolved context changed/);
            assert.deepEqual(await readFile(join(journal, 'journal.json')), bytes);
          } else {
            assert.ok(['prepared:file-synced', 'prepared:renamed'].includes(options.point), 'unexpected missing durable journal');
            await assert.rejects(transact('recover'), { code: 'ENOENT' });
          }
          assert.equal(guard, true); assert.equal(hits(), 0);
          // Explicit fixture-only authorization of a new epoch. No live adoption API.
          const archive = `/state/previous-${control.bootId}`;
          await rename(journal, archive); await syncDirectory('/state');
          await mkdir(journal, { mode: 0o700 }); await syncDirectory('/state');
          if (bytes) assert.equal(sha256(await readFile(join(archive, 'journal.json'))), sha256(bytes));
          const enabled = await transact('enable');
          if (oldRecord) assert.notEqual(enabled.id, oldRecord.id);
          await lookup('new-epoch-managed-a', '192.0.2.123');
          await lookup('new-epoch-managed-aaaa-tcp', '2001:db8::12', true, 6);
          assert.equal(hits(), 0);
          await transact('disable');
          await lookup('explicit-disable-baseline-udp', '203.0.113.8');
          await lookup('explicit-disable-baseline-tcp', '203.0.113.8', true);
          assert.ok(observer.hits() >= 2);
          await bindText('/etc/resolv.conf', 'nameserver ::1\noptions timeout:1 attempts:1\n');
          await lookup('explicit-disable-ipv6-baseline-udp', '203.0.113.8');
          await lookup('explicit-disable-ipv6-baseline-tcp', '203.0.113.8', true);
          assert.ok(observer6.hits() >= 2);
          assert.equal(lab.stats().dnsCalls, 0, 'upstream bootstrap must not invoke system DNS');
          emit('passed', { bootId, previousBootId: control.bootId, ...options, version, checks,
            oldJournalPresent: !!bytes, oldJournalPreserved: true, staleRecoveryRefused: true,
            baselineQueriesDuringProtection: 0, baselinePositiveControl: true, upstreamSystemDnsCalls: 0 });
          return 0;
        }
        assert.ok(options.phase !== 'inspect'); await saveControl();
        const checkpoint = async (point) => {
          if (options.phase !== 'cut' || point !== options.point) return;
          emit('cut-ready', { bootId, point });
          await new Promise(() => {}); // Host kills this VM; never flush after this checkpoint.
        };
        await transact('enable', checkpoint);
        await lookup('first-boot-managed', '192.0.2.123'); assert.equal(hits(), 0);
        if (options.phase === 'cut') {
          await transact('disable', checkpoint); throw new Error('cut checkpoint not reached');
        }
        emit('reboot-ready', { bootId }); return 42;
      } });
  } finally { await lab?.close(); await observer?.close(); await observer6?.close(); }
}
main().then((code) => process.exit(code)).catch((error) => { emit('failed', { message: error.stack }); process.exit(1); });
