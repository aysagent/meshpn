import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { namespaceArgs } from './lib/browser-soak.mjs';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';

for (const family of [4, 6]) test(`CLI protected readiness over IPv${family} exit, startup faults, cancellation and recovery`, { timeout: 45000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-dns-ready-real-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = `
    import {runDnsAdapterReadyLab} from './scripts/lib/dns-adapter-ready-lab.mjs';
    process.umask(0o077); console.log = console.warn = console.error = () => {};
    try { const r = await runDnsAdapterReadyLab(process.env.MESHPN_READY_DIR, ${family});
      process.stdout.write('DNS_READY_RESULT ' + JSON.stringify(r) + '\\n');
    } catch (e) { process.stderr.write('DNS_READY_FAILED ' + e.message); process.exitCode = 1; }
  `;
  const r = await runCommand('unshare', [...namespaceArgs, 'sh', '-eu', '-c', 'ulimit -c 0; ip link set lo up; exec "$@"',
    'dns-ready', process.execPath, '--input-type=module', '-e', source], { timeoutMs: 40000,
    env: { ...cleanEnvironment(process.env), MESHPN_READY_DIR: directory,
      MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  assert.ok(r.stdout.startsWith('DNS_READY_RESULT ')); const report = JSON.parse(r.stdout.slice('DNS_READY_RESULT '.length));
  assert.equal(report.status, 'passed'); assert.equal(report.family, family); assert.equal(report.systemDnsChanged, false);
  assert.equal(report.systemdNotificationTested, false); assert.equal(report.dnsCalls, 0);
  assert.deepEqual(report.checks, ['four-probes-before-ready-and-clean-stop', 'denied-readiness-name-refused-before-network',
    'exit-down-no-ready', 'resolver-reset-no-ready', 'negative-answer-no-ready', 'sigterm-during-probe-no-ready', 'port-reusable-and-recovery-ready']);
  assert.deepEqual(report.resources, { processes: 1, zombies: 0 });
});
