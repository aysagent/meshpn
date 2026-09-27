/** Disposable guest operator. Archives epochs explicitly; never a live recovery policy. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, cp, chmod, unlink, readFile, writeFile, rename, open } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertRadxaVm, journalBytes as dnsJournalBytes, journalRecords, guardJournal } from './dns-radxa-vm-worker.mjs';
import { journal, emit, exists, ctl, lookup, control } from './dnsmasq-vm-worker.mjs';
import { readRadxaJournal } from './dns-radxa-journal.mjs';
import { RESOLVER_MANAGED } from './dns-resolver-object-journal.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';
import { startDnsmasqUsbPeer } from './dnsmasq-usb-peer.mjs';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';
import { readDnsGuardJournal } from './dns-client-guard-journal.mjs';
import { boundedInspectRead } from './dns-inspect.mjs';
const worker = '/project/scripts/lib/dns-radxa-vm-worker.mjs';
const args = ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node', worker, 'disable'];
const journalBytes = async () => [...await dnsJournalBytes(), await readFile(`${guardJournal}/journal.json`, 'utf8')];
const bootGuard = async (action = '--inspect') => {
  const r = await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
    '/opt/clean-vpn/scripts/dns-boot-guard.mjs', action], { timeout: 60000 });
  if (action === '--inspect') assert.deepEqual(JSON.parse(r.stdout).states, ['present', 'present']);
};
const disable = () => exec('/usr/bin/flock', args, { timeout: 180000 });
const state = async (unit) => (await ctl('show', `dns-vm-${unit}.service`, '--property=ActiveState', '--value')).stdout.trim();
async function inactive(unit) {
  const end = performance.now() + 20000;
  while (['active', 'activating', 'deactivating'].includes(await state(unit))) { assert.ok(performance.now() < end); await delay(100); }
}
async function seed() {
  await mkdir(journal, { mode: 0o700 }); await mkdir(`${journal}/radxa`, { mode: 0o700 });
  const fd = await open(`${journal}/dnsmasq.conf`, 'wx', 0o600);
  try { await fd.writeFile(await readFile('/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf')); await fd.sync(); } finally { await fd.close(); }
  // Copy the synthetic guest /etc, NOT host files. Directory bind preserves
  // systemd units while making atomic resolver rename visible to NSS.
  await cp('/etc', `${journal}/resolver-etc`, { recursive: true, verbatimSymlinks: true });
  await chmod(`${journal}/resolver-etc`, 0o700);
  await unlink(`${journal}/resolver-etc/resolv.conf`);
  await writeFile(`${journal}/resolver-etc/resolv.conf`, RESOLVER_MANAGED, { flag: 'wx', mode: 0o644 });
  await chmod(`${journal}/resolver-etc/resolv.conf`, 0o644);
  await syncDirectory(`${journal}/resolver-etc`); await syncDirectory(journal); await syncDirectory('/state');
}
const bind = () => exec('mount', ['--bind', `${journal}/resolver-etc`, '/etc']);
async function archive(label) {
  await bootGuard('--start'); await ctl('stop', 'dns-vm-controller.service', 'dns-vm-dnsmasq.service');
  const before = await journalBytes(); await exec('/usr/bin/umount', ['/etc']);
  await rename(journal, `/state/archived-${label}`); await syncDirectory('/state');
  await seed(); await bind();
  for (const [i, name] of ['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json'].entries()) assert.equal(await readFile(`/state/archived-${label}/${name}`, 'utf8'), before[i]);
  await rename(guardJournal, `/state/archived-guard-${label}`); await syncDirectory('/state');
  await mkdir(guardJournal, { mode: 0o700 }); await syncDirectory('/state');
  assert.equal(await readFile(`/state/archived-guard-${label}/journal.json`, 'utf8'), before[3]);
}
async function persist(data) {
  const fd = await open('/state/radxa-first-boot.json', 'wx', 0o600);
  try { await fd.writeFile(JSON.stringify(data)); await fd.sync(); } finally { await fd.close(); } await syncDirectory('/state');
}
async function cutDisable() {
  const child = spawn('/usr/bin/flock', args, { stdio: ['ignore', 'inherit', 'inherit'] });
  const timer = setTimeout(() => child.kill('SIGKILL'), 180000);
  try { const [code, signal] = await once(child, 'close'); assert.equal(code, 0); assert.equal(signal, null); }
  finally { clearTimeout(timer); }
}
async function main() {
  const options = await assertRadxaVm(); process.umask(0o077);
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const previous = await exists('/state/radxa-first-boot.json') ? JSON.parse(await readFile('/state/radxa-first-boot.json', 'utf8')) : null;
  if (options.phase === 'radxa-cut') assert.equal(previous, null);
  if (options.phase === 'radxa-inspect') assert.ok(previous);
  const checks = [], check = (label) => { checks.push(label); emit('radxa-check', { label }); };
  for (const tool of ['iptables', 'ip6tables']) for (const p of ['udp', 'tcp'])
    await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', p, '--dport', '53', '-j', 'REJECT']);
  emit('boot-guard', { bootId, ...options, pid1: (await readFile('/proc/1/comm', 'utf8')).trim() });
  if (!previous && options.phase === 'radxa') {
    await writeFile('/run/meshpn/deny-start', 'fixture', { flag: 'wx', mode: 0o600 });
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    for (const u of ['network', 'adapter', 'dnsmasq', 'consumer']) assert.equal(await state(u), 'inactive');
    assert.equal(await exists(`${journal}/radxa/journal.json`), false);
    await unlink('/run/meshpn/deny-start'); await ctl('reset-failed'); check('failed-guard-prevents-services');
  }
  await ctl('start', 'dns-vm-guard.service'); await bootGuard();
  await ctl('stop', 'dns-vm-guard.service'); await bootGuard();
  assert.equal(await state('guard'), 'inactive');
  await ctl('start', 'dns-vm-network.service', 'dns-vm-sentinel.service');
  const guardEnd = BigInt((await ctl('show', 'dns-vm-guard.service', '--property=ExecMainExitTimestampMonotonic', '--value')).stdout.trim());
  const networkStart = BigInt((await ctl('show', 'dns-vm-network.service', '--property=ExecMainStartTimestampMonotonic', '--value')).stdout.trim());
  assert.ok(guardEnd > 0n && networkStart >= guardEnd); await bootGuard(); check('boot-guard-cli-before-network');
  const peer = await startDnsmasqUsbPeer(); let inspected;
  try {
    await ctl('start', 'dns-vm-fixture.service');
    const initialQueries = (await control('fixture', 'stats')).resolverBodies;
    await ctl('start', 'dns-vm-adapter.service');
    assert.equal((await control('fixture', 'stats')).resolverBodies - initialQueries, 4);
    const fixturePid = (await ctl('show', 'dns-vm-fixture.service', '--property=MainPID', '--value')).stdout.trim();
    const adapterPid = (await ctl('show', 'dns-vm-adapter.service', '--property=MainPID', '--value')).stdout.trim();
    assert.notEqual(adapterPid, fixturePid); assert.match(adapterPid, /^[1-9]\d*$/);
    assert.ok((await readFile(`/proc/${adapterPid}/cmdline`, 'utf8')).split('\0').includes('/opt/clean-vpn/scripts/dns-exit-adapter.mjs'));
    const status = await readFile(`/proc/${adapterPid}/status`, 'utf8');
    assert.match(status, /^Uid:\s+[1-9]\d*\s+/m); assert.match(status, /^CapEff:\s+0+$/m);
    assert.match(status, /^NoNewPrivs:\s+1$/m); check('cli-adapter-readiness-and-isolation');
    const noFallback = async () => assert.deepEqual(await control('sentinel', 'stats'), [0, 0, 0]);
    if (previous) {
      assert.notEqual(previous.bootId, bootId); await bind(); const before = await journalBytes();
      if (previous.journals) assert.deepEqual(before, previous.journals);
      inspected = { ...await journalRecords(), guard: await readDnsGuardJournal(guardJournal) };
      assert.equal(inspected.guard.context.bootId, previous.bootId);
      await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
      assert.equal(await state('controller'), 'failed'); assert.equal(await state('dnsmasq'), 'inactive');
      assert.equal(await exists('/run/meshpn/consumers'), false); assert.deepEqual(await journalBytes(), before);
      await noFallback(); check('stale-four-journals-refused'); await archive('previous-boot'); await ctl('reset-failed');
    } else { await seed(); await bind(); }
    if (options.phase === 'radxa-cut') await persist({ bootId, checks });
    await ctl('start', 'dns-vm-consumer.service');
    assert.equal(await state('controller'), 'active'); assert.equal(await state('dnsmasq'), 'active');
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), RESOLVER_MANAGED);
    assert.equal((await readDnsGuardJournal(guardJournal)).stage, 'active');
    await exec('/usr/bin/flock', [...args.slice(0, -1), 'guard-proof-check'], { timeout: 60000 });
    check('active-dns-refuses-release'); check('missing-guard-journal-retains-protection');
    const acquire = async (managed = true) => {
      const r = await peer.acquire(); assert.deepEqual(r.ack.dns, [managed ? '192.168.7.1' : '1.1.1.1']); return r.ack.address;
    };
    const lease = await acquire();
    const local = async () => {
      const r = await peer.lookup({ local: true }); assert.equal(r.rcode, 0);
      assert.equal(r.answer, Buffer.from(lease.split('.').map(Number)).toString('hex'));
    };
    await local(); await lookup('managed-tcp', '192.0.2.123', true); await noFallback(); check('paired-readiness-and-dhcp');
    if (options.phase === 'radxa-cut') {
      await ctl('stop', 'dns-vm-controller.service'); await inactive('consumer');
      await cutDisable(); throw new Error('cut checkpoint not reached');
    }
    const id = (await readRadxaJournal(journal)).id;
    if (!previous) {
      await ctl('stop', 'dns-vm-controller.service'); await inactive('consumer'); await lookup('controller-down', '192.0.2.123');
      await ctl('start', 'dns-vm-consumer.service'); assert.equal((await readRadxaJournal(journal)).id, id); check('controller-restart-same-transaction');
      await control('fixture', 'stop-exit'); await lookup('exit-down', null); assert.equal(await acquire(), lease); await local(); await noFallback();
      await control('fixture', 'start-exit'); await lookup('exit-back', '192.0.2.123'); check('exit-outage-preserves-dhcp');
      await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-adapter.service');
      for (const u of ['adapter', 'controller', 'consumer']) await inactive(u);
      assert.equal(await state('fixture'), 'active');
      assert.equal((await ctl('show', 'dns-vm-fixture.service', '--property=MainPID', '--value')).stdout.trim(), fixturePid);
      assert.equal(await state('dnsmasq'), 'active'); assert.equal(await acquire(), lease); await local(); await lookup('adapter-down', null); await noFallback();
      await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service'); assert.equal((await readRadxaJournal(journal)).id, id);
      check('adapter-sigkill-preserves-dhcp');
      await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-dnsmasq.service'); await inactive('dnsmasq'); await lookup('daemon-dead', null);
      await ctl('stop', 'dns-vm-controller.service'); await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
      assert.equal((await readRadxaJournal(journal)).id, id); assert.equal(await acquire(), lease); await local(); check('dnsmasq-sigkill-recovered');
      const before = await journalBytes();
      await writeFile('/etc/resolv.conf', 'nameserver 192.0.2.2\n');
      await assert.rejects(disable()); assert.deepEqual(await journalBytes(), before);
      assert.equal(await readFile('/etc/resolv.conf', 'utf8'), 'nameserver 192.0.2.2\n'); await noFallback();
      await writeFile('/etc/resolv.conf', RESOLVER_MANAGED); check('foreign-resolver-preserves-four-journals');
    }
    await ctl('stop', 'dns-vm-controller.service'); await inactive('consumer');
    await control('fixture', 'stop-exit'); await noFallback(); await disable();
    assert.equal((await readRadxaJournal(journal)).phase, 'restored');
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), RESOLVER_MANAGED);
    assert.equal((await readDnsGuardJournal(guardJournal)).stage, 'released');
    assert.equal(await readFile(`${journal}/dnsmasq.conf`, 'utf8'), await readFile('/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf', 'utf8'));
    // Before DHCP reacquisition, the client still selects managed dnsmasq.
    // Explicit disable now restores a reviewed working baseline and releases
    // guard after the matching running daemon, including the original offer.
    await local(); assert.equal(await acquire(false), lease);
    const baselineClient = await peer.lookup({ local: true });
    assert.equal(baselineClient.rcode, 0); assert.equal(baselineClient.answer, 'cb007108');
    check('offline-rollback-verifies-daemon-before-release');
    await lookup('baseline-udp', '203.0.113.8'); await lookup('baseline-tcp', '203.0.113.8', true);
    assert.ok((await control('sentinel', 'stats')).reduce((a, b) => a + b, 0) >= 2);
    assert.equal((await control('fixture', 'stats')).dnsCalls, 0);
    if (!previous) {
      const before = await journalBytes(), hits = await control('sentinel', 'stats');
      await control('fixture', 'start-exit');
      await assert.rejects(ctl('start', 'dns-vm-consumer.service')); assert.deepEqual(await journalBytes(), before);
      await lookup('restored-refused', null); assert.deepEqual(await control('sentinel', 'stats'), hits); check('restored-start-refused');
      await archive('restored'); await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
      await lookup('before-reboot', '192.0.2.123'); await persist({ bootId, checks, journals: await journalBytes() });
      await peer.close(); emit('reboot-ready', { bootId }); await ctl('--no-block', 'reboot'); return;
    }
    await peer.close();
    emit('passed', { ...options, bootId, previousBootId: previous.bootId, checks: [...previous.checks, ...checks],
      systemdPid1: true, fourJournalsPreserved: true, exactLocalhostBaselineRestored: true, verifiedGuardRelease: true,
      bootGuardImplementation: 'cli', adapterImplementation: 'cli', unprivilegedAdapter: true, sharedGuardDnsLock: true,
      dhcpPreservedOnAdapterFailure: options.phase === 'radxa', automaticStaleAdoption: false, baselineQueriesDuringProtection: 0, baselinePositiveControl: true,
      ...(options.phase === 'radxa-inspect' ? { inspected } : {}) });
    await ctl('--no-block', 'poweroff');
  } finally { await peer.close(); }
}
main().catch(async (e) => {
  try { await assertRadxaVm(); emit('boot-guard-diagnostics', { log: await boundedInspectRead('/run/meshpn/boot-guard.log', 16384) }); } catch { /* guest only */ }
  try { await assertRadxaVm(); emit('adapter-diagnostics', { log: await boundedInspectRead('/run/meshpn/adapter.log', 16384) }); } catch { /* guest only */ }
  emit('failed', { message: e.stack }); process.exitCode = 1;
});
