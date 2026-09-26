/** Disposable guest operator. Archives epochs explicitly; never a live recovery policy. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, cp, chmod, unlink, symlink, readlink, readFile, writeFile, rename, open } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertRadxaVm, journalBytes, journalRecords } from './dns-radxa-vm-worker.mjs';
import { journal, emit, exists, ctl, guard, lookup, control } from './dnsmasq-vm-worker.mjs';
import { readRadxaJournal } from './dns-radxa-journal.mjs';
import { RESOLVER_TARGET, RESOLVER_MANAGED } from './dns-resolver-object-journal.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';
import { startDnsmasqUsbPeer } from './dnsmasq-usb-peer.mjs';
const worker = '/project/scripts/lib/dns-radxa-vm-worker.mjs';
const args = ['-n', '-F', '/state/controller.lock', '/usr/bin/node', worker, 'disable'];
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
  await unlink(`${journal}/resolver-etc/resolv.conf`); await symlink(RESOLVER_TARGET, `${journal}/resolver-etc/resolv.conf`);
  await syncDirectory(`${journal}/resolver-etc`); await syncDirectory(journal); await syncDirectory('/state');
}
const bind = () => exec('mount', ['--bind', `${journal}/resolver-etc`, '/etc']);
async function archive(label) {
  await guard(true); await ctl('stop', 'dns-vm-controller.service', 'dns-vm-dnsmasq.service');
  const before = await journalBytes(); await exec('/usr/bin/umount', ['/etc']);
  await rename(journal, `/state/archived-${label}`); await syncDirectory('/state');
  await seed(); await bind();
  for (const [i, name] of ['radxa/journal.json', 'journal.json', 'resolver-etc/journal.json'].entries()) assert.equal(await readFile(`/state/archived-${label}/${name}`, 'utf8'), before[i]);
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
  await guard(true); emit('boot-guard', { bootId, ...options, pid1: (await readFile('/proc/1/comm', 'utf8')).trim() });
  if (!previous && options.phase === 'radxa') {
    await writeFile('/run/meshpn/deny-start', 'fixture', { flag: 'wx', mode: 0o600 });
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    for (const u of ['network', 'adapter', 'dnsmasq', 'consumer']) assert.equal(await state(u), 'inactive');
    assert.equal(await exists(`${journal}/radxa/journal.json`), false);
    await unlink('/run/meshpn/deny-start'); await ctl('reset-failed'); check('failed-guard-prevents-services');
  }
  await ctl('start', 'dns-vm-network.service', 'dns-vm-sentinel.service');
  const peer = await startDnsmasqUsbPeer(); let inspected;
  try {
    await ctl('start', 'dns-vm-adapter.service');
    const noFallback = async () => assert.deepEqual(await control('sentinel', 'stats'), [0, 0, 0]);
    if (previous) {
      assert.notEqual(previous.bootId, bootId); await bind(); const before = await journalBytes();
      if (previous.journals) assert.deepEqual(before, previous.journals);
      inspected = await journalRecords();
      await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
      assert.equal(await state('controller'), 'failed'); assert.equal(await state('dnsmasq'), 'inactive');
      assert.equal(await exists('/run/meshpn/consumers'), false); assert.deepEqual(await journalBytes(), before);
      await noFallback(); check('stale-three-journals-refused'); await archive('previous-boot'); await ctl('reset-failed');
    } else { await seed(); await bind(); }
    if (options.phase === 'radxa-cut') await persist({ bootId, checks });
    await ctl('start', 'dns-vm-consumer.service');
    assert.equal(await state('controller'), 'active'); assert.equal(await state('dnsmasq'), 'active');
    assert.equal(await readFile('/etc/resolv.conf', 'utf8'), RESOLVER_MANAGED);
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
      await writeFile('/etc/resolv.conf', RESOLVER_MANAGED); check('foreign-resolver-preserves-three-journals');
    }
    await ctl('stop', 'dns-vm-controller.service'); await inactive('consumer');
    await control('fixture', 'stop-exit'); await disable(); await noFallback();
    assert.equal((await readRadxaJournal(journal)).phase, 'restored'); assert.equal(await readlink('/etc/resolv.conf'), RESOLVER_TARGET);
    assert.equal(await readFile(`${journal}/dnsmasq.conf`, 'utf8'), await readFile('/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf', 'utf8'));
    // Before DHCP reacquisition, the client still selects managed dnsmasq.
    // The exact baseline offer then selects 1.1.1.1, which must stay blocked.
    await local(); assert.equal(await acquire(false), lease);
    const baselineClient = await peer.lookup({ local: true });
    assert.ok(['client-deadline', 'transport-error'].includes(baselineClient.outcome));
    await lookup('rollback-blocked', null);
    for (const tool of ['iptables', 'ip6tables']) for (const p of ['udp', 'tcp']) await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', p, '--dport', '53', '-j', 'REJECT']);
    await noFallback(); check('offline-rollback-retains-guard');
    // Only the synthetic driver permits baseline positive controls. Neither
    // controller nor service stop authorizes release for a dangling baseline.
    await guard(false); await lookup('baseline-udp', '203.0.113.8'); await lookup('baseline-tcp', '203.0.113.8', true);
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
      systemdPid1: true, threeJournalsPreserved: true, exactResolverLinkRestored: true, rollbackGuardRetained: true,
      dhcpPreservedOnAdapterFailure: options.phase === 'radxa', automaticStaleAdoption: false, baselineQueriesDuringProtection: 0, baselinePositiveControl: true,
      ...(options.phase === 'radxa-inspect' ? { inspected } : {}) });
    await ctl('--no-block', 'poweroff');
  } finally { await peer.close(); }
}
main().catch((e) => { emit('failed', { message: e.stack }); process.exitCode = 1; });
