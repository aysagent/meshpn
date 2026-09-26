/** Bounded coupled lifecycle + whole-guest crash acceptance. No live installation. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, open, mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { journal, coupledBaseline, emitSystemd as emit, exists, lookup, control } from './dns-systemd-vm-worker.mjs';
import { coupledVmContext } from './dns-coupled-vm-worker.mjs';
import { readCoupledJournal, coupledExpected } from './dns-coupled-journal.mjs';
import { readOwnedLinkJournal } from './dns-owned-link-journal.mjs';
import { assertSystemdVmBaselineBlocked } from './dns-vm-fault-lab.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';

const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args], { timeout: 200000 });
const disable = () => exec('/usr/bin/flock', ['-n', '-F', '/state/controller.lock', '/usr/bin/node',
  '/project/scripts/lib/dns-coupled-vm-worker.mjs', 'disable'], { timeout: 180000 });
async function cutDisable() {
  await assertCoupledDnsVm();
  // Unlike execFile's buffered stdout, inherited console delivers cut-ready
  // while the worker is still alive and waiting for the host to kill QEMU.
  const child = spawn('/usr/bin/flock', ['-n', '-F', '/state/controller.lock', '/usr/bin/node',
    '/project/scripts/lib/dns-coupled-vm-worker.mjs', 'disable'], { stdio: ['ignore', 'inherit', 'inherit'] });
  const timer = setTimeout(() => child.kill('SIGKILL'), 180000);
  try { const [code, signal] = await once(child, 'close'); assert.equal(code, 0); assert.equal(signal, null); }
  finally { clearTimeout(timer); }
}
const state = async (name) => (await ctl('show', name, '--property=ActiveState', '--value')).stdout.trim();
async function inactive(name) {
  const deadline = performance.now() + 20000;
  while (['active', 'activating', 'deactivating'].includes(await state(name))) {
    assert.ok(performance.now() < deadline, `${name} failed to stop`); await delay(100);
  }
}
const bytes = async () => Promise.all(['journal.json', 'link/journal.json'].map((name) => readFile(`${journal}/${name}`, 'utf8')));
async function archive(label) {
  const before = await bytes();
  await rename(journal, `/state/archived-${label}`); await syncDirectory('/state');
  await mkdir(journal, { mode: 0o700 }); await syncDirectory('/state');
  for (const [i, name] of ['journal.json', 'link/journal.json'].entries()) {
    assert.equal(await readFile(`/state/archived-${label}/${name}`, 'utf8'), before[i]);
  }
}
async function persist(value) {
  const fd = await open('/state/coupled-first-boot.json', 'wx', 0o600);
  try { await fd.writeFile(JSON.stringify(value)); await fd.sync(); } finally { await fd.close(); }
  await syncDirectory('/state');
}
async function main() {
  const options = await assertCoupledDnsVm(); process.umask(0o077);
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const previous = await exists('/state/coupled-first-boot.json') ? JSON.parse(await readFile('/state/coupled-first-boot.json', 'utf8')) : null;
  if (options.phase === 'coupled-cut') assert.equal(previous, null);
  if (options.phase === 'coupled-inspect') assert.ok(previous, 'missing first-boot evidence');
  const resolverBefore = await readFile('/etc/resolv.conf'), checks = [];
  const check = (label) => { checks.push(label); emit('coupled-check', { label }); };
  for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
    await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
  }
  emit('boot-guard', { bootId, ...options, pid1: (await readFile('/proc/1/comm', 'utf8')).trim() });
  if (!previous && options.phase === 'coupled') {
    await writeFile('/run/meshpn/deny-start', 'fixture\n', { flag: 'wx', mode: 0o600 });
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    assert.equal(await state('dns-vm-guard.service'), 'failed');
    assert.equal(await exists('/run/meshpn/consumers'), false);
    assert.equal(await exists(`${journal}/journal.json`), false);
    assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
    assert.equal(await state('dns-vm-adapter.service'), 'inactive');
    await unlink('/run/meshpn/deny-start'); await ctl('reset-failed');
    check('failed-guard-prevents-services');
  }
  await ctl('start', 'dns-vm-sentinel.service', 'dns-vm-baseline.service', 'dns-vm-adapter.service');
  const { bus, backend, ifindex } = await coupledVmContext();
  const baseline = async () => {
    const owner = await bus.owner();
    for (const [key, value] of Object.entries(coupledBaseline)) assert.deepEqual(await bus.property(owner, ifindex, key), value);
  };
  const noFallback = async () => {
    for (const address of ['127.0.0.55', '::1']) for (const tcp of [false, true]) await assertSystemdVmBaselineBlocked(address, tcp);
    assert.deepEqual(await control('sentinel', 'stats'), { ipv4: 0, ipv6: 0 }); await baseline();
  };
  let inspected;
  if (previous) {
    assert.notEqual(bootId, previous.bootId);
    const before = await bytes();
    inspected = { root: await readCoupledJournal(journal), child: await readOwnedLinkJournal(`${journal}/link`) };
    assert.equal(inspected.root.context.bootId, previous.bootId);
    assert.equal(inspected.child.id, inspected.root.id);
    assert.deepEqual(inspected.child.context, inspected.root.context);
    assert.equal(await backend.view(inspected.root.name), null, 'old kernel link must not survive a new boot');
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    assert.equal(await state('dns-vm-controller.service'), 'failed');
    assert.equal(await exists('/run/meshpn/consumers'), false);
    assert.deepEqual(await bytes(), before);
    assert.equal(await backend.view(inspected.root.name), null);
    await noFallback(); check('stale-journals-preserved-start-refused');
    // Explicit test operator archives BOTH journals. This is not automatic
    // recovery authority and must never be copied into a live service.
    await archive('previous-boot'); await ctl('reset-failed');
  }
  if (options.phase === 'coupled-cut') await persist({ bootId, checks });
  await ctl('start', 'dns-vm-consumer.service');
  assert.equal(await state('dns-vm-controller.service'), 'active');
  assert.equal(await state('dns-vm-consumer.service'), 'active');
  const active = await readCoupledJournal(journal);
  assert.deepEqual(await backend.view(active.name), coupledExpected(active, 7));
  await lookup('coupled-aaaa', '2001:db8::12', true, 6); await noFallback();
  check('readiness-owned-link-and-protected-dns');
  if (options.phase === 'coupled-cut') {
    await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
    await cutDisable(); throw new Error('power-cut checkpoint not reached');
  }
  if (!previous) {
    await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
    await lookup('controller-stopped', '192.0.2.123'); await noFallback();
    await ctl('start', 'dns-vm-consumer.service');
    assert.equal((await readCoupledJournal(journal)).id, active.id);
    check('controller-stop-retains-protection');
    await control('fixture', 'stop-exit'); await lookup('exit-down', null); await noFallback();
    await control('fixture', 'start-exit'); await lookup('exit-recovered', '192.0.2.123');
    check('exit-outage-no-baseline-fallback');
    await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-adapter.service');
    for (const unit of ['adapter', 'controller', 'consumer']) await inactive(`dns-vm-${unit}.service`);
    await lookup('adapter-dead', null); await noFallback();
    await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
    assert.equal((await readCoupledJournal(journal)).id, active.id);
    await lookup('adapter-restarted', '192.0.2.123'); await noFallback();
    check('adapter-sigkill-recovery-same-transaction');
    const owner = await bus.owner(), ownedIndex = active.original.ifindex;
    await bus.set(owner, resolvedMethod('Domains', [['foreign.test', true]], ownedIndex));
    const before = await bytes();
    await assert.rejects(disable(), (e) => /ownership conflict/.test(e.stderr));
    assert.deepEqual(await bytes(), before);
    assert.deepEqual(await bus.property(owner, ownedIndex, 'Domains'), [['foreign.test', true]]);
    await noFallback(); check('foreign-policy-preserved');
    await bus.set(owner, resolvedMethod('Domains', [['.', true]], ownedIndex)); // explicit fixture repair
  }
  await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service'); await noFallback();
  await disable();
  assert.equal((await readCoupledJournal(journal)).phase, 'released');
  assert.equal((await readOwnedLinkJournal(`${journal}/link`)).stage, 'released');
  assert.equal(await backend.view(active.name), null); await baseline();
  await lookup('disabled-udp', '203.0.113.8'); await lookup('disabled-tcp', '203.0.113.8', true);
  assert.ok((await control('sentinel', 'stats')).ipv4 >= 2);
  assert.equal((await control('fixture', 'stats')).dnsCalls, 0);
  assert.deepEqual(await readFile('/etc/resolv.conf'), resolverBefore);
  check('disable-removes-owned-link-before-baseline-release');
  if (!previous) {
    const released = await bytes(), hits = await control('sentinel', 'stats');
    await assert.rejects(ctl('start', 'dns-vm-consumer.service')); await inactive('dns-vm-consumer.service');
    assert.deepEqual(await bytes(), released);
    for (const address of ['127.0.0.55', '::1']) for (const tcp of [false, true]) await assertSystemdVmBaselineBlocked(address, tcp);
    assert.deepEqual(await control('sentinel', 'stats'), hits);
    check('released-journal-start-refused');
    await archive('released'); await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
    await lookup('before-reboot', '192.0.2.123'); assert.deepEqual(await control('sentinel', 'stats'), hits);
    await persist({ bootId, checks }); emit('reboot-ready', { bootId }); await ctl('--no-block', 'reboot'); return;
  }
  emit('passed', { ...options, bootId, previousBootId: previous.bootId, systemdPid1: true,
    checks: [...previous.checks, ...checks], automaticStaleAdoption: false, baselineQueriesDuringProtection: 0,
    baselinePositiveControl: true, explicitDisablePassed: true, ownedLinkRemoved: true, bothJournalsPreservedOnRefusal: true,
    resolvConfUnchanged: true, ...(options.phase === 'coupled-inspect' ? { inspected } : {}) });
  await ctl('--no-block', 'poweroff');
}
main().catch((error) => { emit('failed', { message: error.stack }); process.exitCode = 1; });
