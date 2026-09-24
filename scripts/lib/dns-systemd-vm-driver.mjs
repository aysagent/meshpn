/** Bounded acceptance workload, never invoked on a real client. */
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, rename, unlink, open } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertSystemdDnsVm } from './dns-systemd-vm-safety.mjs';
import { journal, baseline, emitSystemd as emit, exists, busContext, lookup, control } from './dns-systemd-vm-worker.mjs';
import { assertSystemdVmBaselineBlocked } from './dns-vm-fault-lab.mjs';
import { readResolvedJournal } from './dns-resolved-journal.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';

const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args], { timeout: 200000 });
const worker = '/project/scripts/lib/dns-systemd-vm-worker.mjs';
const disable = () => exec('/usr/bin/flock', ['-n', '/state/controller.lock', '/usr/bin/node', worker, 'disable'], { timeout: 180000 });
async function state(name) { return (await ctl('show', name, '--property=ActiveState', '--value')).stdout.trim(); }
async function inactive(name) {
  const deadline = performance.now() + 20000;
  while (['active', 'activating', 'deactivating'].includes(await state(name))) {
    assert.ok(performance.now() < deadline, `${name} failed to stop`); await delay(100);
  }
}
async function archive(label) {
  const bytes = await readFile(`${journal}/journal.json`);
  await rename(journal, `/state/archived-${label}`); await syncDirectory('/state');
  await mkdir(journal, { mode: 0o700 }); await syncDirectory('/state');
  assert.deepEqual(await readFile(`/state/archived-${label}/journal.json`), bytes);
}
async function main() {
  const options = await assertSystemdDnsVm(); process.umask(0o077);
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const previous = await exists('/state/systemd-first-boot.json') ? JSON.parse(await readFile('/state/systemd-first-boot.json', 'utf8')) : null;
  const checks = [];
  const resolverBefore = await readFile('/etc/resolv.conf');
  const check = (label) => { checks.push(label); emit('systemd-check', { label }); };
  for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
    await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
  }
  emit('boot-guard', { bootId, ...options, pid1: (await readFile('/proc/1/comm', 'utf8')).trim() });
  // The driver is NOT dependent on the units under test, so a failed dependency
  // can be measured rather than preventing the acceptance workload from running.
  if (!previous) {
    await writeFile('/run/meshpn/deny-start', 'fixture\n', { flag: 'wx', mode: 0o600 });
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    assert.equal(await state('dns-vm-guard.service'), 'failed');
    assert.equal(await exists('/run/meshpn/consumers'), false);
    assert.equal(await exists(`${journal}/journal.json`), false);
    const links = JSON.parse((await exec('ip', ['-j', 'link'])).stdout);
    // systemd itself may raise lo. The outer init guard precedes PID1; the
    // dependency gate covers OUR network unit and consumers, not PID1's lo.
    assert.deepEqual(links.map((l) => l.ifname), ['lo']);
    assert.equal(await state('dns-vm-network.service'), 'inactive');
    assert.equal(await state('dns-vm-adapter.service'), 'inactive');
    await unlink('/run/meshpn/deny-start'); await ctl('reset-failed');
    check('failed-guard-prevents-network-and-consumer');
  }
  await ctl('start', 'dns-vm-sentinel.service', 'dns-vm-baseline.service', 'dns-vm-adapter.service');
  const { bus, ifindex, backend } = await busContext();
  const noFallback = async () => {
    for (const address of ['127.0.0.55', '::1']) for (const tcp of [false, true]) await assertSystemdVmBaselineBlocked(address, tcp);
    assert.deepEqual(await control('sentinel', 'stats'), { ipv4: 0, ipv6: 0 });
  };
  if (previous) {
    assert.notEqual(bootId, previous.bootId);
    const bytes = await readFile(`${journal}/journal.json`);
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    assert.equal(await state('dns-vm-controller.service'), 'failed');
    assert.equal(await exists('/run/meshpn/consumers'), false);
    assert.deepEqual(await readFile(`${journal}/journal.json`), bytes);
    assert.deepEqual((await backend.view()).settings, baseline);
    await noFallback(); check('reboot-stale-journal-refused-with-guard');
    // Explicit fixture operator authorizes a NEW baseline epoch. Never an
    // automatic adoption policy in the service/controller.
    await archive('previous-boot'); await ctl('reset-failed');
  }
  await ctl('start', 'dns-vm-consumer.service');
  assert.equal(await state('dns-vm-controller.service'), 'active');
  assert.equal(await state('dns-vm-consumer.service'), 'active');
  assert.equal(await readFile('/run/meshpn/consumers', 'utf8'), 'ready\n');
  await lookup('managed-aaaa', '2001:db8::12', true, 6); await noFallback();
  check('real-service-readiness-before-consumer');
  if (!previous) {
    const id = (await readResolvedJournal(journal)).id;
    await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
    await lookup('stopped-controller-still-protected', '192.0.2.123'); await noFallback();
    await ctl('start', 'dns-vm-consumer.service');
    assert.equal((await readResolvedJournal(journal)).id, id); check('controller-stop-retains-guard-and-restart-recovers');
    await control('fixture', 'stop-exit');
    await lookup('exit-down-no-fallback', null); await noFallback();
    await control('fixture', 'start-exit'); await lookup('exit-recovered', '192.0.2.123');
    check('exit-outage-no-baseline-fallback');
    await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-adapter.service');
    await inactive('dns-vm-adapter.service'); await inactive('dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
    await lookup('adapter-dead-no-fallback', null); await noFallback();
    await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
    assert.equal((await readResolvedJournal(journal)).id, id); await lookup('adapter-restarted', '192.0.2.123');
    check('adapter-sigkill-stops-dependents-restart-recovers');
    const owner = await bus.owner();
    await bus.set(owner, resolvedMethod('Domains', [['foreign.test', true]], ifindex));
    const bytes = await readFile(`${journal}/journal.json`);
    await assert.rejects(disable(), (e) => /ownership conflict/.test(e.stderr));
    assert.deepEqual(await readFile(`${journal}/journal.json`), bytes);
    assert.deepEqual(await bus.property(owner, ifindex, 'Domains'), [['foreign.test', true]]);
    await noFallback(); check('foreign-policy-not-overwritten');
    await bus.set(owner, resolvedMethod('Domains', [['.', true]], ifindex)); // explicit fixture repair
  }
  await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
  await noFallback();
  await disable();
  assert.deepEqual((await backend.view()).settings, baseline);
  await lookup('explicit-disable-udp', '203.0.113.8'); await lookup('explicit-disable-tcp', '203.0.113.8', true);
  assert.ok((await control('sentinel', 'stats')).ipv4 >= 2);
  assert.equal((await control('fixture', 'stats')).dnsCalls, 0);
  check('explicit-disable-restores-owned-baseline');
  assert.deepEqual(await readFile('/etc/resolv.conf'), resolverBefore);
  if (!previous) {
    const released = await readFile(`${journal}/journal.json`), hitsBefore = await control('sentinel', 'stats');
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    await inactive('dns-vm-consumer.service');
    assert.deepEqual(await readFile(`${journal}/journal.json`), released);
    for (const address of ['127.0.0.55', '::1']) for (const tcp of [false, true]) await assertSystemdVmBaselineBlocked(address, tcp);
    assert.deepEqual(await control('sentinel', 'stats'), hitsBefore);
    check('released-journal-restart-refused-under-guard');
    await archive('released');
    await ctl('reset-failed');
    await ctl('start', 'dns-vm-consumer.service'); await lookup('before-systemd-reboot', '192.0.2.123');
    assert.deepEqual(await control('sentinel', 'stats'), hitsBefore);
    const fd = await open('/state/systemd-first-boot.json', 'wx', 0o600);
    try { await fd.writeFile(JSON.stringify({ bootId, checks })); await fd.sync(); } finally { await fd.close(); }
    await syncDirectory('/state');
    emit('reboot-ready', { bootId });
    await ctl('--no-block', 'reboot');
    return;
  }
  emit('passed', { ...options, bootId, previousBootId: previous.bootId, systemdPid1: true,
    checks: [...previous.checks, ...checks], baselineQueriesDuringProtection: 0, baselinePositiveControl: true,
    hostNetworkUnavailable: true, automaticStaleAdoption: false, explicitDisablePassed: true, resolvConfUnchanged: true });
  await ctl('--no-block', 'poweroff');
}
main().catch(async (error) => {
  emit('failed', { message: error.stack });
  // The host runner kills this owned guest on failure. Never issue poweroff
  // when the VM authority check failed (e.g. accidental host invocation).
  process.exitCode = 1;
});
