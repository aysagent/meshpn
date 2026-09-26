/** Two-boot systemd workload. All changes are to synthetic guest state. */
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, rename, unlink, open } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsmasqVm } from './dnsmasq-vm-safety.mjs';
import { journal, emit, exists, ctl, guard, lookup, control } from './dnsmasq-vm-worker.mjs';
import { readDnsmasqJournal } from './dnsmasq-journal.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';
import { startDnsmasqUsbPeer } from './dnsmasq-usb-peer.mjs';

const worker = '/project/scripts/lib/dnsmasq-vm-worker.mjs';
const disable = () => exec('/usr/bin/flock', ['-n', '-F', '/state/controller.lock', '/usr/bin/node', worker, 'disable'], { timeout: 180000 });
async function state(name) { return (await ctl('show', name, '--property=ActiveState', '--value')).stdout.trim(); }
async function inactive(name) {
  const end = performance.now() + 20000;
  while (['active', 'activating', 'deactivating'].includes(await state(name))) {
    assert.ok(performance.now() < end, `${name} failed to stop`); await delay(100);
  }
}
async function seed() {
  await mkdir(journal, { mode: 0o700 });
  const fd = await open(`${journal}/dnsmasq.conf`, 'wx', 0o600);
  try { await fd.writeFile(await readFile('/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf')); await fd.sync(); }
  finally { await fd.close(); }
  await syncDirectory(journal); await syncDirectory('/state');
}
async function archive(label) {
  await guard(true); await ctl('stop', 'dns-vm-controller.service', 'dns-vm-dnsmasq.service');
  const bytes = await readFile(`${journal}/journal.json`);
  await rename(journal, `/state/archived-${label}`); await syncDirectory('/state'); await seed();
  assert.deepEqual(await readFile(`/state/archived-${label}/journal.json`), bytes);
}
async function main() {
  const options = await assertDnsmasqVm(); process.umask(0o077);
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const previous = await exists('/state/dnsmasq-first-boot.json') ? JSON.parse(await readFile('/state/dnsmasq-first-boot.json', 'utf8')) : null;
  const resolver = await readFile('/etc/resolv.conf'), checks = [];
  const check = (label) => { checks.push(label); emit('systemd-check', { label }); };
  for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
    await exec(tool, ['-w', '2', '-C', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
  }
  emit('boot-guard', { bootId, ...options, pid1: (await readFile('/proc/1/comm', 'utf8')).trim() });
  if (!previous) {
    await writeFile('/run/meshpn/deny-start', 'injected', { flag: 'wx', mode: 0o600 });
    await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
    for (const name of ['network', 'adapter', 'dnsmasq', 'consumer']) assert.equal(await state(`dns-vm-${name}.service`), 'inactive');
    assert.equal(await exists(`${journal}/journal.json`), false);
    assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
    await unlink('/run/meshpn/deny-start'); await ctl('reset-failed'); check('failed-guard-prevents-services');
  }
  await ctl('start', 'dns-vm-network.service', 'dns-vm-sentinel.service');
  const peer = await startDnsmasqUsbPeer();
  try {
    await ctl('start', 'dns-vm-adapter.service');
    const noFallback = async () => assert.deepEqual(await control('sentinel', 'stats'), [0, 0, 0]);
    if (previous) {
      assert.notEqual(previous.bootId, bootId);
      const bytes = await readFile(`${journal}/journal.json`), config = await readFile(`${journal}/dnsmasq.conf`);
      await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
      assert.equal(await state('dns-vm-controller.service'), 'failed');
      assert.equal(await state('dns-vm-dnsmasq.service'), 'inactive');
      assert.equal(await exists('/run/meshpn/consumers'), false);
      assert.deepEqual(await readFile(`${journal}/journal.json`), bytes);
      assert.deepEqual(await readFile(`${journal}/dnsmasq.conf`), config); await noFallback();
      check('reboot-stale-journal-refused');
      // Explicit synthetic operator action, not automatic journal adoption.
      await archive('previous-boot'); await ctl('reset-failed');
    } else await seed();
    await ctl('start', 'dns-vm-consumer.service');
    assert.equal(await state('dns-vm-controller.service'), 'active');
    assert.equal(await state('dns-vm-dnsmasq.service'), 'active');
    const acquire = async () => {
      const result = await peer.acquire(); assert.deepEqual(result.ack.dns, ['192.168.7.1']);
      assert.deepEqual(result.ack.routers, ['192.168.7.1']); return result.ack.address;
    };
    const lease = await acquire(); if (previous) assert.equal(lease, previous.lease);
    const local = async () => {
      for (const tcp of [false, true]) {
        const reply = await peer.lookup({ local: true, tcp });
        assert.equal(reply.rcode, 0); assert.equal(reply.answer, Buffer.from(lease.split('.').map(Number)).toString('hex'));
      }
    };
    await local(); await lookup('managed-tcp', '192.0.2.123', true); await noFallback();
    check('service-readiness-and-usb-dhcp');
    const id = (await readDnsmasqJournal(journal)).id;
    if (!previous) {
      await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
      await lookup('controller-stopped', '192.0.2.123'); await noFallback();
      await ctl('start', 'dns-vm-consumer.service'); assert.equal((await readDnsmasqJournal(journal)).id, id);
      check('controller-stop-retains-protection');
      await control('fixture', 'stop-exit'); await lookup('exit-down', null);
      assert.equal(await acquire(), lease); await local(); await noFallback();
      await control('fixture', 'start-exit'); await lookup('exit-recovered', '192.0.2.123');
      check('exit-outage-preserves-dhcp-local-name');
      await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-adapter.service');
      await inactive('dns-vm-adapter.service'); await inactive('dns-vm-controller.service'); await inactive('dns-vm-consumer.service');
      assert.equal(await state('dns-vm-dnsmasq.service'), 'active');
      assert.equal(await acquire(), lease); await local(); await lookup('adapter-dead', null); await noFallback();
      await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
      assert.equal((await readDnsmasqJournal(journal)).id, id); await lookup('adapter-restarted', '192.0.2.123');
      check('adapter-sigkill-preserves-dhcp-and-stops-consumer');
      await ctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'dns-vm-dnsmasq.service'); await inactive('dns-vm-dnsmasq.service');
      await lookup('daemon-dead', null); await noFallback();
      await ctl('stop', 'dns-vm-controller.service'); await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
      assert.equal((await readDnsmasqJournal(journal)).id, id); assert.equal(await acquire(), lease); await local();
      check('daemon-sigkill-and-journal-recovery');
      const config = await readFile(`${journal}/dnsmasq.conf`), bytes = await readFile(`${journal}/journal.json`);
      await writeFile(`${journal}/dnsmasq.conf`, Buffer.concat([config, Buffer.from('# foreign edit\n')]));
      await assert.rejects(disable(), (e) => /ownership conflict/.test(e.stderr));
      assert.deepEqual(await readFile(`${journal}/journal.json`), bytes);
      assert.match(await readFile(`${journal}/dnsmasq.conf`, 'utf8'), /foreign edit/); await noFallback();
      await writeFile(`${journal}/dnsmasq.conf`, config); // explicit fixture-owner repair, same inode
      check('foreign-config-not-overwritten');
    }
    await ctl('stop', 'dns-vm-controller.service'); await inactive('dns-vm-consumer.service'); await noFallback();
    await disable();
    assert.deepEqual(await readFile(`${journal}/dnsmasq.conf`), await readFile('/project/scripts/fixtures/dns-clients/radxa-dnsmasq.conf'));
    await lookup('explicit-disable-udp', '203.0.113.8'); await lookup('explicit-disable-tcp', '203.0.113.8', true);
    assert.ok((await control('sentinel', 'stats')).reduce((sum, n) => sum + n, 0) >= 2);
    assert.equal((await control('fixture', 'stats')).dnsCalls, 0);
    assert.deepEqual(await readFile('/etc/resolv.conf'), resolver); check('explicit-disable-restores-baseline');
    if (!previous) {
      const bytes = await readFile(`${journal}/journal.json`), hits = await control('sentinel', 'stats');
      await assert.rejects(ctl('start', 'dns-vm-consumer.service'));
      await lookup('released-start-refused', null); assert.deepEqual(await control('sentinel', 'stats'), hits);
      assert.deepEqual(await readFile(`${journal}/journal.json`), bytes); check('released-journal-start-refused');
      await archive('released'); await ctl('reset-failed'); await ctl('start', 'dns-vm-consumer.service');
      await lookup('before-reboot', '192.0.2.123'); assert.deepEqual(await control('sentinel', 'stats'), hits);
      const fd = await open('/state/dnsmasq-first-boot.json', 'wx', 0o600);
      try { await fd.writeFile(JSON.stringify({ bootId, checks, lease })); await fd.sync(); } finally { await fd.close(); }
      await syncDirectory('/state'); await peer.close(); emit('reboot-ready', { bootId }); await ctl('--no-block', 'reboot'); return;
    }
    await peer.close();
    emit('passed', { ...options, bootId, previousBootId: previous.bootId, systemdPid1: true,
      checks: [...previous.checks, ...checks], baselineQueriesDuringProtection: 0, baselinePositiveControl: true,
      automaticStaleAdoption: false, explicitDisablePassed: true, resolvConfUnchanged: true, dhcpPreservedOnAdapterFailure: true });
    await ctl('--no-block', 'poweroff');
  } finally { await peer.close(); }
}
main().catch((error) => { emit('failed', { message: error.stack }); process.exitCode = 1; });
