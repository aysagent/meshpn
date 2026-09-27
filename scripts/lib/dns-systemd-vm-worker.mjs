/** Actual service executor, deliberately restricted to the NIC-less systemd VM. */
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { readFile, readlink, mkdir, mkdtemp, appendFile, access, unlink, writeFile, lstat, rename } from 'node:fs/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertSystemdDnsVm } from './dns-systemd-vm-safety.mjs';
import { startSystemdVmAdapterFixture } from './dns-adapter-soak-lab.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { createResolvedJournalBackend, resolvedMethod } from './dns-resolved-backend.mjs';
import { resolvedTransaction, readResolvedJournal } from './dns-resolved-journal.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';
import { DNS_BOOT_LOCK, loadDnsBootGuard } from './dns-boot-guard.mjs';
import { createBootGuardLifecycle, verifyResolvedGuardRestore } from './dns-boot-guard-lifecycle.mjs';

export const journal = '/state/transaction';
export const guardJournal = '/state/guard-transaction';
let bootLifecycle;
export const baseline = { DNSEx: [[2, [127, 0, 0, 55], 0, '']], Domains: [['.', true], ['baseline.test', false]], DefaultRoute: true };
export const coupledBaseline = { ...baseline, Domains: [['baseline.test', false]] };
export const emitSystemd = (event, data = {}) => console.log(`DNS_VM_EVENT ${JSON.stringify({ event, ...data })}`);
export async function exists(path) { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
export async function guard(enabled) {
  const options = await assertSystemdDnsVm();
  if (options.phase === 'systemd') {
    assert.ok(bootLifecycle, 'controller must own the shared boot/DNS flock');
    await (enabled ? bootLifecycle.prepare() : bootLifecycle.release());
    return;
  }
  for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
    const rule = ['OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT'];
    let present = true;
    try { await exec(tool, ['-w', '2', '-C', ...rule]); } catch (e) { assert.equal(e.code, 1); present = false; }
    if (present !== enabled) await exec(tool, ['-w', '2', enabled ? '-A' : '-D', ...rule]);
    if (enabled) await exec(tool, ['-w', '2', '-C', ...rule]);
  }
}
export async function createVmGuardLifecycle({ restoring, authorizeRelease, dnsStateExists = () => exists(`${journal}/journal.json`) }) {
  await assertSystemdDnsVm();
  const boot = await loadDnsBootGuard(); // Refuses before any setter without our own inherited flock.
  // Protect before creating storage or refusing unreadable metadata. A valid
  // partial release is handled below without automatically reinstalling it.
  try {
    if (!await exists(guardJournal)) { await boot.guard.ensure(); await mkdir(guardJournal, { mode: 0o700 }); }
  } catch (error) { await boot.guard.ensure(); throw error; }
  const backend = boot.createJournalBackend({
    context: async () => {
      const s = await lstat(guardJournal); assert.ok(s.isDirectory() && s.uid === 0 && (s.mode & 0o777) === 0o700);
      return { bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
        netns: await readlink('/proc/self/ns/net'), directoryIdentity: `${s.dev}:${s.ino}`,
        firewall: { ipv4: boot.policy.firewallBackend, ipv6: boot.policy.firewallBackend }, usb: null };
    },
    authorizeRelease,
  });
  let allowBind;
  try { allowBind = !await dnsStateExists(); }
  catch (error) { await boot.guard.ensure(); throw error; }
  return createBootGuardLifecycle({ directory: guardJournal, boot, backend, restoring, allowBind });
}
const controllerGuard = (restoring) => createVmGuardLifecycle({ restoring,
  authorizeRelease: async () => verifyResolvedGuardRestore({ directory: journal, backend: (await busContext()).backend }) });
export async function busContext() {
  await assertSystemdDnsVm();
  const run = (args) => exec('/usr/bin/busctl', ['--address=unix:path=/run/dbus/system_bus_socket', '--timeout=5s',
    '--auto-start=no', '--allow-interactive-authorization=no', '--json=short', ...args], { timeout: 10000 });
  const value = async (args) => JSON.parse((await run(args)).stdout).data;
  const bus = {
    async id() { return (await value(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetId']))[0]; },
    async owner() { return (await value(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.resolve1']))[0]; },
    async property(owner, index, property) {
      const [path] = await value(['call', owner, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'GetLink', 'i', String(index)]);
      assert.match(path, /^\/org\/freedesktop\/resolve1\/link\/[A-Za-z0-9_]+$/);
      return value(['get-property', owner, path, 'org.freedesktop.resolve1.Link', property]);
    },
    async set(owner, args) { await run(['call', owner, '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', ...args]); },
  };
  const identity = async () => {
    const [link] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'dnsfixture'])).stdout);
    return { ifindex: link.ifindex, ifname: link.ifname, address: link.address };
  };
  const ifindex = (await identity()).ifindex;
  const scope = Object.fromEntries(await Promise.all(['net', 'mnt', 'pid'].map(async (key) => [key, await readlink(`/proc/self/ns/${key}`)])));
  const backend = createResolvedJournalBackend({ bus, ifindex, identity, scope, port: 2053,
    ensureGuard: () => guard(true), removeGuard: () => guard(false), probe: protectedProbe });
  return { bus, ifindex, backend, scope };
}
export async function protectedProbe() {
  await assertSystemdDnsVm();
  for (const tcp of [false, true]) {
    const q = makeDnsQuery('systemd-ready.test');
    assert.equal(validateDnsResponse(await queryLabDns(2053, q, { tcp, timeoutMs: 10000 }), q).flags & 15, 0, 'protected readiness');
  }
}
export async function lookup(label, expected, tcp = false, family = 4) {
  await assertSystemdDnsVm();
  assert.match(label, /^[a-z0-9-]+$/);
  let code = 0, stdout;
  try { ({ stdout } = await exec('getent', ['-A', '-s', 'dns', `ahostsv${family}`, `${label}.test`],
    { timeout: 15000, env: { ...process.env, RES_OPTIONS: `timeout:5 attempts:1${tcp ? ' use-vc' : ''}` } })); }
  catch (e) { assert.equal(e.killed, false, label); code = e.code; stdout = e.stdout; }
  assert.equal(code, expected ? 0 : 2, label);
  if (expected) assert.ok(stdout.trim().split('\n').every((line) => line.startsWith(`${expected} `)), label);
  else assert.equal(stdout, '', label);
}
export async function control(name, command) {
  await assertSystemdDnsVm(); assert.ok(['fixture', 'sentinel'].includes(name));
  assert.ok(['stats', 'stop-exit', 'start-exit'].includes(command));
  return new Promise((resolve, reject) => {
    const socket = net.connect(`/run/meshpn/${name}.sock`); let data = '';
    const timer = setTimeout(() => finish(new Error('fixture control timeout')), 10000);
    const finish = (error, result) => { clearTimeout(timer); socket.destroy(); error ? reject(error) : resolve(result); };
    socket.on('error', finish); socket.once('connect', () => socket.write(`${command}\n`));
    socket.on('data', (chunk) => { data += chunk; if (data.length > 8192) return finish(new Error('oversized fixture reply')); });
    socket.once('end', () => { try { finish(null, JSON.parse(data)); } catch (e) { finish(e); } });
  });
}
async function serve(name, action, close) {
  const path = `/run/meshpn/${name}.sock`;
  if (await exists(path)) await unlink(path); // Only this VM's known, owned runtime socket.
  const server = net.createServer((socket) => {
    let data = '', used = false;
    socket.setTimeout(10000, () => socket.destroy()); socket.on('error', () => {});
    socket.on('data', (chunk) => {
      data += chunk;
      if (data.length > 64 || used) return socket.destroy();
      if (!data.endsWith('\n')) return;
      used = true;
      Promise.resolve().then(() => action(data.trim())).then((reply) => socket.end(JSON.stringify(reply)), () => socket.destroy());
    });
  });
  server.listen(path); await once(server, 'listening');
  const stop = async () => { server.close(); await close(); process.exit(0); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  await exec('/usr/bin/systemd-notify', ['--ready', `--pid=${process.pid}`]);
  await new Promise(() => {});
}
async function main(command) {
  const options = await assertSystemdDnsVm(), coupled = options.phase.startsWith('coupled');
  assert.ok(['guard', 'guard-release-check', 'network', 'baseline', 'adapter', 'cli-fixture', 'sentinel', 'activate', 'disable', 'consumer'].includes(command));
  assert.ok(command !== 'cli-fixture' || options.phase === 'systemd' || coupled, 'CLI fixture needs a supported VM case');
  assert.ok(!coupled || !['activate', 'disable'].includes(command), 'use coupled VM controller');
  process.umask(0o077); await mkdir('/run/meshpn', { recursive: true, mode: 0o700 });
  if (command === 'guard-release-check') {
    assert.equal(options.phase, 'systemd');
    const lifecycle = await controllerGuard(false), bytes = await readFile(`${guardJournal}/journal.json`);
    assert.equal((await readResolvedJournal(journal)).direction, 'apply');
    await assert.rejects(lifecycle.release());
    assert.deepEqual(await readFile(`${guardJournal}/journal.json`), bytes);
    assert.deepEqual(await (await loadDnsBootGuard()).guard.inspect(), ['present', 'present']);
    // Synthetic loss under the same lock: do not create a replacement epoch
    // while the DNS transaction exists. Restore only our exact fixture bytes.
    const saved = `${guardJournal}/missing-journal-fixture.json`;
    assert.equal(await exists(saved), false);
    await rename(`${guardJournal}/journal.json`, saved);
    try {
      await assert.rejects(lifecycle.prepare(), /explicit new guard binding/);
      assert.equal(await exists(`${guardJournal}/journal.json`), false);
      assert.deepEqual(await (await loadDnsBootGuard()).guard.inspect(), ['present', 'present']);
    } finally {
      assert.equal(await exists(`${guardJournal}/journal.json`), false);
      assert.deepEqual(await readFile(saved), bytes); await rename(saved, `${guardJournal}/journal.json`);
    }
    return;
  }
  if (command === 'guard') {
    assert.equal(await exists('/run/meshpn/deny-start'), false, 'injected guard dependency failure');
    await guard(true); return;
  }
  if (command === 'network') {
    assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
    if (options.phase === 'systemd' || coupled) {
      await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK, '/usr/bin/node',
        '/opt/clean-vpn/scripts/dns-boot-guard.mjs', '--start'], { timeout: 60000 });
      // Both families proved before removing the outer init fixture guard.
      for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp'])
        await exec(tool, ['-w', '2', '-D', 'OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT']);
    } else for (const protocol of ['udp', 'tcp']) await exec('iptables', ['-w', '2', '-I', 'OUTPUT', '1', '-d', '127.0.0.53', '-p', protocol, '--dport', '53', '-j', 'ACCEPT']);
    await exec('ip', ['link', 'set', 'lo', 'up']);
    await exec('ip', ['link', 'add', 'dnsfixture', 'type', 'dummy']);
    await exec('ip', ['addr', 'add', coupled ? '192.0.2.2/32' : '192.0.2.1/32', 'dev', 'dnsfixture']);
    await exec('ip', ['link', 'set', 'dnsfixture', 'up']);
    return;
  }
  if (command === 'adapter' || command === 'cli-fixture') {
    const lab = await startSystemdVmAdapterFixture(await mkdtemp('/run/meshpn/adapter-'), { cli: command === 'cli-fixture' });
    if (command === 'cli-fixture') {
      const args = await lab.prepareCliAdapter();
      const paths = Object.fromEntries(args.map((arg) => arg.slice(2).split('=')));
      assert.equal(paths['exit-port'], '44443');
      await mkdir('/etc/clean-vpn/dns', { recursive: true, mode: 0o700 });
      await writeFile('/etc/clean-vpn/dns/upstream.json', await readFile(paths.config), { flag: 'wx', mode: 0o600 });
      const key = await readFile(paths['shared-hmac-key']);
      try { await writeFile('/etc/clean-vpn/dns/hmac.key', key, { flag: 'wx', mode: 0o600 }); } finally { key.fill(0); }
      await writeFile('/etc/clean-vpn/dns/domains.json', JSON.stringify({ schema: 1, denySuffixes: ['blocked.test'] }), { flag: 'wx', mode: 0o600 });
    } else await protectedProbe();
    return serve('fixture', async (operation) => {
      if (operation === 'stop-exit') await lab.stopExit();
      else if (operation === 'start-exit') await lab.restartExit();
      else assert.equal(operation, 'stats');
      return lab.stats();
    }, lab.close);
  }
  if (command === 'sentinel') {
    const a = await sentinel('127.0.0.55'), b = await sentinel('::1');
    return serve('sentinel', (operation) => { assert.equal(operation, 'stats'); return { ipv4: a.hits(), ipv6: b.hits() }; },
      async () => { await a.close(); await b.close(); });
  }
  if (command === 'consumer') {
    await lookup('consumer-ready', '192.0.2.123');
    await appendFile('/run/meshpn/consumers', 'ready\n', { mode: 0o600 }); return;
  }
  // A previous explicit disable may have released rules while the oneshot
  // guard unit still reads "active". Recheck actual protection BEFORE parsing
  // even a corrupt/released journal or contacting the DNS backend.
  if (command === 'activate' || command === 'disable') {
    if (options.phase === 'systemd') bootLifecycle = await controllerGuard(command === 'disable');
    await guard(true);
  }
  const { bus, ifindex, scope, backend } = await busContext();
  if (command === 'baseline') {
    const owner = await bus.owner(); assert.deepEqual(await bus.property(owner, ifindex, 'DNSEx'), []);
    for (const [property, value] of Object.entries(coupled ? coupledBaseline : baseline)) await bus.set(owner, resolvedMethod(property, value, ifindex));
    return;
  }
  await mkdir(journal, { recursive: true, mode: 0o700 });
  const operation = command === 'disable' ? 'disable' : await exists(`${journal}/journal.json`) ? 'recover' : 'enable';
  if (operation === 'recover') {
    const record = await readResolvedJournal(journal);
    assert.equal(record.direction, 'apply', 'released/restoring journal requires explicit new epoch');
  }
  const result = await resolvedTransaction({ directory: journal, operation, scope, backend });
  console.log(`DNS_SYSTEMD_TRANSACTION ${JSON.stringify(result)}`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv[2]).catch((error) => { console.error(error.stack); process.exitCode = 1; });
}
