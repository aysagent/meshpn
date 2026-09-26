/** Actual systemd/file executor. Refuses everything outside the dnsmasq VM. */
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { readFile, readlink, mkdir, mkdtemp, appendFile, access, unlink, writeFile } from 'node:fs/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsmasqVm } from './dnsmasq-vm-safety.mjs';
import { startDnsmasqVmAdapterFixture } from './dns-adapter-soak-lab.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';
import { createDnsmasqJournalFiles } from './dnsmasq-journal-files.mjs';
import { dnsmasqTransaction, readDnsmasqJournal, dnsmasqHash } from './dnsmasq-journal.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';
import { queryLabDns } from './transparent-dns-lab.mjs';

export const journal = '/state/dnsmasq';
export const emit = (event, data = {}) => console.log(`DNS_VM_EVENT ${JSON.stringify({ event, ...data })}`);
export async function exists(path) { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
export const ctl = (...args) => exec('/usr/bin/systemctl', ['--no-pager', ...args], { timeout: 180000 });
export async function guard(enabled) {
  await assertDnsmasqVm();
  for (const tool of ['iptables', 'ip6tables']) for (const protocol of ['udp', 'tcp']) {
    for (const rule of [ ['OUTPUT', '-p', protocol, '--dport', '53', '-j', 'REJECT'],
      ['INPUT', '-i', 'usb0', ...(tool === 'iptables' ? ['!', '-d', '192.168.7.1'] : []), '-p', protocol, '--dport', '53', '-j', 'REJECT'],
      ['FORWARD', '-i', 'usb0', '-p', protocol, '--dport', '53', '-j', 'REJECT'] ]) {
      let present = true;
      try { await exec(tool, ['-w', '2', '-C', ...rule]); } catch (e) { assert.equal(e.code, 1); present = false; }
      if (present !== enabled) await exec(tool, ['-w', '2', enabled ? '-A' : '-D', ...rule]);
      if (enabled) await exec(tool, ['-w', '2', '-C', ...rule]);
    }
  }
}
export async function probe(port = 2053) {
  await assertDnsmasqVm(); assert.ok([53, 2053].includes(port));
  for (const tcp of [false, true]) {
    // The guest has a synthetic loopback resolv.conf. Keep queryLabDns's
    // high-port-only contract; exercise the actual system resolver for :53.
    if (port === 53) { await lookup('daemon-ready', '192.0.2.123', tcp); continue; }
    const query = makeDnsQuery('vm-ready.test');
    const reply = await queryLabDns(port, query, { tcp, timeoutMs: 10000 });
    assert.equal(validateDnsResponse(reply, query).rcode, 0, 'protected readiness');
  }
}
export async function lookup(label, expected, tcp = false) {
  await assertDnsmasqVm(); assert.match(label, /^[a-z0-9-]+$/);
  let code = 0, stdout;
  try { ({ stdout } = await exec('getent', ['-A', '-s', 'dns', 'ahostsv4', `${label}.test`],
    { timeout: 15000, env: { ...process.env, RES_OPTIONS: `timeout:5 attempts:1${tcp ? ' use-vc' : ''}` } })); }
  catch (e) { assert.equal(e.killed, false, label); code = e.code; stdout = e.stdout; }
  assert.equal(code, expected ? 0 : 2, label);
  if (expected) assert.ok(stdout.trim().split('\n').every((line) => line.startsWith(`${expected} `)), label);
  else assert.equal(stdout, '', label);
}
export async function control(name, command) {
  await assertDnsmasqVm(); assert.ok(['fixture', 'sentinel'].includes(name));
  assert.ok(['stats', 'stop-exit', 'start-exit'].includes(command));
  return new Promise((resolve, reject) => {
    const socket = net.connect(`/run/meshpn/${name}.sock`); let data = '';
    const timer = setTimeout(() => finish(new Error('control deadline')), 20000);
    const finish = (error, result) => { clearTimeout(timer); socket.destroy(); error ? reject(error) : resolve(result); };
    socket.on('error', finish); socket.once('connect', () => socket.write(`${command}\n`));
    socket.on('data', (part) => { data += part; if (data.length > 8192) finish(new Error('oversized reply')); });
    socket.once('end', () => { try { finish(null, JSON.parse(data)); } catch (e) { finish(e); } });
  });
}
async function serve(name, action, close) {
  const path = `/run/meshpn/${name}.sock`;
  if (await exists(path)) await unlink(path);
  const server = net.createServer((socket) => {
    let data = '', used = false;
    socket.setTimeout(20000, () => socket.destroy()); socket.on('error', () => {});
    socket.on('data', (part) => {
      data += part; if (used || data.length > 64) return socket.destroy();
      if (!data.endsWith('\n')) return; used = true;
      Promise.resolve().then(() => action(data.trim())).then((result) => socket.end(JSON.stringify(result)), () => socket.destroy());
    });
  });
  server.listen(path); await once(server, 'listening');
  process.once('SIGTERM', async () => { server.close(); await close(); process.exit(0); });
  await exec('/usr/bin/systemd-notify', ['--ready', `--pid=${process.pid}`]);
  await new Promise(() => {});
}
async function daemonIdentity() {
  const result = {};
  for (const key of ['ActiveState', 'MainPID', 'InvocationID']) result[key] =
    (await ctl('show', 'dns-vm-dnsmasq.service', `--property=${key}`, '--value')).stdout.trim();
  return result;
}
async function cache() {
  try { return JSON.parse(await readFile('/run/meshpn/dnsmasq-loaded.json', 'utf8')); }
  catch (e) { if (e.code === 'ENOENT' || e instanceof SyntaxError) return null; throw e; }
}
export async function backendContext() {
  await assertDnsmasqVm();
  const scope = Object.fromEntries(await Promise.all(['net', 'mnt', 'pid'].map(async (key) => [key, await readlink(`/proc/self/ns/${key}`)])));
  const backend = await createDnsmasqJournalFiles({ directory: journal, port: 2053, normalizeDhcpDns: true,
    identity: async () => {
      const [link] = JSON.parse((await exec('ip', ['-j', 'link', 'show', 'dev', 'usb0'])).stdout);
      return { scope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
        executableSha256: dnsmasqHash(await readFile('/usr/sbin/dnsmasq')),
        link: { ifindex: link.ifindex, ifname: link.ifname, address: link.address } };
    }, ensureGuard: () => guard(true), removeGuard: () => guard(false), probe: () => probe(),
    activate: async (record) => {
      const view = await backend.view(), current = await daemonIdentity(), loaded = await cache();
      if (current.ActiveState === 'active' && current.MainPID !== '0'
        && JSON.stringify(loaded) === JSON.stringify({ ...view, daemon: current })) return;
      await exec('/usr/sbin/dnsmasq', ['--test', `--conf-file=${journal}/dnsmasq.conf`]);
      await writeFile('/run/meshpn/dnsmasq-permit.json', JSON.stringify(view), { mode: 0o600 });
      await ctl('restart', 'dns-vm-dnsmasq.service');
      const daemon = await daemonIdentity(); assert.equal(daemon.ActiveState, 'active'); assert.notEqual(daemon.MainPID, '0');
      assert.match(daemon.InvocationID, /^[a-f0-9]{32}$/);
      if (record.direction === 'apply') await probe(53);
      await writeFile('/run/meshpn/dnsmasq-loaded.json', JSON.stringify({ ...view, daemon }), { mode: 0o600 });
    } });
  return { scope, backend };
}
async function main(command) {
  await assertDnsmasqVm();
  assert.ok(['guard', 'network', 'adapter', 'sentinel', 'activate', 'disable', 'daemon-check', 'consumer'].includes(command));
  process.umask(0o077); await mkdir('/run/meshpn', { recursive: true, mode: 0o700 });
  if (command === 'guard') { assert.equal(await exists('/run/meshpn/deny-start'), false, 'injected guard failure'); return guard(true); }
  if (command === 'network') {
    assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
    for (const protocol of ['udp', 'tcp']) await exec('iptables', ['-w', '2', '-I', 'OUTPUT', '1', '-d', '127.0.0.1', '-p', protocol, '--dport', '53', '-j', 'ACCEPT']);
    await exec('ip', ['link', 'set', 'lo', 'up']);
    await exec('ip', ['link', 'add', 'dnsfixture', 'type', 'dummy']);
    await exec('ip', ['link', 'set', 'dnsfixture', 'up']);
    for (const address of ['1.1.1.1', '8.8.8.8']) await exec('ip', ['addr', 'add', `${address}/32`, 'dev', 'dnsfixture']);
    await exec('ip', ['-6', 'addr', 'add', '2001:db8:53::1/128', 'dev', 'dnsfixture', 'nodad']); return;
  }
  if (command === 'adapter') {
    const lab = await startDnsmasqVmAdapterFixture(await mkdtemp('/run/meshpn/adapter-')); await probe();
    return serve('fixture', async (op) => {
      if (op === 'stop-exit') await lab.stopExit(); else if (op === 'start-exit') await lab.restartExit(); else assert.equal(op, 'stats');
      return lab.stats();
    }, lab.close);
  }
  if (command === 'sentinel') {
    const observers = [];
    for (const address of ['1.1.1.1', '8.8.8.8', '2001:db8:53::1']) observers.push(await sentinel(address));
    return serve('sentinel', (op) => { assert.equal(op, 'stats'); return observers.map((s) => s.hits()); },
      () => Promise.all(observers.map((s) => s.close())));
  }
  if (command === 'consumer') {
    await lookup('consumer-ready', '192.0.2.123'); await appendFile('/run/meshpn/consumers', 'ready\n', { mode: 0o600 }); return;
  }
  if (command === 'activate' || command === 'disable') await guard(true);
  const { scope, backend } = await backendContext();
  if (command === 'daemon-check') {
    assert.deepEqual(await backend.view(), JSON.parse(await readFile('/run/meshpn/dnsmasq-permit.json', 'utf8')), 'daemon start not authorized'); return;
  }
  const operation = command === 'disable' ? 'disable' : await exists(`${journal}/journal.json`) ? 'recover' : 'enable';
  if (operation === 'recover') assert.equal((await readDnsmasqJournal(journal)).direction, 'apply', 'released/restoring journal requires explicit epoch');
  const result = await dnsmasqTransaction({ directory: journal, operation, scope, backend });
  console.log(`DNSMASQ_SYSTEMD_TRANSACTION ${JSON.stringify(result)}`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv[2]).catch((error) => { console.error(error.stack); process.exitCode = 1; });
