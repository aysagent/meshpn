/** Real cloud DHCP/DNS server in another private network namespace. */
import assert from 'node:assert/strict';
import { readlink, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { child, exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { sentinel } from './dns-lifecycle-lab.mjs';

const entry = fileURLToPath(import.meta.url);
export async function startNetworkdPeer(executable) {
  await assertDnsMountNamespace();
  const peer = child('unshare', ['--net', process.execPath, entry, executable], {
    stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, MESHPN_NETWORKD_GATEWAY: await readlink('/proc/self/ns/net'),
      MESHPN_NETWORKD_PEER_MOUNT: await readlink('/proc/self/ns/mnt') } });
  let id = 0, closed = false;
  const call = async (op, dns) => {
    const n = ++id, reply = peer.waitFor(new RegExp(`CLOUD_REPLY ${n} ([^\\n]+)\\n`), 10000);
    peer.proc.stdin.write(`${JSON.stringify({ id: n, op, dns })}\n`);
    const value = JSON.parse((await reply)[1]); assert.equal(value.ok, true, value.error); return value.result;
  };
  try {
    await peer.waitFor(/CLOUD_READY\n/);
    await exec('ip', ['link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'cloud0']);
    await exec('ip', ['link', 'set', 'cloud0', 'netns', String(peer.proc.pid)]);
    await exec('ip', ['link', 'set', 'eth0', 'up']); await call('configure');
    return { start: (dns) => call('start', dns), stats: () => call('stats'),
      async close() { if (closed) return; closed = true; try { await call('close'); } finally { await peer.stop(); } } };
  } catch (e) { await peer.stop(); throw e; }
}
async function main(executable) {
  assert.equal(process.argv.length, 3); assert.ok(executable.startsWith('/'));
  for (const key of ['net', 'pid', 'mnt']) {
    assert.ok(process.env[`MESHPN_PARENT_${key.toUpperCase()}NS`]);
    assert.notEqual(await readlink(`/proc/self/ns/${key}`), process.env[`MESHPN_PARENT_${key.toUpperCase()}NS`]);
  }
  assert.ok(process.env.MESHPN_NETWORKD_GATEWAY && process.env.MESHPN_NETWORKD_PEER_MOUNT);
  assert.notEqual(await readlink('/proc/self/ns/net'), process.env.MESHPN_NETWORKD_GATEWAY);
  assert.equal(await readlink('/proc/self/ns/mnt'), process.env.MESHPN_NETWORKD_PEER_MOUNT);
  assert.equal(await readlink('/proc/self/ns/pid'), await readlink('/proc/1/ns/pid'));
  assert.deepEqual(JSON.parse((await exec('ip', ['-j', 'link'])).stdout).map((l) => l.ifname), ['lo']);
  let daemon, configured = false, log = '', acks = 0, discovers = 0, requests = 0, pendingLog = '';
  const servers = [];
  const close = async () => { await daemon?.stop(); await Promise.all(servers.map((s) => s.close())); };
  const handle = async ({ op, dns }) => {
    if (op === 'configure') {
      assert.equal(configured, false); configured = true;
      await exec('ip', ['link', 'set', 'lo', 'up']); await exec('ip', ['link', 'set', 'cloud0', 'up']);
      await exec('ip', ['addr', 'add', '10.129.0.2/24', 'dev', 'cloud0']); await exec('ip', ['addr', 'add', '10.129.0.3/32', 'dev', 'cloud0']);
      for (const ip of ['10.129.0.2', '10.129.0.3']) servers.push(await sentinel(ip)); return {};
    }
    assert.equal(configured, true);
    if (op === 'stats') return { hits: servers.map((s) => s.hits()), acks, discovers, requests };
    if (op === 'close') { await close(); return {}; }
    assert.equal(op, 'start'); assert.ok(['10.129.0.2', '10.129.0.3'].includes(dns));
    await daemon?.stop(); pendingLog = '';
    const cfg = '/run/networkd-lab/cloud-dhcp.conf';
    await writeFile(cfg, `port=0\ninterface=cloud0\nbind-interfaces\ndhcp-authoritative\nno-ping\ndhcp-range=10.129.0.18,10.129.0.18,255.255.255.0,2m\ndhcp-option=3,10.129.0.2\ndhcp-option=6,${dns}\ndhcp-option=option:domain-search,ru-central1.internal,auto.internal\n`);
    daemon = child(executable, ['--no-daemon', `--conf-file=${cfg}`, '--pid-file=', '--log-facility=-', '--dhcp-leasefile=/run/networkd-lab/cloud-leases'],
      { env: { PATH: '/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL: 'C' } });
    daemon.proc.stderr.on('data', (b) => {
      log = (log + b).slice(-4096); pendingLog += b;
      const lines = pendingLog.split('\n'); pendingLog = lines.pop();
      for (const line of lines) { if (line.includes('DHCPACK')) acks++; if (line.includes('DHCPDISCOVER')) discovers++; if (line.includes('DHCPREQUEST')) requests++; }
      if (pendingLog.length > 8192) pendingLog = '';
    });
    await daemon.waitFor(/DHCP, sockets bound/, 5000); return {};
  };
  const input = createInterface({ input: process.stdin }); process.stdout.write('CLOUD_READY\n');
  try { for await (const line of input) {
    assert.ok(line.length < 1024); const req = JSON.parse(line); assert.ok(Number.isSafeInteger(req.id));
    try { const result = await handle(req); process.stdout.write(`CLOUD_REPLY ${req.id} ${JSON.stringify({ ok: true, result })}\n`); }
    catch (e) { process.stdout.write(`CLOUD_REPLY ${req.id} ${JSON.stringify({ ok: false, error: `${e.message}: ${log}` })}\n`); }
    if (req.op === 'close') break;
  } } finally { await close(); input.close(); }
}
if (process.argv[1] === entry) main(process.argv[2]).catch((e) => { process.stderr.write(`CLOUD_FAILED ${e.stack}\n`); process.exitCode = 1; });
