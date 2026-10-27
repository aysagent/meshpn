import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import dgram from 'node:dgram';
import os from 'node:os';
import {isIP} from 'node:net';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {startPeer, testAddress, testBody} from './vpn-local-peer.mjs';
import {cleanStatus} from './perf-runner.mjs';
import {sameSubnet} from './perf-lib.mjs';

const execute = promisify(execFile);
export async function localLab({gateway = '192.168.10.1', address, iface,
  host, out, certificate, privateKey, soakSeconds = 120, withoutPeer = false} = {}) {
  if (isIP(host ?? '') !== 4 || !out || !Number.isInteger(soakSeconds) || soakSeconds < 1 || soakSeconds > 7200)
    throw Error('Require --host EXISTING_MAC_LAN_IPV4, --out NEW_DIRECTORY and --soak-seconds 1..7200');
  const candidates = Object.entries(os.networkInterfaces()).flatMap(([name, addresses]) =>
    addresses.filter(a => !a.internal && a.family === 'IPv4' && sameSubnet(a.address, gateway, a.netmask) &&
      (!iface || iface === name) && (!address || address === a.address)).map(a => ({iface: name, address: a.address})));
  if (candidates.length !== 1) throw Error('Expected one directly connected USB IPv4 interface');
  ({iface, address} = candidates[0]);
  await fs.mkdir(path.dirname(path.resolve(out)), {recursive: true}); await fs.mkdir(out);
  const result = {started: new Date().toISOString(), status: 'running',
    scope: withoutPeer ? 'P4 no-exit checks: public DIRECT control and negative tunnel/MTU tests' :
      'Synthetic local IPv4 peer; no internet exit or host network changes', tests: []};
  let token, original, peer, direct, restored = false;
  const peers = [], controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  async function api(resource, data, timeout = 12000) {
    const started = performance.now();
    const response = await new Promise((resolve, reject) => {
      const body = data === undefined ? null : JSON.stringify(data);
      const req = http.request({host: gateway, localAddress: address, path: resource,
        method: body ? 'POST' : 'GET', agent: false,
        headers: {Host: 'dongle.local', ...(token ? {Authorization: `Bearer ${token}`} : {}),
          ...(body ? {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)} : {})}}, res => {
        let text = ''; res.setEncoding('utf8');
        res.on('data', b => { text += b; if (text.length > 256 * 1024) req.destroy(Error('Oversize API response')); });
        res.on('end', () => resolve({code: res.statusCode, text})); res.on('error', reject);
      });
      const timer = setTimeout(() => req.destroy(Error('API deadline exceeded')), timeout);
      req.on('error', reject); req.on('close', () => clearTimeout(timer)); req.end(body);
    });
    if (response.code !== 200) throw Error(`${resource}: HTTP ${response.code} ${response.text.slice(0, 160)}`);
    return {data: JSON.parse(response.text), ms: performance.now() - started};
  }
  const status = async () => (await api('/api/status')).data;
  async function snapshot(label) {
    const s = await status();
    await fs.appendFile(path.join(out, 'status.ndjson'), JSON.stringify({at: new Date().toISOString(), label, status: cleanStatus(s)}) + '\n');
    return s;
  }
  async function waitState(connected) {
    const deadline = Date.now() + 30000;
    let last;
    while (Date.now() < deadline) {
      if (controller.signal.aborted) throw Error('Interrupted');
      const s = await status(); last = s;
      if (s.vpn.connected === connected) return s;
      await delay(300);
    }
    throw Error(`VPN connected=${connected} deadline exceeded: ${last?.vpn?.state}, error ${last?.vpn?.last_error}, failure ${last?.vpn?.socket?.last_failure?.reason}`);
  }
  async function config(type, server, extra = {}) {
    await api('/api/vpn/config', {enabled: true, kill_switch: true, transport: type, server,
      allow_plaintext: true, tls_server_name: '', ...extra});
  }
  async function curl(url, {ok = true, body = testBody, timeout = 10} = {}) {
    try {
      const r = await execute('/usr/bin/curl', ['--noproxy', '*', '-4', '--interface', iface,
        '--connect-timeout', String(timeout), '--max-time', String(timeout + 2), '-sS', url],
      {timeout: (timeout + 4) * 1000, maxBuffer: 2 * 1024 * 1024});
      assert(ok, 'Blocked request unexpectedly reached a server');
      if (body !== null) assert.equal(r.stdout, body);
      return {bytes: Buffer.byteLength(r.stdout)};
    } catch (e) {
      if (ok || e.code === 'ERR_ASSERTION') throw e;
      return {blocked: true, code: e.code};
    }
  }
  async function dns(name = 'meshpn-night.invalid') {
    const socket = dgram.createSocket('udp4');
    try {
      await new Promise(resolve => socket.bind(0, address, resolve));
      const labels = name.split('.').map(s => Buffer.concat([Buffer.from([s.length]), Buffer.from(s)]));
      const header = Buffer.alloc(12); header.writeUInt16BE(0x7352); header[2] = 1; header[5] = 1;
      const q = Buffer.concat([header, ...labels, Buffer.from([0, 0, 1, 0, 1])]);
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error('DNS timeout')), 7000);
        socket.once('error', e => { clearTimeout(timer); reject(e); });
        socket.once('message', b => {
          clearTimeout(timer); assert.equal(b.readUInt16BE(0), 0x7352);
          resolve({rcode: b[3] & 15, answers: b.readUInt16BE(6), last4: [...b.subarray(-4)].join('.')});
        });
        socket.send(q, 53, gateway);
      });
    } finally { socket.close(); }
  }
  async function test(name, fn) {
    if (controller.signal.aborted) throw Error('Interrupted');
    console.log(name);
    const t = {name, started: new Date().toISOString()}; result.tests.push(t);
    try { t.details = await fn(); t.ok = true; }
    catch (e) { t.ok = false; t.error = e.message;
      if (peer) t.peer = structuredClone(peer.stats);
      await snapshot('failure').catch(() => {}); throw e; }
    finally { t.ended = new Date().toISOString(); await fs.writeFile(path.join(out, 'result.json'), JSON.stringify(result, null, 2)); }
  }
  try {
    token = (await api('/api/login', {password: process.env.MESHPN_ADMIN_PASSWORD ?? 'admin'})).data.token;
    if (!token) throw Error('Login returned no token');
    const initial = await snapshot('initial');
    assert.equal(initial.board, 'waveshare_esp32_p4_wifi6', 'Expected the project P4');
    assert.equal(initial.net.usb_ip, gateway); assert(initial.wifi.connected, 'Board STA uplink required');
    original = {enabled: initial.vpn.enabled, transport: initial.vpn.transport, server: initial.vpn.server,
      kill_switch: initial.vpn.kill_switch, tls_server_name: initial.vpn.tls_server_name ?? '',
      saved_servers: initial.vpn.saved_servers ?? {}, allow_plaintext: true};
    result.build = initial.build; result.boot_count = initial.boot_count;
    for (const type of withoutPeer ? [] : ['tcp', 'udp', 'tls']) {
      if (type === 'tls' && (!certificate || !privateKey)) throw Error('Local TLS certificate/key required');
      peer = await startPeer({host, type, cert: certificate && await fs.readFile(certificate),
        key: privateKey && await fs.readFile(privateKey), fragmentFrames: type === 'tls'});
      peers.push(peer);
      console.log(`${type} peer ${host}:${peer.port}`);
      await test(`${type}: connect, HTTP, DNS and MSS`, async () => {
        await config(type, `${host}:${peer.port}`); await waitState(true);
        for (let i = 0; i < 3; i++) await curl(`http://${testAddress}/`);
        const answer = await dns(); assert.equal(answer.rcode, 0); assert.equal(answer.last4, testAddress);
        const local = await dns(initial.hostname || 'dongle.local'); assert.equal(local.last4, gateway);
        assert(peer.stats.mss.length && peer.stats.mss.every(m => m <= 1360));
        return {peer: structuredClone(peer.stats), dns: answer};
      });
      await test(`${type}: bulk transfer with concurrent admin status`, async () => {
        const latencies = [], length = type === 'tls' ? 16384 : 262144;
        let done = false;
        const transfer = curl(`http://${testAddress}/bytes/${length}`, {body: 'Z'.repeat(length), timeout: 20}).finally(() => { done = true; });
        while (!done) { latencies.push((await api('/api/status')).ms); await delay(100); }
        await transfer;
        const s = await snapshot(`${type}-bulk`); assert.equal(s.boot_count, initial.boot_count);
        return {bytes: length, status_requests: latencies.length, status_max_ms: Math.max(...latencies)};
      });
      if (type !== 'udp') await test(`${type}: disconnect and reconnect`, async () => {
        const before = (await status()).vpn.reconnects; peer.drop();
        await delay(500); await waitState(true); await curl(`http://${testAddress}/`);
        assert((await status()).vpn.reconnects > before);
        return {connections: peer.stats.connections};
      });
      await snapshot(`${type}-finished`);
      await config(type, `${host}:1`, {enabled: false}); await waitState(false);
      await peer.close(); peers.pop(); peer = null;
    }
    let url = 'http://1.1.1.1/', directBody = null;
    if (!withoutPeer) {
      direct = http.createServer((req, res) => res.end('MeshPN direct baseline\n'));
      await new Promise((resolve, reject) => { direct.once('error', reject); direct.listen(0, host, resolve); });
      url = `http://${host}:${direct.address().port}/`; directBody = 'MeshPN direct baseline\n';
    }
    await test('DIRECT control before kill-switch checks', async () => {
      await config('tcp', `${host}:1`, {enabled: false}); return curl(url, {body: directBody});
    });
    await test('kill switch: unreachable endpoint, DNS and local admin', async () => {
      await config('tcp', `${host}:1`); await waitState(false);
      await curl(url, {ok: false, timeout: 3});
      const answer = await dns('blocked-night.invalid'); assert.equal(answer.rcode, 2);
      const s = await snapshot('kill-switch'); assert(s.vpn.kill_switch && !s.vpn.connected);
      return {blocked: true, dns_rcode: answer.rcode};
    });
    if (withoutPeer) for (const type of ['udp', 'tls']) {
      await test(`${type}: no-exit HTTP/DNS stays blocked and admin responds`, async () => {
        await config(type, `${host}:1`);
        await curl(url, {ok: false, timeout: 3});
        const answer = await dns(`blocked-${type}-night.invalid`); assert.equal(answer.rcode, 2);
        const s = await snapshot(`${type}-kill-switch`);
        assert.equal(s.boot_count, initial.boot_count); assert(s.vpn.enabled && s.vpn.kill_switch);
        return {blocked: true, dns_rcode: answer.rcode, state: s.vpn.state,
          connected: s.vpn.connected}; // UDP ready is not proof of a peer.
      });
    }
    if (withoutPeer) await test('pre-NAT PMTUD on P4: DF packet at MTU and MTU+1', async () => {
      const before = await status(), probes = [];
      const target = `198.18.${Math.floor(Date.now() / 256) % 256}.${Date.now() % 254 + 1}`;
      for (const size of [1372, 1373]) {
        const {stdout} = await execute('python3', [fileURLToPath(new URL('./vpn-local-probe.py', import.meta.url)),
          '--interface', iface, '--source', address, '--target', target, '--size', String(size), '--df'], {timeout: 5000});
        probes.push(JSON.parse(stdout));
      }
      await delay(200); const after = await snapshot('pmtud');
      assert.equal(after.vpn.mtu_feedback - before.vpn.mtu_feedback, 1);
      assert.equal(after.vpn.mtu_feedback_failed - before.vpn.mtu_feedback_failed, 0);
      return {probes, feedback_sent: 1};
    });
    await test('explicit DIRECT fallback and VPN disabled baseline', async () => {
      await config('tcp', `${host}:1`, {kill_switch: false}); await waitState(false);
      await curl(url, {body: directBody});
      await config('tcp', `${host}:1`, {enabled: false, kill_switch: true});
      await curl(url, {body: directBody}); return {direct_baselines: 2};
    });
    if (!withoutPeer) {
    peer = await startPeer({host, type: 'tcp'}); peers.push(peer);
    await config('tcp', `${host}:${peer.port}`); await waitState(true);
    await test('P4 STA+USB synthetic tunnel soak', async () => {
      const end = Date.now() + soakSeconds * 1000; let requests = 0;
      while (Date.now() < end) {
        await curl(`http://${testAddress}/bytes/65536`, {body: 'Z'.repeat(65536)}); requests++;
        const s = await snapshot('soak'); assert.equal(s.boot_count, initial.boot_count);
        if (controller.signal.aborted) throw Error('Interrupted');
        await delay(100);
      }
      return {requests, seconds: soakSeconds, peer: structuredClone(peer.stats)};
    });
    }
    result.status = 'completed';
  } catch (e) { result.status = 'failed'; result.error = e.message; }
  finally {
    if (original) {
      try { await api('/api/vpn/config', original); restored = true; await snapshot('restored'); }
      catch (e) { result.restore_error = e.message; }
    }
    for (const p of peers) await p.close().catch(() => {});
    if (direct) await new Promise(resolve => direct.close(resolve));
    result.restored = restored; result.ended = new Date().toISOString();
    await fs.writeFile(path.join(out, 'result.json'), JSON.stringify(result, null, 2));
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  }
  return result;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = {};
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--without-peer') { options.withoutPeer = true; continue; }
    const key = {'--host': 'host', '--out': 'out', '--cert': 'certificate', '--key': 'privateKey', '--soak-seconds': 'soakSeconds'}[process.argv[i]];
    if (!key || !process.argv[i + 1]) throw Error('Unknown option or missing value');
    options[key] = key === 'soakSeconds' ? Number(process.argv[++i]) : process.argv[++i];
  }
  const result = await localLab(options);
  console.log(JSON.stringify({status: result.status, error: result.error, restored: result.restored}));
  process.exitCode = result.status === 'completed' && result.restored ? 0 : 1;
}
