// NIC-less disposable QEMU only. Node provisions networks/config and reads
// verdicts; all application traffic, DNS, TLS and capture stay in C++.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { applyNativeNetworkProfile } from './native-network-apply.mjs';
import { runComboNetworkLoad } from './native-combo-network-load.mjs';
import { runComboBenchmark } from './native-combo-benchmark.mjs';

assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-combo-network=1\b/);
const load = process.argv[2] === '--load';
const benchmark = process.argv[2] === '--benchmark';
assert.ok(process.argv.length === 2 || (process.argv.length === 3 && (load || benchmark)));
if (load) assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-combo-load=1\b/);
if (benchmark) assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-combo-benchmark=1\b/);
const run = (bin, args, input) => execFileSync(bin, args, { input, encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
const ip = (...args) => run('/usr/bin/ip', args);
assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(l => l.ifname), ['lo']);
const parent = fs.readlinkSync('/proc/self/ns/net'), engine = '/native/clean-vpn-engine';
const tls = '/native/transparent-socket-test', socket = '/native/socket-test';
const children = [], checks = [];
const gate = key => { checks.push(key); console.log('NATIVE_COMBO_' + key + '_PASS'); };
const inside = (ns, bin, args, input) => run('/usr/bin/ip', ['netns', 'exec', ns, bin, ...args], input);
const nip = (ns, ...args) => ip('-n', ns, ...args);
function start(ns, bin, args) {
  const env = { ...process.env }; delete env.NOTIFY_SOCKET;
  const p = spawn('/usr/bin/ip', ['netns', 'exec', ns, bin, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env });
  const e = { p, output: '', error: '', ended: false, code: null };
  p.stdout.on('data', b => { e.output += b.toString(); if (e.output.length > 1024 * 1024) p.kill('SIGKILL'); });
  p.stderr.on('data', b => { e.error = (e.error + b.toString()).slice(-8192); });
  p.on('error', err => { e.error += err.message; e.ended = true; });
  p.on('close', (code, signal) => { e.ended = true; e.code = code; e.signal = signal; });
  children.push(e); return e;
}
async function until(predicate, seconds = 30) {
  const deadline = Date.now() + seconds * 1000;
  while (!predicate()) { assert.ok(Date.now() < deadline, 'combo_vm_deadline'); await delay(30); }
}
async function stop(e) { e.p.kill('SIGKILL'); await until(() => e.ended); assert.equal(e.signal, 'SIGKILL'); }
const tlsArgs = mode => [mode, '/native/cert.pem', '/native/key.pem', parent];
const probe = mode => inside('coapp', tls, tlsArgs(mode));
async function launch(ns, config) {
  const e = start(ns, engine, ['--config', config, '--service']);
  await until(() => { assert.ok(!e.ended, e.error); return e.output.includes('"state":"ready"'); });
  return e;
}
function guard(ns, config) {
  let state = null;
  const io = { scope: { boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
    net: fs.statSync('/run/netns/' + ns).ino, user: fs.readlinkSync('/proc/self/ns/user') },
    run: (bin, args, input) => inside(ns, bin, args, input), read: () => state, save: s => { state = structuredClone(s); } };
  assert.equal(applyNativeNetworkProfile(config, io).status, 'installed');
  return () => assert.equal(applyNativeNetworkProfile(config, io).status, 'verified');
}
const tunPackets = () => {
  const stats = JSON.parse(nip('cogw', '-s', '-j', 'link', 'show', 'tun0'))[0].stats64;
  return stats.rx.packets + stats.tx.packets;
};
try {
  for (const ns of ['cogw', 'coexit', 'coapp', 'coorigin']) ip('netns', 'add', ns);
  ip('link', 'add', 'cowire', 'type', 'bridge'); ip('link', 'set', 'cowire', 'up');
  const origin = start('coorigin', tls, tlsArgs(benchmark ? '--combo-network-benchmark-origin' : '--combo-network-origin'));
  await until(() => origin.output.includes('namespace-ready'));
  for (const [ns, name, dev] of [['coorigin', 'or', 'cvpublic1'], ['cogw', 'gw', 'wan0'], ['coexit', 'ex', 'wan0']]) {
    ip('link', 'add', 'left' + name, 'type', 'veth', 'peer', 'name', 'right' + name);
    ip('link', 'set', 'right' + name, 'netns', ns); nip(ns, 'link', 'set', 'right' + name, 'name', dev);
    ip('link', 'set', 'left' + name, 'master', 'cowire'); ip('link', 'set', 'left' + name, 'up');
  }
  ip('link', 'add', 'leftlan', 'type', 'veth', 'peer', 'name', 'rightlan');
  ip('link', 'set', 'leftlan', 'netns', 'cogw'); nip('cogw', 'link', 'set', 'leftlan', 'name', 'lan0');
  ip('link', 'set', 'rightlan', 'netns', 'coapp'); nip('coapp', 'link', 'set', 'rightlan', 'name', 'cvpublic0');
  for (const ns of ['cogw', 'coexit', 'coapp']) nip(ns, 'link', 'set', 'lo', 'up');
  for (const [ns, dev, addr] of [['cogw', 'wan0', '198.18.0.1/24'], ['coexit', 'wan0', '198.18.0.3/24'],
    ['cogw', 'lan0', '192.168.7.1/24'], ['coapp', 'cvpublic0', '192.168.7.2/24']]) nip(ns, 'addr', 'add', addr, 'dev', dev);
  nip('coapp', 'link', 'set', 'cvpublic0', 'up'); nip('coapp', 'route', 'add', 'default', 'via', '192.168.7.1');
  await until(() => origin.output.includes('origin-ready'));
  nip('coorigin', 'route', 'add', '192.168.7.0/24', 'via', '198.18.0.1');
  const dataOrigin = start('coorigin', socket, ['serve']);
  await until(() => dataOrigin.output.includes('origin ready'));
  if (benchmark) {
    const benchOrigin = start('coorigin', '/native/throughput-test', ['--server', parent]);
    await until(() => { assert.ok(!benchOrigin.ended,benchOrigin.error); return benchOrigin.output.includes('benchmark-origin-ready'); });
  }
  for (const ns of ['cogw', 'coexit']) {
    nip(ns, 'link', 'set', 'wan0', 'up'); nip(ns, 'route', 'add', 'default', 'via', '198.18.0.2');
  }
  nip('cogw', 'link', 'set', 'lan0', 'up'); inside('cogw', 'sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  // Positive controls: direct traffic really works before the dedicated guard.
  assert.match(inside('coapp', socket, ['probe']), /NATIVE_TUN_PROBE_PASS/);
  assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await delay(100);
  const capture = () => origin.output.trim().split('\n').map(l => JSON.parse(l)).filter(l => Number.isInteger(l.forbiddenPackets)).at(-1);
  const positive = capture().forbiddenPackets; assert.ok(positive > 0); gate('DIRECT_POSITIVE_CONTROL');
  inside('cogw', 'sysctl', ['-w', 'net.ipv4.ip_forward=0']);
  for (const ns of ['cogw', 'coexit']) nip(ns, 'link', 'set', 'wan0', 'down');
  nip('cogw', 'link', 'set', 'lan0', 'down');
  const profile = { version: 1, transport: 'combo-tls', role: 'client', tun: 'tun0', tun_address: '10.99.0.2/32', mtu: 1400,
    uplink: 'wan0', endpoint: '198.18.0.3', port: 33001, listen_port: 33002, lan: { interface: 'lan0', subnet: '192.168.7.0/24' }, deny_ipv4: ['8.8.8.0/24'] };
  const auditClient = guard('cogw', profile), auditExit = guard('coexit', { ...profile, role: 'exit', tun_address: '10.99.0.1/24', listen_port: 33001, lan: null });
  gate('GUARDS_REAL_TUN');
  for (const ns of ['cogw', 'coexit']) {
    nip(ns, 'link', 'set', 'wan0', 'up'); nip(ns, 'route', 'replace', 'default', 'via', '198.18.0.2');
  }
  nip('cogw', 'link', 'set', 'lan0', 'up');
  const routes = action => { for (const dst of ['0.0.0.0/1', '128.0.0.0/1']) nip('cogw', 'route', action, dst, 'dev', 'tun0'); };
  routes('add');
  fs.writeFileSync('/native/relay-psk', Buffer.alloc(32, 0x42), { mode: 0o600 });
  fs.mkdirSync('/native/combo-replay', { mode: 0o700 });
  const common = { version: 1, address: profile.endpoint, port: profile.port, tun: 'tun0' };
  const transparent = { version: 1, transport: 'transparent-tls', public_name: 'relay.example', secret_path: '/native/relay-psk', destination_policy: { mode: 'public-https', deny_ipv4: profile.deny_ipv4 } };
  for (const role of ['client', 'exit']) {
    const boring = role === 'client' ? { ...common, role, secret_path: '/native/psk', dns: true, sni: 'relay.example', server_name: 'localhost', ca: '/native/cert.pem' } :
      { ...common, role, peers: [{ ipv4: '10.99.0.2', secret_path: '/native/psk' }], cert: '/native/cert.pem', key: '/native/key.pem' };
    const relay = { ...transparent, role, listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: role === 'client' ? profile.listen_port : profile.port },
      ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: profile.port } } : { replay_directory: '/native/combo-replay' }) };
    fs.writeFileSync(`/native/combo-${role}.json`, JSON.stringify({ version: 1, transport: 'combo-tls', role, boring, transparent: relay }), { mode: 0o600 });
  }
  inside('coexit', engine, ['--init-transparent-replay', '/native/combo-exit.json']);
  // Exit's ready notification requires a peer, so launch before waiting client.
  let ex = start('coexit', engine, ['--config', '/native/combo-exit.json', '--service']);
  let cl = await launch('cogw', '/native/combo-client.json');
  const beforeTls = tunPackets(); assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  assert.equal(tunPackets(), beforeTls, 'HTTPS_must_not_use_boring_TUN'); gate('HTTPS_TRANSPARENT_NOT_TUN');
  const concurrent = start('coapp', socket, ['probe']);
  assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await until(() => concurrent.ended); assert.equal(concurrent.code, 0, concurrent.error);
  assert.ok(tunPackets() > beforeTls); gate('CONCURRENT_TLS_TCP_UDP');
  for (const ns of ['coapp', 'cogw']) assert.match(inside(ns, socket, ['dns', '203.0.113.53']), /DNS TCP PASS/);
  gate('NATIVE_DNS_HOST_LAN');
  for (const [ns, target] of [['cogw', 'SNAT'], ['coexit', 'MASQUERADE']])
    assert.ok(inside(ns, 'iptables', ['-t', 'nat', '-L', 'POSTROUTING', '-v', '-n', '-x']).split('\n').some(l => new RegExp(`^\\s*[1-9]\\d*\\s+\\d+\\s+${target}\\s`).test(l)));
  gate('DOUBLE_NAT');
  assert.match(probe('--combo-network-negative'), /no fallback PASS/); gate('POLICY_NO_DOWNGRADE');
  let loadReport, benchmarkReport;
  const snapshot = () => Object.fromEntries([['client', cl], ['exit', ex]].map(([name, e]) => {
      assert.ok(!e.ended, 'load_engine_exited'); const base = `/proc/${e.p.pid}`;
      assert.equal(fs.readlinkSync(base + '/exe'), engine);
      const stat = fs.readFileSync(base + '/stat', 'utf8'); const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const status = fs.readFileSync(base + '/status', 'utf8');
      const x = { start: fields[19], ticks: Number(fields[11]) + Number(fields[12]),
        rss: Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1]), threads: Number(status.match(/^Threads:\s+(\d+)/m)?.[1]),
        fds: fs.readdirSync(base + '/fd').length };
      assert.ok(x.start && Number.isInteger(x.ticks) && x.rss > 0 && x.threads > 0 && x.fds > 0);
      return [name, x];
    }));
  if (benchmark) {
    await delay(500);
    benchmarkReport = await runComboBenchmark({ snapshot, tunPackets,
      start: (branch,phase) => start('coapp','/native/throughput-test',[phase,branch,'/native/cert.pem',parent,'--lab-only']),
      progress: x => console.log('NATIVE_COMBO_BENCHMARK_PHASE '+JSON.stringify(x)) });
    gate('DIRECTIONAL_BENCHMARK');
  }
  if (load) {
    await delay(500);
    console.log('NATIVE_COMBO_LOAD_BEGIN');
    loadReport = await runComboNetworkLoad({ snapshot, tunPackets,
      startData: () => start('coapp', socket, ['probe']), startTls: () => start('coapp', tls, tlsArgs('--public-client')),
      startHostDns: () => start('cogw', socket, ['dns', '203.0.113.53']),
      stopEngines: async () => {
        const result = {};
        for (const [name, e] of [['client', cl], ['exit', ex]]) {
          assert.ok(e.p.kill('SIGTERM')); await until(() => e.ended); assert.equal(e.code, 0, e.error);
          await until(() => e.output.includes('"state":"stopped"'));
          const states = e.output.trim().split('\n').map(s => JSON.parse(s));
          const end = states.findLast(s => s.state === 'stopped');
          result[name] = { readyCount: states.filter(s => s.state === 'ready').length, generation: end.generation,
            txPackets: end.tx_packets, rxPackets: end.rx_packets, droppedPackets: end.dropped_packets };
        }
        return result;
      } });
    gate('SUSTAINED_MIXED_LOAD');
    auditClient(); auditExit();
    ex = start('coexit', engine, ['--config', '/native/combo-exit.json', '--service']);
    cl = await launch('cogw', '/native/combo-client.json');
    assert.match(inside('coapp', socket, ['probe']), /NATIVE_TUN_PROBE_PASS/);
    assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate('LOAD_CLEAN_RESTART');
  }
  const blocked = clientDown => {
    assert.match(probe(clientDown ? '--public-network-crash' : '--public-client-blocked'), /(?:no fallback|blocked) PASS/);
    for (const mode of ['data', 'dns']) assert.throws(() => inside('coapp', socket, [mode]));
  };
  await stop(cl); routes('del'); blocked(true); auditClient(); gate('CLIENT_CRASH_DIRECT_ROUTE_BLOCKED');
  routes('add'); cl = await launch('cogw', '/native/combo-client.json');
  assert.match(inside('coapp', socket, ['probe']), /NATIVE_TUN_PROBE_PASS/); assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate('CLIENT_RESTART');
  await stop(ex); blocked(); auditExit(); gate('EXIT_CRASH_BLOCKED');
  ex = start('coexit', engine, ['--config', '/native/combo-exit.json', '--service']);
  await delay(1000);
  assert.match(inside('coapp', socket, ['probe']), /NATIVE_TUN_PROBE_PASS/); assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/); gate('EXIT_RESTART');
  auditClient(); auditExit();
  await delay(100); assert.equal(capture().forbiddenPackets, positive);
  assert.equal(capture().kernelDropped, 0); gate('SELECTED_ORIGIN_NO_DIRECT_PACKETS');
  console.log('NATIVE_COMBO_REPORT ' + JSON.stringify({ status: 'passed', checks, positiveCapturePackets: positive,
    ...(loadReport ? { load: loadReport } : {}),
    ...(benchmarkReport ? { benchmark: benchmarkReport } : {}),
    directPacketsAfterGuard: 0, captureKernelDropped: capture().kernelDropped, realTun: true, roles: ['client', 'exit'], namespaces: 5, packetOwner: 'C++',
    scope: benchmark ? 'runtime-static-routes-selected-IPv4-origin-with-emulated-benchmark' : 'runtime-static-routes-selected-IPv4-origin-not-installer-systemd-reboot-all-egress-or-benchmark' }));
} finally {
  for (const e of children) if (!e.ended) e.p.kill('SIGKILL');
  await Promise.all(children.map(e => e.ended ? null : new Promise(r => e.p.once('close', r))));
  for (const e of children) if (e.error) console.error(e.error);
}
