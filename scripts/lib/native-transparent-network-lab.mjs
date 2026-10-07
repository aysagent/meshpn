// Namespace provisioning and verdicts only. All probes/TLS/packet capture are
// C++; no physical interface, host firewall or real Internet is in this lab.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { applyNativeNetworkProfile } from './native-network-apply.mjs';

const [build, cert, key, parent] = process.argv.slice(2);
const own = fs.readlinkSync('/proc/self/ns/net');
assert.match(parent, /^net:\[\d+\]$/); assert.notEqual(own, parent);
const run = (exe, args, input) => execFileSync(exe, args, { input, encoding: 'utf8', timeout: 12000, maxBuffer: 1024 * 1024 });
const ip = (...args) => run('ip', args);
assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
const fixture = path.join(build, 'transparent-socket-test'), engine = path.join(build, 'clean-vpn-engine');
const dir = fs.mkdtempSync('/tmp/cvpn-transparent-network-');
const children = [];
function start(exe, args) {
  const child = spawn(exe, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const e = { child, lines: [], pending: '', ended: false, error: '', code: null };
  child.on('error', err => { e.error = err.code; e.ended = true; });
  child.on('exit', code => { e.ended = true; e.code = code; });
  child.stderr.on('data', b => { e.error = (e.error + b.toString()).slice(-4096); });
  child.stdout.on('data', b => {
    e.pending += b.toString();
    if (e.pending.length > 65536 || e.lines.length > 128) { e.error = 'metadata_limit'; child.kill('SIGKILL'); return; }
    let n;
    while ((n = e.pending.indexOf('\n')) >= 0) {
      try { e.lines.push(JSON.parse(e.pending.slice(0, n))); } catch { e.error = 'invalid_metadata'; }
      e.pending = e.pending.slice(n + 1);
    }
  });
  children.push(e); return e;
}
async function wait(e, predicate) {
  const until = Date.now() + 6000;
  while (!predicate(e)) {
    assert.equal(e.ended, false, e.error); assert.ok(Date.now() < until, e.error || 'metadata_timeout'); await delay(10);
  }
}
async function stop(e) { e.child.kill('SIGKILL'); await wait(e, x => x.ended); }
const nsargs = e => [`--net=/proc/${e.child.pid}/ns/net`];
const inside = (e, exe, args, input) => run('nsenter', [...nsargs(e), exe, ...args], input);
const nip = (e, ...args) => inside(e, 'ip', args);
async function holder() {
  const e = start('unshare', ['--net', fixture, '--public-holder', cert, key, own]);
  await wait(e, x => x.lines.some(l => l.stage === 'namespace-ready')); return e;
}
function interfacePair(a, nameA, b, nameB, id) {
  ip('link', 'add', 'left' + id, 'type', 'veth', 'peer', 'name', 'right' + id);
  for (const [e, initial, name] of [[a, 'left' + id, nameA], [b, 'right' + id, nameB]]) {
    if (e) { ip('link', 'set', initial, 'netns', String(e.child.pid)); nip(e, 'link', 'set', initial, 'name', name); }
    else ip('link', 'set', initial, 'name', name);
  }
}
function guard(e, profile) {
  let state = null;
  const io = { scope: { boot: 'isolated-fixture', net: fs.readlinkSync(`/proc/${e.child.pid}/ns/net`), user: fs.readlinkSync('/proc/self/ns/user') },
    run: (bin, args, input) => inside(e, bin, args, input), read: () => state, save: s => { state = structuredClone(s); } };
  assert.equal(applyNativeNetworkProfile(profile, io).status, 'installed');
  return () => assert.equal(applyNativeNetworkProfile(profile, io).status, 'verified');
}
async function launch(e, config) {
  // Same network capability bound as the rendered transparent service, after
  // entering the fixture namespace. SO_ORIGINAL_DST must work without ADMIN.
  const process = start('nsenter', [...nsargs(e), 'setpriv', '--bounding-set=-all,+net_bind_service',
    '--inh-caps=-all', '--no-new-privs', '--', engine, '--config', config, '--service']);
  await wait(process, x => x.lines.some(l => l.state === 'listening')); return process;
}
try {
  ip('link', 'set', 'lo', 'up'); ip('link', 'add', 'wire', 'type', 'bridge'); ip('link', 'set', 'wire', 'up');
  const gateway = await holder(), exit = await holder(), app = await holder();
  interfacePair(app, 'cvpublic0', gateway, 'lan0', 'lan');
  for (const [e, port] of [[gateway, 'gw'], [exit, 'ex']]) {
    interfacePair(null, port, e, 'wan0', port); ip('link', 'set', port, 'master', 'wire'); ip('link', 'set', port, 'up');
  }
  const origin = start('unshare', ['--net', fixture, '--public-network-origin', cert, key, own]);
  await wait(origin, x => x.lines.some(l => l.stage === 'namespace-ready'));
  interfacePair(null, 'orig', origin, 'cvpublic1', 'or'); ip('link', 'set', 'orig', 'master', 'wire'); ip('link', 'set', 'orig', 'up');
  await wait(origin, x => x.lines.some(l => l.stage === 'origin-ready'));
  for (const e of [gateway, exit, app]) nip(e, 'link', 'set', 'lo', 'up');
  nip(gateway, 'addr', 'add', '192.168.7.1/24', 'dev', 'lan0');
  nip(gateway, 'addr', 'add', '198.18.0.1/24', 'dev', 'wan0');
  nip(exit, 'addr', 'add', '198.18.0.3/24', 'dev', 'wan0');
  nip(app, 'addr', 'add', '192.168.7.2/24', 'dev', 'cvpublic0'); nip(app, 'link', 'set', 'cvpublic0', 'up');
  nip(app, 'route', 'add', 'default', 'via', '192.168.7.1');
  const probe = mode => inside(app, fixture, [mode, cert, key, own]);
  // Positive capture control with no guard/engine: the synthetic destination
  // is reachable. Close links/forwarding again before the fresh install.
  for (const dev of ['lan0', 'wan0']) nip(gateway, 'link', 'set', dev, 'up');
  nip(gateway, 'route', 'add', '1.1.1.1/32', 'via', '198.18.0.2');
  inside(gateway, 'sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  probe('--public-network-udp');
  await wait(origin, x => x.lines.some(l => l.forbiddenPackets >= 2));
  inside(gateway, 'sysctl', ['-w', 'net.ipv4.ip_forward=0']);
  for (const dev of ['lan0', 'wan0']) nip(gateway, 'link', 'set', dev, 'down');
  const profile = { version: 1, transport: 'transparent-tls', role: 'client', uplink: 'wan0',
    endpoint: '198.18.0.3', port: 33001, listen_port: 33002,
    lan: { interface: 'lan0', subnet: '192.168.7.0/24' }, deny_ipv4: ['8.8.8.0/24'] };
  const auditGateway = guard(gateway, profile);
  const auditExit = guard(exit, { ...profile, role: 'exit', listen_port: 33001, lan: null });
  for (const dev of ['lan0', 'wan0']) nip(gateway, 'link', 'set', dev, 'up'); nip(exit, 'link', 'set', 'wan0', 'up');
  for (const e of [gateway, exit]) nip(e, 'route', 'replace', '1.1.1.1/32', 'via', '198.18.0.2');
  // Counter reads happen only after draining the positive-control metadata.
  await delay(100);
  const before = origin.lines.filter(l => Number.isInteger(l.forbiddenPackets)).at(-1).forbiddenPackets;
  assert.match(probe('--public-network-crash'), /blocked PASS/);
  fs.writeFileSync(path.join(dir, 'secret'), Buffer.alloc(32, 0x42), { mode: 0o600 }); fs.mkdirSync(path.join(dir, 'replay'), { mode: 0o700 });
  const common = { version: 1, transport: 'transparent-tls', public_name: 'relay.example', secret_path: path.join(dir, 'secret'),
    destination_policy: { mode: 'public-https', deny_ipv4: profile.deny_ipv4 } };
  const ecfg = path.join(dir, 'exit.json'), ccfg = path.join(dir, 'client.json');
  fs.writeFileSync(ecfg, JSON.stringify({ ...common, role: 'exit', listen: { ipv4: profile.endpoint, port: profile.port }, replay_directory: path.join(dir, 'replay') }));
  fs.writeFileSync(ccfg, JSON.stringify({ ...common, role: 'client', listen: { ipv4: '0.0.0.0', port: profile.listen_port }, exit: { ipv4: profile.endpoint, port: profile.port } }));
  inside(exit, engine, ['--init-transparent-replay', ecfg]);
  let ex = await launch(exit, ecfg), cl = await launch(gateway, ccfg);
  assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await wait(origin, x => x.lines.some(l => l.connections === 2));
  assert.match(probe('--public-network-negative'), /blocked PASS/);
  await stop(cl); auditGateway(); assert.match(probe('--public-network-crash'), /blocked PASS/);
  cl = await launch(gateway, ccfg); assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await wait(origin, x => x.lines.some(l => l.connections === 4));
  await stop(ex); auditExit(); assert.match(probe('--public-client-blocked'), /no fallback PASS/);
  ex = await launch(exit, ecfg); assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await wait(origin, x => x.lines.some(l => l.connections === 6));
  await delay(100);
  assert.equal(origin.lines.filter(l => Number.isInteger(l.forbiddenPackets)).at(-1).forbiddenPackets, before);
  auditGateway(); auditExit();
  console.log(JSON.stringify({ status: 'passed', kind: 'native-transparent-network-guard', namespaces: 5,
    originConnections: 6, positiveCapturePackets: before, forbiddenPacketsAfterGuard: 0,
    checks: ['LAN-REDIRECT-TLS12-TLS13-HRR', 'engine-without-network-admin-capabilities', 'no-TUN-no-forwarding', 'non-HTTPS-and-direct-listener-blocked',
      'client-SIGKILL-no-fallback', 'exit-SIGKILL-no-fallback', 'restart-both', 'firewall-journal-unchanged'],
    scope: 'namespace-runtime-not-systemd-boot-or-physical-deployment; selected-IPv4-probes' }));
} finally {
  for (const e of children) if (!e.ended) e.child.kill('SIGKILL');
  await Promise.all(children.map(e => e.ended ? null : new Promise(resolve => e.child.once('exit', resolve))));
  fs.rmSync(dir, { recursive: true, force: true });
}
