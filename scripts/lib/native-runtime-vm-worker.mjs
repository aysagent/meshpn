// ONLY the NIC-less disposable QEMU guest. Never run on a physical host.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { inspectPcap } from '../clean-vpn-pcap-fingerprints.mjs';
import { prepareHostWiring, checkHostWiring } from './native-runtime-host-wiring-vm.mjs';
assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').split(/\s+/).includes('meshpn.runtime-vm=1'));
const hostWiring=fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-host-wiring=1');
assert.equal(process.arch, 'x64');
const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
const ip = (...args) => run('ip', args), ns = (name, ...args) => ip('netns', 'exec', name, ...args);
const parent = fs.readlinkSync('/proc/self/ns/net'), children = [], namespaces = [], checks = [];
const env = name => ['env', `CVPN_PARENT_NETNS=${parent}`, `CVPN_STATE_DIRECTORY=/run/clean-vpn-${name}`,
  ...(hostWiring&&name==='client'?['CVPN_UPLINK=auto','CVPN_LAN_INTERFACE=auto','CVPN_LAN_SUBNET=192.168.88.0/24']:[])];
const child = (name, command, args, tag, binaryOutput = false) => {
  const stdout = '/run/' + tag + (binaryOutput ? '.pcap' : '.log'), stderr = '/run/' + tag + '.stderr';
  const out = fs.openSync(stdout, 'w', 0o600), err = fs.openSync(stderr, 'w', 0o600);
  const p = spawn('ip', ['netns', 'exec', name, ...env(name), command, ...args], { stdio: ['ignore', out, err] });
  fs.closeSync(out); fs.closeSync(err); p.on('error', () => {}); children.push(p);
  return { p, stdout, stderr };
};
const stop = async c => {
  if (c.p.exitCode !== null || c.p.signalCode !== null) return;
  c.p.kill('SIGTERM'); for (let i = 0; i < 100 && c.p.exitCode === null && c.p.signalCode === null; i++) await delay(50);
  if (c.p.exitCode === null && c.p.signalCode === null) { c.p.kill('SIGKILL'); throw Error('graceful_stop_timeout'); }
};
const wait = async fn => { let last; for (let i = 0; i < 40; i++) { try { return fn(); } catch (e) { last = e; await delay(250); } } throw last; };
const health = name => ns(name, ...env(name), 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
const step = label => { checks.push(label); console.log('RUNTIME_VM_STEP=' + label); };
let report = { schema: 1, kind: 'native-runtime-standalone-vm', checks, status: 'failed' };
try {
  fs.mkdirSync('/config', { mode: 0o700 });
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=runtime.test',
    '-addext', 'subjectAltName=DNS:runtime.test', '-keyout', '/config/key.pem', '-out', '/config/cert.pem']);
  const write = (f, v) => fs.writeFileSync('/config/' + f, v, { mode: 0o600 });
  write('psk', randomBytes(32)); write('profile.json', fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json'));
  write('client.json', JSON.stringify({ version: 1, role: 'client', tun: 'cvpn0', address: '10.77.0.2', port: 443, dns: true,
    secret_path: '/config/psk', server_name: 'runtime.test', ca: '/config/cert.pem', tls_profile_path: '/config/profile.json' }));
  write('exit.json', JSON.stringify({ version: 1, role: 'exit', tun: 'cvpn0', address: '10.77.0.2', port: 443, alps: true,
    secret_path: '/config/psk', cert: '/config/cert.pem', key: '/config/key.pem' }));
  ip('link', 'add', 'br0', 'type', 'bridge'); ip('addr', 'add', '10.77.0.1/24', 'dev', 'br0'); ip('link', 'set', 'br0', 'up');
  for (const [name, address] of [['exit', '10.77.0.2'], ['client', '10.77.0.3'], ['origin', '10.77.0.4']]) {
    ip('netns', 'add', name); namespaces.push(name);
    ip('link', 'add', name + '-host', 'type', 'veth', 'peer', 'name', name + '-peer');
    ip('link', 'set', name + '-host', 'master', 'br0'); ip('link', 'set', name + '-host', 'up');
    ip('link', 'set', name + '-peer', 'netns', name);
    ns(name, 'ip', 'link', 'set', name + '-peer', 'name', 'eth0'); ns(name, 'ip', 'link', 'set', 'lo', 'up');
    ns(name, 'ip', 'addr', 'add', address + '/24', 'dev', 'eth0'); ns(name, 'ip', 'link', 'set', 'eth0', 'up');
    ns(name, 'ip', 'route', 'add', 'default', 'via', '10.77.0.1');
  }
  ns('origin', 'ip', 'addr', 'add', '198.18.0.80/32', 'dev', 'lo');
  if(hostWiring)prepareHostWiring({ip,ns,namespaces});
  ns('exit', 'sysctl', '-w', 'net.ipv4.ip_forward=1'); ns('exit', 'ip', 'route', 'add', '198.18.0.80/32', 'via', '10.77.0.4');
  const origin = child('origin', 'node', ['/project/scripts/lib/native-runtime-lab-origin.mjs'], 'origin');
  await wait(() => assert.match(fs.readFileSync(origin.stdout, 'utf8'), /ORIGIN_READY/));
  const exit = child('exit', '/usr/local/bin/native-runtime', ['/config/exit.json'], 'exit'); await wait(() => health('exit'));
  for (const server of ['1.1.1.1', '8.8.8.8']) for (const proto of ['udp', 'tcp']) ns('exit', 'iptables-nft', '-t', 'nat', '-A', 'PREROUTING',
    '-i', 'cvpn0', '-d', server, '-p', proto, '--dport', '53', '-j', 'DNAT', '--to-destination', '10.77.0.4:5353');
  const capture = child('exit', '/usr/bin/tcpdump', ['-p', '-n', '-U', '-i', 'eth0', '-s', '0', '-w', '-', 'tcp', 'dst', 'port', '443'], 'capture', true);
  await wait(() => assert.match(fs.readFileSync(capture.stderr, 'utf8'), /listening on eth0/));
  let client = child('client', '/usr/local/bin/native-runtime', ['/config/client.json'], 'client'); await wait(() => health('client'));
  step('standalone-authenticated-tunnel-dns-udp-tcp');
  const httpsProbe = `const https=require('https'),fs=require('fs');https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:5000},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{if(b!=='native-runtime-https-ok\\n')process.exitCode=1;else console.log('HTTPS_OK')})}).on('error',()=>process.exitCode=1).on('timeout',function(){this.destroy()});`;
  assert.match(ns('client', 'node', '-e', httpsProbe), /HTTPS_OK/); step('standalone-https');
  if(hostWiring)client=await checkHostWiring({ns,child,wait,health,step,client,
    restartClient:()=>child('client','/usr/local/bin/native-runtime',['/config/client.json'],'client-host-restart')});
  client.p.kill('SIGKILL'); await wait(() => assert.ok(client.p.signalCode));
  const blocked = `const s=require('net').connect(5353,'10.77.0.4',()=>process.exit(2));s.setTimeout(1200,()=>{s.destroy();console.log('BLOCKED')});s.on('error',()=>console.log('BLOCKED'));`;
  assert.match(ns('client', 'node', '-e', blocked), /BLOCKED/); step('standalone-crash-guard-persists');
  client = child('client', '/usr/local/bin/native-runtime', ['/config/client.json'], 'client-restarted');
  await wait(() => health('client')); assert.match(ns('client', 'node', '-e', httpsProbe), /HTTPS_OK/); step('same-namespace-crash-restart');
  await stop(client); assert.equal(client.p.exitCode, 0); step('standalone-graceful-stop');
  // CLOCK_REALTIME changes are confined to this NIC-less guest. No shared
  // host clock, no disabling certificate date checks, no unauthenticated time.
  const correctEpoch = Date.now(), monotonic = performance.now();
  for (const [label, epoch] of [['past', Date.UTC(2017, 7, 4)], ['expired', correctEpoch + 3 * 86400000]]) {
    try {
      run('date', ['-u', '-s', '@' + Math.floor(epoch / 1000)]);
      const bad = child('client', '/usr/local/bin/native-runtime', ['/config/client.json'], 'clock-' + label);
      const expected = label === 'past' ? 'tls_verify_not_yet_valid' : 'tls_verify_expired';
      await wait(() => assert.ok(fs.readFileSync(bad.stdout, 'utf8').includes(`"state":"${expected}"`), expected));
      let failed; try { health('client'); } catch (e) { failed = e; }
      assert.equal(failed?.status, 1); assert.match(String(failed.stderr), /NATIVE_HEALTH=unhealthy/);
      assert.match(ns('client', 'node', '-e', blocked), /BLOCKED/);
      await stop(bad); step('clock-' + label + '-certificate-fails-closed');
    } finally { run('date', ['-u', '-s', '@' + Math.floor((correctEpoch + performance.now() - monotonic) / 1000)]); }
    const restored = child('client', '/usr/local/bin/native-runtime', ['/config/client.json'], 'clock-restored-' + label);
    await wait(() => health('client')); await stop(restored); step('clock-' + label + '-restored-with-verification');
  }
  await stop(capture);
  report.wire = inspectPcap(fs.readFileSync(capture.stdout), { destination: '10.77.0.2', profile: JSON.parse(fs.readFileSync('/config/profile.json')) });
  assert.ok(report.wire.connections.length >= 2 && report.wire.connections.every(c => c.profile?.status === 'matched'));
  report.capture = fs.readFileSync(capture.stderr, 'utf8'); assert.match(report.capture, /\b0 packets dropped by kernel\b/); step('standalone-independent-profile-match');
  console.log('RUNTIME_VM_PCAP=' + fs.readFileSync(capture.stdout).toString('base64'));
  await stop(exit); assert.equal(exit.p.exitCode, 0); report.status = 'passed';
} finally {
  for (const p of children) if (p.exitCode === null && p.signalCode === null) p.kill('SIGKILL');
  await delay(200);
  for (const name of namespaces.reverse()) ip('netns', 'del', name);
  if (namespaces.length) ip('link', 'del', 'br0');
  console.log('RUNTIME_VM_REPORT=' + JSON.stringify(report));
}
