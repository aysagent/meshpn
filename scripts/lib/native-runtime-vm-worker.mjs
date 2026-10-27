// ONLY the NIC-less disposable QEMU guest. Never run on a physical host.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { inspectPcap } from '../clean-vpn-pcap-fingerprints.mjs';
import { prepareHostWiring, checkHostWiring } from './native-runtime-host-wiring-vm.mjs';
import { runtimeEngineUnit } from './native-runtime-units.mjs';
assert.ok(fs.readFileSync('/proc/cmdline', 'utf8').split(/\s+/).includes('meshpn.runtime-vm=1'));
const hostWiring=fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-host-wiring=1');
const reboot=fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.runtime-reboot=1');
assert.equal(process.arch, 'x64');
const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
const ip = (...args) => run('ip', args), ns = (name, ...args) => ip('netns', 'exec', name, ...args);
const parent = fs.readlinkSync('/proc/self/ns/net'), children = [], namespaces = [], checks = [];
process.env.CVPN_PARENT_NETNS=parent;
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
const wait = async fn => { let last; for (let i = 0; i < 80; i++) { try { return fn(); } catch (e) { last = e; await delay(250); } } throw last; };
const health = name => ns(name, ...env(name), 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
const step = label => { checks.push(label); console.log('RUNTIME_VM_STEP=' + label); };
let report = { schema: 1, kind: 'native-runtime-standalone-vm', checks, status: 'failed',bootId:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim() };
if(reboot){assert.match(fs.readFileSync('/proc/mounts','utf8'),/^\/dev\/vda \/state ext4 /m);report.rebootPhase=fs.existsSync('/state/first-boot.json')?1:0;}
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
  // Exercise the public offline generator with the real production engine.
  // Origin HTTPS keeps its separate fixture certificate above.
  if(reboot&&report.rebootPhase===1){
    assert.notEqual(JSON.parse(fs.readFileSync('/state/first-boot.json')).bootId,report.bootId);
    fs.cpSync('/state/bundle','/bundle',{recursive:true});step('reboot-persistent-credentials-new-kernel-boot');
  }else run('node', ['/project/scripts/clean-vpn-native-runtime-config.mjs', 'create', '--directory=/bundle', '--mode=standalone',
    '--endpoint=10.77.0.2', '--exit-address=10.77.0.2', '--server-name=runtime.test', '--clients=2', '--days=2']);
  report.bundleFingerprint=createHash('sha256').update(fs.readFileSync('/bundle/manifest.json')).update(fs.readFileSync('/bundle/client-1/ca.pem')).update(fs.readFileSync('/bundle/exit/cert.pem')).digest('hex');
  for(const role of ['exit','client-1','client-2'])run('/usr/local/bin/clean-vpn-engine',['--check-config',`/bundle/${role}/engine.json`]);
  for(const role of ['exit','client-1']){
    const diagnostic=run('node',['/project/scripts/clean-vpn-native-runtime-preflight.mjs','--binary=/usr/local/bin/clean-vpn-engine',`--config=/bundle/${role}/engine.json`]);
    assert.match(diagnostic,/"status": "offline-checks-passed"/);assert.match(diagnostic,/"dnsQueriesSent": 0/);
  }
  step('single-readonly-runtime-report-client-and-exit');
  fs.copyFileSync('/bundle/client-1/engine.json','/config/client.json');fs.copyFileSync('/bundle/exit/engine.json','/config/exit.json');
  step('generated-standalone-bundle-two-distinct-peers-native-validation');
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
  if(hostWiring)await prepareHostWiring({ip,ns,namespaces});
  ns('exit', 'sysctl', '-w', 'net.ipv4.ip_forward=1'); ns('exit', 'ip', 'route', 'add', '198.18.0.80/32', 'via', '10.77.0.4');
  const origin = child('origin', 'env', ['CVPN_DNS_TRACE=1','node','/project/scripts/lib/native-runtime-lab-origin.mjs'], 'origin');
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
  if(hostWiring)client=await checkHostWiring({ns,child,wait,health,step,client,origin,
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
  if(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd'){
    const ctl=(...a)=>run('systemctl',a).trim(), unit='cvpn-runtime-client.service';
    fs.writeFileSync('/etc/systemd/system/'+unit,runtimeEngineUnit({namespace:'client',parent,scripts:'/opt/clean-vpn',node:'/usr/local/bin/node',
      config:'/config/client.json',engine:'/usr/local/bin/clean-vpn-engine',instance:'client',lanSubnet:'192.168.88.0/24'})
      .replace('[Unit]\n','[Unit]\nDefaultDependencies=no\n')+'StandardOutput=append:/run/client-systemd.log\nStandardError=append:/run/client-systemd.log\n');
    ctl('daemon-reload');ctl('start',unit);await wait(()=>health('client'));
    assert.match(ns('client','node','-e',httpsProbe),/HTTPS_OK/);step('standalone-rendered-systemd-unit-notify-and-dns');
    const pid=ctl('show',unit,'-p','MainPID','--value');assert.match(fs.readlinkSync('/proc/'+pid+'/exe'),/clean-vpn-engine$/);
    ctl('kill','--kill-whom=main','--signal=SIGKILL',unit);await wait(()=>{assert.notEqual(ctl('show',unit,'-p','MainPID','--value'),pid);health('client');});
    step('standalone-systemd-engine-sigkill-restart');ctl('stop',unit);
    assert.match(ns('client','node','-e',blocked),/BLOCKED/);step('standalone-systemd-stop-retains-namespace-guard');
    fs.unlinkSync('/etc/systemd/system/'+unit);ctl('daemon-reload');
  }
  await stop(capture);
  report.wire = inspectPcap(fs.readFileSync(capture.stdout), { destination: '10.77.0.2', profile: JSON.parse(fs.readFileSync('/config/profile.json')) });
  assert.ok(report.wire.connections.length >= 2 && report.wire.connections.every(c => c.profile?.status === 'matched'));
  report.capture = fs.readFileSync(capture.stderr, 'utf8'); assert.match(report.capture, /\b0 packets dropped by kernel\b/); step('standalone-independent-profile-match');
  console.log('RUNTIME_VM_PCAP=' + fs.readFileSync(capture.stdout).toString('base64'));
  await stop(exit); assert.equal(exit.p.exitCode, 0); report.status = 'passed';
  if(reboot&&report.rebootPhase===0){
    fs.cpSync('/bundle','/state/bundle',{recursive:true});fs.writeFileSync('/state/first-boot.json',JSON.stringify({bootId:report.bootId,bundleFingerprint:report.bundleFingerprint}),{mode:0o600});
    fs.writeFileSync('/state/request-reboot','1',{mode:0o600});run('sync',[]);
  }
} finally {
  if(report.status!=='passed')for(const file of ['origin.log','gateway-dnsmasq.stderr','gateway-dnsmasq-native.stderr','host-wiring.stderr','gateway-systemd.log','client-systemd.log','client.log']){
    if(fs.existsSync('/run/'+file))console.log('RUNTIME_FAILURE_LOG='+file+'\n'+fs.readFileSync('/run/'+file,'utf8').slice(-8000));
  }
  for (const p of children) if (p.exitCode === null && p.signalCode === null) p.kill('SIGKILL');
  await delay(200);
  for (const name of namespaces.reverse()) ip('netns', 'del', name);
  if (namespaces.length) ip('link', 'del', 'br0');
  console.log('RUNTIME_VM_REPORT=' + JSON.stringify(report));
}
