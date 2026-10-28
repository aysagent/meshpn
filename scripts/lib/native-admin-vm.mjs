// Real broker/frontend/systemd/native TLS, only in the NIC-less marked guest.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {atomic, readJson} from '../../admin/lib/common.mjs';
import {checkUsbProxy} from '../../admin/test/usb-proxy-fixture.mjs';
import {fixtureFetch as fetch} from '../../admin/test/http-fixture.mjs';
const containerFixture = process.argv[2] === '--container-fixture';
if (containerFixture) {
  assert.equal(fs.readFileSync('/run/systemd/container', 'utf8').trim(), 'podman');
  assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab', 'utf8'), 'isolated-admin-lab-v1\n');
} else {
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /\bmeshpn.native-admin=1\b/);
}
assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
const run = (file, args) => execFileSync(file, args, {encoding: 'utf8', timeout: 90000, maxBuffer: 1024 * 1024}).trim();
const ctl = (...args) => run('/usr/bin/systemctl', args);
const prop = (unit, name) => ctl('show', unit, '-p', name, '--value');
const netCommand = args => containerFixture && args[0] === 'netns' && args[1] === 'exec' ?
  ['/usr/bin/nsenter', ['--net=/run/netns/' + args[2], '--', ...args.slice(3)]] : containerFixture && args[0] === '-n' ?
  ['/usr/bin/nsenter', ['--net=/run/netns/' + args[1], '--', '/usr/bin/ip', ...args.slice(2)]] : ['/usr/bin/ip', args];
const ip = (...args) => run(...netCommand(args));
const check = name => console.log('NATIVE_ADMIN_' + name + '_PASS');
const state = '/var/lib/admin-broker', webState = containerFixture ? '/shared/web' : '/var/lib/admin-web';
const brokerSocket = containerFixture ? '/shared/socket/broker.sock' : '/run/meshpn-admin/broker.sock';
let cookie, csrf, origin, passed = false;
async function request(route, data, authenticated = true) {
  const res = await fetch('http://127.0.0.1:8080/api/' + route, {method: data ? 'POST' : 'GET',
    timeoutMs:10000, headers: {host: 'mpn.local', origin: 'http://mpn.local',
      ...(data ? {'content-type': 'application/json'} : {}),
      ...(authenticated ? {cookie, 'x-csrf-token': csrf} : {})}, body: data ? JSON.stringify(data) : undefined});
  const value = await res.json();
  if(res.status===401)throw Object.assign(Error('login_required'),{status:401});
  assert.equal(res.status, 200, JSON.stringify(value));
  return {value, res};
}
async function wait(fn, timeout = 45000) {
  const until = performance.now() + timeout; let last;
  while (performance.now() < until) {try {const result = await fn(); if (result) return result;} catch (e) {last = e;} await delay(150);}
  throw Error('wait_timeout: ' + (last?.message ?? 'condition false') + ' ' + (last?.cause?.message ?? ''));
}
async function job(route, payload) {
  const {value: started} = await request(route, payload);
  return wait(async () => {const {value} = await request('status'); const j = value.jobs.find(j => j.id === started.id); return j && j.status !== 'running' ? j : false;});
}
const probe = () => assert.match(ip('netns', 'exec', 'nc2', '/native/socket-test', 'probe'), /NATIVE_TUN_PROBE_PASS/);
try {
  ip('link', 'set', 'lo', 'up');
  ctl('start', 'native-lab-network.service', 'native-lab-guard.service');
  for (const last of [2, 3]) for (const dns of ['1.1.1.1', '8.8.8.8']) ip('-n', 'nc' + last, 'route', 'add', dns + '/32', 'dev', 'tun0');
  origin = spawn(...netCommand(['netns', 'exec', 'nexit', '/native/socket-test', 'serve']), {stdio: 'ignore'});
  ctl('start', 'native-exit.service', 'native-c2.service');
  fs.mkdirSync('/var/lib', {recursive: true, mode: 0o755});
  fs.mkdirSync(state + '/profiles', {recursive: true, mode: 0o700});
  fs.mkdirSync(webState, {recursive: true, mode: 0o700}); fs.chownSync(webState, 65534, 65534);
  fs.mkdirSync('/run/meshpn-admin', {mode: 0o755});
  fs.copyFileSync('/native/profile.json', state + '/profiles/chromium.json');
  atomic('/native/admin-broker.json', {version: 1, usbAddress: '192.168.7.1', usbInterface: 'usb0', wifiInterface: 'wlan0',
    vpnUnit: 'native-c2.service', guardUnit: 'native-lab-guard.service', guardScript: '/native/admin-guard.sh',
    state, profiles: state + '/profiles', engine: '/native/clean-vpn-engine', vpnConfig: '/native/c2.json',
    socket: brokerSocket, nativeManaged: true, publishMdns: false});
  atomic(containerFixture ? '/shared/web.json' : '/native/admin-web.json', {version: 1, address: '127.0.0.1', subnet: '127.0.0.0/8',
    publicAddress: '192.168.7.1', publicPort: 80, publicCapturePort: 8443, port: 8080, capturePort: 18443,
    container: true, loopbackProxy: true, state: webState, brokerSocket}, 0o644);
  ctl('start', 'meshpn-admin-broker.service', ...(containerFixture ? [] : ['meshpn-admin-web.service']));
  await wait(async () => (await fetch('http://127.0.0.1:8080/', {headers: {host: 'mpn.local'}})).status === 200);
  if (containerFixture) checkUsbProxy();
  let login = await request('login', {password: 'admin'}, false);
  cookie = login.res.headers.get('set-cookie').split(';')[0]; csrf = login.value.csrf;
  await request('password', {oldPassword: 'admin', newPassword: 'disposable lab password'});
  login = await request('login', {password: 'disposable lab password'}, false);
  cookie = login.res.headers.get('set-cookie').split(';')[0]; csrf = login.value.csrf;
  if (!containerFixture) assert.equal(prop('meshpn-admin-web.service', 'User'), '65534'); check('AUTH');
  probe(); assert.match(ip('netns', 'exec', 'nc2', '/native/socket-test', 'dns', '10.99.0.2', '1053'), /DNS TCP PASS/); check('REAL_NATIVE_DATA');
  const payload = {address: '154.62.226.216', port: 443, serverName: 'localhost', sni: 'localhost', profile: 'chromium.json'};
  const oldPid = prop('native-c2.service', 'MainPID');
  const applied = await job('vpn/settings', payload); assert.equal(applied.status, 'passed', JSON.stringify(applied));
  assert.equal(applied.result.applied, true); assert.notEqual(prop('native-c2.service', 'MainPID'), oldPid); probe(); check('SETTINGS_APPLY');
  const baseline = fs.readFileSync('/native/c2.json', 'utf8');
  const rejected = await job('vpn/settings', {...payload, serverName: 'wrong.invalid'});
  assert.equal(rejected.error, 'vpn_apply_failed_rolled_back', JSON.stringify(rejected));
  assert.equal(fs.readFileSync('/native/c2.json', 'utf8'), baseline); probe(); check('TLS_FAILURE_ROLLBACK');
  assert.equal((await job('vpn/action', {action: 'stop'})).status, 'passed');
  const stopped = await job('vpn/settings', {...payload, profile: null});
  assert.equal(stopped.result.requiresStart, true); assert.equal(prop('native-c2.service', 'MainPID'), '0');
  assert.equal((await job('vpn/action', {action: 'start'})).status, 'passed'); probe(); check('STOPPED_STAYS_STOPPED');
  // Hold a genuine TLS failure during restart, kill broker while its durable
  // journal exists. systemd restarts broker; startup recovery must restore data.
  const preCrash = fs.readFileSync('/native/c2.json', 'utf8');
  await request('vpn/settings', {...payload, serverName: 'wrong.invalid'});
  await wait(() => fs.existsSync(state + '/vpn-settings-transaction.json') && readJson('/native/c2.json').server_name === 'wrong.invalid');
  const brokerPid = prop('meshpn-admin-broker.service', 'MainPID');
  ctl('kill', '--kill-whom=main', '--signal=SIGKILL', 'meshpn-admin-broker.service');
  await wait(async () => {
    if(prop('meshpn-admin-broker.service','MainPID')===brokerPid||fs.existsSync(state+'/vpn-settings-transaction.json'))return false;
    // A standalone frontend may also restart with its Requires= broker. Its
    // in-memory sessions must be revoked; authenticate again after that restart.
    try{return (await request('status')).value.vpnSettingsRecovery.status==='rolled-back';}
    catch(e){if(e.status!==401)throw e;const login=await request('login',{password:'disposable lab password'},false);
      cookie=login.res.headers.get('set-cookie').split(';')[0];csrf=login.value.csrf;return false;}
  });
  assert.equal(fs.readFileSync('/native/c2.json', 'utf8'), preCrash); probe(); check('BROKER_CRASH_ROLLBACK');
  assert.match(ip('netns', 'exec', 'nc2', 'iptables', '-S', 'OUTPUT'), /-P OUTPUT DROP/);
  assert.match(ip('netns', 'exec', 'nc2', 'ip6tables', '-S', 'OUTPUT'), /-P OUTPUT DROP/); check('GUARD_REMAINS');
  ctl('stop', 'meshpn-admin-web.service', 'meshpn-admin-broker.service', 'native-c2.service', 'native-exit.service');
  for (const u of ['meshpn-admin-web.service','meshpn-admin-broker.service','native-c2.service','native-exit.service']) assert.equal(prop(u, 'MainPID'), '0');
  check('CLEANUP'); passed = true; console.log('NATIVE_ADMIN_LAB_OK');
} catch (e) {
  console.log('NATIVE_ADMIN_LAB_FAILED ' + e.stack);
  for(const args of [['show','meshpn-admin-broker.service','meshpn-admin-web.service','-p','ActiveState','-p','MainPID'],['status','meshpn-admin-web.service','--no-pager']])try{console.log(ctl(...args));}catch{}
  try{console.log(run('/usr/bin/ss',['-lntp']));console.log(run('/usr/sbin/iptables',['-S']));}catch{}
  for (const file of ['/run/admin-broker.log','/run/admin-web.log']) if (fs.existsSync(file)) console.log(file+'\n'+fs.readFileSync(file,'utf8').slice(-12000));
  console.log(run('/usr/bin/journalctl', ['--no-pager', '-n', '100', '-u', 'meshpn-admin-broker', '-u', 'meshpn-admin-web', '-u', 'native-c2', '-u', 'native-lab-network', '-u', 'native-lab-guard']));
} finally {
  origin?.kill();
  if (containerFixture) {atomic('/shared/result.json', {passed}); process.exitCode = passed ? 0 : 1;}
  else {run('/bin/busybox', ['sync']); run('/bin/busybox', ['poweroff', '-f']);}
}
