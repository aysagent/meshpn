import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startCrashCapture, exerciseCrashPeer, recoverCrashNetwork } from './lib/native-trial-crash.mjs';
import { NativeEngineController } from './lib/native-engine-controller.mjs';
import { launchTrialNative } from './clean-vpn-native-trial.mjs';

function child() {
  return Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
}
for (const allowed of [false, true]) test(`SIGKILL targets owned native child only; opt-in=${allowed}`, () => {
  const c = child(), signals = []; c.kill = s => { signals.push(s); return true; };
  const ctl = new NativeEngineController({ binary: '/engine', config: '/config', allowTrialCrash: allowed, spawnChild: () => c });
  if (allowed) { ctl.crashForTrial(); assert.deepEqual(signals, ['SIGKILL']); }
  else { assert.throws(() => ctl.crashForTrial(), /not_allowed/); assert.deepEqual(signals, []); }
  assert.equal(c.stdin.read(), null, 'not a graceful stop command');
  c.emit('close', null, 'SIGKILL');
  assert.throws(() => ctl.crashForTrial(), /not_allowed/);
});
for (const kind of ['sigkill', 'graceful', 'unrelated-signal']) test(`trial verifies actual engine SIGKILL (${kind})`, async () => {
  const s = launchTrialNative('/unused', { trialCrash: true, spawnChild: (file, args, opts) => {
    assert.ok(args.includes('--trial-crash'));
    return spawn(process.execPath, ['-e', `process.stdin.on('data', b => {
      if (b.toString().includes('trial_crash')) {
        console.error('native-control: engine exited code=${kind === 'graceful' ? '0 signal=null' : 'null signal=' + (kind === 'sigkill' ? 'SIGKILL' : 'SIGTERM')}');
        process.exit(${kind === 'graceful' ? 0 : 1});
      }
    });`], opts);
  } });
  if (kind === 'sigkill') await s.crash();
  else await assert.rejects(s.crash(), /native_crash_not_verified/);
  assert.equal(s.crashRequested(), true); await s.stop();
});
for (const problem of [null, 'direct', 'dropped', 'no-positive', 'bad-line', 'early-exit', 'missing-stats']) {
  test(`capture cannot report a false negative (${problem})`, async () => {
    const c = child();
    const capture = startCrashCapture({ spawnChild: (file, args) => {
      assert.equal(file, 'tcpdump'); assert.ok(args.includes('out')); assert.ok(args.includes('wlan0'));
      assert.ok(!args.includes('-w') && !args.includes('-A') && !args.includes('-X'));
      return c;
    } });
    c.kill = () => {
      if (problem !== 'missing-stats') c.stderr.write(`${problem === 'direct' ? 2 : problem === 'no-positive' ? 0 : 1} packets captured\n${problem === 'dropped' ? 1 : 0} packets dropped by kernel\n`);
      c.emit('close', 0, null); return true;
    };
    c.stderr.write('tcpdump: listening on wlan0, link-type EN10MB\n');
    await capture.ready();
    if (problem !== 'no-positive') c.stdout.write('1790000000.123456 IP 192.168.1.2.4567 > 154.62.226.216.443: Flags [P.], length 123\n');
    if (problem === 'direct') c.stdout.write('1790000000.123457 IP 192.168.7.19.4568 > 1.1.1.1.443: Flags [S], length 0\n');
    if (problem === 'bad-line') c.stdout.write('PRIVATE unexpected input\n');
    if (problem === 'early-exit') c.emit('close', 0, null);
    const result = await capture.stop();
    assert.equal(result.status, problem ? 'failed' : 'passed');
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE|192\.168|4567/);
  });
}
for (const failure of [null, 'native', 'crash', 'release', 'blocked', 'uplink', 'capture']) {
  test(`crash workflow stops capture and never toggles wlan (${failure})`, async () => {
    const calls = [], report = { phases: {} };
    const event = async n => { calls.push(n); if (n === failure) throw Error('injected'); };
    const capture = { ready: () => event('capture'), healthy: () => true,
      stop: async () => { calls.push('capture-stop'); return { status: 'passed' }; } };
    const session = { healthy: () => true, diagnostics: () => ({ stateCounts: {} }), crash: () => event('crash') };
    const work = exerciseCrashPeer({ phase: n => event(n) }, session, report,
      { capture: () => capture, release: () => event('release'), requireUplink: () => event('uplink') });
    if (failure) await assert.rejects(work); else await work;
    assert.equal(calls.at(-1), 'capture-stop');
    if (!failure) assert.deepEqual(calls, ['capture', 'native', 'uplink', 'crash', 'release', 'uplink', 'blocked', 'uplink', 'capture-stop']);
  });
}
for (const failure of [null, 'guard', 'inactive', 'identity', 'remove', 'host-audit', 'dns-audit']) {
  test(`crash recovery refuses foreign state before applying journal recovery (${failure})`, async () => {
    const calls = [];
    const event = n => { calls.push(n); if (n === failure) throw Error('injected'); };
    const host = { state: { tun: 'tun0', links: { tun0: { ifindex: failure === 'identity' ? 99 : 17 } } },
      audit: () => event('host-audit'), restore: () => event('host-restore'), release: () => event('host-unlock') };
    const dns = { state: { config: { tun: 'tun0' }, links: { tun0: { ifindex: 17 } } },
      restore: o => event(o?.apply === false ? 'dns-audit' : 'dns-restore'), release: () => event('dns-unlock') };
    const work = recoverCrashNetwork(17, { guard: () => event('guard'), inactive: () => event('inactive'),
      openHost: () => host, openDns: () => dns, removeTun: n => { assert.equal(n, 17); event('remove'); } });
    if (failure) { await assert.rejects(work); assert.ok(!calls.includes('host-restore') && !calls.includes('dns-restore')); }
    else { await work; assert.deepEqual(calls, ['guard', 'inactive', 'remove', 'host-audit', 'dns-audit', 'dns-restore', 'host-restore', 'guard', 'dns-unlock', 'host-unlock']); }
  });
}

test('real tcpdump parses outbound packets in isolated user/net namespace, no host networking', { timeout: 15000 }, t => {
  if (spawnSync('unshare', ['-Urn', 'true']).status !== 0) return t.skip('unprivileged netns unavailable');
  const url = new URL('./lib/native-trial-crash.mjs', import.meta.url).href;
  const result = spawnSync('unshare', ['-Urn', process.execPath, '--input-type=module', '-e', `
    import { execFileSync, spawn } from 'node:child_process';
    import net from 'node:net';
    import { setTimeout as delay } from 'node:timers/promises';
    import { startCrashCapture } from ${JSON.stringify(url)};
    const ip = (...a) => execFileSync('ip', a);
    ip('link','add','wlan0','type','dummy'); ip('link','set','wlan0','up');
    ip('addr','add','192.168.1.2/24','dev','wlan0'); ip('link','set','wlan0','arp','off');
    ip('route','add','default','dev','wlan0');
    const c = startCrashCapture({ spawnChild: (f,a,o) => spawn(f,['-Z','root',...a],o) });
    await c.ready();
    const sockets = ['154.62.226.216','1.1.1.1'].map(host => net.connect({host,port:443}));
    for (const s of sockets) s.on('error', () => {});
    await delay(500); for (const s of sockets) s.destroy();
    const r = await c.stop(); console.log(JSON.stringify(r));
    if (!r.complete || r.directPackets < 1 || r.encryptedExitPackets < 1 || r.status !== 'failed') process.exitCode = 1;
  `], { encoding: 'utf8', timeout: 12000 });
  assert.equal(result.status, 0, result.stderr + result.stdout);
});

test('real host route journal recovery in netns preserves independent guard (DNS adapter fixture)', { timeout: 60000 }, t => {
  if (spawnSync('unshare', ['-Urn', 'true']).status !== 0) return t.skip('unprivileged netns unavailable');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-crash-journals-'));
  t.after(() => fs.rmSync(dir, { recursive: true }));
  const result = spawnSync('unshare', ['-Urn', process.execPath, '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { execFileSync } from 'node:child_process';
    import { openHostRoutes } from ${JSON.stringify(new URL('./lib/vpn-host-routes.mjs', import.meta.url).href)};
    import { recoverCrashNetwork } from ${JSON.stringify(new URL('./lib/native-trial-crash.mjs', import.meta.url).href)};
    const run = (f,a) => execFileSync(f,a,{encoding:'utf8',timeout:5000});
    const ip = (...a) => run('ip',a);
    for (const [name,addr] of [['wlan0','192.168.1.2/24'],['usb0','192.168.7.1/24'],['tun0','10.99.0.2/30']]) {
      ip('link','add',name,'type','dummy'); ip('link','set',name,'up'); ip('addr','add',addr,'dev',name);
    }
    ip('route','add','default','via','192.168.1.1','dev','wlan0');
    run('sysctl',['-w','net.ipv4.ip_forward=1']);
    run('iptables',['-A','FORWARD','-m','comment','--comment','independent-test-guard','-j','DROP']);
    const index = JSON.parse(ip('-j','link','show','tun0'))[0].ifindex;
    const openHost = () => openHostRoutes({directory:${JSON.stringify(dir + '/host')},run});
    // DNS journal's trusted-ancestor check correctly rejects an unmapped
    // host-owned / in this user namespace. Its actual implementation has a
    // separate filesystem/command-model suite; don't weaken it for this test.
    let dnsRestored = false;
    const openDns = () => ({state:{config:{tun:'tun0'},links:{tun0:{ifindex:index}}},
      restore:o=>{if(o?.apply!==false)dnsRestored=true;},release:()=>{}});
    const host = openHost();
    host.begin('tun0'); host.relaxRpFilter();
    host.add('154.62.226.216/32','wlan0','192.168.1.1');
    host.add('0.0.0.0/1','tun0'); host.add('128.0.0.0/1','tun0');
    host.release();
    const guard = () => assert.match(run('iptables',['-S','FORWARD']),/independent-test-guard.*-j DROP/);
    await recoverCrashNetwork(index,{guard,inactive:async()=>{},openHost,openDns,removeTun:async n=>{
      assert.equal(JSON.parse(ip('-j','link','show','tun0'))[0].ifindex,n); ip('link','del','tun0');
    }});
    const h = openHost();
    assert.equal(h.state.stage,'released'); assert.equal(dnsRestored,true);
    h.audit(); h.release(); guard();
    assert.equal(JSON.parse(ip('-j','route','get','1.1.1.1','from','192.168.7.19','iif','usb0'))[0].dev,'wlan0');
    console.log('owned-journal-recovery-pass');
  `], { encoding: 'utf8', timeout: 55000 });
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, /owned-journal-recovery-pass/);
});
