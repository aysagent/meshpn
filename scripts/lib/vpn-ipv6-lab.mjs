/** Destructive only inside a fresh network+mount+PID namespace; no external NIC. */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import https from 'node:https';
import dgram from 'node:dgram';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { runHostResilienceChecks } from './vpn-host-resilience-lab.mjs';
import { runHostJointChecks } from './vpn-host-joint-lab.mjs';
const run = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const ip = (...args) => run('ip', args);
const at = (ns, file, ...args) => ip('netns', 'exec', ns, file, ...args);

export async function runIpv6Lab(directory, { resilience = false, joint = false } = {}) {
  assertBrowserNamespace(); assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(l => l.ifname), ['lo']);
  run('mount', ['--make-rprivate', '/']); run('mount', ['-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run']); ip('link', 'set', 'lo', 'up');
  run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  const children = [], servers = [], checks = [];
  const check = (name, actual, expected) => { assert.deepEqual(actual, expected, name); checks.push(name); console.error(`IPV6_CHECK ${name}`); };
  async function start(ns, args, env = {}) {
    const p = spawn('ip', ['netns', 'exec', ns, process.execPath, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    p.log = ''; p.stdoutText = '';
    p.stdout.on('data', b => { p.log += b; p.stdoutText += b; });
    p.stderr.on('data', b => p.log += b); children.push(p); return p;
  }
  async function wait(p, text) {
    const end = Date.now() + 90000;
    while (!p.log.includes(text)) { if (p.exitCode !== null || Date.now() > end) throw Error(`waiting ${text}: ${p.log}`); await delay(100); }
  }
  async function stop(p, signal = 'SIGINT') {
    if (p.exitCode !== null || p.signalCode !== null) return;
    const done = once(p, 'exit'); p.kill(signal);
    const timer = setTimeout(() => p.kill('SIGKILL'), 90000);
    try { await done; } finally { clearTimeout(timer); }
    if (signal === 'SIGINT') assert.equal(p.exitCode, 0, p.log);
  }
  const query = async (host, udp = false) => {
    const p = await start('client', ['-e', `
      const host=${JSON.stringify(host)}, ca=require('fs').readFileSync(${JSON.stringify(directory + '/fullchain.pem')});
      const timer=setTimeout(()=>{console.log('BLOCKED');process.exit(0)},5000);
      ${udp ? `const s=require('dgram').createSocket('udp6');s.on('error',()=>{clearTimeout(timer);console.log('BLOCKED');s.close()});s.on('message',b=>{clearTimeout(timer);console.log(b.toString());s.close()});s.send(Buffer.from('probe'),18444,host);` : `
      const q=require('https').get({host,port:18443,servername:'origin.test',ca,agent:false},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{clearTimeout(timer);console.log(b.length>1024?'LARGE:'+b.length:b)})});
      q.on('error',()=>{clearTimeout(timer);console.log('BLOCKED')});`}
    `]);
    await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return p.log.trim();
  };
  const audit = () => JSON.parse(at('client', process.execPath, 'scripts/clean-vpn-ipv6-recover.mjs'));
  // Controlled dual-stack lookup: exercise Node's own address-family fallback,
  // not a test-written retry or a forced IPv4 connection. No external DNS.
  const dualStackQuery = async (origin) => {
    const p = await start('client', ['-e', `
      const assert=require('node:assert/strict');
      const timer=setTimeout(()=>{console.error('fallback deadline');process.exit(1)},5000);
      const socket=require('net').connect({host:'origin.test',port:18443,
        autoSelectFamily:true,autoSelectFamilyAttemptTimeout:250,
        lookup(host,options,cb){assert.equal(options.all,true);cb(null,[
          {address:${JSON.stringify(origin)},family:6},{address:'1.0.0.1',family:4}]);}});
      socket.on('error',e=>{console.error(e);process.exit(1)});
      socket.on('connect',()=>{
        assert.deepEqual(socket.autoSelectFamilyAttemptedAddresses,[${JSON.stringify(origin + ':18443')},'1.0.0.1:18443']);
        assert.equal(socket.remoteFamily,'IPv4');
        const tls=require('tls').connect({socket,servername:'origin.test',
          ca:require('fs').readFileSync(${JSON.stringify(directory + '/fullchain.pem')})},()=>{
          assert.equal(tls.authorized,true);
          tls.write('GET / HTTP/1.1\\r\\nHost: origin.test\\r\\nConnection: close\\r\\n\\r\\n');
        });
        let body='';tls.on('data',b=>body+=b);
        tls.on('error',e=>{console.error(e);process.exit(1)});
        tls.on('end',()=>{clearTimeout(timer);assert.match(body,/^HTTP\\/1\\.1 200 /);
          assert.ok(body.endsWith('198.51.100.2'));console.log('IPv6 attempted; IPv4 HTTPS via exit');});
      });
    `]);
    await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return p.log.trim();
  };
  try {
    for (const [ns, v4, v6] of [['client', '192.0.2', '2001:db8:1'], ['exit', '198.51.100', '2001:db8:2']]) {
      ip('netns', 'add', ns); ip('link', 'add', `${ns}0`, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', ns);
      ip('addr', 'add', `${v4}.1/24`, 'dev', `${ns}0`); ip('link', 'set', `${ns}0`, 'up');
      ip('-6', 'addr', 'add', `${v6}::1/64`, 'dev', `${ns}0`, 'nodad');
      at(ns, 'ip', 'link', 'set', 'lo', 'up'); at(ns, 'ip', 'link', 'set', 'eth0', 'up');
      at(ns, 'ip', 'addr', 'add', `${v4}.2/24`, 'dev', 'eth0'); at(ns, 'ip', 'route', 'add', 'default', 'via', `${v4}.1`);
      at(ns, 'ip', '-6', 'addr', 'add', `${v6}::2/64`, 'dev', 'eth0', 'nodad'); at(ns, 'ip', '-6', 'route', 'add', 'default', 'via', `${v6}::1`);
    }
    const origin = '2606:4700:4700::1111'; ip('-6', 'addr', 'add', `${origin}/128`, 'dev', 'lo', 'nodad'); ip('addr', 'add', '1.0.0.1/32', 'dev', 'lo');
    at('exit', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1');
    run('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1', '-subj', '/CN=vpn.test',
      '-addext', 'subjectAltName=DNS:vpn.test,DNS:origin.test', '-keyout', directory + '/privkey.pem', '-out', directory + '/fullchain.pem']);
    run('openssl', ['rand', '-out', directory + '/secret.key', '32']);
    let large = false;
    for (const address of [origin, '1.0.0.1']) {
      const s = https.createServer({ key: readFileSync(directory + '/privkey.pem'), cert: readFileSync(directory + '/fullchain.pem') }, (q, r) => r.end(large ? 'x'.repeat(131072) : q.socket.remoteAddress));
      servers.push(s); s.listen(18443, address); await once(s, 'listening');
    }
    const udp = dgram.createSocket('udp6'); udp.on('message', (b, peer) => udp.send(Buffer.from(peer.address), peer.port, peer.address)); udp.bind(18444, origin); await once(udp, 'listening'); servers.push(udp);
    check('baseline direct IPv6', await query(origin), '2001:db8:1::2');
    const base = ['scripts/clean-vpn.js', '--type=tls', `--tls-cert-dir=${directory}`, `--shared-hmac-key=${directory}/secret.key`, '--tls-server-name=vpn.test', '--tls-public-name=vpn.test'];
    const startExit = (auto, extra = [], env = {}) => start('exit', [...base, '--role=exit', '--server=0.0.0.0:443', '--ext=eth0', ...(auto ? ['--ipv6=auto'] : []), ...extra], env);
    const startClient = (h1, extra = [], env = {}) => start('client', [...base, '--role=client', '--server=198.51.100.2:443', '--split-default', ...(joint ? [] : ['--dns-mode=off']), '--ipv6=auto', ...(h1 ? ['--http-vers=1.1'] : []), ...extra], env);
    if (!resilience && !joint) {
    let exit = await startExit(true); await wait(exit, 'exit TLS');
    for (const h1 of [false, true]) {
      const client = await startClient(h1); await wait(client, 'IPv6 client: tunnel');
      check(`${h1 ? 'h1' : 'h2'} IPv6 HTTPS NAT66`, await query(origin), '2001:db8:2::2');
      check(`${h1 ? 'h1' : 'h2'} IPv6 UDP NAT66`, await query(origin, true), '2001:db8:2::2');
      check(`${h1 ? 'h1' : 'h2'} IPv4 unchanged`, await query('1.0.0.1'), '198.51.100.2');
      large = true; check(`${h1 ? 'h1' : 'h2'} IPv6 128KiB TLS`, await query(origin), 'LARGE:131072'); large = false;
      await stop(client); check('clean stop journal released', audit().stage, 'released');
      check('clean stop direct IPv6 restored', await query(origin), '2001:db8:1::2');
    }
    await stop(exit); at('exit', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=0');
    for (const auto of [true, false]) {
      exit = await startExit(auto); await wait(exit, 'exit TLS');
      const client = await startClient(false); await wait(client, 'IPv6 client: blocked');
      check(auto ? 'no exit forwarding blocks IPv6' : 'legacy exit blocks IPv6', await query(origin), 'BLOCKED');
      check('blocked IPv6 leaves IPv4 usable', await query('1.0.0.1'), '198.51.100.2');
      await stop(client); await stop(exit);
    }
    at('exit', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1');
    // Match an IPv4-only provider: forwarding alone must not advertise IPv6.
    at('exit', 'ip', '-6', 'addr', 'del', '2001:db8:2::2/64', 'dev', 'eth0');
    for (const h1 of [false, true]) {
      exit = await startExit(true); await wait(exit, 'IPv6 exit: blocked');
      const client = await startClient(h1); await wait(client, 'IPv6 client: blocked');
      check(`${h1 ? 'h1' : 'h2'} no public exit IPv6 blocks IPv6`, await query(origin), 'BLOCKED');
      check(`${h1 ? 'h1' : 'h2'} application IPv6 to IPv4 fallback`, await dualStackQuery(origin), 'IPv6 attempted; IPv4 HTTPS via exit');
      await stop(client); check('IPv4-only exit clean stop journal released', audit().stage, 'released');
      await stop(exit);
    }
    at('exit', 'ip', '-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'eth0', 'nodad');
    exit = await startExit(true); await wait(exit, 'exit TLS');
    const client = await startClient(false); await wait(client, 'IPv6 client: tunnel');
    await stop(client, 'SIGKILL'); check('SIGKILL does not restore direct IPv6', await query(origin), 'BLOCKED');
    const collision = await startClient(false); await once(collision, 'exit'); check('stale IPv6 journal refuses restart', collision.exitCode, 1);
    const restored = JSON.parse(at('client', process.execPath, 'scripts/clean-vpn-ipv6-recover.mjs', '--apply'));
    at('client', process.execPath, 'scripts/clean-vpn-host-recover.mjs', '--apply');
    check('explicit crash recovery releases journal', restored.stage, 'released');
    check('explicit recovery restores direct IPv6', await query(origin), '2001:db8:1::2');
    await stop(exit);
    // Durable intent before mutation and interruption after installed protection.
    at('client', 'ip', 'link', 'add', 'testtun', 'type', 'dummy'); at('client', 'ip', 'link', 'set', 'testtun', 'up');
    for (const [label, count] of [['saved', 8], ['applied', 8], ['applied', 11]]) {
      const fault = await start('client', ['--input-type=module', '-e', `
        import {openIpv6Runtime} from './scripts/lib/vpn-ipv6-runtime.mjs';
        const r=openIpv6Runtime({checkpoint(label,s){if(label===${JSON.stringify(label)} && s.stage==='installing' && s.count===${count}) throw Error('injected cut');}});
        try {r.begin('client','testtun')} finally {r.release()}
      `]);
      await once(fault, 'exit'); check(`cut ${label}/${count} reached`, fault.exitCode, 1);
      assert.match(fault.log, /injected cut/);
      if (label === 'applied') check(`cut ${count} retains IPv6 guard`, await query(origin), 'BLOCKED');
      at('client', process.execPath, 'scripts/clean-vpn-ipv6-recover.mjs', '--apply');
      check(`cut ${label}/${count} recovery`, await query(origin), '2001:db8:1::2');
    }
    }
    const hostResilience = resilience ? await runHostResilienceChecks({ directory, start, wait, stop, startExit, startClient, query, check, at, ip }) : undefined;
    const hostJoint = joint ? await runHostJointChecks({ start, wait, stop, startExit, startClient, query, check, at, ip }) : undefined;
    return { status: 'passed', actualTransportTested: 'tls-ipv6', hostNetworkChanged: false, checks, hostResilience, hostJoint };
  } finally {
    for (const p of children) if (p.exitCode === null && p.signalCode === null) p.kill('SIGKILL');
    for (const s of servers) s.close();
  }
}
