/** Runs only inside runIpv6Lab's disposable namespaces / NIC-less guest. */
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { assertBrowserNamespace } from './browser-soak.mjs';

export async function runHostResilienceChecks(c) {
  assertBrowserNamespace();
  const { directory, start, wait, stop, startExit, startClient, query, check, at, ip } = c;
  const origin = '2606:4700:4700::1111', soaks = [], gaps = [], reconnects = [];
  const snapshot = p => ({ rssKiB: Number(/^VmRSS:\s+(\d+)/m.exec(readFileSync(`/proc/${p.pid}/status`, 'utf8'))[1]),
    fds: readdirSync(`/proc/${p.pid}/fd`).length });
  let received = 0;
  const s = https.createServer({ key: readFileSync(`${directory}/privkey.pem`), cert: readFileSync(`${directory}/fullchain.pem`) }, (q, r) => {
    let size = 0; const hash = createHash('sha256');
    q.on('data', b => { size += b.length; if (size > 32768) q.destroy(); else hash.update(b); });
    q.on('end', () => {
      if (size !== 32768) { r.writeHead(400); r.end(); return; }
      received++; r.setHeader('x-upload-sha256', hash.digest('hex')); r.setHeader('x-peer', q.socket.remoteAddress);
      r.end(Buffer.alloc(65536, 0x62));
    });
  });
  s.listen(19443, '1.0.0.1'); await once(s, 'listening');
  const udp = dgram.createSocket('udp4');
  udp.on('message', (b, peer) => udp.send(Buffer.from(peer.address), peer.port, peer.address));
  udp.bind(18445, '1.0.0.1'); await once(udp, 'listening');
  const udpQuery = async (v6, port) => {
    const p = await start('client', ['-e', `
      const s=require('dgram').createSocket(${JSON.stringify(v6 ? 'udp6' : 'udp4')});
      const timer=setTimeout(()=>{console.log('BLOCKED');s.close()},1500);
      s.on('error',()=>{clearTimeout(timer);console.log('BLOCKED');s.close()});
      s.on('message',b=>{clearTimeout(timer);console.log(b.toString());s.close()});
      s.bind(${port},()=>s.send(Buffer.from('synthetic probe'),${v6 ? 18444 : 18445},${JSON.stringify(v6 ? origin : '1.0.0.1')}));
    `]);
    await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return p.log.trim();
  };
  const idleCheck = async (h1, phase) => {
      const label = `${h1 ? 'h1' : 'h2'} ${phase}`;
      const debug = { CLEAN_VPN_PACKET_DEBUG: '1', CLEAN_VPN_KEEPALIVE_DEBUG: '1' };
      let idleExit = await startExit(true, ['--keep-alive=2'], debug); await wait(idleExit, 'exit TLS');
      const lazy = await startClient(h1, ['--keep-alive=2'], debug);
      // Startup includes synchronous audited IPv6 policy installation in this
      // emulated guest. Start the request deadline only after authentication.
      await wait(lazy, 'IPv6 client: tunnel');
      const initial = await query('1.0.0.1');
      if (initial !== '198.51.100.2') console.error(`IDLE_RECONNECT_LOG ${JSON.stringify({client:lazy.log,exit:idleExit.log})}`);
      check(`${label} lazy first request`, initial, '198.51.100.2');
      // A client's "отключено" can mean idle-disarm with an OPEN TCP socket.
      await wait(idleExit, 'TCP server → FIN');
      const answers = [], began = Date.now();
      for (let attempt = 0; attempt < 3; attempt++) {
        answers.push(await query('1.0.0.1'));
        if (answers.at(-1) !== 'BLOCKED') break;
      }
      if (answers.at(-1) !== '198.51.100.2') console.error(`IDLE_RECONNECT_LOG ${JSON.stringify({client:lazy.log,exit:idleExit.log})}`);
      check(`${label} idle FIN bounded reconnect`, answers.at(-1), '198.51.100.2');
      reconnects.push({ transport: h1 ? 'h1' : 'h2', phase, keepAliveSeconds: 2, answers, elapsedMs: Date.now() - began });
      console.error(`HOST_RESILIENCE_PROGRESS ${JSON.stringify({ case: 'idle-reconnect', ...reconnects.at(-1) })}`);
      if (answers[0] === 'BLOCKED') gaps.push(`${label}-first-request-after-idle-exceeded-5s`);
      check(`${label} second authenticated TLS session`, (lazy.log.match(/TLS \(VPN\) соединение установлено/g) ?? []).length >= 2, true);
      await stop(lazy); await stop(idleExit);
  };
  try {
    await auditGuard();
    for (const h1 of [false, true]) {
      const label = h1 ? 'h1' : 'h2';
      await idleCheck(h1, 'before-load');
      let exit = await startExit(true); await wait(exit, 'exit TLS');
      const client = await startClient(h1); await wait(client, 'IPv6 client: tunnel');
      check(`${label} fault baseline HTTPS`, await query('1.0.0.1'), '198.51.100.2');
      await stop(exit);
      check(`${label} exit down no IPv4 fallback`, await query('1.0.0.1'), 'BLOCKED');
      check(`${label} exit down no IPv6 fallback`, await query(origin), 'BLOCKED');
      exit = await startExit(true); await wait(exit, 'exit TLS');
      check(`${label} exit restart new HTTPS recovers`, await query('1.0.0.1'), '198.51.100.2');
      // Interrupt just the outer IPv4 TLS path; not the host network or SSH.
      const fault = ['FORWARD', '-s', '192.0.2.2', '-d', '198.51.100.2', '-p', 'tcp', '--dport', '443', '-j', 'DROP'];
      ip('netns', 'exec', 'client', 'ip', 'route', 'get', '1.0.0.1');
      const { execFileSync } = await import('node:child_process');
      const fw = action => execFileSync('iptables', ['-w', '5', action, ...fault]);
      fw('-I');
      try { check(`${label} outer TLS path blackhole no bypass`, await query('1.0.0.1'), 'BLOCKED'); }
      finally { fw('-D'); }
      let answer;
      for (let attempt = 0; attempt < 4; attempt++) { answer = await query('1.0.0.1'); if (answer !== 'BLOCKED') break; }
      check(`${label} path restored HTTPS recovers`, answer, '198.51.100.2');
      const before = snapshot(client), serverBefore = received;
      const load = await start('client', ['--input-type=module', '-e', `import {hostWorkload} from './scripts/lib/vpn-host-workload.mjs';console.log(JSON.stringify(await hostWorkload(${JSON.stringify(directory)})));`]);
      const samples = [before];
      while (load.exitCode === null && load.signalCode === null) { await delay(1000); samples.push(snapshot(client)); }
      if (load.exitCode !== 0) console.error(`HOST_RESILIENCE_PROGRESS ${JSON.stringify({ case: 'soak', transport: label,
        status: 'failed', workload: load.log, client: client.log.slice(-16000), exit: exit.log.slice(-16000) })}`);
      assert.equal(load.exitCode, 0, load.log); const result = JSON.parse(load.log);
      check(`${label} upload/download origin request accounting`, received - serverBefore, result.completed);
      await delay(6000); const after = snapshot(client);
      check(`${label} bounded daemon RSS`, Math.max(...samples.map(v => v.rssKiB), after.rssKiB) < 262144, true);
      check(`${label} daemon descriptors return near baseline`, after.fds <= before.fds + 8, true);
      soaks.push({ transport: label, ...result, daemon: { before, after, peakRssKiB: Math.max(...samples.map(v => v.rssKiB)) } });
      console.error(`HOST_RESILIENCE_PROGRESS ${JSON.stringify({ case: 'soak', status: 'passed', ...soaks.at(-1) })}`);
      await stop(client); await stop(exit);
      await idleCheck(h1, 'after-load');
    }
    async function auditGuard() {
    const ks = (...args) => at('client', 'bash', 'scripts/autostart/killswitch.sh', ...args);
    const options = ['--server=198.51.100.2', '--scope=both', '--ipv6=block', '--ssh-port=2222'];
    const ssh = await start('client', ['-e', `
      const s=require('net').createServer(c=>{c.on('error',()=>{});c.pipe(c)});
      s.listen(2222,'::',()=>console.log('READY'));
      process.on('SIGINT',()=>process.exit(0));
    `]);
    await wait(ssh, 'READY');
    const echo = socket => new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.off('data', done); reject(Error('management reply deadline')); }, 2000);
      function done(b) { clearTimeout(timer); resolve(b.toString()); }
      socket.once('data', done); socket.write('synthetic SSH reply');
    });
    const faultDir = `${directory}/guard-fault`; mkdirSync(faultDir);
    writeFileSync(`${faultDir}/iptables-restore`, `#!/bin/bash
case " $* " in
  *" --version "*|*" --test "*) exec /usr/sbin/iptables-restore "$@" ;;
esac
echo 'injected IPv4 commit failure' >&2
exit 42
`, { mode: 0o700 });
    for (const v6 of [false, true]) {
      const source = v6 ? '2001:db8:1::2' : '192.0.2.2';
      const management = net.connect({ host: source, localAddress: v6 ? origin : '1.0.0.1', port: 2222 });
      management.on('error', () => {}); await once(management, 'connect');
      check(`KS incoming TCP baseline IPv${v6 ? 6 : 4}`, await echo(management), 'synthetic SSH reply');
      // Enable tracking BEFORE the baseline flow. Without a conntrack consumer,
      // the kernel need not track packets preceding installation of the guard.
      // No verdict: this rule only loads/uses conntrack in the isolated namespace.
      const fw = v6 ? 'ip6tables' : 'iptables';
      const tracking = ['OUTPUT', '-p', 'udp', '--dport', String(v6 ? 18444 : 18445), '-m', 'conntrack', '--ctstate', 'ESTABLISHED'];
      at('client', fw, '-w', '5', '-A', ...tracking);
      check(`KS baseline IPv${v6 ? 6 : 4}`, await udpQuery(v6, 31001), source);
      ks('up', ...options);
      check(`KS established incoming TCP replies survive IPv${v6 ? 6 : 4}`, await echo(management), 'synthetic SSH reply');
      check(`KS new IPv${v6 ? 6 : 4} flow blocked`, await udpQuery(v6, 31002), 'BLOCKED');
      const existing = await udpQuery(v6, 31001);
      check(`KS established IPv${v6 ? 6 : 4} flow blocked`, existing, 'BLOCKED');
      const snapshot = () => [4, 6].map(f => at('client', f === 4 ? 'iptables' : 'ip6tables', '-S')).join('\n');
      const installed = snapshot();
      const burst = await start('client', ['-e', `
        const s=require('dgram').createSocket(${JSON.stringify(v6 ? 'udp6' : 'udp4')});
        let sent=0, received=0;
        s.on('message',()=>received++); s.on('error',()=>{});
        const timer=setInterval(()=>{sent++;s.send(Buffer.from('guard update probe'),${v6 ? 18444 : 18445},${JSON.stringify(v6 ? origin : '1.0.0.1')})},10);
        console.log('READY');
        process.on('SIGINT',()=>{clearInterval(timer);console.log(JSON.stringify({sent,received}));s.close()});
        setTimeout(()=>process.exit(2),60000).unref();
      `]);
      await wait(burst, 'READY');
      for (let n = 0; n < 3; n++) ks('up', ...options);
      await delay(500); await stop(burst);
      const traffic = JSON.parse(burst.log.trim().split('\n').at(-1));
      assert.ok(traffic.sent >= 10, burst.log);
      check(`KS repeated up no observed UDP window IPv${v6 ? 6 : 4}`, traffic.received, 0);
      check('KS repeated up has identical rules and no duplicate hooks', snapshot(), installed);
      const before4 = at('client', 'iptables', '-S');
      assert.throws(() => at('client', 'bash', '-c',
        'export PATH="$1:$PATH"; shift; exec bash scripts/autostart/killswitch.sh "$@"',
        'guard-fault', faultDir, 'up', '--server=198.51.100.3', '--ssh-port=2222'), /injected IPv4 commit failure/);
      check('KS failed second-family commit retains IPv4 rules', at('client', 'iptables', '-S'), before4);
      check(`KS failed update retains IPv${v6 ? 6 : 4} blocking`, await udpQuery(v6, 31002), 'BLOCKED');
      ks('up', ...options);
      check('KS retry reconciles partial per-family update', snapshot(), installed);
      // Corrupt just our lab-owned chain and confirm refusal without a flush.
      at('client', fw, '-A', 'CLEANVPN_KS_OUT', '-m', 'comment', '--comment', 'lab-foreign', '-j', 'RETURN');
      const foreign = snapshot();
      assert.throws(() => ks('up', '--server=198.51.100.2'), /foreign\/legacy\/modified/);
      assert.throws(() => ks('down'), /foreign\/legacy\/modified/);
      check('KS refuses foreign rule without mutation', snapshot(), foreign);
      at('client', fw, '-D', 'CLEANVPN_KS_OUT', '-m', 'comment', '--comment', 'lab-foreign', '-j', 'RETURN');
      ks('down');
      check(`KS explicit down restores IPv${v6 ? 6 : 4}`, await udpQuery(v6, 31002), source);
      at('client', fw, '-w', '5', '-D', ...tracking);
      management.destroy();
    }
    await stop(ssh);
    const source = readFileSync('scripts/autostart/killswitch.sh', 'utf8');
    assert.match(source, /--noflush/);
    const installer = readFileSync('scripts/autostart/install.sh', 'utf8');
    assert.match(installer, /TimeoutStopSec=420/);
    assert.match(installer, /^KillMode=mixed$/m);
    check('autostart stop template accommodates DNS and IPv6 cleanup', true, true);
    gaps.push('systemd-boot-restart-uninstall-not-executed-in-this-namespace-lab');
    console.error(`HOST_RESILIENCE_PROGRESS ${JSON.stringify({ case: 'guard-audit', gaps })}`);
    }
    return { acceptance: 'not-ready-for-deployment', soaks, reconnects, gaps,
      limitations: ['synthetic-60s-soak-not-long-pilot', 'DNS-proxy-disabled-in-this-suite',
        'no-live-provider-network', 'no-mid-transfer-resumption-guarantee', 'systemd-lifecycle-not-accepted'] };
  } finally { s.closeAllConnections(); s.close(); udp.close(); }
}
