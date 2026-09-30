/** Joint host-only crash test, inside the existing NIC-less disposable lab. */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { once } from 'node:events';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { tunnelDnsFixtureAnswer } from './dns-tunnel-cli-lab.mjs';

export async function runHostJointChecks({ start, wait, stop, startExit, startClient, query, check, at, ip }) {
  assertBrowserNamespace();
  const servers = [], peers = [], sockets = new Set(), cases = [];
  const answer = (b, peer) => { peers.push(peer); return tunnelDnsFixtureAnswer(b, 10); };
  const ks = (...a) => at('client', 'bash', 'scripts/autostart/killswitch.sh', ...a);
  const snapshot = () => JSON.stringify({ routes: JSON.parse(at('client', 'ip', '-N', '-j', '-4', 'route', 'show', 'table', 'main')),
    rules: at('client', 'ip', '-4', 'rule', 'show'), rp: at('client', 'sysctl', '-n', 'net.ipv4.conf.all.rp_filter') });
  const dns = async tcp => {
    const p = await start('client', ['--input-type=module', '-e', `
      import {exchangePlainDns} from './scripts/lib/dns-tunnel-forwarder.mjs';
      import {makeDnsQuery,parseDns} from './scripts/lib/lab-dns-wire.mjs';
      try { const b=await exchangePlainDns({server:'1.1.1.1',localAddress:'0.0.0.0',tcp:${tcp},
        query:makeDnsQuery('joint.test'),timeoutMs:5000});
        const a=parseDns(b).records.find(r=>r.type===1);console.log(a?[...b.subarray(a.offset,a.offset+4)].join('.'):'NOANSWER');
      }catch{console.log('BLOCKED')}
    `]);
    await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return p.log.trim();
  };
  const recover = async (script, apply = false) => {
    // Recovery has its own 120s bounded command budget; the lab's general
    // 20s read-only executor must not kill it halfway through in slow TCG.
    const p = await start('client', [`scripts/${script}`, ...(apply ? ['--apply'] : [])]);
    const timer = setTimeout(() => p.kill('SIGKILL'), 150000);
    try { await once(p, 'exit'); assert.equal(p.exitCode, 0, p.log); return JSON.parse(p.stdoutText); }
    finally { clearTimeout(timer); }
  };
  try {
    for (const address of ['1.1.1.1', '8.8.8.8']) {
      ip('addr', 'add', `${address}/32`, 'dev', 'lo');
      const u = dgram.createSocket('udp4'); u.on('message', (b, r) => u.send(answer(b, r.address), r.port, r.address));
      u.bind(53, address); await once(u, 'listening'); servers.push(u);
      const t = net.createServer(s => {
        sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); let pending = Buffer.alloc(0);
        s.on('data', b => { pending = Buffer.concat([pending, b]); if (pending.length < 2 || pending.length < pending.readUInt16BE(0) + 2) return;
          const reply = answer(pending.subarray(2, pending.readUInt16BE(0) + 2), s.remoteAddress), n = Buffer.alloc(2);
          n.writeUInt16BE(reply.length); s.end(Buffer.concat([n, reply]));
        });
      }); t.listen(53, address); await once(t, 'listening'); servers.push(t);
    }
    check('joint baseline DNS direct control', await dns(false), '192.0.2.10');
    check('joint baseline DNS source is client', peers.at(-1), '192.0.2.2');
    for (const h1 of [false, true]) {
      const label = h1 ? 'h1' : 'h2', baseline = snapshot();
      ks('up', '--server=198.51.100.2');
      check(`${label} guard blocks baseline DNS`, await dns(false), 'BLOCKED');
      const exit = await startExit(true); await wait(exit, 'exit TLS');
      let client = await startClient(h1);
      try { await wait(client, 'DNS tunnel:'); await wait(client, 'IPv6 client: tunnel'); }
      catch (error) {
        console.error('JOINT_EXIT_LOG', exit.log);
        for (const ns of ['client', 'exit']) for (const [file, ...args] of [
          ['ip', '-4', 'route', 'get', ns === 'client' ? '198.51.100.2' : '192.0.2.2'],
          ['iptables', '-t', 'filter', '-nvL'], ['iptables', '-t', 'nat', '-nvL'],
        ]) { try { console.error('JOINT_DIAGNOSTIC', ns, file, args, at(ns, file, ...args)); } catch {} }
        throw error;
      }
      check(`${label} joint IPv4 HTTPS`, await query('1.0.0.1'), '198.51.100.2');
      check(`${label} joint IPv6 HTTPS`, await query('2606:4700:4700::1111'), '2001:db8:2::2');
      const beforePeers = peers.length;
      for (const tcp of [false, true]) check(`${label} joint DNS ${tcp ? 'TCP' : 'UDP'}`, await dns(tcp), '192.0.2.10');
      check(`${label} joint DNS only from exit`, peers.slice(beforePeers).every(p => p === '198.51.100.2'), true);
      await stop(client, 'SIGKILL');
      check(`${label} SIGKILL blocks direct IPv4`, await query('1.0.0.1'), 'BLOCKED');
      check(`${label} SIGKILL blocks direct IPv6`, await query('2606:4700:4700::1111'), 'BLOCKED');
      for (const tcp of [false, true]) check(`${label} SIGKILL blocks DNS ${tcp ? 'TCP' : 'UDP'}`, await dns(tcp), 'BLOCKED');
      const collision = await startClient(h1); await once(collision, 'exit');
      check(`${label} stale journal refuses automatic restart`, collision.exitCode, 1);
      assert.match(collision.log, /(Host IPv4|IPv6) recovery required/);
      check(`${label} refusal creates no replacement TUN`, JSON.parse(at('client', 'ip', '-j', 'link', 'show')).some(l => /^tun/.test(l.ifname)), false);
      // Operator recovery while standalone guard remains up. No automatic
      // fail-open restart policy is inferred from this laboratory step.
      await recover('clean-vpn-dns-recover.mjs', true);
      await recover('clean-vpn-ipv6-recover.mjs', true);
      await recover('clean-vpn-host-recover.mjs', true);
      check(`${label} crash recovery restores original IPv4 routes and rp_filter`, snapshot(), baseline);
      check(`${label} guard survives explicit recovery IPv4`, await query('1.0.0.1'), 'BLOCKED');
      check(`${label} guard survives explicit recovery IPv6`, await query('2606:4700:4700::1111'), 'BLOCKED');
      check(`${label} guard survives explicit recovery DNS`, await dns(false), 'BLOCKED');
      client = await startClient(h1); await wait(client, 'DNS tunnel:'); await wait(client, 'IPv6 client: tunnel');
      check(`${label} explicit recovery permits new session`, await query('1.0.0.1'), '198.51.100.2');
      await stop(client);
      for (const script of ['clean-vpn-dns-recover.mjs', 'clean-vpn-ipv6-recover.mjs', 'clean-vpn-host-recover.mjs'])
        check(`${label} ${script} released`, (await recover(script)).stage, 'released');
      check(`${label} clean stop restores original IPv4 routes and rp_filter`, snapshot(), baseline);
      check(`${label} standalone guard remains after clean stop`, await query('1.0.0.1'), 'BLOCKED');
      ks('down'); await stop(exit);
      check(`${label} explicit guard removal restores baseline IPv4`, await query('1.0.0.1'), '192.0.2.2');
      cases.push(label);
    }
    return { cases, acceptance: 'not-ready-for-deployment', limitations: ['no-PID1-systemd-or-boot-test', 'explicit-recovery-not-automatic-restart',
      'host-only-not-LAN', 'same-boot-no-power-cut', 'iptables-legacy-only', 'synthetic-DNS-not-system-resolver'] };
  } finally { for (const s of sockets) s.destroy(); for (const s of servers) s.close(); }
}
