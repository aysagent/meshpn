/** Invoked only inside the disposable ingress namespace/VM fixture. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import net from 'node:net';
import dgram from 'node:dgram';
import { fixtureDnsAnswer, parseDnsQuery } from './lab-dns-wire.mjs';
import { openTunnelDnsJournal } from './dns-tunnel-journal.mjs';
import { recoverIngress } from '../clean-vpn-recover.mjs';

export function tunnelDnsFixtureAnswer(query, suffix) {
  const ipv6 = parseDnsQuery(query).type === 28;
  const rdata = ipv6 ? Buffer.alloc(16) : Buffer.from([192, 0, 2, 0]);
  if (ipv6) rdata.writeUInt32BE(0x20010db8);
  rdata[rdata.length - 1] = suffix;
  return fixtureDnsAnswer(query, { rdata });
}

export const tunnelDnsFixtureSource = `
  if (process.env.TUNNEL_DNS_CLI_LAB) {
    const {tunnelDnsFixtureAnswer} = require('./scripts/lib/dns-tunnel-cli-lab.mjs');
    const primary = [];
    for (const [address, last] of [['1.1.1.1',10], ['8.8.8.8',20], ['10.55.0.1',30]]) {
      const answer = b => {
        console.log('DNS_QUERY ' + address);
        const suffix=tag === 'uplink' ? 30 : last;
        return tunnelDnsFixtureAnswer(b,suffix);
      };
      servers.push(new Promise(resolve => {
        const s=dgram.createSocket('udp4'); s.on('error',()=>{});
        s.on('message',(b,r)=>{try{s.send(answer(b),r.port,r.address)}catch{}});
        s.bind(53,address,resolve); if(address==='1.1.1.1') primary.push(s);
      }));
      servers.push(new Promise(resolve => {
        const s=net.createServer(c=>{
          c.on('error',()=>{}); let pending=Buffer.alloc(0);
          c.on('data',b=>{pending=Buffer.concat([pending,b]); if(pending.length<2)return;
            const n=pending.readUInt16BE(0); if(pending.length<n+2)return;
            try {const reply=answer(pending.subarray(2,n+2)), prefix=Buffer.alloc(2);
              prefix.writeUInt16BE(reply.length);c.end(Buffer.concat([prefix,reply]));}catch{c.destroy()}
          });
        }).listen(53,address,resolve); if(address==='1.1.1.1') primary.push(s);
      }));
    }
    process.on('SIGUSR1',()=>{for(const s of primary)s.close();console.log('PRIMARY_STOPPED')});
  }
`;

async function dnsQuery(namespace, tcp = false, type = 1, address = '10.55.0.1') {
  const code = `
    import {exchangePlainDns} from './scripts/lib/dns-tunnel-forwarder.mjs';
    import {makeDnsQuery,parseDns} from './scripts/lib/lab-dns-wire.mjs';
    try {
      const b=await exchangePlainDns({server:${JSON.stringify(address)},localAddress:'0.0.0.0',tcp:${tcp},
        query:makeDnsQuery('origin.test',${type}),timeoutMs:5000});
      const p=parseDns(b), a=p.records.find(r=>r.type===${type});
      console.log(a ? (${type}===28 ? 'AAAA:'+b[a.offset+15] : [...b.subarray(a.offset,a.offset+4)].join('.')) : 'RCODE:'+p.rcode);
    } catch { console.log('BLOCKED'); }
  `;
  const child = spawn(namespace ? 'ip' : process.execPath,
    namespace ? ['netns', 'exec', namespace, process.execPath, '--input-type=module', '-e', code]
      : ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.on('data', b => { out += b; }); child.stderr.on('data', b => { err += b; });
  const [codeExit] = await once(child, 'exit'); assert.equal(codeExit, 0, err); return out.trim();
}

async function ingressStopProbe() {
  const child = spawn('ip', ['netns', 'exec', 'peer', process.execPath, '--input-type=module', '-e', `
    import dgram from 'node:dgram'; import {makeDnsQuery} from './scripts/lib/lab-dns-wire.mjs';
    const s=dgram.createSocket('udp4'), q=makeDnsQuery('stop-probe.test');s.on('error',()=>{});let sent=0;
    const timer=setInterval(()=>{for(const dst of ['10.55.0.1','10.44.0.1'])s.send(q,53,dst,e=>{if(!e)sent++})},50);
    process.on('SIGTERM',()=>{clearInterval(timer);s.close(()=>{console.log('SENT '+sent);process.exit(0)})});
    console.log('READY');
  `], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  await new Promise((resolve, reject) => {
    child.stdout.on('data', b => { output += b; if (output.includes('READY')) resolve(); });
    child.once('error', reject); child.once('exit', () => reject(Error('stop probe exited early')));
  });
  return async () => {
    const ended = once(child, 'exit'); child.kill('SIGTERM'); await ended;
    assert.ok(Number(/SENT (\d+)/.exec(output)?.[1]) > 0, 'stop probe must actually emit DNS packets');
  };
}

async function gatewayDnsFixture() {
  let received = 0;
  const answer = q => { received++; return fixtureDnsAnswer(q, { rdata: Buffer.from([192, 0, 2, 30]) }); };
  const udp = dgram.createSocket('udp4'), sockets = new Set();
  udp.on('message', (b, r) => { try { udp.send(answer(b), r.port, r.address); } catch {} });
  const tcp = net.createServer(s => {
    sockets.add(s); s.on('error', () => {}); s.once('close', () => sockets.delete(s)); let pending = Buffer.alloc(0);
    s.on('data', b => {
      pending = Buffer.concat([pending, b]);
      if (pending.length < 2 || pending.length < pending.readUInt16BE(0) + 2) return;
      try { const reply = answer(pending.subarray(2)), prefix = Buffer.alloc(2); prefix.writeUInt16BE(reply.length); s.end(Buffer.concat([prefix, reply])); }
      catch { s.destroy(); }
    });
  });
  const listening = [once(udp, 'listening'), once(tcp, 'listening')];
  udp.bind(53, '10.44.0.1'); tcp.listen(53, '10.44.0.1'); await Promise.all(listening);
  return { count: () => received, close: async () => {
    for (const s of sockets) s.destroy();
    await Promise.all([udp, tcp].map(s => new Promise(resolve => s.close(resolve))));
  } };
}

export async function runTunnelDnsCliChecks({ scope, transport, launch, stop, common, exit, fixture,
  counters, snapshot, check, checks }) {
  const namespace = scope === 'host' ? null : 'peer';
  const gateway = scope === 'ingress' ? await gatewayDnsFixture() : null;
  try {
  const flags = scope === 'ingress' ? ['--from-tun=wg0', '--from-tun-restart-safe']
    : scope === 'lan' ? ['--client-lan-subnet=10.44.0.0/24', '--split-default'] : [];
  const start = () => launch(null, ['--role=client', `--type=${transport}`, '--server=192.0.3.2:24443',
    '--tls-server-name=vpn.test', '--tls-client-sni=vpn.test', ...flags, ...common],
    scope === 'ingress' ? 'restart guard released' : 'DNS tunnel:');
  const baseline = snapshot();
  for (const tcp of [false, true]) check(`baseline ${tcp ? 'TCP' : 'UDP'} DNS`, await dnsQuery(namespace, tcp), '192.0.2.30');
  if (gateway) for (const tcp of [false, true]) check(`baseline gateway ${tcp ? 'TCP' : 'UDP'} DNS`, await dnsQuery(namespace, tcp, 1, '10.44.0.1'), '192.0.2.30');
  const gatewayBefore = gateway?.count();
  let client = start(); await client.started;
  // The transport is lazy and TCG can take longer than the bounded DNS request
  // budget for its first TLS handshake. Retry requests, never the direct path.
  let initial;
  for (let attempt = 0; attempt < 6; attempt++) { initial = await dnsQuery(namespace); if (initial === '192.0.2.10') break; }
  check('cold transport eventually resolves via primary', initial, '192.0.2.10');
  for (const tcp of [false, true]) check(`default primary ${tcp ? 'TCP' : 'UDP'} via ${transport}`, await dnsQuery(namespace, tcp), '192.0.2.10');
  for (const tcp of [false, true]) check(`AAAA answer over ${tcp ? 'TCP' : 'UDP'} via ${transport}`, await dnsQuery(namespace, tcp, 28), 'AAAA:10');
  if (gateway) for (const tcp of [false, true]) check(`gateway-addressed ${tcp ? 'TCP' : 'UDP'} DNS is captured`, await dnsQuery(namespace, tcp, 1, '10.44.0.1'), '192.0.2.10');
  if (scope === 'ingress') check('gateway DNS unchanged', await dnsQuery(null), '192.0.2.30');
  if (scope === 'lan') check('LAN mode also protects gateway DNS', await dnsQuery(null), '192.0.2.10');
  check('other ingress DNS unchanged', await dnsQuery('other'), '192.0.2.30');
  const upstreamBefore = counters.uplink;
  const stopped = new Promise(resolve => {
    const read = b => { if (String(b).includes('PRIMARY_STOPPED')) { fixture.stdout.off('data', read); resolve(); } };
    fixture.stdout.on('data', read);
  });
  fixture.kill('SIGUSR1'); await stopped;
  for (const tcp of [false, true]) check(`backup ${tcp ? 'TCP' : 'UDP'} via ${transport}`, await dnsQuery(namespace, tcp), '192.0.2.20');
  await stop(client.child, 'SIGKILL');
  for (const tcp of [false, true]) check(`crashed client blocks ${tcp ? 'TCP' : 'UDP'} DNS`, await dnsQuery(namespace, tcp), 'BLOCKED');
  client = start(); await client.started;
  check('same-boot restart restores backup DNS', await dnsQuery(namespace), '192.0.2.20');
  await stop(exit.child, 'SIGTERM');
  for (const tcp of [false, true]) {
    const answer = await dnsQuery(namespace, tcp);
    assert.ok(answer === 'BLOCKED' || answer === 'RCODE:2', `exit down must fail closed: ${answer}`);
    checks.push(`exit down ${tcp ? 'TCP' : 'UDP'} fails closed`);
  }
  check('no direct DNS queries during backup, crash, restart or exit outage', counters.uplink, upstreamBefore);
  const stopProbe = scope === 'ingress' ? await ingressStopProbe() : null;
  try { await stop(client.child, 'SIGTERM'); } finally { await stopProbe?.(); }
  if (stopProbe) check('continuous private DNS stays blocked throughout safe stop', counters.uplink, upstreamBefore);
  if (gateway) {
    for (const tcp of [false, true]) check(`safe stop keeps gateway ${tcp ? 'TCP' : 'UDP'} DNS blocked`, await dnsQuery(namespace, tcp, 1, '10.44.0.1'), 'BLOCKED');
    check('gateway DNS never receives bypass queries during capture or safe stop', gateway.count(), gatewayBefore);
  }
  const j = openTunnelDnsJournal();
  try {
    if (scope === 'ingress') {
      check('safe stop retains DNS journal', j.state.stage, 'active');
      j.restore(); // Explicit operator recovery, not automatic release at SIGTERM.
    }
    check(`${scope === 'ingress' ? 'explicit recovery' : 'normal stop'} releases DNS journal`, j.state.stage, 'released');
    // Audit all reserved DNS chains/table/priorities with zero owned operations.
    // Do not mistake legacy host routing crash recovery for DNS ownership.
    check('released DNS network audit has no remaining operations', j.restore({ apply: false }).operations, 0);
  } finally { j.release(); }
  if (scope === 'ingress') recoverIngress(['--from-tun=wg0', '--apply']);
  const after = snapshot(), nonDnsNetworkRestored = after === baseline;
  if (scope === 'ingress') check('ingress recovery restores original routes and rules', after, baseline);
  const beforeState = JSON.parse(baseline), afterState = JSON.parse(after);
  const nonDnsDifferences = Object.keys(beforeState).filter(k => beforeState[k] !== afterState[k]);
  for (const tcp of [false, true]) check(`${scope === 'ingress' ? 'explicit recovery' : 'normal stop'} restores baseline ${tcp ? 'TCP' : 'UDP'} DNS`, await dnsQuery(namespace, tcp), '192.0.2.30');
  return { status: 'passed', checks, scope, hostNetworkChanged: false, actualTransportTested: transport,
    actualDnsDefaultTested: true, nonDnsNetworkRestored, nonDnsDifferences,
    limitations: scope === 'ingress' ? [] : ['legacy-host-routing-is-not-journaled-across-SIGKILL'] };
  } finally { await gateway?.close(); }
}
