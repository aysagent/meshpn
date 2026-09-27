/** Packet-path test only, in an empty private PID/net/mount namespace.
 * A veth models TUN routing; this does not certify transport encryption. */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { compileTunnelDnsPlan } from './dns-tunnel-plan.mjs';
import { createTunnelDnsForwarder, exchangePlainDns } from './dns-tunnel-forwarder.mjs';
import { startTunnelDnsStub } from './dns-tunnel-stub.mjs';
import { openTunnelDnsJournal } from './dns-tunnel-journal.mjs';
import { startTunnelDnsRuntime } from './dns-tunnel-runtime.mjs';
import { makeDnsQuery, validateDnsResponse } from './lab-dns-wire.mjs';

const run = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const ip = (...args) => run('ip', args);
const at = (namespace, ...args) => ip('netns', 'exec', namespace, ...args);
const serverSource = `
  const net=require('node:net'), dgram=require('node:dgram');
  const {fixtureDnsAnswer}=require('./scripts/lib/lab-dns-wire.mjs');
  const tag=process.argv[1], pairs=[];
  const closePair=p=>Promise.all(p.map(s=>new Promise(r=>s.close(r))));
  async function serve(address,index) {
    const sockets=new Set();
    const reply=q=>{
      console.log('QUERY '+JSON.stringify({address}));
      return fixtureDnsAnswer(q,{rdata:Buffer.from([192,0,2,tag==='tunnel'?(index===0?10:20):30])});
    };
    const udp=dgram.createSocket(address.includes(':')?'udp6':'udp4');udp.on('message',(q,p)=>udp.send(reply(q),p.port,p.address));
    const tcp=net.createServer(s=>{sockets.add(s);s.on('error',()=>{});s.once('close',()=>sockets.delete(s));let pending=Buffer.alloc(0);
      s.on('data',b=>{pending=Buffer.concat([pending,b]);if(pending.length<2||pending.length!==pending.readUInt16BE(0)+2)return;
        const r=reply(pending.subarray(2)),p=Buffer.alloc(2);p.writeUInt16BE(r.length);s.end(Buffer.concat([p,r]));});});
    await Promise.all([new Promise(r=>udp.bind(53,address,r)),new Promise(r=>tcp.listen(53,address,r))]);
    pairs.push({pair:[udp,tcp],sockets});
  }
  (async()=>{for(const [i,address] of ['1.1.1.1','8.8.8.8','10.123.0.1'].entries())await serve(address,i);
    if(tag==='uplink')await serve('fd00:100::53',3);
    process.once('SIGUSR1',async()=>{const p=pairs[0];for(const s of p.sockets)s.destroy();await closePair(p.pair);console.log('PRIMARY_OFF');});
    console.log('READY');})();
`;
export async function runTunnelDnsRoutingLab({ ingress = false, lan = false, journaled = false } = {}) {
  assertBrowserNamespace(); assert.equal(typeof ingress, 'boolean'); assert.equal(typeof lan, 'boolean');
  assert.ok(!(ingress && lan));
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map((l) => l.ifname), ['lo']);
  run('mount', ['--make-rprivate', '/']); run('mount', ['-t', 'tmpfs', 'tmpfs', '/run']);
  ip('link', 'set', 'lo', 'up'); run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  run('sysctl', ['-w', 'net.ipv6.conf.all.forwarding=1']);
  run('sysctl', ['-w', 'net.ipv6.conf.default.forwarding=1']);
  run('sysctl', ['-w', 'net.ipv4.conf.all.rp_filter=0']);
  const children = [], installed = [], checks = []; let stub, journal, owner, deletedTun = false;
  const link = (name, iface, gateway, peer) => {
    ip('netns', 'add', name); ip('link', 'add', iface, 'type', 'veth', 'peer', 'name', `${iface}p`);
    ip('link', 'set', `${iface}p`, 'netns', name);
    ip('addr', 'add', `${gateway}/24`, 'dev', iface); ip('link', 'set', iface, 'up');
    at(name, 'ip', 'link', 'set', 'lo', 'up'); at(name, 'ip', 'addr', 'add', `${peer}/24`, 'dev', `${iface}p`);
    at(name, 'ip', 'link', 'set', `${iface}p`, 'up'); at(name, 'ip', 'route', 'add', 'default', 'via', gateway);
  };
  const startServer = async (name) => {
    for (const address of ['1.1.1.1', '8.8.8.8', '10.123.0.1']) at(name, 'ip', 'addr', 'add', `${address}/32`, 'dev', 'lo');
    const child = spawn('ip', ['netns', 'exec', name, process.execPath, '-e', serverSource, name], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child); const events = [], waiting = new Map(); let pending = '', stderr = '';
    child.stderr.on('data', (b) => { stderr += b; });
    child.stdout.on('data', (b) => { pending += b; for (;;) {
      const end = pending.indexOf('\n'); if (end < 0) break;
      const line = pending.slice(0, end); pending = pending.slice(end + 1); events.push(line); waiting.get(line)?.();
    } });
    const wait = (line) => new Promise((resolve, reject) => {
      if (events.includes(line)) return resolve();
      const timer = setTimeout(() => reject(new Error(`fixture ${line} timeout: ${stderr}`)), 3000);
      waiting.set(line, () => { clearTimeout(timer); resolve(); });
    });
    await wait('READY'); return { child, wait, count: () => events.filter((s) => s.startsWith('QUERY ')).length };
  };
  const query = async (namespace, tcp, address = '10.123.0.1', timeoutMs = 1500) => {
    if (!namespace) {
      const q = makeDnsQuery('path.test');
      const response = await exchangePlainDns({ server: address, localAddress: '192.0.2.1', query: q, tcp, timeoutMs });
      const rr = validateDnsResponse(response, q); return { rcode: rr.rcode, answer: response[rr.records[0]?.offset + 3] };
    }
    const code = `import {exchangePlainDns} from './scripts/lib/dns-tunnel-forwarder.mjs';
      import {makeDnsQuery,validateDnsResponse} from './scripts/lib/lab-dns-wire.mjs';
      const q=makeDnsQuery('path.test');const r=await exchangePlainDns({server:${JSON.stringify(address)},localAddress:'10.44.0.2',query:q,tcp:${tcp},timeoutMs:${timeoutMs}});
      const p=validateDnsResponse(r,q);console.log(JSON.stringify({rcode:p.rcode,answer:r[p.records[0]?.offset+3]}));`;
    const child = spawn('ip', ['netns', 'exec', namespace, process.execPath, '--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', error = ''; child.stdout.on('data', (b) => { output += b; }); child.stderr.on('data', (b) => { error += b; });
    const [status] = await once(child, 'close'); assert.equal(status, 0, error); return JSON.parse(output);
  };
  const query6 = async (namespace, tcp) => {
    const code = `import net from 'node:net';import dgram from 'node:dgram';
      import {makeDnsQuery,validateDnsResponse} from './scripts/lib/lab-dns-wire.mjs';
      const q=makeDnsQuery('ipv6-path.test'),tcp=${tcp},s=tcp?new net.Socket():dgram.createSocket('udp6');
      let pending=Buffer.alloc(0),done=false;
      const finish=(ok)=>{if(done)return;done=true;clearTimeout(timer);console.log(ok?'answer':'blocked');if(tcp)s.destroy();else s.close();};
      const timer=setTimeout(()=>finish(false),1500);s.on('error',()=>finish(false));
      const check=b=>{try{validateDnsResponse(b,q);finish(true);}catch{finish(false);}};
      if(tcp){s.on('data',b=>{pending=Buffer.concat([pending,b]);if(pending.length>=2&&pending.length===pending.readUInt16BE(0)+2)check(pending.subarray(2));});
        s.once('connect',()=>{const p=Buffer.alloc(2);p.writeUInt16BE(q.length);s.write(Buffer.concat([p,q]));});
        s.connect({host:'fd00:100::53',port:53,family:6});}
      else {s.on('message',check);s.send(q,53,'fd00:100::53',e=>{if(e)finish(false);});}`;
    const child = namespace ? spawn('ip', ['netns', 'exec', namespace, process.execPath, '--input-type=module', '-e', code])
      : spawn(process.execPath, ['--input-type=module', '-e', code]);
    let output = '', error = ''; child.stdout.on('data', (b) => { output += b; }); child.stderr.on('data', (b) => { error += b; });
    const [status] = await once(child, 'close'); assert.equal(status, 0, error); return output.trim();
  };
  try {
    link('uplink', 'up0', '192.0.2.1', '192.0.2.2'); ip('route', 'add', 'default', 'via', '192.0.2.2');
    ip('-6', 'addr', 'add', 'fd00:100::1/64', 'dev', 'up0', 'nodad');
    at('uplink', 'ip', '-6', 'addr', 'add', 'fd00:100::2/64', 'dev', 'up0p', 'nodad');
    at('uplink', 'ip', '-6', 'addr', 'add', 'fd00:100::53/128', 'dev', 'lo', 'nodad');
    ip('-6', 'route', 'add', 'fd00:100::53/128', 'via', 'fd00:100::2');
    // DNS filtering is under test, not link-local DAD/NDP startup timing.
    const uplinkMac = JSON.parse(at('uplink', 'ip', '-j', 'link', 'show', 'up0p'))[0].address;
    const gatewayMac = JSON.parse(ip('-j', 'link', 'show', 'up0'))[0].address;
    ip('-6', 'neigh', 'add', 'fd00:100::2', 'lladdr', uplinkMac, 'nud', 'permanent', 'dev', 'up0');
    at('uplink', 'ip', '-6', 'neigh', 'add', 'fd00:100::1', 'lladdr', gatewayMac, 'nud', 'permanent', 'dev', 'up0p');
    link('tunnel', 'cvpntun', '10.99.0.2', '10.99.0.1');
    if (ingress || lan) { link('peer', lan ? 'usb0' : 'wg0', '10.44.0.1', '10.44.0.2');
      const iface = lan ? 'usb0' : 'wg0';
      ip('-6', 'addr', 'add', 'fd00:200::1/64', 'dev', iface, 'nodad');
      at('peer', 'ip', '-6', 'addr', 'add', 'fd00:200::2/64', 'dev', `${iface}p`, 'nodad');
      at('peer', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:200::1');
      const peerMac = JSON.parse(at('peer', 'ip', '-j', 'link', 'show', `${iface}p`))[0].address;
      const ingressMac = JSON.parse(ip('-j', 'link', 'show', iface))[0].address;
      ip('-6', 'neigh', 'add', 'fd00:200::2', 'lladdr', peerMac, 'nud', 'permanent', 'dev', iface);
      at('peer', 'ip', '-6', 'neigh', 'add', 'fd00:200::1', 'lladdr', ingressMac, 'nud', 'permanent', 'dev', `${iface}p`);
      at('uplink', 'ip', '-6', 'route', 'add', 'fd00:200::/64', 'via', 'fd00:100::1');
      run('iptables', ['-t', 'nat', '-A', 'POSTROUTING', '-o', 'up0', '-j', 'MASQUERADE']); }
    const uplink = await startServer('uplink'), tunnel = await startServer('tunnel');
    for (const tcp of [false, true]) assert.equal((await query(null, tcp)).answer, 30);
    checks.push('answering-uplink-positive-control');
    for (const tcp of [false, true]) assert.equal(await query6(ingress || lan ? 'peer' : null, tcp), 'answer');
    checks.push('answering-ipv6-uplink-positive-control');
    const config = { tun: 'cvpntun', fromTun: ingress ? 'wg0' : null,
      lanSubnet: lan ? '10.44.0.0/24' : null, lanInterface: lan ? 'usb0' : null };
    const plan = compileTunnelDnsPlan(config);
    const apply = (stage) => {
      if (journal) return journal.applyStage(stage);
      for (const op of plan.operations.filter((v) => v.stage === stage)) { run(op.file, op.args); installed.unshift(op); }
    };
    if (journaled) {
      const code = `import {openTunnelDnsJournal} from './scripts/lib/dns-tunnel-journal.mjs';
        import {startTunnelDnsRuntime} from './scripts/lib/dns-tunnel-runtime.mjs';
        const runtime=await startTunnelDnsRuntime({journal:openTunnelDnsJournal(),config:${JSON.stringify(config)},timeoutMs:150});
        runtime.activate();
        process.send({ready:true});`;
      owner = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
      children.push(owner); let errors = ''; owner.stderr.on('data', (b) => { errors += b; });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`DNS owner readiness timeout: ${errors}`)), 10000);
        owner.once('message', (m) => { clearTimeout(timer); m.ready ? resolve() : reject(new Error('bad owner readiness')); });
        owner.once('exit', () => { clearTimeout(timer); reject(new Error(`DNS owner exited: ${errors}`)); });
        owner.once('error', (error) => { clearTimeout(timer); reject(error); });
      });
    } else {
      apply('guard'); apply('route');
      stub = await startTunnelDnsStub({ forwarder: createTunnelDnsForwarder({ timeoutMs: 150 }) }); apply('activate');
    }
    const before = uplink.count();
    for (const tcp of [false, true]) assert.equal((await query(ingress || lan ? 'peer' : null, tcp)).answer, 10);
    assert.equal(uplink.count(), before); assert.equal(tunnel.count(), 2); checks.push('udp-tcp-private-original-dns-through-tunnel');
    for (const tcp of [false, true]) assert.equal(await query6(ingress || lan ? 'peer' : null, tcp), 'blocked');
    assert.equal(uplink.count(), before); checks.push('ipv6-udp-tcp-dns-bypass-blocked');
    tunnel.child.kill('SIGUSR1'); await tunnel.wait('PRIMARY_OFF');
    for (const tcp of [false, true]) assert.equal((await query(ingress || lan ? 'peer' : null, tcp)).answer, 20);
    assert.equal(uplink.count(), before); checks.push('primary-failure-uses-backup-through-tunnel');
    if (ingress) { for (const tcp of [false, true]) assert.equal((await query(null, tcp)).answer, 30); checks.push('gateway-own-dns-unchanged'); }
    if (lan) { for (const tcp of [false, true]) assert.equal((await query(null, tcp)).answer, 20); checks.push('lan-mode-also-protects-host-dns'); }
    const protectedHits = uplink.count();
    if (journaled) {
      const exited = once(owner, 'close'); owner.kill('SIGKILL'); await exited;
      assert.equal(owner.signalCode, 'SIGKILL');
      for (const tcp of [false, true]) await assert.rejects(query(ingress || lan ? 'peer' : null, tcp, '10.123.0.1', 250));
      assert.equal(uplink.count(), protectedHits); checks.push('sigkill-owner-no-direct-dns');
      journal = openTunnelDnsJournal(); journal.prepareRestart(config);
      assert.equal(journal.state.stage, 'parked');
      for (const tcp of [false, true]) await assert.rejects(query(ingress || lan ? 'peer' : null, tcp, '10.123.0.1', 250));
      assert.equal(uplink.count(), protectedHits); checks.push('recovery-gate-no-direct-dns');
      stub = await startTunnelDnsRuntime({ journal, config, timeoutMs: 150 }); stub.activate();
      for (const tcp of [false, true]) assert.equal((await query(ingress || lan ? 'peer' : null, tcp)).answer, 20);
      assert.equal(uplink.count(), protectedHits); checks.push('restart-restores-tunnel-dns');
    }
    ip('link', 'set', 'cvpntun', 'down');
    for (const tcp of [false, true]) assert.equal((await query(ingress || lan ? 'peer' : null, tcp)).rcode, 2);
    assert.equal(uplink.count(), protectedHits); checks.push('down-tunnel-servfail-no-direct-fallback');
    ip('link', 'delete', 'cvpntun'); deletedTun = true;
    for (const tcp of [false, true]) await assert.rejects(query(ingress || lan ? 'peer' : null, tcp, '10.123.0.1', 250));
    assert.equal(uplink.count(), protectedHits); checks.push('deleted-tunnel-no-dnat-escape');
    await stub.close({ restore: !journaled }); stub = null;
    if (journal) {
      // Runtime abnormal close released the flock but retained the journal.
      journal = openTunnelDnsJournal();
      journal.restore(); assert.equal(journal.state.stage, 'released');
      journal.restore(); journal.release(); journal = null;
    }
    while (installed.length) {
      const op = installed.shift();
      if (deletedTun && op.file === 'ip' && op.remove.includes('route') && op.remove.includes('cvpntun')) continue;
      run(op.file, op.remove);
    }
    for (const tcp of [false, true]) assert.equal((await query(null, tcp)).answer, 30);
    checks.push('explicit-cleanup-restores-baseline');
    return { status: 'passed', hostNetworkChanged: false, transportEncryptionTested: false, scope: ingress ? 'ingress' : lan ? 'lan' : 'host', checks };
  } catch (error) {
    error.message = `after [${checks.join(', ')}]: ${error.message}`;
    console.error(run('iptables-save', ['-c']));
    console.error(ip('-6', 'route', 'show', 'table', 'all'));
    console.error(ip('-6', 'neigh', 'show'));
    if (ingress || lan) console.error(at('peer', 'ip', '-6', 'route', 'show'));
    console.error(at('uplink', 'ip', '-6', 'route', 'show'));
    throw error;
  } finally {
    await stub?.close();
    journal?.release();
    for (const child of children) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      const closed = once(child, 'close'); child.kill('SIGKILL'); await closed;
    }
    // Namespace init lifetime removes any residual rules. Never flush host state.
  }
}
