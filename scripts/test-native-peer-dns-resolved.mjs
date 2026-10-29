#!/usr/bin/env node
// Destructive only inside a disposable, NIC-less systemd test container. Never
// grants a host installer permission to create interfaces or change DNS.
import fs from 'node:fs';
import path from 'node:path';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { parseDnsQuery, dnsFailure } from './lib/lab-dns-wire.mjs';
import { peerDnsUnit } from './lib/native-peer-dns.mjs';
import { peerDnsZoneOperation, createPeerDnsZoneBackend } from './lib/native-peer-dns-zone.mjs';
import { peerDnsZoneUnit } from './clean-vpn-native-peer-dns-zone.mjs';
import { createDnsSystemBus } from './lib/dns-system-bus.mjs';

const exec = promisify(execFile);
const run = async (cmd, args, { allowFailure = false, timeout = 15000 } = {}) => {
  try { return { code: 0, ...(await exec(cmd, args, { timeout, maxBuffer: 65536, env: { ...process.env, LC_ALL: 'C' } })) }; }
  catch (error) { if (!allowFailure) throw error; return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }; }
};
assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
assert.equal(process.env.CVPN_DISPOSABLE_HOST_NET, '1');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab', 'utf8').trim(), 'isolated-admin-lab-v1');
assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
assert.deepEqual(JSON.parse((await run('ip', ['-j', 'link'])).stdout).map(x => x.ifname), ['lo']);
assert.equal((await run('ip', ['-4', 'route', 'show', 'default'])).stdout, '');
const root = fs.mkdtempSync('/var/lib/peer-dns-lab-'), registry = root + '/registry.json';
const cli = fileURLToPath(new URL('./clean-vpn-native-peer-dns.mjs', import.meta.url));
const unit = 'cvpn-peer-dns-test.service', unitFile = '/etc/systemd/system/' + unit;
const zoneUnit='cvpn-peer-zone-test.service', zoneFile='/etc/systemd/system/'+zoneUnit, zoneDirectory=root+'/zone';
const zoneCli=fileURLToPath(new URL('./clean-vpn-native-peer-dns-zone.mjs',import.meta.url));
const zone=args=>peerDnsZoneOperation({directory:zoneDirectory,...args});
const bus=createDnsSystemBus(run); let publicSettings, publicIndex;
assert.ok(!fs.existsSync(unitFile));
const publish = object => { fs.writeFileSync(registry + '.next', JSON.stringify(object), { mode: 0o600 }); fs.renameSync(registry + '.next', registry); };
const document = (revoked = false, name = 'laptop', revision = 1) => ({ version: 1, revision, clients: [{ name, ipv4: '10.99.0.3', revoked }] });
const checks = [], mark = name => { checks.push(name); console.log('PEER_DNS_RESOLVED_CHECK ' + name); };
const beforeNss = fs.readFileSync('/etc/nsswitch.conf'), beforeResolv = fs.readFileSync('/etc/resolv.conf');
const upstream = dgram.createSocket('udp4'), observed = [];
upstream.on('message', (query, remote) => {
  let q; try { q = parseDnsQuery(query); } catch { return; } observed.push(q.name);
  const r = dnsFailure(query, 0); r.writeUInt16BE(1, 6);
  const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 198, 51, 100, 20]);
  upstream.send(Buffer.concat([r.subarray(0, q.questionEnd), answer, r.subarray(q.questionEnd)]), remote.port, remote.address);
});
upstream.bind(1056, '127.0.0.2'); await once(upstream, 'listening');
let createdPrivate = false, createdPublic = false, started = false;
const flush = () => run('resolvectl', ['flush-caches']);
const ready = async name => { for(let i=0;i<30;i++){const r=await run('dig',['@127.0.0.1','-p','1055',name,'A','+short','+time=1','+tries=1'],{allowFailure:true,timeout:2000});if(r.stdout.trim()==='10.99.0.3')return;await delay(100);}throw Error('private_dns_not_ready');};
const query = name => run('getent', ['ahostsv4', name], { allowFailure: true, timeout: 20000 });
try {
  await run('systemctl', ['start', 'systemd-resolved']);
  publish(document()); fs.writeFileSync(unitFile, peerDnsUnit({ node: process.execPath, script: cli, registry, port: 1055 }));
  await run('systemctl', ['daemon-reload']); await run('systemctl', ['start', unit]); started = true; await ready('laptop.mpn');
  for (const [name, address, dns, domains, isDefault] of [
    ['cvpublictest', '192.0.2.253/32', '127.0.0.2:1056', [], 'true'],
  ]) {
    await run('ip', ['link', 'add', name, 'type', 'dummy']); if (name === 'cvmpntest') createdPrivate = true; else createdPublic = true;
    await run('ip', ['address', 'add', address, 'dev', name]); await run('ip', ['link', 'set', name, 'up']);
    await run('resolvectl', ['dns', name, dns]); if (domains.length) await run('resolvectl', ['domain', name, ...domains]);
    await run('resolvectl', ['default-route', name, isDefault]);
  }
  publicIndex=JSON.parse((await run('ip',['-j','link','show','cvpublictest'])).stdout)[0].ifindex;
  publicSettings=await bus.linkSnapshot(await bus.owner(),publicIndex);
  await run('resolvectl',['domain','cvpublictest','~mpn']);
  await assert.rejects(zone({}),/peer_dns_foreign_zone_conflict/); assert.equal(fs.existsSync(zoneDirectory+'/zone.json'),false);
  await run('resolvectl',['domain','cvpublictest','']); mark('foreign mpn scope refuses installation without mutation');
  await assert.rejects(zone({checkpoint:point=>{if(point==='created')throw Error('simulated_power_loss');}}),/simulated_power_loss/);
  createdPrivate=true; assert.equal((await zone({})).status,'active'); mark('real ip-link crash recovery adopts only journalled identity');
  fs.writeFileSync(zoneFile,peerDnsZoneUnit({directory:zoneDirectory,node:process.execPath,script:zoneCli}));
  await run('systemctl',['daemon-reload']); await run('systemctl',['start',zoneUnit]);
  assert.equal((await run('systemctl',['is-active',zoneUnit])).stdout.trim(),'active'); mark('notify owner unit reaches READY');
  assert.deepEqual(await bus.linkSnapshot(await bus.owner(),publicIndex),publicSettings); mark('existing public link DNS unchanged after apply');
  await flush(); const publicResult = await query('public.example'); assert.equal(publicResult.code, 0); assert.match(publicResult.stdout, /198\.51\.100\.20/); assert.ok(observed.includes('public.example')); mark('public DNS positive control');
  observed.length = 0;
  const result = await query('laptop.mpn'); assert.equal(result.code, 0); assert.match(result.stdout, /10\.99\.0\.3/); assert.deepEqual(observed, []); mark('ordinary getent uses private route only');
  const tcp = await run('dig', ['@127.0.0.53', 'laptop.mpn', 'A', '+tcp', '+short']); assert.equal(tcp.stdout.trim(), '10.99.0.3'); mark('resolved stub TCP serves private zone');
  const ptr = await run('getent', ['hosts', '10.99.0.3']); assert.match(ptr.stdout, /laptop\.mpn/); mark('private reverse lookup');
  assert.notEqual((await query('absent.mpn')).code, 0); assert.deepEqual(observed, []); mark('unknown private name never falls back to public DNS');
  const pid = (await run('systemctl', ['show', unit, '-p', 'MainPID', '--value'])).stdout.trim();
  publish(document(true, 'laptop', 2)); await flush(); assert.notEqual((await query('laptop.mpn')).code, 0); assert.deepEqual(observed, []); mark('revocation removes name without daemon restart');
  publish(document(false, 'tablet', 3)); await flush(); assert.equal((await query('tablet.mpn')).code, 0); assert.notEqual((await query('laptop.mpn')).code, 0);
  assert.equal((await run('systemctl', ['show', unit, '-p', 'MainPID', '--value'])).stdout.trim(), pid); mark('rename changes DNS with same service PID');
  fs.writeFileSync(root + '/transaction.json', '{}', { mode: 0o600 }); await flush(); assert.notEqual((await query('tablet.mpn')).code, 0); assert.deepEqual(observed, []); fs.unlinkSync(root + '/transaction.json'); mark('pending transaction SERVFAIL has no public fallback');
  fs.writeFileSync(registry, '{', { mode: 0o600 }); await flush(); assert.notEqual((await query('tablet.mpn')).code, 0); assert.deepEqual(observed, []); publish(document(false, 'tablet', 4)); mark('invalid registry SERVFAIL has no public fallback');
  await run('systemctl', ['kill', '--kill-whom=main', '--signal=KILL', unit]);
  let newPid = pid;
  for (let i = 0; i < 60; i++) { newPid = (await run('systemctl', ['show', unit, '-p', 'MainPID', '--value'])).stdout.trim(); if (newPid !== '0' && newPid !== pid) break; await delay(100); }
  assert.ok(newPid !== '0' && newPid !== pid); await ready('tablet.mpn'); await flush(); assert.equal((await query('tablet.mpn')).code, 0); assert.deepEqual(observed, []); mark('SIGKILL unit auto-restart restores answers');
  await run('systemctl', ['restart', 'systemd-resolved']); await flush(); assert.equal((await query('tablet.mpn')).code, 0); assert.deepEqual(observed, []); mark('resolved restart preserves per-link private routing'); await delay(5500); assert.equal((await zone({operation:'status'})).status,'active'); assert.equal((await run('systemctl',['is-active',zoneUnit])).stdout.trim(),'active'); mark('owner monitor survives resolved backend restart');
  const ownerPid=(await run('systemctl',['show',zoneUnit,'-p','MainPID','--value'])).stdout.trim(); await run('systemctl',['kill','--kill-whom=main','--signal=KILL',zoneUnit]);
  for(let i=0;i<60;i++){await delay(100);const now=(await run('systemctl',['show',zoneUnit,'-p','MainPID','--value'])).stdout.trim();if(now!=='0'&&now!==ownerPid&&(await run('systemctl',['is-active',zoneUnit],{allowFailure:true})).stdout.trim()==='active')break;}
  assert.equal((await run('systemctl',['is-active',zoneUnit])).stdout.trim(),'active'); assert.equal((await zone({operation:'status'})).status,'active'); mark('owner SIGKILL auto-recovery retains owned scope');
  await run('systemctl',['stop',zoneUnit]); assert.equal((await zone({operation:'status'})).status,'active'); mark('owner stop preserves private scope to prevent fallback');
  await run('systemctl', ['stop', unit]); started = false; await flush(); assert.notEqual((await query('tablet.mpn')).code, 0); assert.deepEqual(observed, []); mark('stopped private daemon cannot fall back to public DNS');
  assert.equal((await query('public-again.example')).code, 0); assert.deepEqual(observed, ['public-again.example']); mark('public DNS still works during private daemon outage');
  await run('systemctl', ['start', unit]); started = true; await ready('tablet.mpn'); await flush(); assert.equal((await query('tablet.mpn')).code, 0); mark('private daemon resumes without host DNS rewrite');
} finally {
  if (started) await run('systemctl', ['stop', unit], { allowFailure: true });
  fs.rmSync(unitFile, { force: true }); await run('systemctl', ['daemon-reload']); await run('systemctl', ['reset-failed', unit], { allowFailure: true });
  await run('systemctl',['stop',zoneUnit],{allowFailure:true}); fs.rmSync(zoneFile,{force:true}); await run('systemctl',['daemon-reload']);
  if (createdPrivate) { await zone({operation:'remove'}); assert.deepEqual(await bus.linkSnapshot(await bus.owner(),publicIndex),publicSettings); mark('explicit removal preserves foreign DNS exactly'); } if (createdPublic) await run('ip', ['link', 'delete', 'cvpublictest']);
  await new Promise(resolve => upstream.close(resolve)); fs.rmSync(root, { recursive: true, force: true });
}
assert.deepEqual(JSON.parse((await run('ip', ['-j', 'link'])).stdout).map(x => x.ifname), ['lo']);
assert.deepEqual(fs.readFileSync('/etc/nsswitch.conf'), beforeNss); assert.deepEqual(fs.readFileSync('/etc/resolv.conf'), beforeResolv); mark('owned test scopes removed, NSS/resolv.conf unchanged');
console.log(JSON.stringify({ status: 'passed', checks: checks.length, labels: checks, scope: 'disposable systemd255 container; real NSS, resolved, UDP/TCP, private/public DNS scopes; no WAN or host mutation' }));
