#!/usr/bin/env node
// Explicit NIC-less disposable container only. Tests pre-TUN OUTPUT guard window.
import assert from 'node:assert/strict';import fs from 'node:fs';import dgram from 'node:dgram';import {execFileSync} from 'node:child_process';
import {runtimePlan,restoreTable,auditRuntimeTables} from './lib/native-runtime-plan.mjs';
assert.equal(process.env.CVPN_EMPTY_NETNS_TEST,'1');assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
const run=(c,a,input)=>execFileSync(c,a,{input,encoding:'utf8',timeout:10000});
assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(l=>l.ifname),['lo']);
const config={version:1,role:'client',dns:true,address:'192.0.2.2',port:443,tun:'cvpn0'};
const plan=runtimePlan(config),tables=plan.tables.filter(t=>t.family===4),counts=()=>run('iptables-nft-save',['-c','-t','filter']);
let created=false;
try{
 run('ip',['link','add','eth0','type','dummy']);created=true;run('ip',['addr','add','192.0.2.3/24','dev','eth0']);run('ip',['link','set','eth0','up']);run('ip',['route','add','default','via','192.0.2.1','dev','eth0']);
 for(const t of tables)run('iptables-nft-restore',['--noflush'],restoreTable(t));
 auditRuntimeTables({...plan,tables},Object.fromEntries(tables.map(t=>[`4/${t.name}`,run('iptables-nft-save',['-t',t.name])])));
 const socket=dgram.createSocket('udp4');await new Promise((resolve,reject)=>{socket.send(Buffer.from('12340100000100000000000003707265076578616d706c650000010001','hex'),53,'1.1.1.1',e=>{socket.close();e&&e.code!=='EPERM'?reject(e):resolve();});});
 await new Promise(r=>setTimeout(r,50));const state=counts();const translated=state.split('\n').filter(l=>l.includes('-A CVPN_R_OUTPUT ')&&l.includes('--dport 1053'));assert.equal(translated.length,2);for(const line of translated){assert.match(line,/^\[0:0\]/);assert.match(line,/--dst-type LOCAL/);}
 const dropped=state.split('\n').find(l=>l.includes('-A CVPN_R_OUTPUT -j DROP'));assert.ok(Number(/^\[(\d+):/.exec(dropped)?.[1])>=1,'pre_tun_DNS_dropped');
 assert.ok(!JSON.parse(run('ip',['-j','link'])).some(l=>l.ifname==='cvpn0'));
 console.log(JSON.stringify({status:'passed',checks:['canonical-rule-audit','pre-TUN-DNS-DNAT-is-not-LOCAL-and-is-dropped'],scope:'NIC-less private namespace; no host routes or firewall'}));
}finally{for(const t of tables){for(const e of t.entries){try{run('iptables-nft',['-t',t.name,'-D',e.hook,'-j',e.chain]);run('iptables-nft',['-t',t.name,'-F',e.chain]);run('iptables-nft',['-t',t.name,'-X',e.chain]);}catch{}}}if(created)run('ip',['link','delete','eth0']);}
assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(l=>l.ifname),['lo']);
