#!/usr/bin/env node
// Independent WAN packet observer for the DNS DNAT startup/teardown window.
// Runs only inside an explicitly marked, NIC-less disposable Linux container.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {runtimePlan,restoreTable,auditRuntimeTables} from './lib/native-runtime-plan.mjs';
const run=(c,a,input)=>execFileSync(c,a,{input,encoding:'utf8',timeout:10000,stdio:['pipe','pipe','pipe']}).trim();
const ip=(...a)=>run('ip',a),ns=(name,...a)=>ip('netns','exec',name,...a);
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.env.CVPN_DNS_DNAT_WAN_TEST,'1');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
const root=fs.mkdtempSync('/var/lib/dns-dnat-wan-'),resolv=fs.readFileSync('/etc/resolv.conf'),checks=[];
const canonical=s=>s.split('\n').filter(l=>!l.startsWith('#')).join('\n');
const snapshots=Object.fromEntries(['nft','legacy'].flatMap(b=>['iptables','ip6tables'].map(p=>[`${p}-${b}-save`,canonical(run(`${p}-${b}-save`,[]))])));
const write=(name,text)=>fs.writeFileSync(root+'/'+name,text,{mode:0o600});
const wait=async fn=>{let error;for(let i=0;i<50;i++){try{return fn();}catch(e){error=e;await delay(50);}}throw error;};
const children=[];
const launch=(name,command,args,tag)=>{const fd=fs.openSync(root+'/'+tag+'.log','w',0o600);const p=spawn('ip',['netns','exec',name,command,...args],{stdio:['ignore',fd,fd]});fs.closeSync(fd);children.push(p);return p;};
const stop=async p=>{if(p.exitCode!==null||p.signalCode!==null)return;p.kill('SIGTERM');for(let i=0;i<40&&p.exitCode===null&&p.signalCode===null;i++)await delay(25);if(p.exitCode===null&&p.signalCode===null){p.kill('SIGKILL');await delay(50);}};
write('observer.py',`import socket,sys,json,os
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('wan0',0));s.settimeout(.05)
counts={'udp':0,'tcp':0}
def publish():
 with open(sys.argv[1]+'.next','w') as f: json.dump(counts,f)
 os.replace(sys.argv[1]+'.next',sys.argv[1])
publish()
while True:
 try: p=s.recv(65535)
 except socket.timeout: continue
 if len(p)>=34 and p[12:14]==b'\\x08\\x00' and p[30:34]==bytes([10,99,0,17]) and p[23] in (6,17):
  counts['tcp' if p[23]==6 else 'udp']+=1;publish()
`);
write('stub.mjs',`import dgram from 'node:dgram';import net from 'node:net';import fs from 'node:fs';
const [address,port,ready]=process.argv.slice(2);const reply=q=>{const b=Buffer.from(q);b.writeUInt16BE(0x8180,2);return b;};
const udp=dgram.createSocket('udp4');udp.on('message',(q,r)=>udp.send(reply(q),r.port,r.address));
const tcp=net.createServer(s=>{let b=Buffer.alloc(0);s.on('error',()=>{});s.on('data',c=>{b=Buffer.concat([b,c]);if(b.length>=2&&b.length>=2+b.readUInt16BE(0)){const a=reply(b.subarray(2,2+b.readUInt16BE(0))),h=Buffer.alloc(2);h.writeUInt16BE(a.length);s.end(Buffer.concat([h,a]));}});s.setTimeout(1000,()=>s.destroy());});
await Promise.all([new Promise(r=>udp.bind(+port,address,r)),new Promise(r=>tcp.listen(+port,address,r))]);fs.writeFileSync(ready,'ready');
`);
const query=(tcp,address='192.0.2.1',port=53)=>ns('dnatclient','dig','@'+address,'-p',String(port),'laptop.mpn','A','+time=1','+tries=1',...(tcp?['+tcp']:[]));
try{
 for(const backend of ['nft','legacy']){
  const local=[];let clientMade=false,originMade=false;
  try{
   ip('netns','add','dnatclient');clientMade=true;ip('netns','add','dnatorigin');originMade=true;
   ip('link','add','dnatc','type','veth','peer','name','dnato');ip('link','set','dnatc','netns','dnatclient');ip('link','set','dnato','netns','dnatorigin');
   for(const [name,iface,last]of[['dnatclient','dnatc',2],['dnatorigin','dnato',1]]){ip('-n',name,'link','set',iface,'name','wan0');ip('-n',name,'link','set','lo','up');ip('-n',name,'addr','add',`192.0.2.${last}/24`,'dev','wan0');ip('-n',name,'link','set','wan0','up');}
   ip('-n','dnatclient','route','add','default','via','192.0.2.1');ip('-n','dnatorigin','addr','add','10.99.0.17/32','dev','lo');
   const counter=root+'/'+backend+'.json';local.push(launch('dnatorigin','python3',[root+'/observer.py',counter],backend+'-observer'));
   const startStub=(name,address,port,tag)=>{const ready=root+'/'+tag+'.ready';local.push(launch(name,'node',[root+'/stub.mjs',address,String(port),ready],tag));return wait(()=>assert.ok(fs.existsSync(ready)));};
   await wait(()=>assert.deepEqual(JSON.parse(fs.readFileSync(counter)),{udp:0,tcp:0}));
   await startStub('dnatorigin','192.0.2.1',53,backend+'-upstream');await startStub('dnatorigin','10.99.0.17',1053,backend+'-leak-target');
   for(const tcp of [false,true]){assert.match(query(tcp),/status: NOERROR/);assert.match(query(tcp,'10.99.0.17',1053),/status: NOERROR/);}
   await delay(150);const baseline=JSON.parse(fs.readFileSync(counter));assert.ok(baseline.udp>=1&&baseline.tcp>=3,'raw capture positive controls');
   const plan=runtimePlan({version:1,role:'client',dns:true,peer_ipv4:'10.99.0.17',address:'192.0.2.123',port:3443,tun:'cvpn0'},{uplink:'wan0'});
   for(const table of plan.tables)run('ip',['netns','exec','dnatclient',`${table.family===6?'ip6tables':'iptables'}-${backend}-restore`,'--noflush'],restoreTable(table));
   auditRuntimeTables(plan,Object.fromEntries(plan.tables.map(t=>[`${t.family}/${t.name}`,ns('dnatclient',`${t.family===6?'ip6tables':'iptables'}-${backend}-save`,'-t',t.name)])));
   const noLeak=async phase=>{for(const tcp of [false,true])assert.throws(()=>query(tcp),phase);await delay(150);assert.deepEqual(JSON.parse(fs.readFileSync(counter)),baseline,phase+' WAN capture');checks.push(backend+': '+phase+' UDP/TCP no WAN packets');};
   await noLeak('before TUN');
   const filter=ns('dnatclient',`iptables-${backend}-save`,'-c','-t','filter');assert.match(filter,/\[[1-9][0-9]*:[0-9]+\] -A CVPN_R_OUTPUT -j DROP/);for(const line of filter.split('\n').filter(l=>l.includes('--dport 1053')))assert.match(line,/^\[0:0\]/);
   ip('-n','dnatclient','tuntap','add','dev','cvpn0','mode','tun');ip('-n','dnatclient','addr','add','10.99.0.17/32','dev','cvpn0');ip('-n','dnatclient','link','set','cvpn0','up');await startStub('dnatclient','10.99.0.17',1053,backend+'-local');
   for(const tcp of [false,true])assert.match(query(tcp),/status: NOERROR/);await delay(150);assert.deepEqual(JSON.parse(fs.readFileSync(counter)),baseline,'local stub did not emit WAN DNS');checks.push(backend+': on-link original resolver UDP/TCP reaches local TUN stub');
   ip('-n','dnatclient','link','delete','cvpn0');await noLeak('after TUN removal');
  }finally{for(const p of local.reverse())await stop(p);if(clientMade)ip('netns','delete','dnatclient');if(originMade)ip('netns','delete','dnatorigin');}
 }
}finally{for(const p of children)await stop(p);fs.rmSync(root,{recursive:true,force:true});}
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');assert.deepEqual(fs.readFileSync('/etc/resolv.conf'),resolv);
for(const [command,before]of Object.entries(snapshots))assert.equal(canonical(run(command,[])),before);
console.log(JSON.stringify({status:'passed',checks,scope:'private namespaces and synthetic WAN only; parent DNS/firewall unchanged'}));
