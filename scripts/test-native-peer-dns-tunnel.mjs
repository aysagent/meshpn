#!/usr/bin/env node
// Actual native TLS packet tunnel and production dedicated network plan. Only
// the explicitly marked NIC-less disposable systemd lab may run this fixture.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { nativeNetworkPlan } from './lib/native-network-profile.mjs';
const run=(c,a,o={})=>execFileSync(c,a,{encoding:'utf8',timeout:10000,maxBuffer:1048576,...o}).trim();
const ip=(...a)=>run('ip',a), ns=(n,...a)=>ip('netns','exec',n,...a);
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.env.CVPN_DISPOSABLE_HOST_NET,'1');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');
assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']);assert.equal(ip('netns','list'),'');
const engine=process.env.CVPN_BUILD?process.env.CVPN_BUILD+'/clean-vpn-engine-dns':'/native/clean-vpn-engine-dns';
const root=fs.mkdtempSync('/var/lib/peer-tunnel-'), namespaces=[],children=[],checks=[];
const cli=fileURLToPath(new URL('./clean-vpn-native-peer-dns.mjs',import.meta.url));
const mark=x=>{checks.push(x);console.log('PEER_DNS_TUNNEL_CHECK '+x);};
const put=(f,v)=>fs.writeFileSync(root+'/'+f,typeof v==='object'?JSON.stringify(v):v,{mode:0o600});
const child=(n,cmd,args,tag)=>{const fd=fs.openSync(root+'/'+tag+'.log','w',0o600);const p=spawn('ip',['netns','exec',n,cmd,...args],{stdio:['ignore',fd,fd]});fs.closeSync(fd);p.on('error',()=>{});children.push(p);return p;};
const stop=async p=>{if(!p||p.exitCode!==null||p.signalCode!==null)return;p.kill('SIGTERM');for(let i=0;i<60&&p.exitCode===null&&p.signalCode===null;i++)await delay(50);if(p.exitCode===null&&p.signalCode===null){p.kill('SIGKILL');await delay(100);}};
const ready=async f=>{let error;for(let i=0;i<50;i++){try{return f();}catch(e){error=e;await delay(100);}}throw error;};
const dig=(n,name,tcp=false,server='10.99.0.2',port=1053)=>ns(n,'dig','@'+server,'-p',String(port),name,'A','+noall','+comments','+answer','+time=3','+tries=1',...(tcp?['+tcp']:[]));
const counts=()=>fs.existsSync(root+'/public.log')?fs.readFileSync(root+'/public.log','utf8').trim().split('\n').filter(Boolean):[];
const registry=revoked=>({version:1,revision:revoked?2:1,clients:[{name:'laptop',ipv4:'10.99.0.2',revoked},{name:'tablet',ipv4:'10.99.0.3',revoked:false}]});
let backend,exit,client,passed=false;
try{
 ip('link','add','cvpdbr','type','bridge');ip('link','set','cvpdbr','up');
 for(const [name,address]of[['pdclient','192.0.2.2'],['pdexit','192.0.2.1'],['pdorigin','192.0.2.3']]){
  ip('netns','add',name);namespaces.push(name);ip('-n',name,'link','set','lo','up');ip('link','add',name+'h','type','veth','peer','name',name+'p');ip('link','set',name+'h','master','cvpdbr');ip('link','set',name+'h','up');ip('link','set',name+'p','netns',name);ip('-n',name,'link','set',name+'p','name','wan0');ip('-n',name,'addr','add',address+'/24','dev','wan0');ip('-n',name,'link','set','wan0','up');
 }
 for(const a of ['1.1.1.1','8.8.8.8'])ip('-n','pdorigin','addr','add',a+'/32','dev','lo');
 ip('-n','pdexit','route','add','default','via','192.0.2.3');ns('pdexit','sysctl','-w','net.ipv4.ip_forward=1');
 for(const [name,role,address]of[['pdclient','client','10.99.0.2/32'],['pdexit','exit','10.99.0.1/24']]){
  const p=nativeNetworkPlan({version:1,role,tun:'cvpn0',tun_address:address,mtu:1400,uplink:'wan0',endpoint:'192.0.2.1',port:3443,lan:null,...(role==='exit'?{private_peer_dns:true}:{})});
  for(const args of p.tun)ip('-n',name,...args);
  for(const [command,text]of[['iptables-restore',p.ipv4+p.nat+p.mangle],['ip6tables-restore',p.ipv6]])run('ip',['netns','exec',name,command],{input:text});
 }
 ip('-n','pdclient','route','add','default','dev','cvpn0');ip('-n','pdorigin','route','add','10.99.0.0/24','via','192.0.2.1');
 run('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=peer.test','-addext','subjectAltName=DNS:peer.test','-keyout',root+'/key.pem','-out',root+'/cert.pem']);
 fs.writeFileSync(root+'/peer.key',randomBytes(32),{mode:0o600});put('registry.json',registry(false));
 const common={version:1,address:'192.0.2.1',port:3443,tun:'cvpn0'},peer={ipv4:'10.99.0.2',secret_path:root+'/peer.key'};
 const exitConfig={...common,role:'exit',private_peer_dns:true,peers:[peer],cert:root+'/cert.pem',key:root+'/key.pem'};
 put('exit.json',exitConfig);put('client.json',{...common,role:'client',dns:true,peer_ipv4:'10.99.0.2',secret_path:root+'/peer.key',server_name:'peer.test',ca:root+'/cert.pem'});
 for(const file of ['exit.json','client.json'])run(engine,['--check-config',root+'/'+file]);
 for(const value of [true,false]){put('invalid.json',{...JSON.parse(fs.readFileSync(root+'/client.json')),private_peer_dns:value});assert.throws(()=>run(engine,['--check-config',root+'/invalid.json']));}put('invalid.json',{...exitConfig,private_peer_dns:'yes'});assert.throws(()=>run(engine,['--check-config',root+'/invalid.json']));mark('private DNS config is boolean and exit-only');
 const wire=fileURLToPath(new URL('./lib/lab-dns-wire.mjs',import.meta.url));
 put('origin.mjs',`import fs from 'node:fs';import dgram from 'node:dgram';import net from 'node:net';import {parseDnsQuery,dnsFailure} from ${JSON.stringify(wire)};const answer=q=>{const p=parseDnsQuery(q);fs.appendFileSync(${JSON.stringify(root+'/public.log')},p.name+'\\n');const a=dnsFailure(q,0);a.writeUInt16BE(1,6);return Buffer.concat([a.subarray(0,p.questionEnd),Buffer.from([192,12,0,1,0,1,0,0,0,0,0,4,198,51,100,20]),a.subarray(p.questionEnd)]);};for(const address of ['1.1.1.1','8.8.8.8']){const u=dgram.createSocket('udp4');u.on('message',(q,r)=>{try{u.send(answer(q),r.port,r.address);}catch{}});u.bind(53,address);}net.createServer(s=>{let b=Buffer.alloc(0);s.setTimeout(2000,()=>s.destroy());s.on('data',d=>{b=Buffer.concat([b,d]);if(b.length>4098)return s.destroy();if(b.length>=2&&b.length===b.readUInt16BE(0)+2){try{const a=answer(b.subarray(2)),p=Buffer.alloc(2);p.writeUInt16BE(a.length);s.end(Buffer.concat([p,a]));}catch{s.destroy();}}});}).listen(53,'0.0.0.0');`);
 child('pdorigin','node',[root+'/origin.mjs'],'origin');backend=child('pdexit','node',[cli,'run','--registry='+root+'/registry.json'],'registry');
 exit=child('pdexit',engine,['--config',root+'/exit.json','--service'],'exit');client=child('pdclient',engine,['--config',root+'/client.json','--service'],'client');
 await ready(()=>assert.match(dig('pdclient','laptop.mpn'),/10\.99\.0\.2/));mark('native authenticated TLS tunnel resolves registry name');
 for(const tcp of [false,true])assert.match(dig('pdclient','public.example',tcp),/198\.51\.100\.20/);assert.equal(counts().length,2);mark('both public upstream transports have positive control');
 const before=counts();
 for(const tcp of [false,true])assert.match(dig('pdclient','public.example',tcp,'10.99.0.1',1055),/REFUSED/);assert.deepEqual(counts(),before);mark('authenticated peer cannot use private bridge as recursive DNS');
 for(const tcp of [false,true])assert.match(dig('pdclient','tablet.mpn',tcp),/10\.99\.0\.3/);
 fs.mkdirSync('/etc/netns/pdclient',{recursive:true});fs.writeFileSync('/etc/netns/pdclient/resolv.conf','nameserver 9.9.9.9\noptions timeout:1 attempts:1\n');fs.writeFileSync('/etc/netns/pdclient/nsswitch.conf','hosts: files dns\n');
 assert.match(ns('pdclient','getent','ahostsv4','laptop.mpn'),/10\.99\.0\.2/);assert.match(ns('pdclient','getent','hosts','10.99.0.3'),/tablet\.mpn/);mark('ordinary client NSS and PTR traverse native DNS tunnel');
 for(const tcp of [false,true])assert.match(dig('pdclient','missing.mpn',tcp),/NXDOMAIN/);
 fs.writeFileSync(root+'/transaction.json','{}',{mode:0o600});assert.match(dig('pdclient','laptop.mpn'),/SERVFAIL/);fs.unlinkSync(root+'/transaction.json');mark('NXDOMAIN and pending registry transaction never reach public DNS');
 put('registry.next',registry(true));fs.renameSync(root+'/registry.next',root+'/registry.json');assert.match(dig('pdclient','laptop.mpn'),/NXDOMAIN/);mark('registry revoke visible across real tunnel without restart');
 await stop(backend);for(const tcp of [false,true])assert.match(dig('pdclient','tablet.mpn',tcp),/SERVFAIL/);assert.deepEqual(counts(),before);mark('private resolver outage has zero public fallback');
 backend=child('pdexit','node',[cli,'run','--registry='+root+'/registry.json'],'registry-restart');await ready(()=>assert.match(dig('pdclient','tablet.mpn'),/10\.99\.0\.3/));
 assert.throws(()=>dig('pdorigin','tablet.mpn',true,'10.99.0.1',1055));assert.throws(()=>dig('pdorigin','tablet.mpn',false,'192.0.2.1',1055));ip('-n','pdorigin','addr','add','10.99.0.2/32','dev','lo');
 for(const tcp of [false,true])assert.throws(()=>ns('pdorigin','dig','-b','10.99.0.2','@10.99.0.1','-p','1055','tablet.mpn','A','+time=1','+tries=1',...(tcp?['+tcp']:[])));
 ip('-n','pdorigin','addr','del','10.99.0.2/32','dev','lo');mark('WAN and spoofed authorized source cannot reach private bridge');
 const old=exit.pid;put('exit.next',{...exitConfig,peers:[]});fs.renameSync(root+'/exit.next',root+'/exit.json');exit.kill('SIGHUP');await delay(300);assert.equal(exit.pid,old);assert.match(fs.readFileSync(root+'/exit.log','utf8'),/"event":"peer_reload"/);
 assert.doesNotMatch(dig('pdclient','tablet.mpn'),/10\.99\.0\.3/);assert.deepEqual(counts(),before);mark('native revoke removes tunnel and bridge requester authorization without restart');
 passed=true;
}finally{
 if(!passed){for(const n of namespaces)console.error(n+' routes '+ns(n,'ip','route')+' rules '+ns(n,'iptables-save'));console.error('public queries '+JSON.stringify(counts()));}
 for(const p of [...children].reverse())await stop(p);
 if(!passed)for(const name of ['exit','client','registry','registry-restart','origin']){try{console.error(name+': '+fs.readFileSync(root+'/'+name+'.log','utf8').slice(-4000));}catch{}}
 for(const n of namespaces.reverse()){fs.rmSync('/etc/netns/'+n,{recursive:true,force:true});ip('netns','delete',n);}try{ip('link','delete','cvpdbr');}catch{}
 fs.rmSync(root,{recursive:true,force:true});
}
await ready(()=>assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']));assert.equal(ip('netns','list'),'');mark('all owned processes namespaces and interfaces removed');
console.log(JSON.stringify({status:'passed',checks:checks.length,labels:checks,scope:'disposable native TLS/TUN/NSS; production network plan; no physical nodes or host settings'}));
