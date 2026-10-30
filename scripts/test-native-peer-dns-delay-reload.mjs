#!/usr/bin/env node
// Opt-in NIC-less Linux fixture: real TUN/TLS, netem and bounded DNS faults.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync,execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
import {nativeNetworkPlan} from './lib/native-network-profile.mjs';
const run=(c,a,o={})=>(execFileSync(c,a,{encoding:'utf8',timeout:10000,maxBuffer:1048576,...o})?.trim() ?? ''),exec=promisify(execFile);
const ip=(...a)=>run('ip',a),ns=(n,...a)=>ip('netns','exec',n,...a);
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.env.CVPN_DISPOSABLE_HOST_NET,'1');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');
assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']);assert.equal(ip('netns','list'),'');
const engine=process.env.CVPN_ENGINE;assert.ok(engine?.startsWith('/'));
const transport=process.env.CVPN_DNS_TRANSPORT??'boring-tls';assert.ok(['boring-tls','combo-tls'].includes(transport));
const pressure=process.env.CVPN_DNS_CPU_PRESSURE==='1';
const root=fs.mkdtempSync('/var/lib/dns-delay-'),children=[],spaces=[],results=[],checks=[];
const put=(name,data)=>fs.writeFileSync(root+'/'+name,typeof data==='string'?data:JSON.stringify(data),{mode:0o600});
const atomic=(name,data)=>{put(name+'.next',data);fs.renameSync(root+'/'+name+'.next',root+'/'+name);};
const start=(space,command,args,tag)=>{const fd=fs.openSync(root+'/'+tag+'.log','w',0o600),p=spawn('ip',['netns','exec',space,command,...args],{stdio:['ignore',fd,fd]});fs.closeSync(fd);children.push(p);return p;};
const stop=async p=>{if(p.exitCode!==null||p.signalCode!==null)return;p.kill('SIGTERM');for(let i=0;i<40&&p.exitCode===null&&p.signalCode===null;i++)await delay(50);if(p.exitCode===null&&p.signalCode===null){p.kill('SIGKILL');for(let i=0;i<40&&p.exitCode===null&&p.signalCode===null;i++)await delay(50);assert.ok(p.exitCode!==null||p.signalCode!==null,'child must exit before namespace removal');}};
const wait=async fn=>{let error;for(let i=0;i<100;i++){try{return fn();}catch(e){error=e;await delay(50);}}throw error;};
const mark=x=>{checks.push(x);console.log('DNS_DELAY_CHECK '+x);};
let passed=false,report;
const rounds=Number(process.env.CVPN_DNS_RELOAD_ROUNDS??24);assert.ok(Number.isInteger(rounds)&&rounds>=8&&rounds<=64);
const cpuBefore=fs.readFileSync('/sys/fs/cgroup/cpu.stat','utf8');
try{
 ip('link','add','ddbridge','type','bridge');ip('link','set','ddbridge','up');
 for(const [name,address]of[['ddclient','192.0.2.2'],['ddexit','192.0.2.1'],['ddorigin','192.0.2.3']]){
  ip('netns','add',name);spaces.push(name);ip('-n',name,'link','set','lo','up');ip('link','add',name+'h','type','veth','peer','name',name+'p');ip('link','set',name+'h','master','ddbridge');ip('link','set',name+'h','up');ip('link','set',name+'p','netns',name);ip('-n',name,'link','set',name+'p','name','wan0');ip('-n',name,'addr','add',address+'/24','dev','wan0');ip('-n',name,'link','set','wan0','up');
 }
 for(const [name,role,address]of[['ddclient','client','10.99.0.2/32'],['ddexit','exit','10.99.0.1/24']]){
  const p=nativeNetworkPlan({version:1,role,tun:'cvpn0',tun_address:address,mtu:1400,uplink:'wan0',endpoint:'192.0.2.1',port:3443,lan:null,...(role==='exit'?{private_peer_dns:true}:{})});
  for(const a of p.tun)ip('-n',name,...a);
  run('ip',['netns','exec',name,'iptables-restore'],{input:p.ipv4+p.nat+p.mangle});run('ip',['netns','exec',name,'ip6tables-restore'],{input:p.ipv6});
 }
 ip('-n','ddclient','route','add','default','dev','cvpn0');ip('-n','ddexit','route','add','default','via','192.0.2.3');ns('ddexit','sysctl','-w','net.ipv4.ip_forward=1');
 ip('-n','ddorigin','route','add','10.99.0.0/24','via','192.0.2.1');for(const a of ['1.1.1.1','8.8.8.8'])ip('-n','ddorigin','addr','add',a+'/32','dev','lo');
 run('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=delay.test','-addext','subjectAltName=DNS:delay.test','-keyout',root+'/key.pem','-out',root+'/cert.pem'],{stdio:['ignore','ignore','pipe']});
 for(const name of ['laptop','canary','rotated'])fs.writeFileSync(root+'/'+name+'.key',randomBytes(32),{mode:0o600});
 const common={version:1,address:'192.0.2.1',port:3443,tun:'cvpn0'},peer={ipv4:'10.99.0.2',secret_path:root+'/laptop.key'},canary={ipv4:'10.99.0.3',secret_path:root+'/canary.key'};
 const config={...common,role:'exit',private_peer_dns:true,peers:[peer,canary],cert:root+'/cert.pem',key:root+'/key.pem'};
 fs.writeFileSync(root+'/relay.key',randomBytes(32),{mode:0o600});fs.mkdirSync(root+'/replay',{mode:0o700});
 const wrap=(role,packet)=>transport==='combo-tls'?{version:1,transport,role,boring:{...packet,...(role==='client'?{sni:'relay.example'}:{})},transparent:{version:1,transport:'transparent-tls',role,public_name:'relay.example',secret_path:root+'/relay.key',destinations:[{ipv4:'11.22.33.44',port:443}],listen:{ipv4:role==='client'?'127.0.0.1':'192.0.2.1',port:role==='client'?10443:3443},...(role==='client'?{exit:{ipv4:'192.0.2.1',port:3443}}:{replay_directory:root+'/replay'})}}:packet;
 put('exit.json',wrap('exit',config));put('client.json',wrap('client',{...common,role:'client',dns:true,peer_ipv4:peer.ipv4,secret_path:peer.secret_path,server_name:'delay.test',ca:root+'/cert.pem'}));
 if(transport==='combo-tls')run(engine,['--init-transparent-replay',root+'/exit.json']);
 put('registry.json',{version:1,revision:1,clients:[{name:'laptop',ipv4:'10.99.0.2',revoked:false},{name:'canary',ipv4:'10.99.0.3',revoked:false}]});put('delay.json',{milliseconds:0});
 const resolver=fileURLToPath(new URL('./lib/native-peer-dns.mjs',import.meta.url)),wire=fileURLToPath(new URL('./lib/lab-dns-wire.mjs',import.meta.url));
 // Proxy has at most 16 active requests, 4KiB frames and 2s deadline. This
 // changes only a disposable fixture's loopback upstream, never production.
 put('backend.mjs',`import fs from 'node:fs';import dgram from 'node:dgram';import net from 'node:net';import {startPeerDns} from ${JSON.stringify(resolver)};
 const root=${JSON.stringify(root)};await startPeerDns({registry:root+'/registry.json',port:1056});let pending=0;const timers=new Set();
 const upstream=(q,done)=>{if(pending>=16)return done(null);pending++;const u=dgram.createSocket('udp4');let finished=false;const finish=a=>{if(finished)return;finished=true;clearTimeout(deadline);u.close();pending--;done(a);};const deadline=setTimeout(()=>finish(null),2000);u.on('error',()=>finish(null));u.on('message',a=>{const ms=JSON.parse(fs.readFileSync(root+'/delay.json')).milliseconds;fs.appendFileSync(root+'/backend-events.jsonl',JSON.stringify({at:Date.now(),rcode:a[3]&15,delayMs:ms})+'\\n');const t=setTimeout(()=>{timers.delete(t);finish(a);},ms);timers.add(t);});u.send(q,1056,'127.0.0.1');};
 const udp=dgram.createSocket('udp4');udp.on('message',(q,p)=>{if(q.length<=4096)upstream(q,a=>{if(a)udp.send(a,p.port,p.address);});});udp.bind(1055,'127.0.0.1');
 net.createServer(s=>{let b=Buffer.alloc(0),sent=false;s.setTimeout(2500,()=>s.destroy());s.on('error',()=>{});s.on('data',d=>{b=Buffer.concat([b,d]);if(b.length>4098)return s.destroy();if(!sent&&b.length>=2&&b.length===b.readUInt16BE(0)+2){sent=true;upstream(b.subarray(2),a=>{if(!a)return s.destroy();const p=Buffer.alloc(2);p.writeUInt16BE(a.length);s.end(Buffer.concat([p,a]));});}});}).listen(1055,'127.0.0.1');console.log('BACKEND_READY');`);
 put('origin.mjs',`import fs from 'node:fs';import dgram from 'node:dgram';import net from 'node:net';import{parseDnsQuery,dnsFailure}from ${JSON.stringify(wire)};
 const answer=(q,protocol)=>{const v=parseDnsQuery(q);fs.appendFileSync(${JSON.stringify(root+'/public.log')},protocol+' '+v.name+'\\n');const a=dnsFailure(q,0);a.writeUInt16BE(1,6);return Buffer.concat([a.subarray(0,v.questionEnd),Buffer.from([192,12,0,1,0,1,0,0,0,0,0,4,198,51,100,20]),a.subarray(v.questionEnd)]);};
 for(const host of ['1.1.1.1','8.8.8.8']){const s=dgram.createSocket('udp4');s.on('message',(q,p)=>s.send(answer(q,'udp'),p.port,p.address));s.bind(53,host);}
 net.createServer(s=>{let b=Buffer.alloc(0),done=false;s.setTimeout(2000,()=>s.destroy());s.on('error',()=>{});s.on('data',d=>{b=Buffer.concat([b,d]);if(b.length>4098)return s.destroy();if(!done&&b.length>=2&&b.length===b.readUInt16BE(0)+2){done=true;const a=answer(b.subarray(2),'tcp'),p=Buffer.alloc(2);p.writeUInt16BE(a.length);s.end(Buffer.concat([p,a]));}});}).listen(53,'0.0.0.0');`);
 start('ddexit','node',[root+'/backend.mjs'],'backend');start('ddorigin','node',[root+'/origin.mjs'],'origin');
 await wait(()=>assert.match(fs.readFileSync(root+'/backend.log','utf8'),/BACKEND_READY/));
 const exit=start('ddexit',engine,['--config',root+'/exit.json','--service'],'exit'),client=start('ddclient',engine,['--config',root+'/client.json','--service'],'client');
 await wait(()=>assert.match(fs.readFileSync(root+'/client.log','utf8'),/"state":"ready"/));
 const query=async(tcp=false,name='laptop.mpn',phase='normal')=>{const began=performance.now(),r=await exec('ip',['netns','exec','ddclient','dig','@10.99.0.2','-p','1053',name,'A','+noall','+comments','+answer','+time=4','+tries=1',...(tcp?['+tcp']:[])],{timeout:6000,maxBuffer:65536});const code=/status: ([A-Z]+)/.exec(r.stdout)?.[1];assert.ok(code,r.stdout);const result={phase,tcp,name,code,ms:Math.round(performance.now()-began)};results.push(result);return result;};
 ns('ddexit','iptables','-N','DDPUBLIC');ns('ddexit','iptables','-A','DDPUBLIC','-j','RETURN');for(const protocol of ['udp','tcp'])ns('ddexit','iptables','-I','FORWARD','1','-i','cvpn0','-p',protocol,'--dport','53','-j','DDPUBLIC');
 const attemptedPublic=()=>Number(ns('ddexit','iptables','-L','DDPUBLIC','-n','-v','-x').split('\n').find(line=>line.includes('RETURN')).trim().split(/\s+/)[0]);
 for(const tcp of [false,true])assert.equal((await query(tcp,'public.example')).code,'NOERROR');await delay(300);const publicBefore=fs.readFileSync(root+'/public.log','utf8');assert.equal(publicBefore,'udp public.example\ntcp public.example\n');const packetsBefore=attemptedPublic();assert.ok(packetsBefore>=2);
 for(const name of ['ddclient','ddexit'])ns(name,'tc','qdisc','add','dev','wan0','root','netem','delay','40ms','10ms','distribution','normal');
 if(pressure)start('ddexit','node',['-e','setInterval(()=>{const end=performance.now()+20;while(performance.now()<end){}},50)'],'cpu-pressure');
 mark('two-way netem40±10ms and working public positive control');
 let revision=0;const reload=async peers=>{atomic('exit.json',wrap('exit',{...config,peers}));exit.kill('SIGHUP');const expected=++revision;await wait(()=>{const events=fs.readFileSync(root+'/exit.log','utf8').split('\n').filter(x=>x.includes('"event":"peer_reload"')).map(JSON.parse);assert.equal(events.at(-1)?.revision,expected);assert.equal(events.at(-1)?.status,'applied');});};
 // Separate native reload from registry publication: any NOERROR failure here
 // is unexpected. The deliberate pending journal is checked in a later phase.
 for(let round=0;round<rounds;round++){
  const tasks=[0,1].map(async()=>{for(const tcp of [false,true])assert.equal((await query(tcp,'laptop.mpn','concurrent-reload')).code,'NOERROR');});
  await delay(20);await reload(round%3===0?[peer]:[peer,{...canary,secret_path:root+'/'+(round%2?'rotated':'canary')+'.key'}]);await Promise.all(tasks);
 }
 assert.equal(client.exitCode,null);assert.equal(exit.exitCode,null);assert.equal((fs.readFileSync(root+'/client.log','utf8').match(/"state":"ready"/g)||[]).length,1);
 mark(`${rounds*4} concurrent same-peer UDP/TCP queries survive ${rounds} canary rotations/revokes without session restart`);
 put('transaction.json',{});for(const tcp of [false,true])assert.equal((await query(tcp,'laptop.mpn','pending-registry')).code,'SERVFAIL');fs.unlinkSync(root+'/transaction.json');
 for(const tcp of [false,true])assert.equal((await query(tcp,'laptop.mpn','after-registry')).code,'NOERROR');mark('intentional pending registry fails closed and recovers');
 atomic('delay.json',{milliseconds:1450});
 for(const tcp of [false,true])assert.equal((await query(tcp,'laptop.mpn','over-deadline')).code,'SERVFAIL');
 atomic('delay.json',{milliseconds:0});await delay(1600);
 for(const tcp of [false,true])assert.equal((await query(tcp,'laptop.mpn','after-deadline')).code,'NOERROR');
 assert.equal(fs.readFileSync(root+'/public.log','utf8'),publicBefore);assert.equal(attemptedPublic(),packetsBefore);mark('1450ms backend delay exceeds unchanged1200ms deadline: SERVFAIL then same-process recovery with zero public fallback');
 const backendEvents=fs.readFileSync(root+'/backend-events.jsonl','utf8').trim().split('\n').map(JSON.parse);
 assert.equal(backendEvents.filter(x=>x.rcode===2).length,2);assert.equal(backendEvents.filter(x=>x.delayMs===1450&&x.rcode===0).length,2);
 const cpu=fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim();assert.equal(cpu,'50000 100000','run this fixture with container --cpus=0.5');
 report={kind:'private-dns-delay-reload',status:'passed',transport,cpuPressure:pressure,engineSha256:createHash('sha256').update(fs.readFileSync(process.env.CVPN_ENGINE_BINARY??engine)).digest('hex'),cpuMax:cpu,networkDelayPerDirection:'40ms±10ms',nativeReloads:revision,privatePublicFallback:0,privatePublicAttemptPackets:0,publicPositiveControlPackets:packetsBefore,results,backendResponses:backendEvents.length,backendIntentionalServfail:2,delayedGoodAnswers:2,cpuBefore,cpuAfter:fs.readFileSync('/sys/fs/cgroup/cpu.stat','utf8'),scope:'isolated '+transport+' packet branch; no transparent traffic load; does not explain historical physical combo failure'};passed=true;
}finally{
 for(const child of children.reverse())await stop(child);
 if(!passed)for(const name of ['exit','client','backend','origin']){try{console.error(name,fs.readFileSync(root+'/'+name+'.log','utf8').slice(-5000));}catch{}}
 for(const name of spaces.reverse()){assert.equal(ip('netns','pids',name),'','no process may retain fixture namespace');ip('netns','delete',name);if(JSON.parse(ip('-j','link')).some(x=>x.ifname===name+'h'))ip('link','delete',name+'h');}try{ip('link','delete','ddbridge');}catch{}
 fs.rmSync(root,{recursive:true,force:true});
}
await wait(()=>assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']));assert.equal(ip('netns','list'),'');mark('all fixture processes and network resources removed');console.log(JSON.stringify(report));
