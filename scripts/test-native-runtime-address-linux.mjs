#!/usr/bin/env node
// Full runtime owner, native TLS discovery and packet traffic in a fresh,
// explicitly marked NIC-less disposable Linux systemd container only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';
const run=(c,a,o={})=>execFileSync(c,a,{encoding:'utf8',timeout:20000,maxBuffer:1048576,stdio:['ignore','pipe','pipe'],...o}).trim();
const ip=(...a)=>run('ip',a),ns=(n,...a)=>{if(a[0]==='ping'){a.shift();const six=a.includes('-6');a=a.filter(x=>x!=='-6');a.unshift('busybox',six?'ping6':'ping');}return ip('netns','exec',n,...a);};
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.env.CVPN_DISPOSABLE_ADDRESS_OWNER,'1');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']);assert.equal(ip('netns','list'),'');
const beforeResolv=fs.readFileSync('/etc/resolv.conf'),beforeRules=run('iptables-save',[]),beforeRules6=run('ip6tables-save',[]);
const root=fs.mkdtempSync('/var/lib/address-owner-'),parent=fs.readlinkSync('/proc/self/ns/net'),engine='/native/clean-vpn-engine';
const runtime=fileURLToPath(new URL('./clean-vpn-native-runtime.mjs',import.meta.url)),resolver=fileURLToPath(new URL('./clean-vpn-native-peer-dns.mjs',import.meta.url));
const children=[],namespaces=[],states=[],checks=[];let client,exit,passed=false;
const mark=x=>{checks.push(x);console.log('ADDRESS_OWNER_CHECK '+x);};
const put=(file,v)=>fs.writeFileSync(root+'/'+file,Buffer.isBuffer(v)||typeof v==='string'?v:JSON.stringify(v),{mode:0o600});
const child=(n,cmd,args,tag)=>{const fd=fs.openSync(root+'/'+tag+'.log','w',0o600),p=spawn('ip',['netns','exec',n,cmd,...args],{stdio:['ignore',fd,fd]});fs.closeSync(fd);p.on('error',()=>{});children.push(p);return p;};
const stop=async p=>{if(!p||p.exitCode!==null||p.signalCode!==null)return;p.kill('SIGTERM');for(let i=0;i<80&&p.exitCode===null&&p.signalCode===null;i++)await delay(25);if(p.exitCode===null&&p.signalCode===null){p.kill('SIGKILL');await delay(100);throw Error('engine_stop_deadline');}};
const wait=async fn=>{let error;for(let i=0;i<80;i++){try{return fn();}catch(e){error=e;await delay(100);}}throw error;};
const state=n=>'/run/clean-vpn-'+n;
const owner=(n,file,discovery=false)=>{if(!states.includes(state(n)))states.push(state(n));return ns(n,'env','CVPN_PARENT_NETNS='+parent,'CVPN_ENGINE='+engine,'CVPN_STATE_DIRECTORY='+state(n),'CVPN_UPLINK=wan0',...(discovery?['CVPN_ADDRESS_DISCOVERY=1']:[]),'node',runtime,root+'/'+file);};
const link=(name,last)=>{ip('netns','add',name);namespaces.push(name);ip('-n',name,'link','set','lo','up');ip('link','add',name+'h','type','veth','peer','name',name+'p');ip('link','set',name+'h','master','cvaobr');ip('link','set',name+'h','up');ip('link','set',name+'p','netns',name);ip('-n',name,'link','set',name+'p','name','wan0');ip('-n',name,'addr','add','192.0.2.'+last+'/24','dev','wan0');ip('-n',name,'-6','addr','add','fd42:99::'+last+'/64','dev','wan0','nodad');ip('-n',name,'link','set','wan0','up');ip('-n',name,'route','add','default','via',last===3?'192.0.2.1':'192.0.2.3');};
const tun=n=>JSON.parse(ns(n,'ip','-j','addr','show','cvpn0'))[0];
// TUN carrier drops when its engine FD closes; that transient flag is not a route mutation.
const routes=n=>JSON.parse(ns(n,'ip','-j','route')).map(r=>({...r,flags:r.flags.filter(f=>f!=='linkdown')}));
const digest=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const query=(n,address,name='laptop.mpn')=>ns(n,'dig','@'+address,'-p','1053',name,'A','+short','+time=2','+tries=1');
const online=async(n,address)=>wait(()=>{assert.equal(query(n,address),address);assert.match(ns(n,'ping','-I','cvpn0','-c','1','-W','1','1.1.1.1'),/1 (?:packets )?received/);});
try{
 ip('link','add','cvaobr','type','bridge');ip('link','set','cvaobr','up');for(const[n,last]of[['aoclient',2],['aoexit',1],['aoorigin',3],['aobad',4]])link(n,last);
 ns('aoexit','sysctl','-w','net.ipv4.ip_forward=1');ip('-n','aoorigin','addr','add','1.1.1.1/32','dev','lo');ip('-n','aoorigin','addr','add','8.8.8.8/32','dev','lo');
 // Reachable positive controls before guard installation, then the same
 // attempts must fail behind the failed-discovery bootstrap guard.
 assert.match(ns('aobad','ping','-c','1','-W','1','192.0.2.3'),/1 (?:packets )?received/);assert.match(ns('aobad','ping','-6','-c','1','-W','1','fd42:99::3'),/1 (?:packets )?received/);mark('IPv4 and IPv6 direct egress positive controls');
 run('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=assignment.test','-addext','subjectAltName=DNS:assignment.test','-keyout',root+'/key.pem','-out',root+'/cert.pem']);put('peer.key',randomBytes(32));put('wrong.key',randomBytes(32));
 const common={version:1,address:'192.0.2.1',port:3443,tun:'cvpn0'};
 const clientConfig={...common,role:'client',dns:true,address_assignment:'v1',server_name:'assignment.test',ca:root+'/cert.pem',secret_path:root+'/peer.key',connection_mode:'persistent'};
 const exitConfig={...common,role:'exit',private_peer_dns:true,peers:[{ipv4:'10.99.0.17',secret_path:root+'/peer.key'}],cert:root+'/cert.pem',key:root+'/key.pem'};
 put('client.json',clientConfig);put('bad.json',{...clientConfig,secret_path:root+'/wrong.key'});put('exit.json',exitConfig);put('registry.json',{version:1,revision:0,clients:[{name:'laptop',ipv4:'10.99.0.17',revoked:false}]});
 owner('aoexit','exit.json');exit=child('aoexit',engine,['--config',state('aoexit')+'/engine.json','--service'],'exit');child('aoexit','node',[resolver,'run','--registry='+root+'/registry.json'],'registry');
 await wait(()=>assert.match(fs.readFileSync(root+'/exit.log','utf8'),/"state":"listening"/));
 assert.ok(!JSON.parse(ns('aoclient','ip','-j','link')).some(l=>l.ifname==='cvpn0'));
 const ownerOutput=owner('aoclient','client.json',true);assert.match(ownerOutput,/"phase":"guarded"/);
 const effective=JSON.parse(fs.readFileSync(state('aoclient')+'/engine.json'));assert.equal(effective.peer_ipv4,'10.99.0.17');assert.equal(effective.address_assignment,'v1');assert.equal(JSON.parse(fs.readFileSync(root+'/client.json')).peer_ipv4,undefined);
 assert.equal(JSON.parse(fs.readFileSync(state('aoclient')+'/assignment.json')).phase,'complete');const firstTun=tun('aoclient');assert.deepEqual(firstTun.addr_info.filter(x=>x.family==='inet').map(x=>x.local),['10.99.0.17']);mark('fresh runtime verifies assignment .17 before TUN and keeps source config unchanged');
 client=child('aoclient',engine,['--config',state('aoclient')+'/engine.json','--service'],'client');await online('aoclient','10.99.0.17');
 fs.mkdirSync('/etc/netns/aoclient',{recursive:true});fs.writeFileSync('/etc/netns/aoclient/resolv.conf','nameserver 9.9.9.9\noptions timeout:1 attempts:1\n');fs.writeFileSync('/etc/netns/aoclient/nsswitch.conf','hosts: files dns\n');assert.match(ns('aoclient','getent','ahostsv4','laptop.mpn'),/10\.99\.0\.17/);mark('assigned address carries native TUN ping DNS and ordinary client NSS');
 await stop(client);const routeBefore=routes('aoclient'),assignmentBefore=digest(state('aoclient')+'/assignment.json');owner('aoclient','client.json',true);assert.equal(tun('aoclient').ifindex,firstTun.ifindex);assert.deepEqual(routes('aoclient'),routeBefore);assert.equal(digest(state('aoclient')+'/assignment.json'),assignmentBefore);client=child('aoclient',engine,['--config',state('aoclient')+'/engine.json','--service'],'client-restart');await online('aoclient','10.99.0.17');mark('clean engine restart reconfirms same IP and preserves TUN ifindex and routes');
 await stop(client);const before={assignment:digest(state('aoclient')+'/assignment.json'),network:digest(state('aoclient')+'/network.json'),engine:digest(state('aoclient')+'/engine.json')};
 exitConfig.peers[0].ipv4='10.99.0.23';fs.writeFileSync(state('aoexit')+'/engine.next',JSON.stringify(exitConfig),{mode:0o600});fs.renameSync(state('aoexit')+'/engine.next',state('aoexit')+'/engine.json');exit.kill('SIGHUP');await wait(()=>assert.match(fs.readFileSync(root+'/exit.log','utf8'),/"event":"peer_reload"/));
 put('registry-next.json',{version:1,revision:1,clients:[{name:'laptop',ipv4:'10.99.0.23',revoked:false}]});fs.renameSync(root+'/registry-next.json',root+'/registry.json');
 assert.throws(()=>owner('aoclient','client.json',true),e=>e.stderr.includes('assignment_changed_recreate_required'));for(const key of ['assignment','network','engine'])assert.equal(digest(state('aoclient')+'/'+key+'.json'),before[key]);assert.equal(tun('aoclient').ifindex,firstTun.ifindex);assert.equal(tun('aoclient').addr_info.find(x=>x.family==='inet').local,'10.99.0.17');mark('reassignment .23 refuses existing namespace without stale rewrite');
 const badStarted=performance.now();assert.throws(()=>owner('aobad','bad.json',true),e=>e.stderr.includes('assignment_discovery_failed'));assert.ok(performance.now()-badStarted<15000);assert.ok(!JSON.parse(ns('aobad','ip','-j','link')).some(l=>l.ifname==='cvpn0'));assert.equal(fs.existsSync(state('aobad')+'/engine.json'),false);assert.equal(fs.existsSync(state('aobad')+'/network.json'),false);
 for(const command of [['ping','-c','1','-W','1','192.0.2.3'],['ping','-6','-c','1','-W','1','fd42:99::3']])assert.throws(()=>ns('aobad',...command));for(const command of ['iptables-save','ip6tables-save']){const rules=ns('aobad',command);assert.match(rules,/-A OUTPUT -j CVPN_A_OUTPUT/);assert.match(rules,/-A CVPN_A_OUTPUT -j DROP/);assert.doesNotMatch(rules,/CVPN_R_/);}mark('wrong PSK leaves no TUN or effective config and blocks IPv4 IPv6 direct egress');
 link('aofresh',5);owner('aofresh','client.json',true);assert.equal(tun('aofresh').addr_info.find(x=>x.family==='inet').local,'10.99.0.23');child('aofresh',engine,['--config',state('aofresh')+'/engine.json','--service'],'fresh');await online('aofresh','10.99.0.23');mark('fresh namespace safely adopts reassigned .23 and repeats full session proof');
 passed=true;
}finally{
 if(!passed){for(const name of ['exit','client','client-restart','fresh','registry'])try{console.error(name+': '+fs.readFileSync(root+'/'+name+'.log','utf8').slice(-4000));}catch{};for(const n of namespaces)try{console.error(n+' '+ns(n,'ip','route')+' '+ns(n,'iptables-save'));}catch{}}
 for(const p of [...children].reverse())try{await stop(p);}catch{}
 for(const n of namespaces.reverse()){fs.rmSync('/etc/netns/'+n,{recursive:true,force:true});ip('netns','delete',n);}try{ip('link','delete','cvaobr');}catch{}for(const s of states)fs.rmSync(s,{recursive:true,force:true});fs.rmSync(root,{recursive:true,force:true});
}
await wait(()=>assert.deepEqual(JSON.parse(ip('-j','link')).map(x=>x.ifname),['lo']));assert.equal(ip('netns','list'),'');assert.deepEqual(fs.readFileSync('/etc/resolv.conf'),beforeResolv);
const canonical=s=>s.split('\n').filter(l=>!l.startsWith('#')).join('\n');assert.equal(canonical(run('iptables-save',[])),canonical(beforeRules));assert.equal(canonical(run('ip6tables-save',[])),canonical(beforeRules6));mark('owned namespaces TUN processes and state removed with parent DNS firewall unchanged');
console.log(JSON.stringify({status:'passed',checks:checks.length,labels:checks,engineSha256:digest(engine),scope:'NIC-less disposable Linux; no physical hosts or host network changes'}));
