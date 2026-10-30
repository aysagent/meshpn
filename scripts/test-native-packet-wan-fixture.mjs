// Explicit disposable Linux gate: no physical host, no external NIC.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {createRuntimeConfig} from './clean-vpn-native-runtime-config.mjs';
const enabled=process.platform==='linux'&&process.getuid()===0&&process.env.CVPN_PACKET_WAN_FIXTURE_TEST==='1';
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const run=(c,a)=>execFileSync(c,a,{encoding:'utf8',timeout:15000,stdio:['pipe','pipe','pipe']}).trim();
for(const transport of ['boring-tls','combo-tls'])for(const relayProbe of (transport==='combo-tls'?[false,true]:[false]))for(const http of ['2','1.1'])test(`packet WAN fixture ${transport} HTTP ${http} relay=${relayProbe}`,{skip:!enabled,timeout:60000},async t=>{
 assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab','utf8').trim(),'isolated-admin-lab-v1');
 assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(x=>x.ifname),['lo']);
 const snapshot=()=>['link','addr','route','rule'].map(x=>run('ip',['-j',x,'show'])).concat(run('iptables-save',[]),run('ip6tables-save',[]),fs.readFileSync('/etc/resolv.conf','utf8'));
 const before=snapshot(),root=fs.mkdtempSync('/tmp/cvpn-packet-wan-'),directory=root+'/bundle',children=[];
 const engine=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build','clean-vpn-engine');
 const write=(file,doc)=>fs.writeFileSync(file,JSON.stringify(doc)+'\n',{mode:0o600});
 const launch=args=>{const p=spawn('python3',args);p.output='';for(const s of [p.stdout,p.stderr])s.on('data',b=>p.output+=b);p.done=once(p,'close');children.push(p);return p;};
 const stop=async p=>{if(p.exitCode===null&&p.signalCode===null)p.kill('SIGTERM');const timer=setTimeout(()=>p.kill('SIGKILL'),5000);try{return await p.done;}finally{clearTimeout(timer);}};
 t.after(async()=>{for(const p of children.reverse())await stop(p);fs.rmSync(root,{recursive:true,force:true});});
 const wait=async fn=>{for(let i=0;i<200;i++){if(fn())return;await pause(50);}assert.fail('readiness: '+children.map(p=>p.output).join('\n')+'\n'+['native.log','resolver.log'].map(n=>{try{return fs.readFileSync(directory+'/exit/'+n,'utf8');}catch{return'';}}).join('\n'));};
 createRuntimeConfig({directory,mode:'standalone',endpoint:'192.0.2.1',exitAddress:'192.0.2.1',port:33443,serverName:'physical.test',transport,publicName:transport==='combo-tls'?'relay.example':undefined,relayPort:10443,clients:2,days:2,addressDiscovery:true,privatePeerDns:true,profile:fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json')});

 const exitFile=directory+'/exit/engine.json',clientFile=directory+'/client-1/engine.json';
 const exitConfig=JSON.parse(fs.readFileSync(exitFile));const packet=exitConfig.boring??exitConfig;packet.address='127.0.0.2';packet.tun='cvpw0';packet.http_version=http==='1.1'?'1.1':'auto';
 if(exitConfig.transparent){exitConfig.transparent.listen.ipv4='127.0.0.2';if(relayProbe){delete exitConfig.transparent.destination_policy;exitConfig.transparent.destinations=[{ipv4:'11.22.33.44',port:443}];}}write(exitFile,exitConfig);
 const clientConfig=JSON.parse(fs.readFileSync(clientFile));const clientPacket=clientConfig.boring??clientConfig;clientPacket.address='127.0.0.2';clientPacket.tun='cvpw0';clientPacket.http_version=http==='1.1'?'auto':'2';
 if(clientConfig.transparent){clientConfig.transparent.exit.ipv4='127.0.0.2';if(relayProbe){delete clientConfig.transparent.destination_policy;clientConfig.transparent.destinations=[{ipv4:'11.22.33.44',port:443}];}}write(clientFile,clientConfig);
 try{run(engine,['--check-config',clientFile]);}catch(e){throw Error(String(e.stderr));}
 if(transport==='combo-tls'){fs.mkdirSync(directory+'/exit/replay',{mode:0o700});run(engine,['--init-transparent-replay',exitFile]);}
 const registry=root+'/registry.json';write(registry,{version:1,revision:1,clients:[{name:'laptop',ipv4:'10.99.0.2',revoked:false},{name:'canary',ipv4:'10.99.0.3',revoked:false}]});
 const reserve=net.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const base=['scripts/clean-vpn-native-packet-wan-lab.py','--engine',engine,'--exit-address','127.0.0.1','--port',String(port),'--seconds','40',...(relayProbe?['--relay-probe']:[])];
 const exit=launch([...base,'--role','exit','--directory',directory+'/exit','--node',process.execPath,'--registry-script',path.resolve('scripts/clean-vpn-native-peer-dns.mjs'),'--registry-file',registry]);
 await wait(()=>exit.output.includes('packet_wan_exit_listening'));
 const client=launch([...base,'--role','client','--directory',directory+'/client-1']);
 await wait(()=>client.output.includes('"event": "packet_wan_probe"')&&client.output.includes('"status": "passed"'));
 const enginePid=Number(fs.readFileSync(directory+'/exit/engine.pid')),clientPid=Number(fs.readFileSync(directory+'/client-1/engine.pid'));
 const namespacePid=fs.readFileSync(directory+'/client-1/namespace.pid','utf8').trim();
 const probe=()=>JSON.parse(run('nsenter',['-t',namespacePid,'-n','python3',path.resolve(base[0]),'probe','--address','10.99.0.2','--name','laptop.mpn',...(relayProbe?['--config',clientFile]:[])]));
 const baseline=probe();assert.equal(baseline.status,'passed');if(relayProbe){assert.deepEqual(baseline.relayHttps.map(x=>x.tls),['TLSv1.2','TLSv1.3']);assert.ok(baseline.relayHttps.every(x=>x.certificateVerified&&x.bytes===3584));
  const rule=['OUTPUT','-d','11.22.33.44','-p','tcp','--dport','443','-j','REDIRECT','--to-ports','10443'];
  run('nsenter',['-t',namespacePid,'-n','iptables','-t','nat','-D',...rule]);try{assert.throws(probe,'origin must refuse direct packet path');}finally{run('nsenter',['-t',namespacePid,'-n','iptables','-t','nat','-A',...rule]);}
  assert.equal(probe().relayHttps.length,2);
 }assert.equal(JSON.parse(fs.readFileSync(directory+'/client-1/assignment.json')).ipv4,'10.99.0.2');
 packet.peers.pop();if(exitConfig.transparent)exitConfig.transparent.peers.pop();write(exitFile+'.next',exitConfig);fs.renameSync(exitFile+'.next',exitFile);process.kill(enginePid,'SIGHUP');
 await wait(()=>fs.readFileSync(directory+'/exit/native.log','utf8').includes('"status":"applied"'));
 assert.equal(probe().status,'passed');assert.equal(Number(fs.readFileSync(directory+'/client-1/engine.pid')),clientPid);
 write(root+'/transaction.json',{});await wait(()=>client.output.includes('"status": "failed"'));assert.equal(client.exitCode,null);fs.unlinkSync(root+'/transaction.json');assert.equal(probe().status,'passed');
 assert.equal((await stop(client))[0],0,client.output);assert.equal((await stop(exit))[0],0,exit.output);
 for(const pid of [enginePid,clientPid,Number(namespacePid),Number(fs.readFileSync(directory+'/exit/namespace.pid')),Number(fs.readFileSync(directory+'/exit/resolver.pid'))])assert.throws(()=>process.kill(pid,0));
 assert.deepEqual(snapshot(),before,'host network and DNS unchanged');
 const bind=net.createServer();bind.listen(port,'127.0.0.1');await once(bind,'listening');await new Promise(r=>bind.close(r));
 t.diagnostic(JSON.stringify({transport,http,relayHttps:relayProbe,realTun:true,privateDnsUdpTcp:true,discovery:true,hotReloadPreservedPeer:true,pendingMarkerRecovered:true,hostUnchanged:true,portReleased:true}));
});
