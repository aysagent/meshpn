#!/usr/bin/env node
// Three independent clients and LANs, one exit, generated private role bundles.
// No host bindings or physical machines. Run only on a dedicated Linux engine.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,execFile,spawnSync} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {parseRuntimeConfig,createRuntimeConfig} from './clean-vpn-native-runtime-config.mjs';
import {applicationProbe} from './lib/native-runtime-application-probe.mjs';
import {nativeProcessProbe} from './lib/native-runtime-metrics.mjs';
import {cleanupLab} from './clean-vpn-native-runtime-cleanup.mjs';

const cli=JSON.parse(process.env.CVPN_CONTAINER_COMMAND??'["podman"]');
assert.ok(Array.isArray(cli)&&cli.length&&cli.every(s=>typeof s==='string'));
const image=process.env.CVPN_RUNTIME_IMAGE;assert.ok(image);
const output=path.resolve(process.argv[2]??'');assert.ok(process.argv.length===3&&!fs.existsSync(output));
const prefix='cvpnrt-'+randomBytes(8).toString('hex'),label='org.meshpn.native-runtime-lab='+prefix;
const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'cvpn-multi-'));
const opts={encoding:'utf8',timeout:60000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']};
const p=a=>execFileSync(cli[0],[...cli.slice(1),...a],opts).trim();
const pa=async a=>(await promisify(execFile)(cli[0],[...cli.slice(1),...a],{...opts,timeout:90000})).stdout.trim();
const e=(name,...a)=>p(['exec',name,...a]);
const net=prefix+'-net',exit=prefix+'-exit',init=prefix+'-init',origin=prefix+'-origin',replay=prefix+'-replay';
const exitVolume=prefix+'-exit-config',originVolume=prefix+'-origin-config';
const clients=[0,1,2].map(i=>({i,name:prefix+'-c'+i,app:prefix+'-a'+i,volume:prefix+'-config'+i,lan:prefix+'-lan'+i,
  ip:'10.77.0.'+(10+i),subnet:`192.168.${88+i}.0/24`,gateway:`192.168.${88+i}.2`,appIP:`192.168.${88+i}.3`}));
const ownership={schema:1,kind:'native-runtime-lab-ownership',prefix,cli};
fs.writeFileSync(output+'.ownership.json',JSON.stringify(ownership)+'\n',{flag:'wx',mode:0o600});
const report={schema:1,kind:'native-combo-multi-client',status:'failed',image,clients:3,checks:[]};
const step=s=>{report.checks.push(s);console.log('MULTI_CLIENT='+s);};
const wait=async fn=>{const end=Date.now()+30000;let error;while(Date.now()<end){try{return fn();}catch(e){error=e;await delay(250);}}throw error;};
const health=name=>e(name,'node','/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
const relay=String.raw`const https=await import('node:https'),fs=await import('node:fs');
await new Promise((resolve,reject)=>{const req=https.get({host:'11.22.33.44',port:443,servername:'runtime.test',ca:fs.readFileSync('/config/ca.pem'),agent:false,timeout:3000},res=>{
let b='';res.on('data',c=>b+=c);res.on('error',reject);res.on('end',()=>b==='multi-ok\n'?resolve():reject(Error('body')));
});req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));});`;
const probe=(c,body)=>e(c.app,'node','--input-type=module','-e',body);
const launch=(c=null)=>{
  const engine=path.basename(cli[0]),args=['scripts/clean-vpn-native-container.mjs','start','--engine='+engine,
    '--name='+(c?c.name:exit),'--role='+(c?'client':'exit'),'--image='+image,'--network='+net,
    '--ip='+(c?c.ip:'10.77.0.2'),'--config-volume='+(c?c.volume:exitVolume),'--lab-owner='+prefix,
    ...(c?['--lan-network='+c.lan,'--lan-ip='+c.gateway,'--lan-subnet='+c.subnet,'--relay-health=relay-health.json']:['--replay-volume='+replay])];
  if(cli.length>1){assert.equal(cli.length,3);assert.equal(cli[1],'--connection');args.push('--connection='+cli[2]);}
  execFileSync(process.execPath,args,{...opts,env:{...process.env,PATH:path.dirname(cli[0])+':'+process.env.PATH}});
};
const snapshot=()=>Object.fromEntries([exit,...clients.map(c=>c.name)].map(n=>[n,JSON.parse(e(n,'node','-e',nativeProcessProbe))]));
let passed=false;
try{
  report.imageId=JSON.parse(p(['image','inspect',image]))[0].Id;
  report.engineSha256=p(['run','--rm','--network=none','--entrypoint=sha256sum',image,'/usr/local/bin/clean-vpn-engine']).split(/\s/)[0];
  const bundle=path.join(root,'bundle');
  createRuntimeConfig(parseRuntimeConfig(['create','--directory='+bundle,'--mode=container','--endpoint=10.77.0.2','--exit-address=10.77.0.2',
    '--server-name=runtime.test','--clients=3','--port=3443','--transport=combo-tls','--public-name=relay.example']));
  p(['network','create','--label',label,'--internal','--subnet=10.77.0.0/24',net]);
  for(const c of clients)p(['network','create','--label',label,'--internal','--subnet='+c.subnet,c.lan]);
  for(const v of [exitVolume,originVolume,replay,...clients.map(c=>c.volume)])p(['volume','create','--label',label,v]);
  p(['run','-d','--name',init,'--label',label,'--network=none','--no-healthcheck',
    '-v',exitVolume+':/exit','-v',originVolume+':/origin','-v',replay+':/replay',...clients.flatMap(c=>['-v',c.volume+':/c'+c.i]),'--entrypoint=sleep',image,'1200']);
  p(['cp',bundle+'/exit/.',init+':/exit/']);
  for(const c of clients){
    const dir=bundle+'/client-'+(c.i+1);
    fs.writeFileSync(dir+'/relay-health.json',JSON.stringify({version:1,ipv4:'11.22.33.44',server_name:'runtime.test',path:'/',ca:'/config/ca.pem',sha256:createHash('sha256').update('multi-ok\n').digest('hex')}),{mode:0o600});
    p(['cp',dir+'/.',init+':/c'+c.i+'/']);
  }
  for(const file of ['cert.pem','key.pem'])p(['cp',bundle+'/exit/'+file,init+':/origin/'+file]);
  const originCode=fs.readFileSync('scripts/lib/native-runtime-lab-origin.mjs','utf8')+String.raw`
https.createServer({key:fs.readFileSync('/config/key.pem'),cert:fs.readFileSync('/config/cert.pem')},(q,r)=>{
 if(q.url==='/hold'){r.writeHead(200);r.write('hold\n');const t=setInterval(()=>r.write('hold\n'),500);r.on('close',()=>clearInterval(t));}
 else r.end('multi-ok\n');
}).listen(443,'0.0.0.0');`;
  fs.writeFileSync(root+'/origin.mjs',originCode,{mode:0o600});p(['cp',root+'/origin.mjs',init+':/origin/origin.mjs']);
  for(const f of ['origin.mjs','cert.pem','key.pem'])e(init,'test','-f','/origin/'+f);
  e(init,'mkdir','-m','700','/replay/state');
  p(['run','--rm','--network=none','-v',exitVolume+':/config:ro','-v',replay+':/replay','--entrypoint=clean-vpn-engine',image,'--init-transparent-replay','/config/engine.json']);
  p(['run','-d','--name',origin,'--label',label,'--network',net,'--ip=10.77.0.4','--cap-add=NET_ADMIN','--no-healthcheck','-v',originVolume+':/config:ro','--entrypoint=sh',image,'-ec',
    'ip addr add 198.18.0.80/32 dev lo; ip addr add 11.22.33.44/32 dev lo; exec node /config/origin.mjs']);
  await wait(()=>assert.match(p(['logs',origin]),/ORIGIN_READY/));launch();await wait(()=>health(exit));
  for(const dst of ['198.18.0.80','11.22.33.44'])e(exit,'ip','route','add',dst+'/32','via','10.77.0.4','dev','eth0');
  for(const ip of ['1.1.1.1','8.8.8.8'])for(const proto of ['udp','tcp'])e(exit,'iptables-nft','-t','nat','-A','PREROUTING','-i','cvpn0','-d',ip,'-p',proto,'--dport','53','-j','DNAT','--to-destination','10.77.0.4:5353');
  for(const c of clients){
    launch(c);await wait(()=>assert.match(health(c.name),/relay-https/));
    p(['run','-d','--name',c.app,'--label',label,'--network',c.lan,'--ip='+c.appIP,'--cap-add=NET_ADMIN','--no-healthcheck','-v',c.volume+':/config:ro','--entrypoint=sh',image,'-ec',
      'ip route replace default via '+c.gateway+'; exec sleep 1200']);
    probe(c,applicationProbe(c.gateway,'/config/ca.pem'));probe(c,relay);
  }
  step('generated-role-bundles-three-independent-clients-and-LANs');
  const initial=snapshot(),pids=[exit,...clients.map(c=>c.name)].map(n=>JSON.parse(p(['inspect',n]))[0].State.Pid);
  const workload=c=>`const output=console.log;console.log=()=>{};const packet=async()=>{${applicationProbe(c.gateway,'/config/ca.pem')}},relay=async()=>{${relay}};
let rounds=0;const start=performance.now();do{await Promise.all([packet(),relay()]);rounds++;await new Promise(r=>setTimeout(r,500));}while(performance.now()-start<60000);output(JSON.stringify({rounds,elapsedMs:performance.now()-start}));`;
  let done=false,loadError;const job=Promise.all(clients.map(async c=>({client:c.i,...JSON.parse(await pa(['exec',c.app,'node','--input-type=module','-e',workload(c)]))}))).catch(e=>{loadError=e;}).finally(()=>done=true);
  const samples=[];while(!done){samples.push(snapshot());await delay(1000);}report.normal=await job;if(loadError)throw loadError;
  for(const r of report.normal)assert.ok(r.rounds>=10&&r.elapsedMs>=60000);
  report.peak={};for(const n of Object.keys(initial)){
    for(const s of samples){assert.equal(s[n].nativeProcesses,1);assert.equal(s[n].zombies,0);assert.ok(s[n].rssKiB<131072&&s[n].fds<128&&s[n].threads<48);}
    report.peak[n===exit?'exit':'client-'+clients.find(c=>c.name===n).i]=Object.fromEntries(['rssKiB','fds','threads'].map(k=>[k,Math.max(...samples.map(s=>s[n][k]))]));
  }step('all-clients-progress-under-concurrent-packet-and-relay-load');
  // Fill all 16 shared relay slots from one client. This measures global-cap
  // fairness honestly; it does not manufacture a per-client guarantee.
  const hold=String.raw`const https=require('node:https'),fs=require('node:fs'),requests=new Set();let active=0,ready=false;
const add=()=>{const q=https.get({host:'11.22.33.44',port:443,path:'/hold',servername:'runtime.test',ca:fs.readFileSync('/config/ca.pem'),agent:false},r=>{
 active++;r.on('data',()=>{});r.on('close',()=>active--);if(active===16&&!ready){ready=true;console.log('HOLD_READY=16');}});
 requests.add(q);q.on('error',()=>{});q.on('close',()=>requests.delete(q));};
const fill=setInterval(()=>{if(requests.size<16)add();},100);setTimeout(()=>{clearInterval(fill);for(const q of requests)q.destroy();},45000);`;
  fs.writeFileSync(root+'/hold.cjs',hold,{mode:0o600});p(['cp',root+'/hold.cjs',init+':/c0/hold.cjs']);
  // App rootfs is writable, credentials remain read-only.
  e(clients[0].app,'sh','-ec','node /config/hold.cjs >/tmp/hold.log 2>&1 & echo $! >/tmp/hold.pid');
  await wait(()=>assert.match(e(clients[0].app,'cat','/tmp/hold.log'),/HOLD_READY=16/));
  const pressure=c=>`const output=console.log;console.log=()=>{};const packet=async()=>{${applicationProbe(c.gateway,'/config/ca.pem')}},relay=async()=>{${relay}};
const counts={packet:0,relay:0,relayRefused:0};for(let i=0;i<8;i++){await packet();counts.packet++;try{await relay();counts.relay++;}catch{counts.relayRefused++;}await new Promise(r=>setTimeout(r,200));}output(JSON.stringify(counts));`;
  report.pressure=await Promise.all(clients.slice(1).map(async c=>({client:c.i,...JSON.parse(await pa(['exec',c.app,'node','--input-type=module','-e',pressure(c)]))})));
  for(const r of report.pressure){assert.equal(r.packet,8);assert.equal(r.relay+r.relayRefused,8);}
  report.relayFairness='no-per-client-guarantee-global-16-slot-cap';
  report.starvationObserved=report.pressure.some(r=>r.relay===0);
  step('saturated-relay-cap-measured-packet-clients-continue');
  e(clients[0].app,'sh','-ec','kill "$(cat /tmp/hold.pid)"');
  for(const c of clients){await wait(()=>health(c.name));probe(c,applicationProbe(c.gateway,'/config/ca.pem'));probe(c,relay);}
  await wait(()=>{const after=snapshot();for(const n of Object.keys(initial)){assert.ok(after[n].fds<=initial[n].fds&&after[n].threads<=initial[n].threads);assert.ok(after[n].rssKiB-initial[n].rssKiB<32768);}report.settled=after;});
  assert.deepEqual([exit,...clients.map(c=>c.name)].map(n=>JSON.parse(p(['inspect',n]))[0].State.Pid),pids);
  step('all-clients-recover-without-engine-restart-and-resources-reclaimed');
  for(const n of [exit,...clients.map(c=>c.name)]){p(['stop','--time=5',n]);assert.equal(JSON.parse(p(['inspect',n]))[0].State.ExitCode,0);}
  step('all-native-PID1-SIGTERM-clean');passed=true;
}catch(error){report.error=String(error.message).slice(0,4000);
  for(const n of [origin,exit,...clients.map(c=>c.name)]){const r=spawnSync(cli[0],[...cli.slice(1),'logs',n],opts);if(r.status===0)(report.logs??={})[n]=(r.stdout+r.stderr).slice(-2000);}
  console.error(report.error);
}finally{
  try{report.cleanup=cleanupLab(ownership,p);}catch(error){report.cleanup={status:'failed',error:error.message};passed=false;}
  fs.rmSync(root,{recursive:true,force:true});report.status=passed?'passed':'failed';fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
}
assert.equal(report.status,'passed');console.log('MULTI_CLIENT_REPORT='+output);
