#!/usr/bin/env node
// Rootful, internal container bridges only. No published ports or physical hosts.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, execFile, spawnSync} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {cleanupLab} from './clean-vpn-native-runtime-cleanup.mjs';
import {applicationProbe} from './lib/native-runtime-application-probe.mjs';
import {nativeProcessProbe} from './lib/native-runtime-metrics.mjs';
import {netemPhases,netemCommands,tcpCountersProbe,bulkRelayProbe,faultWorkload,assertNetemEvidence} from './lib/native-combo-netem.mjs';
import {inspectPcap} from './clean-vpn-pcap-fingerprints.mjs';

const cli=JSON.parse(process.env.CVPN_CONTAINER_COMMAND??'["podman"]');
assert.ok(Array.isArray(cli)&&cli.length&&cli.every(v=>typeof v==='string'));
const image=process.env.CVPN_RUNTIME_IMAGE;assert.ok(image);
const observerImage=process.env.CVPN_OBSERVER_IMAGE;
const activeHealth=process.env.CVPN_COMBO_HEALTH==='1';
assert.ok(process.env.CVPN_COMBO_HEALTH===undefined||activeHealth);
const netem=process.env.CVPN_COMBO_NETEM==='1';
assert.ok(process.env.CVPN_COMBO_NETEM===undefined||netem,'CVPN_COMBO_NETEM_must_be_1');
const profilePath=process.env.CVPN_COMBO_PROFILE??'fixtures/native-tls-profiles/chromium-156-bounded-cold.json';
const profileStat=fs.lstatSync(profilePath);assert.ok(profileStat.isFile()&&!profileStat.isSymbolicLink()&&profileStat.size<=16384,'bounded_profile_file');
const profileBytes=fs.readFileSync(profilePath),profile=JSON.parse(profileBytes);
const seconds=Number(process.env.CVPN_COMBO_LOAD_SECONDS??60);assert.ok(Number.isInteger(seconds)&&seconds>=30&&seconds<=1800);
const reportPath=path.resolve(process.argv[2]??'');assert.ok(process.argv.length===3&&!fs.existsSync(reportPath));
const lifetime=String(seconds+1800);
const prefix='cvpnrt-'+randomBytes(8).toString('hex'), label='org.meshpn.native-runtime-lab='+prefix;
const net=prefix+'-net',lan=prefix+'-lan',config=prefix+'-config',replay=prefix+'-replay';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-combo-runtime-'));
const options={encoding:'utf8',timeout:45000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']};
const p=a=>execFileSync(cli[0],[...cli.slice(1),...a],options).trim();
const pa=async (a,extra={})=>(await promisify(execFile)(cli[0],[...cli.slice(1),...a],{...options,...extra})).stdout.trim();
const logs=n=>{const r=spawnSync(cli[0],[...cli.slice(1),'logs',n],options);assert.equal(r.status,0);return r.stdout+r.stderr;};
const e=(n,...a)=>p(['exec',n,...a]);
const checks=[],report={schema:1,kind:'native-combo-container-lifecycle',status:'failed',image,port:3443,profileSha256:createHash('sha256').update(profileBytes).digest('hex'),checks,scope:'internal-Linux-container-lab-only'};
const step=s=>{checks.push(s);console.log('COMBO_RUNTIME='+s);};
const wait=async (fn,ms=25000)=>{let error;const end=performance.now()+ms;while(performance.now()<end){try{return fn();}catch(e){error=e;await delay(250);}}throw error;};
const ownership={schema:1,kind:'native-runtime-lab-ownership',prefix,cli};
fs.writeFileSync(reportPath+'.ownership.json',JSON.stringify(ownership)+'\n',{flag:'wx',mode:0o600});
const put=(f,b)=>fs.writeFileSync(path.join(root,f),b,{mode:0o600});
const names=Object.fromEntries(['init','origin','client','exit','app','holder','second'].map(s=>[s,prefix+'-'+s]));
const health=n=>e(n,'node','/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
const relayProbe=String.raw`const https=await import('node:https'),fs=await import('node:fs');
await new Promise((resolve,reject)=>https.get({host:'11.22.33.44',port:443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),agent:false,timeout:2500},r=>{
let b='';r.on('data',c=>b+=c);r.on('end',()=>b==='relay-ok\n'?resolve():reject(Error('relay_body')));
}).on('error',reject).on('timeout',function(){this.destroy(Error('relay_timeout'));}));`;
const probe=(body,n=names.app)=>e(n,'node','--input-type=module','-e',body);
const packetProbe=applicationProbe('192.168.88.2');
const launch=(role,name=names[role],file=role+'.json')=>{
  const engine=path.basename(cli[0]);assert.ok(['podman','docker'].includes(engine));
  const args=['scripts/clean-vpn-native-container.mjs','start','--engine='+engine,'--name='+name,'--role='+role,'--image='+image,
    '--network='+net,'--ip='+ (name===names.second?'10.77.0.6':role==='exit'?'10.77.0.2':'10.77.0.3'),
    '--config-volume='+config,'--config-file='+file,'--lab-owner='+prefix,
    ...(activeHealth&&role==='client'?['--relay-health=relay-health.json']:[]),
    ...(role==='exit'?['--replay-volume='+replay]:['--lan-network='+lan,'--lan-ip=192.168.88.2','--lan-subnet=192.168.88.0/24'])];
  if(cli.length>1){assert.deepEqual(cli.slice(1,2),['--connection']);assert.equal(cli.length,3);args.push('--connection='+cli[2]);}
  execFileSync(process.execPath,args,{...options,timeout:60000,env:{...process.env,PATH:path.dirname(cli[0])+':'+process.env.PATH}});
};
const exitRoutes=()=>{for(const dst of ['198.18.0.80','11.22.33.44'])e(names.exit,'ip','route','add',dst+'/32','via','10.77.0.4','dev','eth0');
  for(const server of ['1.1.1.1','8.8.8.8'])for(const proto of ['udp','tcp'])e(names.exit,'iptables-nft','-t','nat','-A','PREROUTING','-i','cvpn0','-d',server,'-p',proto,'--dport','53','-j','DNAT','--to-destination','10.77.0.4:5353');};
const snapshot=async()=>Object.fromEntries(await Promise.all(['client','exit'].map(async role=>[role,JSON.parse(await pa(['exec',names[role],'node','-e',nativeProcessProbe]))])));
const replayHash=()=>e(names.init,'sha256sum','/replay/state/state').split(/\s/)[0];
const capture=(name,namespace,filter,iface='eth0')=>{
  p(['run','-d','--name',prefix+'-'+name,'--label',label,'--network=container:'+namespace,
    '--cap-drop=ALL','--cap-add=NET_RAW','--cap-add=SETUID','--cap-add=SETGID','-v',config+':/capture',
    '--entrypoint=sh',observerImage,'-c',`exec tcpdump -p -n -U -i ${iface} -s 0 -w - "${filter}" > /capture/${name}.pcap 2>/capture/${name}.log`]);
};
const recoveryCapture=()=>{
  if(!observerImage)return;
  p(['stop','--time=5',prefix+'-recovery']);
  report.recoveryPackets=p(['run','--rm','--network=none','-v',config+':/capture:ro','--entrypoint=tcpdump',observerImage,'-nn','-r','/capture/recovery.pcap','-c','80']);
  p(['rm',prefix+'-recovery']);
};
let finished=false;
try{
  const info=JSON.parse(p(['image','inspect',image]))[0];report.imageId=info.Id;report.architecture=info.Architecture;
  report.engineSha256=p(['run','--rm','--network=none','--entrypoint=sha256sum',image,'/usr/local/bin/clean-vpn-engine']).split(/\s/)[0];
  p(['network','create','--label',label,'--internal','--subnet=10.77.0.0/24',net]);
  p(['network','create','--label',label,'--internal','--subnet=192.168.88.0/24',lan]);
  for(const volume of [config,replay])p(['volume','create','--label',label,volume]);
  p(['run','-d','--name',names.init,'--label',label,'--network=none','--no-healthcheck','-v',config+':/config','-v',replay+':/replay','--entrypoint=sleep',image,lifetime]);
  e(names.init,'openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem');
  if(activeHealth)put('relay-health.json',JSON.stringify({version:1,ipv4:'11.22.33.44',server_name:'runtime.test',path:'/',ca:'/config/cert.pem',sha256:createHash('sha256').update('relay-ok\n').digest('hex')}));
  put('packet.psk',randomBytes(32));put('relay.psk',randomBytes(32));
  put('profile.json',profileBytes);
  const configs={};for(const role of ['client','exit']){
    configs[role]={version:1,transport:'combo-tls',role,
      boring:{version:1,role,tun:'cvpn0',address:'10.77.0.2',port:3443,secret_path:'/config/packet.psk',
        ...(role==='client'?{dns:true,server_name:'runtime.test',sni:'relay.example',ca:'/config/cert.pem',tls_profile_path:'/config/profile.json'}:{cert:'/config/cert.pem',key:'/config/key.pem',alps:true})},
      transparent:{version:1,transport:'transparent-tls',role,public_name:'relay.example',secret_path:'/config/relay.psk',destination_policy:{mode:'public-https',deny_ipv4:[]},
        listen:{ipv4:role==='client'?'0.0.0.0':'10.77.0.2',port:role==='client'?10443:3443},
        ...(role==='client'?{exit:{ipv4:'10.77.0.2',port:3443}}:{replay_directory:'/replay/state'})}};
    put(role+'.json',JSON.stringify(configs[role]));
  }
  const second=structuredClone(configs.exit);second.boring.address=second.transparent.listen.ipv4='10.77.0.6';second.boring.port=second.transparent.listen.port=3444;
  put('second.json',JSON.stringify(second));
  put('origin.mjs',fs.readFileSync('scripts/lib/native-runtime-lab-origin.mjs','utf8')+`\nhttps.createServer({key:fs.readFileSync('/config/key.pem'),cert:fs.readFileSync('/config/cert.pem')},(q,r)=>r.end(q.url==='/bulk'?Buffer.alloc(256*1024,0x5a):'relay-ok\\n')).listen(443,'0.0.0.0');\n`);
  p(['cp',root+'/.',names.init+':/config/']);e(names.init,'sh','-ec','chmod 600 /config/*; mkdir -m 700 /replay/state');
  // A fresh volume is NOT silently initialized by ordinary start.
  launch('exit');await wait(()=>assert.equal(JSON.parse(p(['inspect',names.exit]))[0].State.Running,false));
  assert.match(logs(names.exit),/configuration or startup refused/);
  assert.throws(()=>e(names.init,'test','-e','/replay/state/state'));
  p(['rm',names.exit]);step('uninitialized-replay-start-refused-without-reset');
  e(names.init,'/usr/local/bin/clean-vpn-engine','--init-transparent-replay','/config/exit.json');
  assert.throws(()=>e(names.init,'/usr/local/bin/clean-vpn-engine','--init-transparent-replay','/config/exit.json'));step('explicit-init-and-repeat-init-refusal');
  p(['run','-d','--name',names.origin,'--label',label,'--network',net,'--ip=10.77.0.4','--cap-add=NET_ADMIN','--no-healthcheck','-v',config+':/config:ro','--entrypoint=sh',image,'-ec',
    'ip addr add 198.18.0.80/32 dev lo; ip addr add 11.22.33.44/32 dev lo; exec node /config/origin.mjs']);
  await wait(()=>assert.match(p(['logs',names.origin]),/ORIGIN_READY/));
  launch('exit');await wait(()=>health(names.exit));exitRoutes();
  if(observerImage){capture('wire',names.exit,'tcp dst port 3443');await wait(()=>assert.match(e(names.init,'cat','/config/wire.log'),/listening/));}
  launch('client');await wait(()=>health(names.client));
  p(['run','-d','--name',names.app,'--label',label,'--network',lan,'--ip=192.168.88.3','--cap-add=NET_ADMIN','--no-healthcheck','-v',config+':/config:ro','--entrypoint=sh',image,'-ec',
    'ip route replace default via 192.168.88.2; exec sleep '+lifetime]);
  if(observerImage){capture('original',names.app,'dst host 11.22.33.44 and tcp dst port 443');await wait(()=>assert.match(e(names.init,'cat','/config/original.log'),/listening/));}
  probe(packetProbe);probe(relayProbe);step('public-launcher-real-TUN-DNS-and-LAN-HTTPS-relay');
  // A direct route is deliberately reachable; the guard must still block it.
  e(names.client,'ip','route','add','11.22.33.44/32','via','10.77.0.4','dev','eth0');
  assert.throws(()=>probe(relayProbe,names.client));probe(relayProbe);if(activeHealth)assert.match(health(names.client),/relay-https/);step('direct-uplink-HTTPS-blocked-LAN-relay-works');
  const hash=replayHash();launch('exit',names.second,'second.json');
  await wait(()=>assert.equal(JSON.parse(p(['inspect',names.second]))[0].State.Running,false));
  assert.match(logs(names.second),/configuration or startup refused/);assert.equal(replayHash(),hash);p(['rm',names.second]);
  probe(packetProbe);probe(relayProbe);step('second-owner-free-port-and-netns-refused-existing-pair-healthy');
  if(observerImage){
    for(const name of ['wire','original']){p(['stop','--time=5',prefix+'-'+name]);assert.match(e(names.init,'cat','/config/'+name+'.log'),/\b0 packets dropped by kernel\b/);p(['cp',names.init+':/config/'+name+'.pcap',root+'/'+name+'.pcap']);p(['rm',prefix+'-'+name]);}
    const wire=inspectPcap(fs.readFileSync(root+'/wire.pcap'),{destination:'10.77.0.2',port:3443,profile});
    const app=inspectPcap(fs.readFileSync(root+'/original.pcap'),{destination:'11.22.33.44'});
    const packet=wire.connections.filter(c=>c.sni?.includes('relay.example')),relay=wire.connections.filter(c=>c.sni?.some(n=>n.endsWith('.relay.example')));
    assert.ok(packet.length&&relay.length&&app.connections.length);
    assert.ok(packet.every(c=>c.profile?.status==='matched'));
    assert.ok(relay.every(c=>c.status==='observed'&&app.connections.some(a=>a.status==='observed'&&a.ja3===c.ja3&&a.ja4===c.ja4)));
    report.observer={wireSha256:wire.pcapSha256,applicationSha256:app.pcapSha256,packetProfileMatches:packet.length,relayFingerprintMatches:relay.length,scope:'ClientHello-only-not-full-browser-equivalence'};
    step('independent-pcap-packet-profile-and-original-relay-JA3-JA4-match');
  }
  e(names.client,'iptables-nft','-N','FOREIGN_SENTINEL');e(names.client,'iptables-nft','-A','OUTPUT','-j','FOREIGN_SENTINEL');
  e(names.client,'node','/opt/clean-vpn/clean-vpn-native-runtime.mjs','/config/client.json');
  assert.match(e(names.client,'iptables-nft-save'),/-A OUTPUT -j FOREIGN_SENTINEL/);step('same-namespace-reentry-preserves-foreign-rules');
  await delay(500);const initial=await snapshot(), samples=[];const start=performance.now();
  const pids=['client','exit'].map(r=>JSON.parse(p(['inspect',names[r]]))[0].State.Pid);
  let loadDone=false,loadResult,loadError;
  // Stay below the production 32 admissions/s guard. Saturation is exercised
  // separately as expected rejection, never by raising production limits.
  const workload=`const output=console.log;console.log=()=>{};const packet=async()=>{${packetProbe}},relay=async()=>{${relayProbe}};let rounds=0;const start=performance.now();do{await Promise.all([packet(),...Array.from({length:4},relay)]);rounds++;await new Promise(r=>setTimeout(r,500));}while(performance.now()-start<${seconds*1000});output('COMBO_LOAD='+JSON.stringify({rounds,relayRequests:rounds*4,packetBatches:rounds,elapsedMs:performance.now()-start}));`;
  const job=pa(['exec',names.app,'node','--input-type=module','-e',workload],{timeout:(seconds+20)*1000}).then(v=>loadResult=v,e=>loadError=e).finally(()=>loadDone=true);
  let progress=0;
  while(!loadDone){assert.ok(performance.now()-start<(seconds+20)*1000);samples.push(await snapshot());
    const elapsed=Math.floor((performance.now()-start)/1000);if(elapsed-progress>=30){progress=elapsed;console.log('COMBO_LOAD_PROGRESS='+elapsed+'/'+seconds);}
    await delay(seconds>300?5000:250);}
  await job;if(loadError){report.loadFailure={samples,stderr:loadError.stderr,completedPacketBatches:null,reason:'quiet-workload-did-not-emit-final-counters'};throw loadError;}
  const line=loadResult.split('\n').find(l=>l.startsWith('COMBO_LOAD='));assert.ok(line);
  report.load={...JSON.parse(line.slice(11)),seconds,samples: samples.length,initial,peak:{}};
  assert.ok(report.load.rounds>=2&&report.load.elapsedMs>=seconds*1000);
  for(const role of ['client','exit']){
    for(const sample of samples){const x=sample[role];assert.equal(x.nativeProcesses,1);assert.equal(x.zombies,0);assert.ok(x.rssKiB<131072&&x.fds<128&&x.threads<48);}
    report.load.peak[role]=Object.fromEntries(['rssKiB','fds','threads'].map(k=>[k,Math.max(...samples.map(s=>s[role][k]))]));
  }
  let settled;for(let i=0;i<40;i++){settled=await snapshot();if(['client','exit'].every(r=>settled[r].fds<=initial[r].fds&&settled[r].threads<=initial[r].threads))break;await delay(250);}
  for(const r of ['client','exit']){assert.ok(settled[r].fds<=initial[r].fds);assert.ok(settled[r].threads<=initial[r].threads);assert.ok(settled[r].rssKiB-initial[r].rssKiB<32768);}
  report.load.windows={};
  for(const r of ['client','exit']){
    const width=Math.max(1,Math.floor(samples.length/3));
    const median=xs=>xs.map(x=>x[r].rssKiB).sort((a,b)=>a-b)[Math.floor(xs.length/2)];
    const first=median(samples.slice(0,width)),last=median(samples.slice(-width));
    report.load.windows[r]={firstThirdMedianRssKiB:first,lastThirdMedianRssKiB:last,growthKiB:last-first};
    assert.ok(last-first<8192,'steady_state_RSS_growth');
  }
  report.load.settled=settled;assert.deepEqual(['client','exit'].map(r=>JSON.parse(p(['inspect',names[r]]))[0].State.Pid),pids);
  step('parallel-packet-and-four-relay-users-bounded-load-resources-reclaimed');
  const burst=`const relay=async()=>{${relayProbe}};const [requests]=await Promise.all([Promise.allSettled(Array.from({length:64},relay)),(async()=>{${packetProbe}})()]);const rejected=requests.filter(r=>r.status==='rejected').length;if(!rejected)throw Error('admission_cap_not_observed');console.log('BURST='+JSON.stringify({total:requests.length,rejected,completed:requests.length-rejected}));`;
  const burstOutput=probe(burst);report.burst=JSON.parse(burstOutput.split('\n').find(l=>l.startsWith('BURST=')).slice(6));
  await delay(1200);probe(packetProbe);probe(relayProbe);step('overload-rejects-excess-relays-packet-branch-and-fresh-requests-survive');
  if(netem){
    report.netem=[];
    const tcp=()=>Object.fromEntries(['client','exit'].map(r=>[r,JSON.parse(e(names[r],'node','-e',tcpCountersProbe))]));
    const qdisc=()=>Object.fromEntries(['client','exit'].map(r=>[r,JSON.parse(e(names[r],'tc','-s','-j','qdisc','show','dev','eth0'))]));
    const namespaces=Object.fromEntries(['client','exit'].map(r=>[r,e(names[r],'readlink','/proc/self/ns/net')]));
    for(const phase of netemPhases){
      const result={name:phase.name,seconds:phase.seconds,args:phase.args,before:tcp(),samples:[]};report.netem.push(result);
      const owned=new Set();console.log('NETEM_PHASE='+phase.name);
      try{
        for(const role of ['client','exit']){
          assert.equal(e(names[role],'readlink','/proc/self/ns/net'),namespaces[role]);
          assert.ok(qdisc()[role].every(q=>q.kind==='noqueue'),'foreign_qdisc_refused');
          const commands=netemCommands(role,phase);
          e(names[role],'tc',...commands[0]);owned.add(role);
          for(const args of commands.slice(1))e(names[role],'tc',...args);
        }
        let done=false,output,error;
        const job=pa(['exec',names.app,'node','--input-type=module','-e',faultWorkload(packetProbe,phase.seconds)],{timeout:(phase.seconds+30)*1000})
          .then(s=>output=s,e=>error=e).finally(()=>done=true);
        while(!done){result.samples.push(await snapshot());await delay(1000);}await job;
        if(error)throw error;
        result.load=JSON.parse(output.split('\n').find(l=>l.startsWith('NETEM_LOAD=')).slice(11));
        result.qdisc=qdisc();result.after=tcp();result.observed=assertNetemEvidence(phase,result);
        for(const sample of result.samples)for(const role of ['client','exit']){
          const x=sample[role];assert.equal(x.nativeProcesses,1);assert.equal(x.zombies,0);
          assert.ok(x.rssKiB<131072&&x.fds<128&&x.threads<48,'fault_resource_budget');
        }
      }finally{
        for(const role of owned){
          assert.equal(e(names[role],'readlink','/proc/self/ns/net'),namespaces[role]);
          assert.ok(qdisc()[role].some(q=>q.root&&q.kind==='prio'&&q.handle==='1:'),'owned_qdisc_changed');
          e(names[role],'tc','qdisc','del','dev','eth0','root','handle','1:');
        }
        result.removed=qdisc();assert.ok(Object.values(result.removed).every(qs=>qs.every(q=>q.kind==='noqueue')));
      }
      const recoveryStart=performance.now();await wait(()=>health(names.client),30000);probe(packetProbe);probe(bulkRelayProbe);
      result.recoveryMs=performance.now()-recoveryStart;
      await wait(()=>{result.settled=null;const x=Object.fromEntries(['client','exit'].map(r=>[r,JSON.parse(e(names[r],'node','-e',nativeProcessProbe))]));
        for(const r of ['client','exit']){assert.ok(x[r].fds<=initial[r].fds&&x[r].threads<=initial[r].threads);assert.ok(x[r].rssKiB-initial[r].rssKiB<32768);}
        result.settled=x;},30000);
      assert.deepEqual(['client','exit'].map(r=>JSON.parse(p(['inspect',names[r]]))[0].State.Pid),pids);
      result.status='passed';step('netem-'+phase.name+'-both-paths-recover-resources-reclaimed');
    }
  }
  // Block relay admission without interrupting the authenticated packet branch.
  e(names.client,'iptables-nft','-I','CVPN_R_INPUT','1','-p','tcp','--dport','10443','-j','REJECT');
  assert.throws(()=>probe(relayProbe));probe(packetProbe);if(activeHealth)assert.throws(()=>health(names.client));else health(names.client);
  e(names.client,'iptables-nft','-D','CVPN_R_INPUT','-p','tcp','--dport','10443','-j','REJECT');probe(relayProbe);
  step('relay-failure-does-not-downgrade-to-packet-branch');
  if(activeHealth){
    health(names.client);
    for(const patch of [{server_name:'wrong.test'},{ca:null},{sha256:'0'.repeat(64)}]){
      assert.throws(()=>e(names.client,'node','--input-type=module','-e',`import fs from 'node:fs';import {relayHttpsProbe} from '/opt/clean-vpn/lib/native-relay-health.mjs';const s=JSON.parse(fs.readFileSync('/run/clean-vpn/network.json'));await relayHttpsProbe({...s.plan.relayHealth,...${JSON.stringify(patch)}},s.plan.address);`));
    }
    health(names.client);step('relay-health-rejects-wrong-CA-hostname-and-body');
    const rule=['-s','10.99.0.2/32','-d','11.22.33.44/32','-p','tcp','--dport','443','-j','REDIRECT','--to-ports','10443'];
    if(observerImage){capture('health',names.client,'tcp port 10443 or tcp port 443','lo');await wait(()=>assert.match(e(names.init,'cat','/config/health.log'),/listening/));}
    report.healthFaultStage='redirect-removed';
    e(names.client,'iptables-nft','-t','nat','-D','CVPN_R_DNS',...rule);
    assert.throws(()=>health(names.client));probe(packetProbe);
    e(names.client,'iptables-nft','-t','nat','-I','CVPN_R_DNS','1',...rule);
    report.healthFaultStage='redirect-restored';const redirectRestored=performance.now();
    await wait(()=>assert.match(health(names.client),/packet-dns-and-relay-https/));report.redirectHealthRecoveryMs=performance.now()-redirectRestored;
    if(observerImage){p(['stop','--time=5',prefix+'-health']);p(['rm',prefix+'-health']);}
    report.healthFaultStage='origin-blocked';
    e(names.exit,'iptables-nft','-I','CVPN_R_OUTPUT','1','-d','11.22.33.44','-p','tcp','--dport','443','-j','REJECT');
    assert.throws(()=>health(names.client));probe(packetProbe);
    e(names.exit,'iptables-nft','-D','CVPN_R_OUTPUT','-d','11.22.33.44','-p','tcp','--dport','443','-j','REJECT');
    report.healthFaultStage='origin-restored';const originRestored=performance.now();await wait(()=>health(names.client));report.originHealthRecoveryMs=performance.now()-originRestored;step('active-relay-health-refuses-missing-redirect-and-blocked-origin-with-packet-healthy');
  }
  const beforeCrash=replayHash();p(['kill','--signal=KILL',names.exit]);
  assert.throws(()=>probe(relayProbe));assert.throws(()=>health(names.client));
  if(observerImage)capture('recovery',names.client,'arp or tcp port 3443');
  p(['rm',names.exit]);const exitRecoveryStart=performance.now();launch('exit');await wait(()=>health(names.exit));assert.equal(replayHash(),beforeCrash);exitRoutes();
  step('recreated-exit-listens-with-original-replay-state');
  await wait(()=>health(names.client),30000);recoveryCapture();probe(packetProbe);probe(relayProbe);
  report.exitRecreateMs=performance.now()-exitRecoveryStart;step('exit-SIGKILL-recreate-preserves-replay-and-recovers-both-paths');
  p(['run','-d','--name',names.holder,'--label',label,'--network=container:'+names.client,'--cap-drop=ALL','--no-healthcheck','--entrypoint=sleep',image,lifetime]);
  p(['kill','--signal=KILL',names.client]);assert.throws(()=>probe(relayProbe));assert.throws(()=>probe(packetProbe));
  assert.match(e(names.holder,'cat','/proc/net/route'),/cvpn0/);step('client-SIGKILL-held-namespace-remains-closed');
  p(['rm','-f',names.holder]);p(['rm',names.client]);const clientRecoveryStart=performance.now();launch('client');await wait(()=>health(names.client));probe(packetProbe);probe(relayProbe);
  report.clientRecreateMs=performance.now()-clientRecoveryStart;
  step('fresh-client-namespace-recovers-both-paths');
  for(const role of ['client','exit']){p(['stop','--time=5',names[role]]);assert.equal(JSON.parse(p(['inspect',names[role]]))[0].State.ExitCode,0);}
  step('native-PID1-SIGTERM-clean');finished=true;
}catch(error){report.error=String(error.message).slice(0,4000);console.error(report.error);
  try{recoveryCapture();}catch{}
  if(activeHealth)try{report.relayHealthError=e(names.client,'node','--input-type=module','-e',"import fs from 'node:fs';import {relayHttpsProbe} from '/opt/clean-vpn/lib/native-relay-health.mjs';const s=JSON.parse(fs.readFileSync('/run/clean-vpn/network.json'));try{await relayHttpsProbe(s.plan.relayHealth,s.plan.address);console.log('ok');}catch(e){console.log(e.code,e.message);}");}catch{}
  for(const n of [names.client,names.exit])try{report[n.endsWith('client')?'clientLog':'exitLog']=logs(n).slice(-4000);}catch{}
  if(activeHealth&&observerImage)try{p(['stop','--time=5',prefix+'-health']);report.healthPackets=p(['run','--rm','--network=none','-v',config+':/capture:ro','--entrypoint=tcpdump',observerImage,'-nn','-r','/capture/health.pcap','-c','80']);p(['rm',prefix+'-health']);}catch{}
  report.networkFailure={};for(const n of [names.client,names.exit])try{report.networkFailure[n.endsWith('client')?'client':'exit']={
    addresses:e(n,'ip','-j','-4','addr'),routes:e(n,'ip','-j','-4','route'),neighbors:e(n,'ip','-j','neigh'),firewall:e(n,'iptables-nft-save','-c'),sockets:e(n,'ss','-nt')};}catch{}
}finally{
  try{report.cleanup=cleanupLab(ownership,p);}catch(e){report.cleanup={status:'failed',error:e.message};finished=false;}
  fs.rmSync(root,{recursive:true,force:true});report.status=finished?'passed':'failed';fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
}
assert.equal(report.status,'passed');console.log('COMBO_RUNTIME_REPORT='+reportPath);
