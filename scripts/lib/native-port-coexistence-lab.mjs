// Run only inside the NIC-less disposable systemd container started by port-lab.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
import {applyNativeNetworkProfile} from './native-network-apply.mjs';
import {inspectPcap} from '../clean-vpn-pcap-fingerprints.mjs';

assert.equal(process.env.CVPN_DISPOSABLE_PORT_LAB,'1');
assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const run=(f,a,opts={})=>execFileSync(f,a,{encoding:'utf8',timeout:65000,maxBuffer:2*1024*1024,stdio:['ignore','pipe','pipe'],...opts}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('systemctl',a);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
const ns=(n,f,a,opts)=>run('ip',['netns','exec',n,f,...a],opts);
const put=(p,b)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/'))||'/',{recursive:true});fs.writeFileSync(p,b,{mode:0o600});};
const unit=(n,b)=>{put('/etc/systemd/system/'+n,b);fs.chmodSync('/etc/systemd/system/'+n,0o644);};
const prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const wait=async fn=>{let e;const end=performance.now()+45000;while(performance.now()<end){try{return fn();}catch(x){e=x;await delay(250);}}throw e;};
const binary='/usr/local/bin/clean-vpn-engine',endpoint='198.18.0.10',profile=JSON.parse(fs.readFileSync('/project/fixtures/native-tls-profiles/chromium-156-bounded-cold.json'));
const checks=[],phases=[],units=[],owners=[];
const check=s=>{checks.push(s);console.log('PORT_LAB='+s);};
const normal=s=>s.split('\n').filter(l=>!l.startsWith('#')).map(l=>l.replace(/\[\d+:\d+\]/g,'[0:0]')).join('\n');
const snapshot=n=>({routes:JSON.parse(ns(n,'ip',['-j','-4','route','show','table','all'])),rules:normal(ns(n,'iptables-save',[]))});
const digest=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const newns=n=>{ip('netns','add',n);ns(n,'sysctl',['-w','net.ipv4.ip_forward=0']);ip('-n',n,'link','set','lo','up');};
const link=(a,an,addr,b,bn,baddr)=>{
 ip('link','add',an,'netns',a,'type','veth','peer','name',bn,'netns',b);
 for(const [n,d,c]of[[a,an,addr],[b,bn,baddr]]){ip('-n',n,'addr','add',c,'dev',d);ip('-n',n,'link','set',d,'up');}
};
const probe=(port=8443)=>`const https=require('node:https'),fs=require('node:fs');const r=https.get({host:'11.22.33.44',port:${port},servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:2000},s=>{let b='';s.on('data',c=>b+=c);s.on('end',()=>process.exit(b==='native-runtime-https-ok\\n'?0:2));});r.on('error',()=>process.exit(3));r.on('timeout',()=>r.destroy());setTimeout(()=>process.exit(4),2500).unref();`;
const https=(n,port=8443)=>ns(n,'node',['-e',probe(port)]);
const dns=n=>ns(n,'node',['--input-type=module','-e',`import {dnsProbe} from '/project/scripts/clean-vpn-native-runtime-health.mjs';await dnsProbe('9.9.9.9',53,false);await dnsProbe('9.9.9.9',53,true);`]);
function topology(n,subnet,back){
 for(const s of [n,n+'usb',n+'exit'])newns(s);
 link(n,'wlan0',`192.168.${subnet}.8/24`,'front','c'+subnet,`192.168.${subnet}.1/24`);
 link(n,'usb0','192.168.7.1/24',n+'usb','gadget','192.168.7.19/24');
 link(n+'exit','eth0',`192.168.${back}.2/24`,'front','e'+back,`192.168.${back}.1/24`);
 ip('-n',n,'route','add','default','via',`192.168.${subnet}.1`);ip('-n',n+'usb','route','add','default','via','192.168.7.1');
 ip('-n',n+'exit','route','add','default','via',`192.168.${back}.1`);
}
function installPair(n,mode,port,back){
 const root='/config/'+n;put(root+'/packet.psk',randomBytes(32));put(root+'/relay.psk',randomBytes(32));
 const relay=(role)=>({version:1,transport:'transparent-tls',role,public_name:'relay.example',secret_path:root+'/relay.psk',destination_policy:{mode:'public-https',deny_ipv4:[]},listen:{ipv4:role==='client'?'0.0.0.0':`192.168.${back}.2`,port:role==='client'?10443:port},...(role==='client'?{exit:{ipv4:endpoint,port}}:{replay_directory:root+'/replay'})});
 const configs={};
 for(const role of ['client','exit']){
   const packet={version:1,role,address:role==='client'?endpoint:`192.168.${back}.2`,port,tun:role==='client'?'tun0':'cvexit0',secret_path:root+'/packet.psk',...(role==='client'?{dns:true,server_name:'runtime.test',sni:'relay.example',ca:'/config/cert.pem',tls_profile_path:'/config/profile.json'}:{cert:'/config/cert.pem',key:'/config/key.pem'})};
   configs[role]=mode==='transparent-tls'?relay(role):mode==='combo-tls'?{version:1,transport:mode,role,boring:packet,transparent:relay(role)}:packet;
   put(root+'/'+role+'.json',JSON.stringify(configs[role]));
 }
 if(mode==='transparent-tls'){
   fs.mkdirSync(root+'/replay',{mode:0o700});
   run(binary,['--init-transparent-replay',root+'/exit.json']);
   for(const [role,namespace,up]of[['client',n,'wlan0'],['exit',n+'exit','eth0']]){
     const defaultRoute=JSON.parse(ip('-n',namespace,'-j','route','show','default'))[0];
     const links=role==='client'?['wlan0','usb0']:['eth0'];for(const d of links)ip('-n',namespace,'link','set',d,'down');
     const c={version:1,transport:mode,role,uplink:up,endpoint:role==='client'?endpoint:`192.168.${back}.2`,port,listen_port:role==='client'?10443:port,lan:role==='client'?{interface:'usb0',subnet:'192.168.7.0/24'}:null,deny_ipv4:[]};
     applyNativeNetworkProfile(c,{run:(f,a,input)=>ns(namespace,f,a,input===undefined?{}:{input,stdio:['pipe','pipe','pipe']}),read:()=>null,save:()=>{},scope:namespace});
     for(const d of links)ip('-n',namespace,'link','set',d,'up');
     ip('-n',namespace,'route','replace','default','via',defaultRoute.gateway,'dev',defaultRoute.dev);
     const u=`port-${n}-${role}.service`;units.push(u);
     unit(u,`[Service]\nType=notify\nNetworkNamespacePath=/run/netns/${namespace}\nExecStart=${binary} --config ${root}/${role}.json --service\nRestart=on-failure\nRestartSec=1\nTimeoutStartSec=15\n`);
   }
   return {client:`port-${n}-client.service`,exit:`port-${n}-exit.service`,start:[`port-${n}-exit.service`,`port-${n}-client.service`],stop:[`port-${n}-client.service`,`port-${n}-exit.service`],configs};
 }
 for(const namespace of [n,n+'exit'])ns(namespace,'sysctl',['-w','net.ipv4.ip_forward=1']);
 const guard=`port-${n}-guard.service`;units.push(guard);
 unit(guard,`[Service]\nType=oneshot\nRemainAfterExit=yes\nNetworkNamespacePath=/run/netns/${n}\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=${endpoint} --ssh-port=22 --usb-dns=1 --usb-strict=1\n`);
 put(root+'/host.json',JSON.stringify({version:1,guard_unit:guard,guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));put(root+'/exit-host.json',JSON.stringify({version:1,uplink:'eth0'}));
 for(const [role,name]of[['client',n],['exit',n+'exit']]){
   const args={name,binary,config:root+'/'+role+'.json',apply:true,...(role==='client'?{hostProfile:root+'/host.json'}:{exitProfile:root+'/exit-host.json'})};installNative(args);
   for(const u of [`native-${name}.service`,`native-${name}-network.service`])put('/etc/systemd/system/'+u+'.d/lab.conf',`[Service]\nNetworkNamespacePath=/run/netns/${name}\n`);
   owners.push(`native-${name}-network.service`);
 }
 return {client:`native-${n}.service`,exit:`native-${n}exit.service`,start:[`native-${n}exit-network.service`,`native-${n}-network.service`],stop:[`native-${n}-network.service`,`native-${n}exit-network.service`],configs};
}
const mapping=(op,port,back)=>ns('front','iptables',['-t','nat',op,'PREROUTING','-d',endpoint,'-p','tcp','--dport',String(port),'-j','DNAT','--to-destination',`192.168.${back}.2:${port}`]);
let baseline,baselineState,success=false;
const baselineCheck=()=>{
 assert.equal(prop('port-baseline-heartbeat.service','ActiveState'),'active','baseline_https_monitor_failed');
 for(const [u,pid]of baselineState.pids)assert.equal(prop(u,'MainPID'),pid,'baseline_process_changed');
 assert.deepEqual(snapshot('base'),baselineState.client);assert.deepEqual(snapshot('baseexit'),baselineState.exit);
 assert.equal(digest('/opt/clean-vpn-native/base/config.json'),baselineState.config);
 assert.ok(ns('front','iptables',['-t','nat','-S']).includes('--to-destination 192.168.40.2:443'));
 https('baseusb');dns('baseusb');
};
try{
 newns('front');newns('origin');link('front','out','192.168.42.1/24','origin','uplink','192.168.42.2/24');
 ip('-n','front','route','add','default','via','192.168.42.2');
 ip('-n','front','addr','add',endpoint+'/32','dev','lo');ns('front','sysctl',['-w','net.ipv4.ip_forward=1']);
 ns('front','iptables',['-t','nat','-A','POSTROUTING','-o','out','-j','MASQUERADE']);
 for(const a of ['11.22.33.44','198.18.0.80','1.1.1.1','8.8.8.8'])ip('-n','origin','addr','add',a+'/32','dev','lo');
 for(const p of ['udp','tcp'])ns('origin','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
 fs.mkdirSync('/config',{mode:0o700});run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem']);
 put('/config/profile.json',JSON.stringify(profile));put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('/project/scripts/autostart/killswitch.sh'));fs.chmodSync('/usr/local/bin/clean-vpn-killswitch.sh',0o755);
 put('/config/origin.mjs',fs.readFileSync('/project/scripts/lib/native-runtime-lab-origin.mjs','utf8')+`\nhttps.createServer({key:fs.readFileSync('/config/key.pem'),cert:fs.readFileSync('/config/cert.pem')},(q,r)=>r.end('native-runtime-https-ok\\n')).listen(443,'0.0.0.0');\n`);
 unit('port-origin.service','[Service]\nNetworkNamespacePath=/run/netns/origin\nExecStart=/usr/bin/node /config/origin.mjs\n');units.push('port-origin.service');
 topology('base',11,40);baseline=installPair('base','boring-tls',443,40);mapping('-A',443,40);
 ctl('daemon-reload');ctl('start','port-origin.service',...baseline.start);await wait(()=>{https('baseusb');dns('baseusb');});
 put('/config/heartbeat.mjs',`import https from 'node:https';import fs from 'node:fs';let busy=false,count=0;const probe=()=>{if(busy)return;busy=true;const r=https.get({host:'11.22.33.44',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:2000},s=>{let b='';s.on('data',c=>b+=c);s.on('end',()=>{if(b!=='native-runtime-https-ok\\n')process.exit(2);fs.writeFileSync('/config/heartbeat.json',JSON.stringify({passed:++count}));busy=false;});});r.on('error',()=>process.exit(3));r.on('timeout',()=>r.destroy());};setInterval(probe,500);probe();\n`);
 unit('port-baseline-heartbeat.service','[Service]\nNetworkNamespacePath=/run/netns/baseusb\nExecStart=/usr/bin/node /config/heartbeat.mjs\n');units.push('port-baseline-heartbeat.service');ctl('daemon-reload');ctl('start','port-baseline-heartbeat.service');
 baselineState={pids:[...baseline.start,baseline.client,baseline.exit].map(u=>[u,prop(u,'MainPID')]),client:snapshot('base'),exit:snapshot('baseexit'),config:digest('/opt/clean-vpn-native/base/config.json')};
 check('baseline 443 installed and serving real TUN DNS HTTPS');
 for(const [mode,n,subnet,back]of[['boring-tls','trialboring',12,41],['combo-tls','trialcombo',14,43],['transparent-tls','trialrelay',15,44]]){
   topology(n,subnet,back);const pair=installPair(n,mode,3443,back);mapping('-A',3443,back);ctl('daemon-reload');
   const capture=`port-${n}-capture.service`,original=`port-${n}-original.service`;units.push(capture,original);
   for(const [u,namespace,dev,file,filter]of[[capture,n,'wlan0',n+'-wire','dst host '+endpoint+' and tcp dst port 3443'],[original,n+'usb','gadget',n+'-original','dst host 11.22.33.44 and tcp dst port 443']]){
     ctl('start','port-origin.service');run('systemd-run',['--unit='+u,'--property=NetworkNamespacePath=/run/netns/'+namespace,'--property=RuntimeMaxSec=180','--property=KillSignal=SIGINT','/usr/bin/tcpdump','-p','-nn','-U','-i',dev,'-s','0','-w','/config/'+file+'.pcap',filter]);
   }
   await delay(300);ctl('start',...pair.start);
   const healthy=()=>{assert.equal(prop(pair.client,'ActiveState'),'active');https(n+'usb',mode==='boring-tls'?8443:443);if(mode!=='transparent-tls'){https(n+'usb');dns(n+'usb');}};
   await wait(healthy);baselineCheck();check(mode+' 3443 data path; baseline 443 unchanged');
   const pid=prop(pair.exit,'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',pair.exit);baselineCheck();await wait(()=>{assert.notEqual(prop(pair.exit,'MainPID'),pid);healthy();});baselineCheck();check(mode+' exit crash recovery independent of baseline');
   const stopExit=pair.start[0];ctl('stop',stopExit);assert.throws(()=>https(n+'usb',mode==='boring-tls'?8443:443));baselineCheck();
   ctl('start',stopExit);await wait(healthy);baselineCheck();check(mode+' exit stop blocks candidate without direct or 443 fallback');
   ctl('stop',capture,original);
   const wire=inspectPcap(fs.readFileSync('/config/'+n+'-wire.pcap'),{destination:endpoint,port:3443,profile});
   const observed=wire.connections.filter(c=>c.status==='observed');assert.ok(observed.length>0);
   const packet=observed.filter(c=>c.sni?.includes('relay.example'));
   if(mode!=='transparent-tls'){assert.ok(packet.length>0);assert.ok(packet.every(c=>c.profile.status==='matched'));}
   let transparentMatched=0;
   if(mode!=='boring-tls'){
     const app=inspectPcap(fs.readFileSync('/config/'+n+'-original.pcap'),{destination:'11.22.33.44'}).connections.filter(c=>c.status==='observed');
     const relay=observed.filter(c=>c.sni?.some(s=>s.endsWith('.relay.example')));assert.ok(app.length>0&&relay.length>0);
     assert.ok(relay.every(c=>app.some(a=>a.ja3===c.ja3&&a.ja4===c.ja4)));transparentMatched=relay.length;
   }
   // Exercise public CLI too: the complete capture contains only the selected endpoint/port.
   const cli=JSON.parse(run('node',['/project/scripts/clean-vpn-pcap-fingerprints.mjs','--pcap=/config/'+n+'-wire.pcap','--destination='+endpoint,'--port=3443']));assert.equal(cli.connections.length,wire.connections.length);
   ctl('stop',...pair.stop);mapping('-D',3443,back);baselineCheck();
   assert.equal(prop(pair.client,'MainPID'),'0');assert.equal(prop(pair.exit,'MainPID'),'0');
   if(mode!=='transparent-tls')for(const namespace of [n,n+'exit'])assert.ok(!JSON.parse(ns(namespace,'ip',['-j','link'])).some(l=>['tun0','cvexit0'].includes(l.ifname)));
   phases.push({transport:mode,port:3443,profiledPacketHellos:packet.length,transparentFingerprintMatches:transparentMatched,baselinePreserved:true});check(mode+' cleanup leaves baseline 443 healthy');
 }
 success=true;
}finally{
 if(!success)for(const n of ['trialrelay','trialrelayexit'])try{console.error(n,ns(n,'ip',['route']),ns(n,'iptables-save',[]),ns(n,'ss',['-lnt']));}catch{}
 if(!success)for(const u of [...owners,...owners.map(n=>n.replace('-network.service','.service')),...units])try{console.error(run('journalctl',['-u',u,'-n','12','--no-pager','-o','cat']));}catch{}
 try{ctl('stop','port-baseline-heartbeat.service');}catch{}
 for(const u of [...owners,...units].reverse())try{ctl('stop',u);}catch{}
}
const report={schema:1,kind:'native-test-port-coexistence',status:'passed',engineSha256:digest(binary),baselinePort:443,testPort:3443,baselineHttpsProbes:JSON.parse(fs.readFileSync('/config/heartbeat.json')).passed,checks,phases,limitations:['disposable-systemd-netns-with-local-origin','not-physical-Radxa-or-VPS','same-address-port-DNAT-model-not-container-publish-test','transparent-SNI-token-changes-name-even-when-JA3-JA4-match','no-WAN-performance-or-long-soak-claim']};
put('/port-lab-report.json',JSON.stringify(report,null,2)+'\n');console.log('PORT_LAB_REPORT='+JSON.stringify(report));
