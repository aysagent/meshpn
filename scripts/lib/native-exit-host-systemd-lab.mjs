// Disposable NIC-less systemd fixture. Real TUN forwarding/NAT to a separate
// origin namespace; never run on a physical host.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_EXIT_SYSTEMD,'1');
assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:180000,maxBuffer:1024*1024}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('systemctl',a),ns=(name,f,a)=>run('ip',['netns','exec',name,f,...a]);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
const put=(p,s,mode=0o600)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,s,{mode});};
const unit=(name,body)=>put('/etc/systemd/system/'+name,body,0o644),prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const wait=async(fn,ms=60000)=>{let error;const end=performance.now()+ms;while(performance.now()<end){try{return fn();}catch(e){error=e;await delay(200);}}throw error??Error('timeout');};
const checks=[],check=name=>{checks.push(name);console.log('EXIT_SYSTEMD_CHECK '+name);};
const engine='native-exit-lab.service',network='native-exit-lab-network.service',client='native-client-lab.service',clientNetwork='native-client-lab-network.service';
const binary='/usr/local/bin/clean-vpn-engine',bundle='/opt/clean-vpn-native/exit-lab';
const sha=b=>createHash('sha256').update(b).digest('hex');
const probe=`const https=require('node:https'),fs=require('node:fs');const q=https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:4000},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{if(b!=='native-runtime-https-ok\\n'||r.headers['x-native-runtime-peer']!=='198.18.1.1')process.exit(2);console.log('HTTPS_NAT_OK')});});q.on('error',()=>process.exit(3));q.on('timeout',()=>q.destroy());setTimeout(()=>process.exit(4),5000).unref();`;
const https=()=>assert.equal(ns('client','node',['-e',probe]),'HTTPS_NAT_OK');
const dns=()=>assert.equal(ns('client','node',['--input-type=module','-e',`import {dnsProbe} from '/project/scripts/clean-vpn-native-runtime-health.mjs';await dnsProbe('10.99.0.2',1053,false);await dnsProbe('10.99.0.2',1053,true);console.log('DNS_OK');`]),'DNS_OK');
try{
  for(const n of ['client','exit','origin','usb']){ip('netns','add',n);ip('-n',n,'link','set','lo','up');}
  for(const [left,ld,la,right,rd,ra] of [['client','wlan0','192.168.1.8/24','exit','client0','192.168.1.1/24'],['exit','eth0','198.18.1.1/24','origin','wan0','198.18.1.2/24'],['client','usb0','192.168.7.1/24','usb','gadget','192.168.7.19/24']]){
    ip('link','add',ld,'netns',left,'type','veth','peer','name',rd,'netns',right);
    for(const [n,d,a] of [[left,ld,la],[right,rd,ra]]){ip('-n',n,'address','add',a,'dev',d);ip('-n',n,'link','set',d,'up');}
  }
  ip('-n','exit','address','add','154.62.226.216/32','dev','lo');ip('-n','exit','route','add','default','via','198.18.1.2');
  ip('-n','client','route','add','default','via','192.168.1.1');ip('-n','usb','route','add','default','via','192.168.7.1');
  for(const n of ['client','exit'])ns(n,'sysctl',['-w','net.ipv4.ip_forward=1']);
  for(const a of ['198.18.0.80','1.1.1.1','8.8.8.8'])ip('-n','origin','address','add',a+'/32','dev','lo');
  for(const p of ['udp','tcp'])ns('origin','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
  ns('exit','iptables',['-N','FOREIGN_SENTINEL']);ns('exit','iptables',['-A','FORWARD','-j','FOREIGN_SENTINEL']);ns('exit','iptables',['-P','FORWARD','DROP']);
  ns('exit','iptables',['-t','nat','-A','POSTROUTING','-s','203.0.113.0/24','-o','eth0','-j','MASQUERADE']);
  const baseline=()=>({filter:ns('exit','iptables',['-S']),nat:ns('exit','iptables',['-t','nat','-S']),routes:ip('-n','exit','-N','-j','-4','route','show','table','all'),forward:ns('exit','sysctl',['-n','net.ipv4.ip_forward'])});
  const before=baseline();fs.mkdirSync('/config',{mode:0o700});
  run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem']);put('/config/psk',randomBytes(32));
  const common={version:1,address:'154.62.226.216',port:443,secret_path:'/config/psk'};
  put('/config/client.json',JSON.stringify({...common,role:'client',tun:'tun0',dns:true,server_name:'runtime.test',sni:'runtime.test',ca:'/config/cert.pem'}));
  put('/config/exit.json',JSON.stringify({...common,role:'exit',tun:'cvexit0',cert:'/config/cert.pem',key:'/config/key.pem'}));
  put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('/project/scripts/autostart/killswitch.sh'),0o755);
  unit('client-lab-guard.service',`[Service]\nType=oneshot\nRemainAfterExit=yes\nNetworkNamespacePath=/run/netns/client\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=154.62.226.216 --ssh-port=22 --usb-dns=1 --usb-strict=1\n`);
  unit('exit-lab-origin.service',`[Service]\nNetworkNamespacePath=/run/netns/origin\nExecStart=/usr/bin/node /project/scripts/lib/native-runtime-lab-origin.mjs\n`);
  put('/config/client-host.json',JSON.stringify({version:1,guard_unit:'client-lab-guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
  put('/config/exit-host.json',JSON.stringify({version:1,uplink:'eth0'}));
  const a=installNative({name:'client-lab',binary,config:'/config/client.json',hostProfile:'/config/client-host.json',apply:true});
  const b=installNative({name:'exit-lab',binary,config:'/config/exit.json',exitProfile:'/config/exit-host.json',apply:true});
  assert.equal(a.activation,clientNetwork);assert.equal(b.activation,network);
  for(const [u,n] of [[client,'client'],[clientNetwork,'client'],[engine,'exit'],[network,'exit']])put('/etc/systemd/system/'+u+'.d/lab.conf','[Service]\nNetworkNamespacePath=/run/netns/'+n+'\n',0o644);
  ctl('daemon-reload');assert.equal(prop(engine,'MainPID'),'0');assert.equal(prop(network,'MainPID'),'0');check('fresh exit installation remains stopped');
  const updater='/project/scripts/clean-vpn-native-update.mjs';run('node',[updater,'--enroll','exit-lab']);check('binary updater binds owned exit units');
  ctl('start','exit-lab-origin.service',network,clientNetwork);await wait(()=>{assert.equal(prop(client,'ActiveState'),'active');https();});dns();check('actual forwarding NAT HTTPS and UDP TCP DNS');
  let pid=prop(engine,'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',engine);await wait(()=>{assert.notEqual(prop(engine,'MainPID'),pid);https();});check('exit engine crash recovers with owner retained');
  pid=prop(network,'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',network);await wait(()=>{assert.notEqual(prop(network,'MainPID'),pid);assert.equal(prop(engine,'ActiveState'),'active');https();});dns();check('exit owner crash cleans then recreates scoped network');
  const candidate='/config/candidate';put(candidate,Buffer.concat([fs.readFileSync(binary),Buffer.from('\nexit-update\n')]),0o755);
  assert.equal(JSON.parse(run('node',[updater,'--apply','exit-lab',candidate,sha(fs.readFileSync(candidate))])).status,'updated');https();check('exit binary update retains forwarding');
  const bad='/config/bad';put(bad,`#!/bin/sh\ncase "$1" in --capabilities|--check-config) exec ${candidate} "$@";; *) exit 77;; esac\n`,0o755);
  assert.throws(()=>run('node',[updater,'--apply','exit-lab',bad,sha(fs.readFileSync(bad))]));assert.equal(sha(fs.readFileSync(bundle+'/engine')),sha(fs.readFileSync(candidate)));https();dns();check('bad exit binary rolls back and restores traffic');
  ctl('stop',network);assert.equal(prop(network,'Result'),'success');assert.equal(prop(engine,'MainPID'),'0');assert.deepEqual(baseline(),before);check('stop restores foreign firewall routes and forwarding exactly');
  assert.throws(https);assert.equal(prop('client-lab-guard.service','ActiveState'),'active');check('stopped exit has no client direct fallback');
  ctl('start',network);await wait(https);dns();check('exit restarts without client intervention');
  ctl('stop',clientNetwork,network);assert.deepEqual(baseline(),before);check('final scoped cleanup');
  console.log(JSON.stringify({status:'passed',checks,scope:'disposable NIC-less systemd container; real native TUN forwarding and NAT; separate origin; not physical boot'}));
}catch(e){for(const u of [network,engine,clientNetwork,client])try{console.error(run('journalctl',['--no-pager','-u',u,'-n','30']));}catch{}throw e;}
