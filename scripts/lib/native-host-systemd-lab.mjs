// Disposable, NIC-less Linux systemd fixture; never run on a physical host.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_HOST_SYSTEMD,'1');
assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:30000,maxBuffer:1024*1024}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('systemctl',a);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);
assert.equal(ip('netns','list'),'');
const checks=[];const check=(name)=>{checks.push(name);console.log('HOST_SYSTEMD_CHECK '+name);};
const put=(p,s,mode=0o600)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,s,{mode});};
const unit=(name,body)=>put('/etc/systemd/system/'+name,body,0o644);
const prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const wait=async(fn,ms=40000)=>{let error;const end=performance.now()+ms;while(performance.now()<end){try{return fn();}catch(e){error=e;await delay(200);}}throw error??Error('timeout');};
const ns=(name,f,a)=>run('ip',['netns','exec',name,f,...a]);
const binary='/usr/local/bin/clean-vpn-engine',name='host-lab',engine='native-'+name+'.service',network='native-'+name+'-network.service';
const probe=`const https=require('node:https'),fs=require('node:fs');const q=https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:4000},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{if(b!=='native-runtime-https-ok\\n')process.exit(2);console.log('HTTPS_OK')});});q.on('error',()=>process.exit(3));q.on('timeout',()=>q.destroy());setTimeout(()=>process.exit(4),5000).unref();`;
const https=where=>assert.equal(ns(where,'node',['-e',probe]),'HTTPS_OK');
try{
  for(const name of ['client','exit','usb']){ip('netns','add',name);ip('-n',name,'link','set','lo','up');}
  for(const [dev,peer,other,local,remote] of [['wlan0','uplink','exit','192.168.1.8/24','192.168.1.1/24'],['usb0','gadget','usb','192.168.7.1/24','192.168.7.19/24']]){
    ip('link','add',dev,'netns','client','type','veth','peer','name',peer,'netns',other);
    ip('-n','client','addr','add',local,'dev',dev);ip('-n',other,'addr','add',remote,'dev',peer);
    ip('-n','client','link','set',dev,'up');ip('-n',other,'link','set',peer,'up');
  }
  ip('-n','client','route','add','default','via','192.168.1.1');ip('-n','usb','route','add','default','via','192.168.7.1');
  ns('client','sysctl',['-w','net.ipv4.ip_forward=1']);
  for(const address of ['154.62.226.216','1.1.1.1','8.8.8.8','198.18.0.80'])ip('-n','exit','addr','add',address+'/32','dev','lo');
  ns('exit','ip',['tuntap','add','dev','tun0','mode','tun']);ip('-n','exit','addr','add','10.99.0.1/24','dev','tun0');ip('-n','exit','link','set','tun0','mtu','1400','up');
  for(const p of ['udp','tcp'])ns('exit','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
  fs.mkdirSync('/config',{mode:0o700});
  run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem']);
  put('/config/psk',randomBytes(32));
  const common={version:1,address:'154.62.226.216',port:443,tun:'tun0',secret_path:'/config/psk'};
  put('/config/client.json',JSON.stringify({...common,role:'client',dns:true,server_name:'runtime.test',sni:'runtime.test',ca:'/config/cert.pem'}));
  put('/config/exit.json',JSON.stringify({...common,role:'exit',cert:'/config/cert.pem',key:'/config/key.pem'}));
  const executable=fs.readFileSync('/project/scripts/autostart/killswitch.sh');put('/usr/local/bin/fixture-killswitch.sh',executable,0o755);
  put('/usr/local/bin/clean-vpn-killswitch.sh','#!/bin/sh\nif [ "$1" = status ] && [ -e /run/hold-native-audit ]; then touch /run/native-audit-entered; sleep 2; fi\nexec /usr/local/bin/fixture-killswitch.sh "$@"\n',0o755);
  unit('host-lab-guard.service',`[Unit]\nDescription=Disposable native guard\n[Service]\nType=oneshot\nRemainAfterExit=yes\nNetworkNamespacePath=/run/netns/client\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=154.62.226.216 --ssh-port=22 --usb-dns=1 --usb-strict=1\n`);
  unit('host-lab-exit.service',`[Service]\nType=notify\nNetworkNamespacePath=/run/netns/exit\nExecStart=${binary} --config /config/exit.json --service\nRestart=on-failure\nRestartSec=1\n`);
  unit('host-lab-origin.service',`[Service]\nNetworkNamespacePath=/run/netns/exit\nExecStart=/usr/bin/node /project/scripts/lib/native-runtime-lab-origin.mjs\n`);
  put('/config/host.json',JSON.stringify({version:1,guard_unit:'host-lab-guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
  const installed=installNative({name,binary,config:'/config/client.json',hostProfile:'/config/host.json',apply:true});assert.equal(installed.activation,network);
  for(const u of [engine,network])put('/etc/systemd/system/'+u+'.d/lab.conf','[Service]\nNetworkNamespacePath=/run/netns/client\n',0o644);
  ctl('daemon-reload');assert.equal(prop(engine,'MainPID'),'0');assert.equal(prop(network,'MainPID'),'0');check('installer leaves network and engine stopped');
  ctl('start','host-lab-origin.service','host-lab-exit.service');ctl('start',network);
  await wait(()=>assert.equal(prop(engine,'ActiveState'),'active'));https('client');https('usb');check('installed native host and USB HTTPS');
  const dnsCode=`import {dnsProbe} from '/project/scripts/clean-vpn-native-runtime-health.mjs';await dnsProbe('10.99.0.2',1053,false);await dnsProbe('10.99.0.2',1053,true);console.log('DNS_OK');`;
  assert.equal(ns('client','node',['--input-type=module','-e',dnsCode]),'DNS_OK');check('native UDP and TCP DNS');
  const oldPid=prop(engine,'MainPID');ctl('kill','--signal=SIGKILL',engine);await wait(()=>{assert.notEqual(prop(engine,'MainPID'),oldPid);assert.equal(prop(engine,'ActiveState'),'active');https('usb');});check('engine SIGKILL restarts with network owner retained');
  put('/run/hold-native-audit','hold');await wait(()=>assert.ok(fs.existsSync('/run/native-audit-entered')));fs.unlinkSync('/run/hold-native-audit');
  ctl('stop',network);await wait(()=>assert.equal(prop(network,'ActiveState'),'inactive'));assert.equal(prop(network,'Result'),'success');check('graceful stop during synchronous audit succeeds');
  assert.equal(prop(engine,'MainPID'),'0');assert.ok(!JSON.parse(ip('-n','client','-j','link')).some(l=>l.ifname==='tun0'));
  assert.throws(()=>https('usb'));assert.match(ns('client','/usr/local/bin/clean-vpn-killswitch.sh',['status']),/IPv6: cvks4/);check('network stop cleans owned state and keeps guard closed');
  ctl('start',network);await wait(()=>{assert.equal(prop(engine,'ActiveState'),'active');https('usb');});check('network restart recreates TUN without legacy');
  const oldOwner=prop(network,'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',network);
  await wait(()=>{assert.notEqual(prop(network,'MainPID'),oldOwner);assert.equal(prop(network,'ActiveState'),'active');assert.equal(prop(engine,'ActiveState'),'active');https('usb');},60000);check('network SIGKILL ExecStopPost recovers then restarts');
  ctl('stop','host-lab-exit.service');assert.throws(()=>https('usb'));check('exit outage has no direct fallback');
  ctl('start','host-lab-exit.service');await wait(()=>https('usb'));check('exit recovery needs no client manual restart');
  ctl('stop',network);check('final cleanup');
  console.log(JSON.stringify({status:'passed',checks,scope:'disposable systemd container, real native TLS and USB topology, no physical boot'}));
}catch(e){
  for(const u of [network,engine,'host-lab-exit.service'])try{console.error(run('journalctl',['--no-pager','-u',u,'-n','45']));}catch{}
  throw e;
}
