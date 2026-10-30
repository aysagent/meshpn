// Disposable NIC-less Linux systemd container, never a physical installation.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
import {brokerRequest} from '../../admin/server.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_HOST_ADMIN,'1');
assert.equal(fs.readFileSync('/run/systemd/container','utf8').trim(),'podman');
assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:90000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('systemctl',a),ns=(n,f,a)=>run('ip',['netns','exec',n,f,...a]);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
const put=(p,b,mode=0o600)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,b,{mode});};
const unit=(n,b)=>put('/etc/systemd/system/'+n,b,0o644),checks=[];
const check=n=>{checks.push(n);console.log('HOST_ADMIN_CHECK '+n);};
const prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const wait=async fn=>{let error;const end=performance.now()+60000;while(performance.now()<end){try{return await fn();}catch(e){error=e;await delay(250);}}throw error;};
const engine='native-admin-lab.service',network='native-admin-lab-network.service',guard='clean-vpn-killswitch.service';
const request=(r,p={})=>brokerRequest('/run/meshpn-admin/broker.sock',r,p);
const job=async(r,p)=>{const begun=await request(r,p);return wait(async()=>{const s=await request('/status'),j=s.jobs.find(j=>j.id===begun.id);assert.ok(j&&j.status!=='running');assert.equal(j.status,'passed',j.error);return j.result;});};
try{
 for(const n of ['exit','usb']){ip('netns','add',n);ip('-n',n,'link','set','lo','up');}
 for(const [dev,peer,other,a,b] of [['wlan0','uplink','exit','192.168.1.8/24','192.168.1.1/24'],['usb0','gadget','usb','192.168.7.1/24','192.168.7.19/24']]){
  ip('link','add',dev,'type','veth','peer','name',peer,'netns',other);ip('addr','add',a,'dev',dev);ip('-n',other,'addr','add',b,'dev',peer);ip('link','set',dev,'up');ip('-n',other,'link','set',peer,'up');
 }
 ip('route','add','default','via','192.168.1.1');ip('-n','usb','route','add','default','via','192.168.7.1');run('sysctl',['-w','net.ipv4.ip_forward=1']);
 for(const a of ['154.62.226.216','1.1.1.1','8.8.8.8','198.18.0.80'])ip('-n','exit','addr','add',a+'/32','dev','lo');
 ns('exit','ip',['tuntap','add','dev','tun0','mode','tun']);ip('-n','exit','addr','add','10.99.0.1/24','dev','tun0');ip('-n','exit','link','set','tun0','mtu','1400','up');
 for(const p of ['udp','tcp'])ns('exit','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
 fs.mkdirSync('/config',{mode:0o700});run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=runtime.test','-addext','subjectAltName=DNS:runtime.test','-keyout','/config/key.pem','-out','/config/cert.pem']);put('/config/psk',randomBytes(32));
 const common={version:1,address:'154.62.226.216',port:443,tun:'tun0',secret_path:'/config/psk'};
 put('/config/client.json',JSON.stringify({...common,role:'client',dns:true,ca:'/config/cert.pem',server_name:'runtime.test',sni:'runtime.test'}));
 put('/config/exit.json',JSON.stringify({...common,role:'exit',cert:'/config/cert.pem',key:'/config/key.pem'}));
 put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('/project/scripts/autostart/killswitch.sh'),0o755);
 unit(guard,'[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=154.62.226.216 --ssh-port=22 --usb-dns=1 --usb-strict=1\n');
 unit('admin-lab-exit.service','[Service]\nType=notify\nNetworkNamespacePath=/run/netns/exit\nExecStart=/usr/local/bin/clean-vpn-engine --config /config/exit.json --service\n');
 unit('admin-lab-origin.service','[Service]\nNetworkNamespacePath=/run/netns/exit\nExecStart=/usr/bin/node /project/scripts/lib/native-runtime-lab-origin.mjs\n');
 put('/config/host.json',JSON.stringify({version:1,guard_unit:guard,guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
 installNative({name:'admin-lab',binary:'/usr/local/bin/clean-vpn-engine',config:'/config/client.json',hostProfile:'/config/host.json',apply:true});
 ctl('daemon-reload');ctl('start',guard,'admin-lab-exit.service','admin-lab-origin.service','avahi-daemon.service');
 run('git',['-C','/project','init']);run('git',['-C','/project','-c','user.name=Disposable fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-m','disposable lab snapshot']);
 const plan=JSON.parse(run('node',['/project/admin/install.mjs','--plan','--native-name=admin-lab']));assert.equal(plan.networkUnit,network);
 // Container PID1 has no udev device activation. Keep address binding and
 // subnet checks; interface-bound socket activation is a physical/VM gate.
 put('/etc/systemd/system/meshpn-admin.socket.d/container.conf','[Socket]\nBindToDevice=\n',0o644);
 run('node',['/project/admin/install.mjs','--apply','--native-name=admin-lab']);
 assert.equal(prop(engine,'MainPID'),'0');assert.equal(prop(network,'MainPID'),'0');check('fresh-admin-install-does-not-start-vpn');
 await wait(()=>request('/settings'));assert.equal((await request('/settings')).vpn.nativeManaged,true);check('broker-native-binding');
 // Reproduce the physical upgrade failure with a real systemd mount sandbox:
 // the old drop-in grants writes to a previous bundle, not the selected one.
 const brokerUnit='/etc/systemd/system/meshpn-admin-broker.service';
 const selectedBundle='/opt/clean-vpn-native/admin-lab';
 put(brokerUnit,fs.readFileSync(brokerUnit,'utf8').replace(' '+selectedBundle+' /run/meshpn-admin',' /run/meshpn-admin'),0o644);
 fs.mkdirSync('/opt/clean-vpn-native/previous',{recursive:true});
 put('/etc/systemd/system/meshpn-admin-broker.service.d/native-daily.conf','# clean-vpn-daily-native-binding\n[Service]\nReadWritePaths=/opt/clean-vpn-native/previous\n',0o644);
 ctl('daemon-reload');ctl('restart','meshpn-admin-broker.service');await wait(()=>request('/settings'));
 const oldSettings=await request('/settings');
 const failed=await request('/vpn/settings',{address:oldSettings.vpn.address,port:oldSettings.vpn.port,serverName:oldSettings.vpn.serverName,sni:oldSettings.vpn.sni,profile:null});
 await wait(async()=>{const j=(await request('/status')).jobs.find(j=>j.id===failed.id);assert.equal(j?.status,'failed');});
 ctl('restart','meshpn-admin-broker.service');
 await wait(async()=>{const s=await request('/status');assert.equal(s.vpnSettingsRecovery.status,'blocked');assert.equal(s.vpnSettingsRecovery.pending,true);});
 check('readonly-old-binding-reproduced-diagnostics-stay-available');
 run('node',['/project/admin/install.mjs','--update']);
 await wait(async()=>assert.equal((await request('/status')).vpnSettingsRecovery.pending,false));
 assert.ok(fs.readFileSync(brokerUnit,'utf8').includes(' '+selectedBundle+' /run/meshpn-admin'));
 assert.equal(fs.existsSync('/etc/systemd/system/meshpn-admin-broker.service.d/native-daily.conf'),false);
 assert.equal(prop(engine,'MainPID'),'0');assert.equal(prop(network,'MainPID'),'0');
 check('update-repairs-sandbox-and-recovers-journal-without-starting-vpn');
 const login=ns('usb','curl',['-sS','--max-time','10','--noproxy','*','-H','Host: mpn.local','-H','Origin: http://mpn.local','-H','Content-Type: application/json','-d','{"password":"admin"}','http://192.168.7.1/api/login']);assert.equal(JSON.parse(login).defaultPassword,true);check('USB-web-login');
 await job('/vpn/action',{action:'start'});assert.equal(prop(engine,'ActiveState'),'active');check('admin-starts-network-and-engine');
 const ownerPid=prop(network,'MainPID');ctl('stop',engine);assert.equal(prop(network,'MainPID'),ownerPid);
 await job('/vpn/action',{action:'start'});assert.equal(prop(engine,'ActiveState'),'active');assert.equal(prop(network,'MainPID'),ownerPid);
 check('admin-start-recovers-stopped-engine-with-active-owner');
 const https=()=>assert.equal(ns('usb','curl',['-fsS','--max-time','10','--noproxy','*','--cacert','/config/cert.pem','--resolve','runtime.test:8443:198.18.0.80','https://runtime.test:8443/']),'native-runtime-https-ok');https();check('USB-native-HTTPS');
 const configured=await request('/settings');await job('/vpn/settings',{address:configured.vpn.address,port:configured.vpn.port,serverName:configured.vpn.serverName,sni:configured.vpn.sni,profile:'chromium-156-bounded-cold.json'});https();check('admin-profile-apply-and-native-restart');
 await job('/vpn/action',{action:'stop'});assert.equal(prop(engine,'MainPID'),'0');assert.ok(!JSON.parse(ip('-j','link')).some(l=>l.ifname==='tun0'));assert.throws(https);check('admin-stop-cleans-network-keeps-guard');
 await job('/vpn/action',{action:'start'});https();await job('/vpn/action',{action:'restart'});https();check('admin-restart-recreates-network');
 await job('/guard',{enabled:false,confirmDirect:true});assert.equal(prop(engine,'MainPID'),'0');assert.equal(prop(network,'MainPID'),'0');assert.equal((await request('/status')).guard.active,false);
 check('admin-disable-guard-cleans-vpn-and-releases-protection');
 await job('/guard',{enabled:true});assert.equal((await request('/status')).guard.active,true);await job('/vpn/action',{action:'start'});https();
 check('admin-reenable-guard-and-vpn-restores-USB-HTTPS');
 await job('/vpn/action',{action:'stop'});run('node',['/project/admin/install.mjs','--remove']);check('remove-admin-keeps-native-stopped');
 console.log(JSON.stringify({status:'passed',checks,scope:'real native host-profile + fresh address-bound admin installer in isolated systemd container',limitations:['container socket BindToDevice cleared: no udev device units; not physical USB socket acceptance']}));
}catch(e){for(const u of [network,engine,guard,'meshpn-admin-broker.service','meshpn-admin-web.service'])try{console.error(run('journalctl',['--no-pager','-u',u,'-n','35']));}catch{}throw e;}
