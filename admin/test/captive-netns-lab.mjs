#!/usr/bin/env node
// Run ONLY in the disposable systemd image from native-host.Containerfile.
// The caller creates/removes the container; no host mounts or WAN required.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {captiveUnit} from '../lib/captive-unit.mjs';
import {usbAdminSocketUnit} from '../lib/socket-unit.mjs';
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:12000,stdio:['ignore','pipe','pipe']}).trim();
assert.equal(process.argv[2],'--apply-disposable-lab');assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert(fs.existsSync('/etc/meshpn-admin-disposable-lab'));assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
const results=[],check=(name,fn)=>{fn();results.push(name);console.log('PASS '+name);};
const ip=(...a)=>run('/usr/sbin/ip',a),ipt=(...a)=>run('/usr/sbin/iptables',['-w','2',...a]);
const sys=(...a)=>run('/usr/bin/systemctl',a);
async function wait(fn){for(let i=0;i<80;i++){if(fn())return;await delay(200);}throw Error('lab_wait_timeout');}
const state=()=>{try{return JSON.parse(fs.readFileSync('/run/meshpn-admin/captive.json','utf8'));}catch{return{};}};
const nat=()=>ipt('-t','nat','-S','PREROUTING');
const curl=(ns,url,args=[])=>ip('netns','exec',ns,'curl','-q','--noproxy','*','--max-time','2','-sS','-D','-',...args,url);
const dns=(tcp=false)=>ip('netns','exec','cp-usb','dig','-b','192.168.7.2#54231','@1.1.1.1','probe.example','A','+short','+tries=1','+time=1',...(tcp?['+tcp']:[]));
const children=[];
try{
 for(const[ns,dev,peer,address,client]of[['cp-usb','usb0','cp-usb-peer','192.168.7.1/24','192.168.7.2/24'],['cp-other','lan-test','cp-other-peer','192.168.8.1/24','192.168.8.2/24']]){
  ip('netns','add',ns);ip('link','add',dev,'type','veth','peer','name',peer);ip('link','set',peer,'netns',ns);ip('address','add',address,'dev',dev);ip('link','set',dev,'up');ip('-n',ns,'link','set','lo','up');ip('-n',ns,'address','add',client,'dev',peer);ip('-n',ns,'link','set',peer,'up');ip('-n',ns,'route','add','default','via',address.split('/')[0]);
 }
 ip('link','add','wlan0','type','dummy');ip('link','set','wlan0','up');ip('address','add','192.0.2.2/24','dev','wlan0');ip('route','add','default','via','192.0.2.1','dev','wlan0');ip('address','add','10.99.0.1/32','dev','lo');
 // Real kernel data, simulated radio association only. No real wpa_supplicant.
 assert(!fs.existsSync('/usr/sbin/wpa_cli'),'lab must not replace an existing wpa_cli');
 fs.writeFileSync('/usr/sbin/wpa_cli','#!/bin/sh\ncat /run/captive-lab-wpa\n',{mode:0o755});fs.writeFileSync('/run/captive-lab-wpa','wpa_state=SCANNING\n');
 run('/bin/bash',['/project/scripts/autostart/killswitch.sh','up','--server=198.51.100.1','--tun=tun0','--usb-dns=1','--usb-strict=1']);
 const guardBefore=ipt('-S','CLEANVPN_KS_OUT')+'\n'+ipt('-S','CLEANVPN_KS_FWD');
 // Stand-in for native tunnel DNS DNAT, with a distinct answer and port.
 const dnsRule=p=>['-i','usb0','-s','192.168.7.0/24','-p',p,'--dport','53','-m','comment','--comment','lab-native-dns','-j','DNAT','--to-destination','10.99.0.1:1053'];
 for(const p of['udp','tcp'])ipt('-t','nat','-A','PREROUTING',...dnsRule(p));
 ipt('-A','INPUT','-m','comment','--comment','lab-foreign-rule','-j','ACCEPT');
 fs.mkdirSync('/opt/meshpn-admin',{recursive:true});fs.cpSync('/project/admin','/opt/meshpn-admin/admin',{recursive:true});fs.copyFileSync('/usr/bin/node','/opt/meshpn-admin/node');fs.chmodSync('/opt/meshpn-admin/node',0o755);
 try{run('/usr/bin/id',['meshpn-admin']);}catch{run('/usr/sbin/useradd',['--system','--user-group','meshpn-admin']);}
 fs.mkdirSync('/etc/meshpn-admin',{recursive:true});fs.writeFileSync('/etc/meshpn-admin/broker.json',JSON.stringify({usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',socket:'/run/meshpn-admin/broker.sock'}));
 fs.writeFileSync('/etc/systemd/system/meshpn-admin-broker.service','[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\nUser=root\nGroup=meshpn-admin\nRuntimeDirectory=meshpn-admin\nRuntimeDirectoryMode=0750\n');
 fs.writeFileSync('/etc/systemd/system/meshpn-admin-captive.service',captiveUnit());
 fs.writeFileSync('/run/captive-lab-web.mjs',`import {createAdmin} from '/project/admin/server.mjs';import dgram from 'node:dgram';import {portalDns} from '/project/admin/lib/captive.mjs';const a=await createAdmin({address:'192.168.7.1',subnet:'192.168.7.0/24',port:80,state:'/tmp/captive-web',brokerSocket:'/run/meshpn-admin/broker.sock'},{rpc:async()=>({hostname:'mpn'})});a.server.listen(80,'192.168.7.1');const d=dgram.createSocket('udp4');d.on('message',(b,r)=>{const a=portalDns(b,true);if(a&&a.readUInt16BE(6))Buffer.from([198,51,100,20]).copy(a,a.length-4);if(a)d.send(a,r.port,r.address);});d.bind(1053,'10.99.0.1');`);
 children.push(spawn('/usr/bin/node',['/run/captive-lab-web.mjs'],{stdio:['ignore','ignore','inherit']}));
 sys('daemon-reload');sys('enable','meshpn-admin-captive.service');sys('start','meshpn-admin-captive.service');await wait(()=>state().active===true);
 check('offline: two observations activate USB portal',()=>assert(state().active));
 check('fresh status readable by unprivileged frontend',()=>{const s=run('/usr/sbin/runuser',['-u','meshpn-admin','--','cat','/run/meshpn-admin/captive.json']);assert(JSON.parse(s).active);});
 check('USB DNS UDP/TCP redirected; zero-TTL synthetic answer',()=>{assert.equal(dns(),'192.168.7.1');assert.equal(dns(true),'192.168.7.1');});
 check('HTTP external IP receives fixed redirect; original Host not reflected',()=>{const r=curl('cp-usb','http://203.0.113.9/generate_204',['-H','Host: hostile.example']);assert(r.includes('302'));assert(r.includes('http://192.168.7.1/#wifi'));assert(!r.includes('hostile'));});
 check('DNS-to-board-IP probe redirects through real admin; canonical page works',()=>{assert(curl('cp-usb','http://192.168.7.1/hotspot-detect.html',['-H','Host: captive.apple.com']).includes('302'));assert(curl('cp-usb','http://192.168.7.1/').includes('200 OK'));assert(curl('cp-usb','http://192.168.7.1/api/status').includes('401'));});
 check('direct dedicated ports and non-USB access rejected',()=>{for(const[ns,url]of[['cp-usb','http://192.168.7.1:18080/'],['cp-other','http://192.168.7.1:18080/']])assert.throws(()=>curl(ns,url));assert(!curl('cp-other','http://192.168.7.1/', ['-H','Host: foreign.example']).includes('302'));});
 check('HTTPS remains unintercepted; kill switch stays installed',()=>{assert.throws(()=>curl('cp-usb','https://203.0.113.9/',['-k']));assert.equal(ipt('-S','CLEANVPN_KS_OUT')+'\n'+ipt('-S','CLEANVPN_KS_FWD'),guardBefore);});
 // Simulate DNS owner restarting and inserting its rule before the portal.
 ipt('-t','nat','-D','PREROUTING',...dnsRule('udp'));ipt('-t','nat','-I','PREROUTING','1',...dnsRule('udp'));
 await wait(()=>nat().split('\n').filter(s=>s.startsWith('-A ')).slice(0,3).every(s=>s.includes('meshpn-usb-captive-v1')));
 check('native DNS reinsert reconciled without removing native rules',()=>{assert.equal(dns(),'192.168.7.1');assert(nat().includes('lab-native-dns'));});
 fs.writeFileSync('/run/captive-lab-wpa','wpa_state=COMPLETED\n');await wait(()=>state().active===false&&state().reason==='wifi_ready'&&!nat().includes('meshpn-usb-captive-v1'));
 check('healthy Wi-Fi disables portal even with VPN absent',()=>assert(!nat().includes('meshpn-usb-captive-v1')));
 check('same UDP source tuple returns to native DNS (conntrack cleared)',()=>assert.equal(dns(),'198.51.100.20'));
 check('online admin again rejects foreign Host',()=>assert(curl('cp-usb','http://192.168.7.1/generate_204',['-H','Host: hostile.example']).includes('403')));
 ip('route','del','default');await wait(()=>state().active===true);check('association without default route activates portal and clears old native DNS tuple',()=>{assert.equal(state().reason,'wifi_route_pending');assert.equal(dns(),'192.168.7.1');});
 fs.writeFileSync('/run/captive-lab-wpa','FAIL\n');await wait(()=>state().active===false&&!nat().includes('meshpn-usb-captive-v1'));check('unknown Wi-Fi status removes interception',()=>assert(!nat().includes('meshpn-usb-captive-v1')));
 fs.writeFileSync('/run/captive-lab-wpa','wpa_state=SCANNING\n');await wait(()=>state().active===true);
 const oldPid=sys('show','meshpn-admin-captive.service','-p','MainPID','--value');
 sys('kill','--kill-whom=main','--signal=SIGKILL','meshpn-admin-captive.service');
 await wait(()=>{const pid=sys('show','meshpn-admin-captive.service','-p','MainPID','--value');return pid!=='0'&&pid!==oldPid&&state().active===true;});
 check('automatic restart after SIGKILL reacquires portal without duplicate rules',()=>assert.equal(nat().split('\n').filter(s=>s.includes('meshpn-usb-captive-v1')).length,3));
 // Disable automatic restart for an observable crash recovery boundary.
 fs.mkdirSync('/etc/systemd/system/meshpn-admin-captive.service.d',{recursive:true});fs.writeFileSync('/etc/systemd/system/meshpn-admin-captive.service.d/lab.conf','[Service]\nRestart=no\n');sys('daemon-reload');sys('kill','--kill-whom=main','--signal=SIGKILL','meshpn-admin-captive.service');
 await wait(()=>!nat().includes('meshpn-usb-captive-v1')&&!ipt('-S','INPUT').includes('meshpn-usb-captive-v1'));
 check('SIGKILL: actual ExecStopPost removes only owned rules',()=>{assert(!state().active);assert(nat().includes('lab-native-dns'));assert(ipt('-S','INPUT').includes('lab-foreign-rule'));assert.equal(ipt('-S','CLEANVPN_KS_OUT')+'\n'+ipt('-S','CLEANVPN_KS_FWD'),guardBefore);});
 sys('reset-failed','meshpn-admin-captive.service');sys('start','meshpn-admin-captive.service');await wait(()=>state().active===true);sys('stop','meshpn-admin-broker.service');
 await wait(()=>!nat().includes('meshpn-usb-captive-v1'));
 check('broker stop also stops portal before runtime directory removal',()=>assert.equal(sys('show','meshpn-admin-captive.service','-p','ActiveState','--value'),'inactive'));
 sys('start','meshpn-admin-broker.service');await wait(()=>state().active===true);sys('stop','meshpn-admin-captive.service');
 check('broker start pulls portal back; normal stop cleans up',()=>{assert(!nat().includes('meshpn-usb-captive-v1'));assert(!ipt('-S','INPUT').includes('meshpn-usb-captive-v1'));});
 // Exercise the real --update/--remove installer against disposable owned
 // service fixtures. Native VPN and Wi-Fi settings are sentinel files.
 for(const p of children)p.kill('SIGTERM');await delay(200);
 const broker='/etc/systemd/system/meshpn-admin-broker.service';fs.writeFileSync(broker,'# meshpn-admin-owned-v1\n'+fs.readFileSync(broker,'utf8'));
 fs.writeFileSync('/etc/systemd/system/meshpn-admin.socket','# meshpn-admin-owned-v1\n'+usbAdminSocketUnit());fs.writeFileSync('/etc/systemd/system/meshpn-admin-web.service','# meshpn-admin-owned-v1\n[Service]\nExecStart=/bin/sleep infinity\n');
 // Containers have no udev-backed .device units. Only this installer socket
 // fixture drops the device dependency; earlier HTTP checks use real USB veth.
 fs.mkdirSync('/etc/systemd/system/meshpn-admin.socket.d',{recursive:true});fs.writeFileSync('/etc/systemd/system/meshpn-admin.socket.d/lab.conf','[Socket]\nBindToDevice=\n');
 fs.writeFileSync('/etc/meshpn-admin/manifest.json',JSON.stringify({kind:'meshpn-admin-owned-install'}));fs.copyFileSync('/project/scripts/autostart/killswitch.sh','/usr/local/bin/clean-vpn-killswitch.sh');
 fs.mkdirSync('/var/lib/meshpn-admin-broker',{recursive:true});fs.writeFileSync('/var/lib/meshpn-admin-broker/wifi.json','test-wifi-sentinel');
 run('/usr/bin/git',['-C','/project','init']);run('/usr/bin/git',['-C','/project','-c','user.email=lab@example.invalid','-c','user.name=Lab','commit','--allow-empty','-m','disposable lab']);
 // Mimic an installation from before the portal existed.
 sys('disable','meshpn-admin-captive.service');fs.unlinkSync('/etc/systemd/system/meshpn-admin-captive.service');fs.rmSync('/etc/systemd/system/meshpn-admin-captive.service.d',{recursive:true});sys('daemon-reload');
 const updated=run('/usr/bin/node',['/project/admin/install.mjs','--update']);await wait(()=>state().active===true);
 check('real installer update adds portal to previous installation and preserves Wi-Fi settings',()=>{assert(updated.includes('ADMIN_UPDATED'));assert.equal(fs.readFileSync('/var/lib/meshpn-admin-broker/wifi.json','utf8'),'test-wifi-sentinel');assert.equal(fs.readFileSync('/etc/systemd/system/meshpn-admin-captive.service','utf8'),captiveUnit());});
 run('/usr/bin/node',['/project/admin/install.mjs','--remove']);
 check('real installer removal cleans portal and retains unrelated guard/DNS rules',()=>{assert(!nat().includes('meshpn-usb-captive-v1'));assert(!ipt('-S','INPUT').includes('meshpn-usb-captive-v1'));assert(nat().includes('lab-native-dns'));assert.equal(ipt('-S','CLEANVPN_KS_OUT')+'\n'+ipt('-S','CLEANVPN_KS_FWD'),guardBefore);});
 const report={kind:'meshpn-usb-captive-netns-lab',passed:results.length,checks:results,radio:'simulated wpa_cli; real Linux links/routes',scope:'disposable systemd/netns; real iptables/conntrack; no physical boards or client OS popup test; installer socket fixture clears BindToDevice (container has no udev device units)'};fs.writeFileSync('/run/captive-lab-report.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}finally{try{sys('stop','meshpn-admin-captive.service');}catch{}for(const p of children)p.kill('SIGTERM');}
