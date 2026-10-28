// Real kernel boots, disposable NIC-less QEMU guest only.
import fs from 'node:fs';
import {dirname} from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {installNative} from './native-install.mjs';
assert.match(fs.readFileSync('/proc/cmdline','utf8'),/\bmeshpn.native-host-boot=1\b/);
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor','utf8').trim(),'QEMU');
assert.match(fs.readFileSync('/proc/mounts','utf8'),/^\/dev\/vda \/state ext4 /m);
const phase=fs.existsSync('/state/phase')?Number(fs.readFileSync('/state/phase')):0;
assert.ok([0,1,2].includes(phase));
const mode=process.argv[2],checks=[],timings={},bundle='/opt/clean-vpn-native/host-boot',engine='native-host-boot.service',network='native-host-boot-network.service';
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:180000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const ip=(...a)=>run('ip',a),ctl=(...a)=>run('/usr/bin/systemctl',a),ns=(name,f,a)=>run('ip',['netns','exec',name,f,...a]);
const prop=(u,k)=>ctl('show',u,'-p',k,'--value');
const put=(p,b,mode=0o600)=>{fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,b,{mode});};
const unit=(n,b)=>put('/etc/systemd/system/'+n,b,0o644);
const check=(name,ok=true)=>{assert.ok(ok,name);checks.push(name);console.log('HOST_BOOT_CHECK '+name);};
// TCG includes two full iptables/journal passes during owner crash recovery.
const wait=async fn=>{let error;const until=performance.now()+240000;while(performance.now()<until){try{return fn();}catch(e){error=e;await delay(500);}}throw error;};
const sha=b=>createHash('sha256').update(b).digest('hex');
const inventory=()=>{
  const out={};const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()){for(const n of fs.readdirSync(p).sort())walk(p+'/'+n);return;}
    out[p]={mode:s.mode&0o777,value:s.isSymbolicLink()?'link:'+fs.readlinkSync(p):sha(fs.readFileSync(p))};};
  for(const p of ['/opt/clean-vpn-native','/config','/etc/systemd/system'])walk(p);return out;
};
if(mode==='prepare'){
  assert.deepEqual(fs.readdirSync('/sys/class/net'),['lo']);
  fs.mkdirSync('/opt',{recursive:true});
  if(phase){for(const p of ['opt/clean-vpn-native','config','etc/systemd/system'])fs.cpSync('/state/root/'+p,'/'+p,{recursive:true,verbatimSymlinks:true});assert.deepEqual(inventory(),JSON.parse(fs.readFileSync('/state/inventory.json')));}
  // Fixture driver observes boot activation; it does not start the client.
  if(phase)put('/etc/systemd/system/native-lab-driver.service.d/order.conf','[Unit]\nAfter='+network+' host-boot-exit.service host-boot-origin.service\n',0o644);
  if(phase===2)put('/etc/systemd/system/host-boot-guard.service.d/fault.conf','[Service]\nExecStartPost=/bin/false\n',0o644);
}else if(mode==='links'){
  assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);assert.equal(ip('netns','list'),'');
  for(const n of ['client','exit','usb']){ip('netns','add',n);ip('-n',n,'link','set','lo','up');}
  for(const [dev,peer,other,a,b] of [['wlan0','uplink','exit','192.168.1.8/24','192.168.1.1/24'],['usb0','gadget','usb','192.168.7.1/24','192.168.7.19/24']]){
    ip('link','add',dev,'netns','client','type','veth','peer','name',peer,'netns',other);ip('-n','client','addr','add',a,'dev',dev);ip('-n',other,'addr','add',b,'dev',peer);ip('-n','client','link','set',dev,'up');ip('-n',other,'link','set',peer,'up');
  }
  ip('-n','client','route','add','default','via','192.168.1.1');ip('-n','usb','route','add','default','via','192.168.7.1');ns('client','sysctl',['-w','net.ipv4.ip_forward=1']);
  for(const a of ['154.62.226.216','1.1.1.1','8.8.8.8','198.18.0.80'])ip('-n','exit','addr','add',a+'/32','dev','lo');
  ns('exit','ip',['tuntap','add','dev','tun0','mode','tun']);ip('-n','exit','addr','add','10.99.0.1/24','dev','tun0');ip('-n','exit','link','set','tun0','mtu','1400','up');
  for(const p of ['udp','tcp'])ns('exit','iptables',['-t','nat','-A','PREROUTING','-p',p,'--dport','53','-j','REDIRECT','--to-ports','5353']);
  ns('client','iptables',['-t','nat','-A','POSTROUTING','-o','wlan0','-m','comment','--comment','foreign-sentinel','-j','MASQUERADE']);
}else{
  assert.equal(mode,'run');assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
  let passed=false;
  const dns=()=>assert.equal(ns('client','node',['--input-type=module','-e',`import {dnsProbe} from '/project/scripts/clean-vpn-native-runtime-health.mjs';await dnsProbe('10.99.0.2',1053,false);await dnsProbe('10.99.0.2',1053,true);console.log('DNS_OK');`]),'DNS_OK');
  const https=()=>assert.equal(ns('usb','node',['-e',`const h=require('node:https'),f=require('node:fs');const q=h.get({host:'198.18.0.80',port:8443,servername:'localhost',ca:f.readFileSync('/config/cert.pem'),timeout:5000},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{if(b!=='native-runtime-https-ok\\n')process.exit(2);console.log('HTTPS_OK')})});q.on('error',()=>process.exit(3));q.on('timeout',()=>q.destroy());setTimeout(()=>process.exit(4),6000).unref();`]),'HTTPS_OK');
  try{
    if(!phase){
      for(const [to,from] of [['cert.pem','cert.pem'],['key.pem','key.pem'],['psk','psk']])put('/config/'+to,fs.readFileSync('/native/'+from));
      const common={version:1,address:'154.62.226.216',port:443,tun:'tun0',secret_path:'/config/psk'};
      put('/config/client.json',JSON.stringify({...common,role:'client',dns:true,ca:'/config/cert.pem',server_name:'localhost'}));
      put('/config/exit.json',JSON.stringify({...common,role:'exit',cert:'/config/cert.pem',key:'/config/key.pem'}));
      const unitPrefix='[Unit]\nDefaultDependencies=no\n';
      unit('host-boot-links.service',unitPrefix+'[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/node /project/scripts/lib/native-host-boot-vm.mjs links\n');
      const links='Requires=host-boot-links.service\nAfter=host-boot-links.service\n';
      unit('host-boot-guard.service',unitPrefix+links+'[Service]\nType=oneshot\nRemainAfterExit=yes\nNetworkNamespacePath=/run/netns/client\nExecStart=/usr/local/bin/clean-vpn-killswitch.sh up --scope=both --ipv6=block --tun=tun0 --server=154.62.226.216 --ssh-port=22 --usb-dns=1 --usb-strict=1\n');
      unit('host-boot-exit.service',unitPrefix+links+'[Service]\nType=notify\nNetworkNamespacePath=/run/netns/exit\nExecStart=/native/clean-vpn-engine --config /config/exit.json --service\n[Install]\nWantedBy=multi-user.target\n');
      unit('host-boot-origin.service',unitPrefix+links+'[Service]\nNetworkNamespacePath=/run/netns/exit\nExecStart=/usr/bin/node /project/scripts/lib/native-runtime-lab-origin.mjs\n[Install]\nWantedBy=multi-user.target\n');
      put('/config/host.json',JSON.stringify({version:1,guard_unit:'host-boot-guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
      put('/config/pin','clean-vpn-clock '+fs.readFileSync('/native/known_hosts','utf8').trim().split(/\s+/).slice(1).join(' ')+'\n');
      put('/config/clock.json',JSON.stringify({version:1,host:'154.62.226.216',port:22,user:'clock-fixture',identity:'/native/admin',known_hosts:'/config/pin'}));
      const result=installNative({name:'host-boot',binary:'/native/clean-vpn-engine',config:'/config/client.json',hostProfile:'/config/host.json',clockProfile:'/config/clock.json',apply:true});
      check('installed-disabled',result.activation===network);
      for(const u of [engine,network])put('/etc/systemd/system/'+u+'.d/lab.conf','[Unit]\nDefaultDependencies=no\n[Service]\nNetworkNamespacePath=/run/netns/client\nStandardOutput=append:/run/'+u+'.log\nStandardError=append:/run/'+u+'.log\n',0o644);
      ctl('daemon-reload');run('node',['/project/scripts/clean-vpn-native-update.mjs','--enroll','host-boot']);
      ctl('start','host-boot-exit.service','host-boot-origin.service',network);
    }
    if(phase<2){
      await wait(()=>assert.equal(prop(engine,'ActiveState'),'active'));https();dns();check(phase?'boot-autostart-data-dns':'installed-data-dns');
      check('clock-not-needed',!fs.existsSync(bundle+'/clock-state/attempt.json'));
      const updater='/project/scripts/clean-vpn-native-update.mjs';
      if(!phase){
        const candidate='/native/host-candidate';put(candidate,Buffer.concat([fs.readFileSync('/native/clean-vpn-engine'),Buffer.from('\nhost-update\n')]),0o755);
        const result=JSON.parse(run('node',[updater,'--apply','host-boot',candidate,sha(fs.readFileSync(candidate))]));
        check('native-update',result.status==='updated');https();dns();check('updated-data-dns');
        const bad='/native/host-bad';put(bad,`#!/bin/sh\ncase "$1" in --capabilities|--check-config) exec ${candidate} "$@";; *) exit 77;; esac\n`,0o755);
        let rejected=false;try{run('node',[updater,'--apply','host-boot',bad,sha(fs.readFileSync(bad))]);}catch{rejected=true;}
        check('native-update-rollback',rejected&&sha(fs.readFileSync(bundle+'/engine'))===sha(fs.readFileSync(candidate))&&prop(engine,'ActiveState')==='active');https();dns();
        check('clock-budget-unchanged',!fs.existsSync(bundle+'/clock-state/attempt.json'));
      }else{
        const began=performance.now(),pid=prop(network,'MainPID');ctl('kill','--kill-whom=main','--signal=SIGKILL',network);
        await wait(()=>{assert.notEqual(prop(network,'MainPID'),pid);assert.equal(prop(engine,'ActiveState'),'active');https();});timings.ownerRecoveryMs=Math.round(performance.now()-began);check('boot-owner-crash-recovery');dns();
      }
      ctl('stop',network);assert.equal(prop(network,'Result'),'success');check('clean-stop-status');assert.equal(prop(engine,'MainPID'),'0');assert.throws(()=>https());check('stop-blocks-egress');
      assert.ok(!JSON.parse(ip('-n','client','-j','link')).some(l=>l.ifname==='tun0'));check('stop-removes-owned-tun');
      check('foreign-state-preserved',ns('client','iptables',['-t','nat','-S']).includes('foreign-sentinel'));
      ctl('enable',network,'host-boot-exit.service','host-boot-origin.service');
      for(const p of ['opt/clean-vpn-native','config','etc/systemd/system']){
        fs.rmSync('/state/root/'+p,{recursive:true,force:true});fs.mkdirSync(dirname('/state/root/'+p),{recursive:true});fs.cpSync('/'+p,'/state/root/'+p,{recursive:true,verbatimSymlinks:true});
      }
      put('/state/inventory.json',JSON.stringify(inventory()));put('/state/phase',String(phase+1));
    }else{
      check('failed-guard-stops-engine',prop('host-boot-guard.service','ActiveState')==='failed'&&prop(engine,'MainPID')==='0');
      check('failed-guard-no-tun',!JSON.parse(ip('-n','client','-j','link')).some(l=>l.ifname==='tun0'));
      assert.throws(()=>https());check('failed-guard-closed');
      check('failed-guard-no-clock-query',!fs.existsSync(bundle+'/clock-state/attempt.json'));
    }
    console.log('NATIVE_HOST_BOOT '+JSON.stringify({phase,bootId:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(),checks,timings}));passed=true;
  }catch(e){console.error(e);try{console.error(ctl('list-jobs','--no-pager'));for(const u of [network,engine]){console.error(ctl('show',u,'-p','ActiveState,SubState,MainPID,Result'));if(fs.existsSync('/run/'+u+'.log'))console.error(fs.readFileSync('/run/'+u+'.log','utf8').slice(-12000));}}catch{}for(const u of [network,engine,'host-boot-exit.service','host-boot-guard.service'])try{console.error(run('journalctl',['--no-pager','-u',u,'-n','45']));}catch{}}
  finally{console.log(passed?'NATIVE_HOST_BOOT_OK':'NATIVE_HOST_BOOT_FAILED');run('sync',[]);run('/bin/busybox',[passed&&phase<2?'reboot':'poweroff','-f']);}
}
