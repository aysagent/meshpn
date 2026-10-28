#!/usr/bin/env node
// Bounded physical architecture/systemd check. All sockets/TUN/firewall policy
// live in a new, unconnected network namespace; existing VPN is never stopped.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync,spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const self=fileURLToPath(import.meta.url),node=process.execPath;
const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:180000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const ctl=(...a)=>run('/usr/bin/systemctl',a),ip=(...a)=>run('/usr/sbin/ip',a);
const need=(v,c)=>{if(!v)throw Error(c);};
const hash=b=>createHash('sha256').update(b).digest('hex');
const hostFirewall=()=>hash((run('/usr/sbin/iptables-save',[])+run('/usr/sbin/ip6tables-save',[]))
  .split('\n').filter(line=>!line.startsWith('#')).join('\n').replace(/\[\d+:\d+\]/g,'[counters]'));
const prop=(u,p)=>ctl('show',u,'-p',p,'--value');
const put=(p,b,mode=0o600)=>{fs.writeFileSync(p,b,{mode,flag:'wx'});fs.chmodSync(p,mode);};
const [action,id]=process.argv.slice(2);
need(process.argv.length<=4,'fixture_arguments');
need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');
need(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd','systemd_required');
const update=(...a)=>JSON.parse(run(node,[root+'/scripts/clean-vpn-native-update.mjs',...a]));
function paths(id){need(/^cvup-[a-f0-9]{8}$/.test(id),'fixture_id');return{dir:'/run/'+id,ns:id,names:[id+'-e',id+'-c'],network:id+'-net.service',guard:id+'-guard.service'};}
function cleanup(id){const p=paths(id);if(!fs.existsSync(p.dir+'/owned.json'))return;
  const owned=JSON.parse(fs.readFileSync(p.dir+'/owned.json'));need(owned.id===id&&owned.kind==='native-update-isolated-check','fixture_ownership');
  for(const name of [...p.names].reverse()){
    for(const unit of ['native-'+name+'-binary-update.service','native-'+name+'.service','native-'+name+'-binary-recovery.service','native-'+name+'-clock.service'])try{ctl('stop',unit);}catch{}
  }
  for(const unit of [p.guard,p.network])try{ctl('stop',unit);}catch{}
  // Do not remove units/data or namespace while an owned process is alive.
  for(const name of p.names)for(const unit of ['native-'+name+'.service','native-'+name+'-binary-update.service'])
    need(['','0'].includes(prop(unit,'MainPID')),'fixture_process_still_alive');
  for(const name of p.names){
    for(const file of ['native-'+name+'.service','.native-'+name+'.service.prepared','native-'+name+'-binary-recovery.service','native-'+name+'-clock.service','.native-'+name+'-clock.service.prepared'])fs.rmSync('/etc/systemd/system/'+file,{force:true});
    fs.rmSync('/etc/systemd/system/native-'+name+'.service.d',{recursive:true,force:true});
    fs.rmSync('/opt/clean-vpn-native/'+name,{recursive:true,force:true});
  }
  for(const unit of [p.network,p.guard])fs.rmSync('/etc/systemd/system/'+unit,{force:true});
  ctl('daemon-reload');
  if(fs.existsSync('/run/netns/'+p.ns)){need(ip('netns','pids',p.ns)==='','fixture_namespace_busy');ip('netns','delete',p.ns);}
  fs.rmSync(p.dir,{recursive:true,force:true});
}
async function wait(fn){for(let i=0;i<200;i++){if(await fn())return;await delay(100);}throw Error('fixture_timeout');}
async function worker(id){
  const p=paths(id),checks=[];const check=(name,ok)=>{need(ok,name);checks.push(name);};
  need(!fs.existsSync(p.dir)&&!fs.existsSync('/run/netns/'+p.ns),'fixture_collision');
  for(const name of p.names){
    need(!fs.existsSync('/opt/clean-vpn-native/'+name),'fixture_instance_collision');
    for(const unit of ['native-'+name+'.service','native-'+name+'-binary-update.service','native-'+name+'-binary-recovery.service','native-'+name+'-clock.service'])
      need(prop(unit,'LoadState')==='not-found'&&!fs.existsSync('/etc/systemd/system/'+unit+'.d'),'fixture_unit_collision');
    need(!fs.existsSync('/etc/systemd/system/.native-'+name+'.service.prepared'),'fixture_prepared_collision');
  }
  for(const unit of [p.network,p.guard])need(prop(unit,'LoadState')==='not-found'&&!fs.existsSync('/etc/systemd/system/'+unit+'.d'),'fixture_dependency_collision');
  const before=hostFirewall();
  fs.mkdirSync(p.dir,{mode:0o700});put(p.dir+'/owned.json',JSON.stringify({id,kind:'native-update-isolated-check'}));
  try {
    ip('netns','add',p.ns);ip('-n',p.ns,'link','set','lo','up');
    for(const [tun,addr]of [['upce0','10.99.0.1/24'],['upcc0','10.99.0.2/32']]){
      ip('netns','exec',p.ns,'ip','tuntap','add','dev',tun,'mode','tun');ip('-n',p.ns,'addr','add',addr,'dev',tun);ip('-n',p.ns,'link','set',tun,'up');
    }
    for(const family of ['iptables','ip6tables']){
      ip('netns','exec',p.ns,family,'-P','OUTPUT','DROP');ip('netns','exec',p.ns,family,'-P','FORWARD','DROP');ip('netns','exec',p.ns,family,'-A','OUTPUT','-o','lo','-j','ACCEPT');
    }
    run('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',p.dir+'/key.pem','-out',p.dir+'/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost']);
    fs.chmodSync(p.dir+'/key.pem',0o600);put(p.dir+'/psk',randomBytes(32));
    for(const [unit,command]of [[p.network,`/usr/sbin/ip -n ${p.ns} link show upcc0`],
      [p.guard,`/usr/sbin/ip netns exec ${p.ns} iptables -C OUTPUT -o lo -j ACCEPT`]])
      put('/etc/systemd/system/'+unit,`[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${command}\n`,0o644);
    ctl('daemon-reload');
    run('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',p.dir+'/identity']);
    const pub=fs.readFileSync(p.dir+'/identity.pub','utf8').trim().split(/\s+/);
    put(p.dir+'/known-hosts',`clean-vpn-clock ${pub[0]} ${pub[1]}\n`);
    put(p.dir+'/clock-profile.json',JSON.stringify({version:1,host:'127.0.0.1',port:2222,user:'clock-fixture',identity:p.dir+'/identity',known_hosts:p.dir+'/known-hosts'}));
    const shared={version:1,address:'127.0.0.1',port:4443};
    for(const [index,name]of p.names.entries()){
      const config=index===0?{...shared,role:'exit',tun:'upce0',peers:[{ipv4:'10.99.0.2',secret_path:p.dir+'/psk'}],cert:p.dir+'/cert.pem',key:p.dir+'/key.pem'}:
        {...shared,role:'client',tun:'upcc0',peer_ipv4:'10.99.0.2',dns:true,ca:p.dir+'/cert.pem',server_name:'localhost',secret_path:p.dir+'/psk',tls_profile_path:root+'/fixtures/native-tls-profiles/chromium-156-bounded-cold.json'};
      put(p.dir+'/'+name+'.json',JSON.stringify(config));
      run(node,[root+'/scripts/clean-vpn-native-install.mjs','--apply','--name='+name,'--binary='+root+'/native/clean_vpn/build/clean-vpn-engine',
        '--config='+p.dir+'/'+name+'.json','--network-unit='+p.network,'--guard-unit='+p.guard,...(index===1?['--clock-profile='+p.dir+'/clock-profile.json']:[])]);
      fs.mkdirSync('/etc/systemd/system/native-'+name+'.service.d',{mode:0o755});
      put('/etc/systemd/system/native-'+name+'.service.d/fixture.conf',`[Service]\nNetworkNamespacePath=/run/netns/${p.ns}\nTimeoutStartSec=15\nRestart=no\n`,0o644);
      ctl('daemon-reload');update('--enroll',name);
    }
    const [exit,client]=p.names,cunit='native-'+client+'.service';
    ctl('start','native-'+exit+'.service');ctl('start',cunit);
    check('profiled-client-ready',prop(cunit,'StatusText')==='ready');
    const original=fs.readFileSync(root+'/native/clean_vpn/build/clean-vpn-engine');
    const candidate=p.dir+'/engine-next';put(candidate,Buffer.concat([original,Buffer.from('\nphysical-update-fixture\n')]),0o755);
    const wanted=hash(fs.readFileSync(candidate));
    for(const name of p.names){const r=update('--apply',name,candidate,wanted);check(name===exit?'exit-update':'client-update',r.status==='updated');}
    const current='/opt/clean-vpn-native/'+client;
    const netFile='/etc/systemd/system/'+p.network,netBytes=fs.readFileSync(netFile),pid=prop(cunit,'MainPID');
    let changedRefused=false;
    try{fs.appendFileSync(netFile,'# deliberate ownership-change fixture\n');try{update('--apply',client,candidate,wanted);}catch{changedRefused=true;}}
    finally{fs.writeFileSync(netFile,netBytes);}
    check('bound-unit-change-refused',changedRefused&&prop(cunit,'MainPID')===pid);
    const clockDir=current+'/clock-state';
    check('healthy-no-clock-query',!fs.existsSync(clockDir+'/attempt.json'));
    put(clockDir+'/last-good.json',JSON.stringify({version:1,unix_seconds:1700000000}));
    const clockFloor=fs.readFileSync(clockDir+'/last-good.json');
    const bad=p.dir+'/bad-engine';put(bad,`#!/bin/sh\ncase "$1" in --capabilities|--check-config) exec ${current}/binary-updates/releases/${wanted} "$@";; *) exit 77;; esac\n`,0o755);
    let refused=false;try{update('--apply',client,bad,hash(fs.readFileSync(bad)));}catch{refused=true;}
    check('failed-candidate-rollback',refused&&hash(fs.readFileSync(current+'/engine'))===wanted&&prop(cunit,'ActiveState')==='active');
    check('update-clock-exclusion-and-floor',!fs.existsSync(clockDir+'/attempt.json')&&fs.readFileSync(clockDir+'/last-good.json').equals(clockFloor));
    ctl('stop',cunit);update('--apply',client,root+'/native/clean_vpn/build/clean-vpn-engine',hash(original));
    check('stopped-preserved',prop(cunit,'MainPID')==='0');ctl('start',cunit);
    const hanging=p.dir+'/hang-engine';put(hanging,`#!/bin/sh\ncase "$1" in --capabilities|--check-config) exec ${current}/binary-updates/releases/${wanted} "$@";; *) exec /bin/sleep 120;; esac\n`,0o755);
    const child=spawn(node,[root+'/scripts/clean-vpn-native-update.mjs','--apply',client,hanging,hash(fs.readFileSync(hanging))],{stdio:'ignore'});
    const finished=new Promise(resolve=>{child.once('error',()=>resolve(-1));child.once('close',resolve);});
    await wait(()=>fs.existsSync(current+'/binary-updates/transaction.json')&&hash(fs.readFileSync(current+'/engine'))===hash(fs.readFileSync(hanging)));
    // Killing the main worker exercises systemd's KillMode=control-group and
    // ExecStopPost. --kill-whom=all may fail on auxiliary process signaling on
    // some host systemd/kernel combinations even after signaling the main PID.
    ctl('kill','--kill-whom=main','--signal=SIGKILL','native-'+client+'-binary-update.service');
    await finished;
    await wait(()=>!fs.existsSync(current+'/binary-updates/transaction.json')&&prop(cunit,'ActiveState')==='active');
    check('worker-sigkill-recovery',hash(fs.readFileSync(current+'/engine'))===hash(original)&&prop(cunit,'StatusText')==='ready');
    check('host-firewall-unchanged',hostFirewall()===before);
    return{status:'passed',kind:'native-update-isolated-physical-check',arch:process.arch,checks,
      limitations:['unconnected-netns-not-WAN','TLS-readiness-not-IP-throughput','appended-ELF-fixture-not-new-production-build','no-physical-reboot']};
  } finally {cleanup(id);}
}
if(action==='--apply'&&id===undefined){
  const id='cvup-'+randomBytes(4).toString('hex');
  run('/usr/bin/systemd-run',['--quiet','--wait','--pipe','--collect','--unit='+id,'--property=RuntimeMaxSec=240','--property=TimeoutStopSec=20',
    '--property=UMask=0077','--property=MemoryMax=192M','--property=TasksMax=32','--property=ExecStopPost='+node+' '+self+' --cleanup '+id,node,self,'--worker',id]);
  // Report is deliberately outside the scratch tree removed by recovery.
  process.stdout.write(fs.readFileSync('/run/'+id+'.result.json'));fs.unlinkSync('/run/'+id+'.result.json');
}else if(action==='--worker'){
  const result=await worker(id);put('/run/'+id+'.result.json',JSON.stringify(result,null,2)+'\n');
}else if(action==='--cleanup')cleanup(id);
else throw Error('usage: node scripts/clean-vpn-native-update-check.mjs --apply');
