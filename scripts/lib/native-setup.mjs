// User-facing native host installer. Payload stays in C++; control plane is Node.
// Never flush foreign firewall state or regenerate existing credentials.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {isIPv4} from 'node:net';
import {parseArgs} from 'node:util';
import {parseRuntimeConfig,createRuntimeConfig} from '../clean-vpn-native-runtime-config.mjs';
import {importClientBundle,readClientPrivate} from './native-client-manager.mjs';
import {installNative} from './native-install.mjs';
import {inspectNativeUsb} from './native-usb-preflight.mjs';
import {networkdGateText} from './host-networkd-gate.mjs';
export const repository=fileURLToPath(new URL('../../',import.meta.url)).replace(/\/$/,'');
const need=(v,code)=>{if(!v)throw Error(code);};
const sha=b=>createHash('sha256').update(b).digest('hex');
const exists=p=>{try{fs.lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
const packet=c=>c.transport==='combo-tls'?c.boring:c;
const command=(file,args,options={})=>execFileSync(file,args,{encoding:'utf8',timeout:30000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe'],...options}).trim();
export const usage=`Native clean-vpn (Linux/systemd; Node 22+; no Python runtime)
  bash install.sh --role=exit --endpoint=PUBLIC_IPV4 [--listen=LOCAL_IPV4] [--uplink=eth0]
  bash install.sh --role=client --bundle=/absolute/client-1.bundle.json [--admin-ui]
  bash install.sh --check --role=client|exit [--name=NAME]
  bash uninstall.sh --role=client|exit [--name=NAME]
Options: --type=combo-tls|boring-tls (exit default combo), --port=443,
  --clients=1..32 (default 3), --name=NAME, --binary=/absolute/engine,
  --profile=FILE, --no-clock, --jobs=1..8, --plan.
Client host profile: usb0 192.168.7.1/24, wlan0. Fresh USB setup requires one UDC.
Install starts/enables owned services. Uninstall retains credentials/settings/replay.
No apt commands are run automatically. Existing foreign installations are refused.`;
export function setupOptions(action,args){
 need(['install','uninstall'].includes(action),'setup_action');
 const strings=['role','endpoint','listen','uplink','type','port','clients','name','binary','profile','bundle','jobs'];
 const {values:v}=parseArgs({args,options:{...Object.fromEntries(strings.map(k=>[k,{type:'string'}])),...Object.fromEntries(['help','admin-ui','no-clock','plan','check'].map(k=>[k,{type:'boolean'}]))}});
 const keys=args.filter(a=>a.startsWith('--')).map(a=>a.split('=')[0]);need(new Set(keys).size===keys.length,'duplicate_option');
 if(v.help)return {help:true};need(['exit','client'].includes(v.role),'role_required');
 v.name??=v.role;need(/^[a-z][a-z0-9-]{0,31}$/.test(v.name),'invalid_instance');
 need(!v['admin-ui']||v.role==='client','admin_ui_client_only');
 if(action==='uninstall'||v.check){need(Object.keys(v).every(k=>['role','name','plan','check'].includes(k)),'uninstall_check_options');return {...v,action:v.check?'check':action};}
 v.port??='443';v.clients??='3';v.jobs??='1';
 need(/^[1-9][0-9]*$/.test(v.port)&&+v.port<=65535,'port');need(/^[1-9][0-9]*$/.test(v.clients)&&+v.clients<=32,'clients');need(/^[1-8]$/.test(v.jobs),'jobs');
 need(!v.type||['combo-tls','boring-tls'].includes(v.type),'transport');
 for(const k of ['binary','profile','bundle'])if(v[k])need(path.isAbsolute(v[k])&&path.normalize(v[k])===v[k]&&/^\/[\w./-]+$/.test(v[k]),'absolute_path_required');
 if(v.role==='exit'){need(isIPv4(v.endpoint),'numeric_public_endpoint_required');if(v.listen)need(isIPv4(v.listen),'local_listener_ipv4');if(v.uplink)need(/^[a-zA-Z0-9_.-]{1,15}$/.test(v.uplink),'uplink');need(!v.bundle,'exit_bundle_option');v.type??='combo-tls';}
 else {need(Boolean(v.bundle),'client_bundle_required');need(!v.endpoint&&!v.listen&&!v.uplink&&!v.profile,'exit_only_options');}
 return {...v,action};
}
function atomic(p,value,mode=0o600){
 const data=Buffer.isBuffer(value)?value:Buffer.from(typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');
 const t=p+'.new-'+randomBytes(8).toString('hex');const fd=fs.openSync(t,'wx',mode);try{fs.writeFileSync(fd,data);fs.fchmodSync(fd,mode);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(t,p);const d=fs.openSync(path.dirname(p),'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
}
function parents(p){for(let d=path.dirname(p);;d=path.dirname(d)){const s=fs.lstatSync(d);need(s.isDirectory()&&!s.isSymbolicLink()&&[0,process.getuid()].includes(s.uid)&&(!(s.mode&0o022)||(s.mode&0o1000)),'unsafe_parent');if(d==='/')break;}}
function safeRead(p){parents(p);const s=fs.lstatSync(p);need(s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&!(s.mode&0o022),'unsafe_owned_file');return fs.readFileSync(p);}
export class NativeSetup {
 constructor(o,{root='',run=command,install=installNative,usb=inspectNativeUsb,source=repository,log=console.error}={}){
  this.o=o;this.root=root;this.run=run;this.install=install;this.usb=usb;this.source=source;this.log=log;
  this.base=this.at('/var/lib/clean-vpn/setup/'+o.name);this.manifest=this.base+'/setup.json';this.bundle='/opt/clean-vpn-native/'+o.name;this.unit='native-'+o.name+'.service';this.owner='native-'+o.name+'-network.service';
 }
 at(p){return this.root+p;}
 ctl(...args){return this.run('/usr/bin/systemctl',args,{timeout:['stop','disable'].includes(args[0])?240000:30000});}
 prop(unit,key){return this.ctl('show',unit,'-p',key,'--value');}
 save(){atomic(this.manifest,this.state);}
 progress(phase){this.state.phase=phase;this.save();this.log('[clean-vpn install] '+phase);}
 file(p,data,mode=0o644,{replace=false}={}){
  const dest=this.at(p),bytes=Buffer.isBuffer(data)?data:Buffer.from(data);
  fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o755});parents(dest);
  let record=this.state.files.find(x=>x.path===p);
  if(record){need(sha(bytes)===record.after,'changed_install_payload');}
  else{
   const before=exists(dest)?safeRead(dest):null;need(!before||replace,'file_collision');
   record={path:p,before:before?.toString('base64')??null,beforeMode:before?(fs.statSync(dest).mode&0o777):null,after:sha(bytes),mode};this.state.files.push(record);this.save();
  }
  if(exists(dest)){const now=safeRead(dest);if(sha(now)===record.after)return;need(record.before!==null&&now.equals(Buffer.from(record.before,'base64')),'file_changed');}
  atomic(dest,bytes,mode);
 }
 rememberService(unit){
  if(!this.state.services[unit]){this.state.services[unit]={active:this.prop(unit,'ActiveState')==='active',enabled:this.prop(unit,'UnitFileState')==='enabled'};this.save();}
 }
 async execute(){
  const o=this.o;
  if(o.plan)return {action:o.action,role:o.role,name:o.name,transport:o.type??'from-client-bundle',adminUi:!!o['admin-ui'],changes:o.action==='check'?[]:o.action==='uninstall'?['stop/remove owned services','restore owned settings and original forwarding','retain credentials/settings/replay']:['credentials/config if absent','owned forwarding setting','owned systemd units','scoped native network owner',...(o.role==='client'?['USB/DHCP boot ordering','persistent guard']:[])],networkChanged:false};
  need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');
  need(fs.readFileSync(this.at('/proc/1/comm'),'utf8').trim()==='systemd','systemd_required');
  if(o.action==='check')return this.check();
  if(o.action==='uninstall'){need(exists(this.manifest),'not_installed');this.state=JSON.parse(safeRead(this.manifest));return this.remove();}
  const identity={role:o.role,name:o.name,endpoint:o.endpoint??null,listen:o.listen??null,uplink:o.uplink??null,profile:o.profile?sha(readClientPrivate(o.profile)):null,binary:o.binary??null,bundle:o.bundle?sha(readClientPrivate(o.bundle)):null,adminUi:!!o['admin-ui'],clock:!o['no-clock'],type:o.type??null,port:o.port,clients:o.clients};
  fs.mkdirSync(this.base,{recursive:true,mode:0o700});parents(this.manifest);
  if(exists(this.manifest)){
   this.state=JSON.parse(safeRead(this.manifest));need(JSON.stringify(this.state.identity)===JSON.stringify(identity),'existing_install_options_differ');
   if(this.state.phase==='installed')return {...this.check(),unchanged:true};
   need(this.state.phase==='uninstalled','incomplete_install_run_uninstall_first');
  }else{this.state={version:1,kind:'clean-vpn-managed-setup',identity,phase:'preparing',files:[],services:{},coreUnits:[],adminUnits:[],forward:false};this.save();}
  try{
   this.preflight();this.build();await this.credentials();
   this.progress('preparing-host');this.forward(true);
   if(o.role==='client'){this.usbSetup();this.guard();}
   this.progress('publishing-native');
   if(!exists(this.at(this.bundle+'/installed.json'))){
    this.state.coreIntent=true;this.save();
    const args={root:this.root||'/',name:o.name,binary:this.binary,config:this.config,tunHelper:this.helper,apply:true};
    const host=this.base+'/host.json';atomic(host,o.role==='exit'?{version:1,uplink:this.uplink}:{version:1,guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'});
    if(o.role==='exit')args.exitProfile=host;else args.hostProfile=host;
    if(this.clock)args.clockProfile=this.clock;
    this.install(args);
    this.captureCore();
   }else{need(this.state.coreIntent&&this.state.coreUnits.length,'foreign_native_bundle');for(const u of this.state.coreUnits)this.restoreUnit(u);}
   this.state.coreRemoved=false;this.save();
   if(o.role==='exit')this.ingress();
   if(o['admin-ui']){
    this.progress('installing-admin-ui');this.rememberService('avahi-daemon.service');this.ctl('enable','--now','avahi-daemon.service');
    if(this.state.adminUnits.length){for(const u of this.state.adminUnits)this.restoreUnit(u);this.ctl('daemon-reload');this.ctl('enable','--now','meshpn-admin-broker.service','meshpn-admin.socket','meshpn-admin-captive.service');this.state.adminRemoved=false;this.save();}
    else{
     this.state.adminIntent=true;this.save();this.run(process.execPath,[this.source+'/admin/install.mjs','--apply','--native-name='+o.name],{timeout:90000});
     for(const name of ['meshpn-admin-broker.service','meshpn-admin-web.service','meshpn-admin.socket','meshpn-admin-captive.service']){const p='/etc/systemd/system/'+name;if(exists(this.at(p)))this.state.adminUnits.push({path:p,text:safeRead(this.at(p)).toString()});}this.save();
    }
   }
   this.progress('starting');this.ctl('daemon-reload');this.ctl('enable','--now',this.owner);
   const deadline=performance.now()+15000;
   while(performance.now()<deadline){if(this.prop(this.unit,'ActiveState')==='active')break;await new Promise(r=>setTimeout(r,250));}
   if(o.role==='exit')need(this.prop(this.unit,'ActiveState')==='active','exit_start_failed');
   this.progress('installed');return {...this.check(),status:'installed',settingsChanged:true,exports:o.role==='exit'&&exists(this.base+'/exports')?this.base+'/exports':undefined,adminUi:o['admin-ui']?'http://mpn.local/ (USB only; initial password admin)':undefined};
  }catch(e){e.setupPhase=this.state.phase;this.state.error=/^[a-z0-9_]+$/.test(e.message)?e.message:e.code??'operation_failed';this.save();throw e;}
 }
 preflight(){
  need(Number(process.versions.node.split('.')[0])>=22,'node_22_or_newer_required');
  for(const tool of ['ip','iptables','ip6tables','flock','openssl','systemctl','bash','c++',...(this.o['admin-ui']?['cc','pkg-config','busctl','wpa_cli','conntrack']:[]),...(!this.o['no-clock']?['ssh','ssh-keygen']:[])])this.run('/usr/bin/env',['sh','-c','command -v "$1"','check',tool]);
  need(exists(this.at('/dev/net/tun')),'tun_device_missing');
  if(this.o.role==='exit'){
   const routes=JSON.parse(this.run('/usr/sbin/ip',['-j','-4','route','show','default']));this.uplink=this.o.uplink??routes[0]?.dev;need(/^[a-zA-Z0-9_.-]{1,15}$/.test(this.uplink??''),'uplink_required');
   this.listen=this.o.listen??JSON.parse(this.run('/usr/sbin/ip',['-j','-4','route','get','1.1.1.1']))[0]?.prefsrc;need(isIPv4(this.listen),'listener_required');
   need(!this.run('/usr/bin/ss',['-H','-lnt','sport','=',':'+this.o.port]),'exit_port_busy');
  }else{
   need(exists(this.at('/sys/class/net/wlan0')),'wlan0_required');
   if(!exists(this.at('/usr/local/bin/usb-gadget-start.sh')))need(fs.readdirSync(this.at('/sys/class/udc')).length===1,'single_usb_udc_required');
  }
  if(!this.state.coreIntent)for(const p of [this.bundle,'/etc/systemd/system/'+this.unit,'/etc/systemd/system/'+this.owner])need(!exists(this.at(p)),'native_install_collision');
  if(this.o['admin-ui']&&!this.state.adminIntent)for(const p of ['/opt/meshpn-admin','/etc/meshpn-admin'])need(!exists(this.at(p)),'admin_install_collision');
 }
 build(){
  this.binary=this.o.binary??this.source+'/native/clean_vpn/build/clean-vpn-engine';
  if(!exists(this.binary)){this.progress('building-native');this.run('/bin/bash',[this.source+'/scripts/build-clean-vpn-native.sh','--low-memory','--jobs='+this.o.jobs],{timeout:7200000,maxBuffer:1024*1024});}
  this.progress('building-control-helpers');this.run('/bin/bash',[this.source+'/scripts/build-clean-vpn-host-helpers.sh',...(this.o['admin-ui']?['--admin-ui']:[])],{timeout:120000});
  this.helper=this.source+'/native/clean_vpn/build/clean-vpn-tun-helper';
 }
 async credentials(){
  this.progress('preparing-credentials');const o=this.o,dir=this.base+'/credentials';
  if(o.role==='exit'){
   if(!exists(dir)){
    const staging=dir+'-preparing-'+randomBytes(8).toString('hex');
    createRuntimeConfig(parseRuntimeConfig(['create','--directory='+staging,'--mode=standalone','--endpoint='+o.endpoint,'--exit-address='+this.listen,'--port='+o.port,'--server-name=personal-cert.internal','--transport='+o.type,'--clients='+o.clients,'--days=365',...(o.profile?['--profile='+o.profile]:[]),...(o.type==='combo-tls'?['--public-name=www.trustpilot.com','--relay-port=10443','--relay-sessions=128','--relay-per-client=64']:[])]));
    for(const role of ['exit',...Array.from({length:+o.clients},(_,i)=>'client-'+(i+1))]){const p=staging+'/'+role+'/engine.json';atomic(p,safeRead(p).toString().replaceAll(staging+'/',dir+'/'));}
    fs.renameSync(staging,dir);
   }
   this.config=dir+'/exit/engine.json';let c=JSON.parse(readClientPrivate(this.config));packet(c).tun='cvexit0';delete packet(c).alps;atomic(this.config,c);this.endpoint=o.endpoint;
   if(!o['no-clock'])this.clockServer(dir);
   fs.mkdirSync(this.base+'/exports',{mode:0o700,recursive:true});
   for(let i=1;i<=+o.clients;i++){
    const clientDir=dir+'/client-'+i,config=JSON.parse(readClientPrivate(clientDir+'/engine.json')),p=packet(config);p.tun='tun0';p.sni='www.trustpilot.com';
    const files={};for(const [obj,key,file] of [[p,'ca','ca.pem'],[p,'secret_path','psk'],[p,'tls_profile_path','profile.json'],...(config.transport==='combo-tls'?[[config.transparent,'secret_path','relay.psk']]:[])]){files[file]=safeRead(obj[key]).toString('base64');obj[key]='@bundle/'+file;}
    const enrollment={version:1,kind:'clean-vpn-client-enrollment',name:'client-'+i,hostname:'client-'+i+'.mpn',ipv4:p.peer_ipv4,config,files};
    const value={version:1,kind:'clean-vpn-install-bundle',enrollment,...(!o['no-clock']?{clock:{host:o.endpoint,port:22,user:'cvpn-clock',identity:safeRead(clientDir+'/clock-identity').toString('base64'),known_hosts:safeRead(clientDir+'/clock-known-hosts').toString('base64')}}:{})};
    const out=this.base+'/exports/client-'+i+'.bundle.json';if(!exists(out))atomic(out,value);
   }
  }else{
   const raw=JSON.parse(readClientPrivate(o.bundle,512*1024));let envelope;
   if(raw.kind==='clean-vpn-install-bundle'){need(raw.version===1&&Object.keys(raw).every(k=>['version','kind','enrollment','clock'].includes(k)),'install_bundle');envelope=raw;}else envelope={enrollment:raw};
   if(!exists(dir)){
    const staging=dir+'-preparing-'+randomBytes(8).toString('hex');
    await importClientBundle(envelope.enrollment,staging,{validateConfig:async p=>this.run(this.binary,['--check-config',p])});
    const p=staging+'/engine.json';atomic(p,safeRead(p).toString().replaceAll(staging+'/',dir+'/'));fs.renameSync(staging,dir);
   }
   this.config=dir+'/engine.json';let c=JSON.parse(readClientPrivate(this.config));packet(c).tun='tun0';if(o.type==='boring-tls')c=packet(c);else if(o.type)need(c.transport===o.type,'bundle_transport');atomic(this.config,c);this.endpoint=packet(c).address;
   if(!o['no-clock']&&envelope.clock){
    const clock=envelope.clock;need(clock.host===this.endpoint&&clock.port===22&&clock.user==='cvpn-clock'&&Object.keys(clock).sort().join(',')==='host,identity,known_hosts,port,user','clock_bundle');
    for(const key of ['identity','known_hosts']){need(typeof clock[key]==='string'&&clock[key].length<=24000,'clock_file');const dest=dir+'/clock-'+key.replace('_','-');if(!exists(dest))atomic(dest,Buffer.from(clock[key],'base64'));}
    this.clock=dir+'/clock.json';atomic(this.clock,{version:1,host:this.endpoint,port:22,user:'cvpn-clock',identity:dir+'/clock-identity',known_hosts:dir+'/clock-known-hosts'});
   }
  }
  this.run(this.binary,['--check-config',this.config]);
 }
 clockServer(dir){
  const provider='/opt/clean-vpn-clock/'+this.o.name,home='/var/lib/clean-vpn-clock';
  if(!this.state.clockAccount){let present=false;try{this.run('/usr/bin/id',['cvpn-clock']);present=true;}catch{}need(!present,'clock_account_collision');this.state.clockAccount='intent';this.save();this.run('/usr/sbin/useradd',['--system','--user-group','--home-dir',home,'--shell','/bin/sh','--password','*','cvpn-clock']);this.state.clockAccount='created';this.save();}
  if(this.state.clockAccount==='intent'){
   let row;try{row=this.run('/usr/bin/getent',['passwd','cvpn-clock']).split(':');}catch{}
   if(row)need(+row[2]>0&&row[5]===home&&row[6]==='/bin/sh','clock_account_changed');
   else this.run('/usr/sbin/useradd',['--system','--user-group','--home-dir',home,'--shell','/bin/sh','--password','*','cvpn-clock']);
   this.state.clockAccount='created';this.save();
  }
  this.file(provider+'/node',fs.readFileSync(process.execPath),0o755);
  this.file(provider+'/clock.mjs',fs.readFileSync(this.source+'/scripts/clean-vpn-native-clock.mjs'));
  const pub=safeRead(this.at('/etc/ssh/ssh_host_ed25519_key.pub')).toString().trim().split(/\s+/);need(pub[0]==='ssh-ed25519','ssh_ed25519_host_key_required');
  const lines=[];
  for(let i=1;i<=+this.o.clients;i++){
   const c=dir+'/client-'+i,key=c+'/clock-identity';if(!exists(key))this.run('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
   if(!exists(c+'/clock-known-hosts'))atomic(c+'/clock-known-hosts','clean-vpn-clock '+pub.slice(0,2).join(' ')+'\n');
   lines.push('restrict,command="/usr/bin/timeout 5s '+provider+'/node --jitless '+provider+'/clock.mjs serve" '+safeRead(key+'.pub').toString().trim());
  }
  this.file(home+'/.ssh/authorized_keys',lines.join('\n')+'\n');
 }
 forward(acquire){
  const file=this.at('/var/lib/clean-vpn/setup/forwarding.json'),conf=this.at('/etc/sysctl.d/90-clean-vpn-native-forward.conf'),text='net.ipv4.ip_forward=1\n';
  let s=exists(file)?JSON.parse(safeRead(file)):null;
  if(s)need(s.version===1&&['0','1'].includes(s.original)&&Array.isArray(s.owners)&&s.owners.every(n=>typeof n==='string'&&/^[a-z][a-z0-9-]{0,31}$/.test(n))&&new Set(s.owners).size===s.owners.length,'forwarding_journal_invalid');
  if(acquire){
   if(!s){need(!exists(conf),'forwarding_file_collision');s={version:1,original:this.run('/usr/sbin/sysctl',['-n','net.ipv4.ip_forward']),owners:[]};need(['0','1'].includes(s.original),'forwarding_value');}
   if(!s.owners.includes(this.o.name))s.owners.push(this.o.name);atomic(file,s);this.state.forward=true;this.state.forwardOriginal=s.original;this.save();
   if(exists(conf))need(safeRead(conf).toString()===text,'forwarding_file_changed');else{fs.mkdirSync(path.dirname(conf),{recursive:true});atomic(conf,text,0o644);}
   this.run('/usr/sbin/sysctl',['-w','net.ipv4.ip_forward=1']);
  }else if(this.state.forward||s?.owners.includes(this.o.name)){
   if(!s){need(!exists(conf)&&this.run('/usr/sbin/sysctl',['-n','net.ipv4.ip_forward'])===this.state.forwardOriginal,'forwarding_ownership');this.state.forward=false;this.save();return;}
   if(!s.owners.includes(this.o.name)){this.state.forward=false;this.save();return;}
   const remaining=s.owners.filter(x=>x!==this.o.name);
   if(!remaining.length){need(!exists(conf)||safeRead(conf).toString()===text,'forwarding_file_changed');need(['1',s.original].includes(this.run('/usr/sbin/sysctl',['-n','net.ipv4.ip_forward'])),'forwarding_changed');this.run('/usr/sbin/sysctl',['-w','net.ipv4.ip_forward='+s.original]);if(exists(conf))fs.unlinkSync(conf);fs.unlinkSync(file);}else atomic(file,{...s,owners:remaining});
   this.state.forward=false;this.save();
  }
 }
 usbSetup(){
  const script='/usr/local/bin/usb-gadget-start.sh',drop='/etc/systemd/system/usb-gadget.service.d/40-meshpn-dhcp.conf';
  this.rememberService('dnsmasq.service');this.rememberService('usb-gadget.service');
  const previous=this.state.files.find(f=>f.path===script);
  if(previous?.before!==null&&previous?.before!==undefined){
   this.file(script,Buffer.from(previous.before,'base64').toString().replace('ip addr flush dev usb0\nip addr add 192.168.7.1/24 dev usb0','ip address replace 192.168.7.1/24 dev usb0'),0o755,{replace:true});
  }else if(exists(this.at(script))&&!previous){
   const old=safeRead(this.at(script)),h=sha(old);
   if(h==='a6846d0ac08b3af378cede7aefc797a43dd79b3a720f0bf12d398a55dbf33cbf')this.file(script,old.toString().replace('ip addr flush dev usb0\nip addr add 192.168.7.1/24 dev usb0','ip address replace 192.168.7.1/24 dev usb0'),0o755,{replace:true});
   else need(h==='c0d55c1d8c765084cd674b013e90075b2558ed7adee1e11e42f64c541de7b94b','unknown_usb_gadget');
  }else{
   this.file(script,fs.readFileSync(this.source+'/scripts/usb/gadget-start.sh'),0o755);
   this.file('/etc/systemd/system/usb-gadget.service','[Unit]\nDescription=MeshPN USB Ethernet\nWants=dnsmasq.service\nAfter=network.target dnsmasq.service\n[Service]\nType=oneshot\nExecStart='+script+'\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n');
   this.file('/etc/dnsmasq.d/90-clean-vpn-usb.conf','interface=usb0\nbind-dynamic\nlisten-address=127.0.0.1,192.168.7.1\ndhcp-range=192.168.7.10,192.168.7.50,255.255.255.0,12h\ndhcp-option=3,192.168.7.1\ndhcp-option=6,192.168.7.1\nno-resolv\nserver=1.1.1.1\nserver=8.8.8.8\n');
  }
  const order=fs.readFileSync(this.source+'/scripts/usb/dhcp-before-gadget.conf');
  if(exists(this.at(drop))&&!this.state.files.some(f=>f.path===drop))need(safeRead(this.at(drop)).equals(order),'usb_order_changed');else this.file(drop,order);
  this.run('/usr/sbin/dnsmasq',['--test']);this.ctl('daemon-reload');this.ctl('enable','--now','dnsmasq.service');
  // enable --now does not load a newly written configuration into an already
  // running dnsmasq. Restart only when we installed our own DHCP configuration.
  if(this.state.files.some(f=>f.path==='/etc/dnsmasq.d/90-clean-vpn-usb.conf'))this.ctl('restart','dnsmasq.service');
  this.ctl('enable','--now','usb-gadget.service');
  const r=this.usb();need(r.status==='passed','usb_preflight_failed');
 }
 guard(){
  const script='/usr/local/bin/clean-vpn-killswitch.sh';
  this.rememberService('clean-vpn-killswitch.service');this.file(script,fs.readFileSync(this.source+'/scripts/autostart/killswitch.sh'),0o755);
  const args=['up','--scope=both','--ipv6=block','--tun=tun0','--ssh-port=22','--server='+this.endpoint,'--usb-dns=1','--usb-strict=1'];
  this.run(this.at(script),['plan',...args.slice(1)]);
  this.file('/etc/systemd/system/clean-vpn-killswitch.service','# clean-vpn-networkd-gate-v1\n[Unit]\nDescription=clean-vpn persistent guard\nDefaultDependencies=no\nBefore=network-pre.target shutdown.target\nWants=network-pre.target\nConflicts=shutdown.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='+script+' '+args.join(' ')+'\nExecStop=/bin/true\n[Install]\nWantedBy=multi-user.target\n');
  for(const unit of ['systemd-networkd.service','systemd-networkd.socket'])if(this.prop(unit,'LoadState')==='loaded')this.file('/etc/systemd/system/'+unit+'.d/90-clean-vpn-clean-vpn.conf',networkdGateText('clean-vpn'));
  this.ctl('daemon-reload');this.ctl('enable','--now','clean-vpn-killswitch.service');
 }
 ingress(){
  const unit='native-'+this.o.name+'-ingress.service',script='/opt/clean-vpn-ingress/'+this.o.name+'.mjs';
  const c=packet(JSON.parse(readClientPrivate(this.config)));
  this.rememberService(unit);this.file(script,fs.readFileSync(this.source+'/scripts/clean-vpn-exit-ingress.mjs'));
  const exec=fs.realpathSync(process.execPath)+' '+script,args=' '+c.address+' '+c.port+' '+this.o.name;
  this.file('/etc/systemd/system/'+unit,'[Unit]\nDescription=clean-vpn owned exit TCP listener exception\nBefore='+this.owner+'\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='+exec+' up'+args+'\nExecStop='+exec+' down'+args+'\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/run\nCapabilityBoundingSet=CAP_NET_ADMIN\n[Install]\nWantedBy=multi-user.target\n');
  this.file('/etc/systemd/system/'+this.owner+'.d/30-ingress.conf','[Unit]\nRequires='+unit+'\nAfter='+unit+'\n');
  this.ctl('daemon-reload');this.ctl('enable','--now',unit);
 }
 captureCore(){
  const m=JSON.parse(safeRead(this.at(this.bundle+'/installed.json')));need(m.name===this.o.name&&m.kind==='clean-vpn-native-install','native_manifest');
  this.state.coreUnits=m.units.map(name=>{need(/^native-[a-z0-9-]+\.service$/.test(name),'unit_name');const p='/etc/systemd/system/'+name;return {path:p,text:safeRead(this.at(p)).toString()};});this.save();
 }
 archiveIncompleteCore(){
  const bundle=this.at(this.bundle);
  if(!this.state.coreIntent||!exists(bundle)||exists(bundle+'/installed.json'))return;
  // Our installer never starts a partially published bundle. Preserve its
  // contents for inspection, remove only hash-verified publication links.
  const manifest=exists(bundle+'/prepared.json')?JSON.parse(safeRead(bundle+'/prepared.json')):null;
  if(!manifest){need(fs.readdirSync(bundle).length===0,'incomplete_bundle_unknown');}
  else{
   need(manifest.kind==='clean-vpn-native-install'&&manifest.name===this.o.name&&manifest.role===this.o.role,'native_manifest');
   const publications=[];
   for(const name of manifest.units){
    need(/^native-[a-z0-9-]+\.service$/.test(name),'unit_name');
    need(['','0'].includes(this.prop(name,'MainPID'))&&!['active','activating','deactivating'].includes(this.prop(name,'ActiveState')),'partial_unit_running');
    const f=manifest.files.find(f=>f.name==='units/'+name);need(f&&/^[a-f0-9]{64}$/.test(f.sha256),'partial_unit_manifest');
    for(const p of ['/etc/systemd/system/'+name,'/etc/systemd/system/.'+name+'.prepared'])if(exists(this.at(p))){need(sha(safeRead(this.at(p)))===f.sha256,'partial_unit_changed');publications.push(this.at(p));}
   }
   for(const p of publications)fs.unlinkSync(p);
  }
  fs.renameSync(bundle,this.base+'/incomplete-native-'+randomBytes(8).toString('hex'));
  this.state.coreIntent=false;this.state.coreUnits=[];this.save();
 }
 restoreUnit(u){const p=this.at(u.path);if(exists(p))need(safeRead(p).toString()===u.text,'unit_changed');else atomic(p,u.text,0o644);}
 check(){
  return {status:'inspected',role:this.o.role,name:this.o.name,units:[this.owner,this.unit,...(this.o.role==='client'?['clean-vpn-killswitch.service']:[])].map(unit=>({unit,active:this.prop(unit,'ActiveState'),status:this.prop(unit,'StatusText')})),settingsChanged:false};
 }
 remove(){
  need(this.state.kind==='clean-vpn-managed-setup'&&this.state.identity.role===this.o.role&&this.state.identity.name===this.o.name,'setup_manifest');
  if(this.state.phase==='uninstalled')return {status:'uninstalled',unchanged:true};
  // Inspect all recorded objects before removing any protection or settings.
  for(const f of this.state.files){const p=this.at(f.path);if(exists(p)){const b=safeRead(p);need(sha(b)===f.after||(f.before!==null&&b.equals(Buffer.from(f.before,'base64'))),'owned_file_changed');}}
  if(this.state.coreIntent&&!this.state.coreUnits.length&&exists(this.at(this.bundle+'/installed.json')))this.captureCore();
  if(this.state.adminIntent&&exists(this.at('/etc/meshpn-admin/manifest.json'))){
   const m=JSON.parse(safeRead(this.at('/etc/meshpn-admin/manifest.json')));
   need(m.kind==='meshpn-admin-owned-install'&&m.vpnUnit===this.unit,'admin_manifest');
   if(m.unitTexts){this.state.adminUnits=Object.entries(m.unitTexts).map(([name,text])=>{need(['meshpn-admin-broker.service','meshpn-admin-web.service','meshpn-admin.socket','meshpn-admin-captive.service'].includes(name)&&typeof text==='string','admin_unit_manifest');return {path:'/etc/systemd/system/'+name,text};});this.save();}
  }
  for(const u of [...this.state.coreUnits,...this.state.adminUnits])if(exists(this.at(u.path)))need(safeRead(this.at(u.path)).toString()===u.text,'owned_unit_changed');
  this.archiveIncompleteCore();
  this.progress('uninstalling');
  if(this.state.adminIntent&&!this.state.adminRemoved&&exists(this.at('/etc/meshpn-admin/manifest.json'))){this.run(process.execPath,[this.source+'/admin/install.mjs','--remove'],{timeout:120000});this.state.adminRemoved=true;this.save();}
  if(this.state.coreUnits.length&&!this.state.coreRemoved){
   if(this.prop(this.owner,'LoadState')==='loaded')this.ctl('disable','--now',this.owner);need(['','0'].includes(this.prop(this.unit,'MainPID')),'engine_still_running');
   const control=this.bundle+'/control/'+(this.o.role==='client'?'clean-vpn-native-host-network.mjs':'clean-vpn-native-exit-host.mjs');
   this.run(process.execPath,[this.at(control),'recover','--config='+this.at(this.bundle+'/network.json')],{timeout:60000});
   for(const u of this.state.coreUnits)if(exists(this.at(u.path)))fs.unlinkSync(this.at(u.path));
   this.state.coreRemoved=true;this.save();
  }
  // Detach boot dependencies before explicitly removing the independent guard.
  for(const f of this.state.files.filter(f=>f.path.includes('/systemd-networkd.')&&f.path.endsWith('.conf')))this.restoreFile(f);
  this.ctl('daemon-reload');
  if(this.o.role==='client'&&this.state.files.some(f=>f.path==='/usr/local/bin/clean-vpn-killswitch.sh')&&exists(this.at('/usr/local/bin/clean-vpn-killswitch.sh'))){
   if(this.prop('clean-vpn-killswitch.service','LoadState')==='loaded')this.ctl('disable','--now','clean-vpn-killswitch.service');this.run(this.at('/usr/local/bin/clean-vpn-killswitch.sh'),['down','--tun=tun0']);
  }
  for(const [unit,old]of Object.entries(this.state.services)){if(this.prop(unit,'LoadState')!=='loaded')continue;if(!old.enabled)this.ctl('disable',unit);if(!old.active)this.ctl('stop',unit);}
  for(const f of [...this.state.files].reverse())this.restoreFile(f);
  this.forward(false);this.ctl('daemon-reload');
  if(this.state.files.some(f=>f.path.startsWith('/etc/dnsmasq.d/'))&&this.state.services['dnsmasq.service']?.active)this.ctl('restart','dnsmasq.service');
  this.progress('uninstalled');return {status:'uninstalled',credentialsRetained:this.base,nativeStateRetained:this.bundle,forwardingRestored:true};
 }
 restoreFile(f){const p=this.at(f.path);if(!exists(p)){need(f.before===null,'missing_original_file');return;}const b=safeRead(p);if(f.before!==null&&b.equals(Buffer.from(f.before,'base64')))return;need(sha(b)===f.after,'owned_file_changed');if(f.before===null)fs.unlinkSync(p);else atomic(p,Buffer.from(f.before,'base64'),f.beforeMode);}
}
