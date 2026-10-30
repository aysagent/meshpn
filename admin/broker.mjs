#!/usr/bin/env node
// Root-only local broker. No TCP listener, shell execution, supplied commands,
// supplied filesystem paths, Docker socket or generic systemctl endpoint.
import {certificateStatus} from './lib/certificates.mjs';
import {createClientAdministration,publicClientList} from './lib/clients.mjs';
import {readPortalState} from './lib/captive.mjs';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {isIPv4} from 'node:net';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {need,exact,hostname,id,atomic,readJson,body,send,safeError} from './lib/common.mjs';
import {command,Jobs} from './lib/command.mjs';
import {Metrics} from './lib/metrics.mjs';
import {Wifi} from './lib/wifi.mjs';
import {Observer} from './lib/observer.mjs';
import {VpnSettingsTransaction} from './lib/vpn-settings-transaction.mjs';
import {setTimeout as delay} from 'node:timers/promises';
export async function createBroker(c,{run=command,clientsFactory=createClientAdministration}={}){
 need(c.version===1&&isIPv4(c.usbAddress)&&/^[a-zA-Z0-9_-]{1,15}$/.test(c.usbInterface),'broker_config');
 if(c.networkUnit!==undefined)need(c.nativeManaged===true&&c.networkUnit!==c.vpnUnit&&c.networkUnit!==c.guardUnit,'broker_network_unit');
 const initialVpn=readJson(c.vpnConfig),isExit=initialVpn.role==='exit';
 const packetConfig=v=>v.transport==='combo-tls'?v.boring:v;
 const packetControls=!isExit&&(!initialVpn.transport||['boring-tls','combo-tls'].includes(initialVpn.transport));
 const activationUnit=c.networkUnit??c.vpnUnit;
 for(const n of [c.vpnUnit,...(isExit?[]:[c.guardUnit]),...(c.networkUnit?[c.networkUnit]:[])])need(/^[a-zA-Z0-9_-]+\.service$/.test(n),'broker_unit');
 for(const p of [c.state,c.engine,c.profiles,c.vpnConfig,c.socket,...(isExit?[]:[c.guardScript]),...(c.clientsDirectory?[c.clientsDirectory]:[])])need(typeof p==='string'&&path.isAbsolute(p)&&!/[\n\r\0]/.test(p),'broker_path');
 need(!c.clientsDirectory||isExit,'clients_exit_only');
 const clients=c.clientsDirectory?clientsFactory(c,{run}):null;
 fs.mkdirSync(c.state,{recursive:true,mode:0o700});const jobs=new Jobs(),metrics=new Metrics();const settingsFile=c.state+'/settings.json';let settings=readJson(settingsFile,{hostname:'mpn',profile:null});let mdns=null,mdnsRetry=null,closing=false,mdnsState={status:'starting'};
 const wifi=isExit?null:new Wifi({file:c.state+'/wifi.json',interface:c.wifiInterface,clientDirectory:path.dirname(c.socket),run});const observer=new Observer({interface:c.wifiInterface,directory:c.state});
 const unit=async name=>Object.fromEntries((await run('/usr/bin/systemctl',['show',name,'-p','ActiveState','-p','SubState','-p','UnitFileState','-p','MainPID'])).out.trim().split('\n').map(l=>l.split('=')));
 const guard=async()=>{if(isExit)return{active:null,summary:'exit forwarding managed separately'};const r=await run(c.guardScript,['status']);return{active:/IPv4: cvks/.test(r.out)&&/IPv6: cvks/.test(r.out),summary:r.out.slice(0,1024)};};
 const nativeState=async()=>Object.fromEntries((await run('/usr/bin/systemctl',['show',c.vpnUnit,'-p','Type','-p','ActiveState','-p','SubState','-p','MainPID','-p','StatusText'])).out.trim().split('\n').map(l=>l.split('=')));
 const service={
  validate:async()=>need((await nativeState()).Type==='notify','native_notify_service_required',409),
  running:async()=>{const s=await nativeState();need(s.Type==='notify','native_notify_service_required',409);need(['active','inactive','failed'].includes(s.ActiveState),'vpn_service_transition',409);return s.ActiveState==='active';},
  guard:async()=>{if(isExit){if(c.networkUnit)need((await unit(c.networkUnit)).ActiveState==='active','network_owner_inactive',409);return;}need((await guard()).active,'enable_guard_first',409);if(c.networkUnit)need((await unit(c.networkUnit)).ActiveState==='active','network_owner_inactive',409);},
  stop:()=>run('/usr/bin/systemctl',['stop',c.vpnUnit],{timeout:60000}),
  start:()=>run('/usr/bin/systemctl',['start',c.vpnUnit],{timeout:60000}),
  restart:()=>run('/usr/bin/systemctl',['restart',c.vpnUnit],{timeout:60000}),
  ready:async()=>{const s=await nativeState();need(s.Type==='notify'&&s.ActiveState==='active'&&s.SubState==='running'&&Number(s.MainPID)>0&&(isExit?['ready','listening','handshake']:['ready','idle_wait']).includes(s.StatusText),'native_not_ready');await service.guard();}
 };
 const transaction=new VpnSettingsTransaction({state:c.state,config:c.vpnConfig,settings:settingsFile,unit:c.vpnUnit,managed:c.nativeManaged,networkUnit:c.networkUnit},service);
 const recovery=await transaction.recover();settings=readJson(settingsFile,{hostname:'mpn',profile:null});
 async function lifecycle(action){
  if(action!=='stop'&&!isExit){
   need((await guard()).active,'enable_guard_first',409);
   if(c.networkUnit){const binds=(await run('/usr/bin/systemctl',['show',c.vpnUnit,'-p','BindsTo','--value'])).out.trim().split(/\s+/);need(binds.includes(c.networkUnit)&&binds.includes(c.guardUnit),'network_owner_binding_required',409);}
  }
  await run('/usr/bin/systemctl',[action,activationUnit],{timeout:210000});
  if(c.networkUnit&&action!=='stop'){
   const deadline=performance.now()+60000;let error;
   do{try{await service.ready();return unit(c.vpnUnit);}catch(e){error=e;}await delay(500);}while(performance.now()<deadline);
   throw error;
  }
  return unit(c.vpnUnit);
 }
 const vpn=()=>readJson(c.vpnConfig);
 const profiles=()=>fs.readdirSync(c.profiles).filter(n=>/^[a-zA-Z0-9_.-]+\.json$/.test(n)).slice(0,256).flatMap(n=>{try{const p=readJson(path.join(c.profiles,n));return p.kind==='clean-vpn-native-tls-profile'?[{id:n,name:p.id,scenario:p.scenario,browserEquivalent:false}]:[];}catch{return[];}});
 const selected=(name)=>{need(typeof name==='string'&&profiles().some(p=>p.id===name),'profile_not_found',404);return path.join(c.profiles,name);};
 function publish(){mdns?.kill('SIGTERM');mdnsState={status:'starting'};const child=spawn('/usr/bin/python3',[fileURLToPath(new URL('./mdns.py',import.meta.url)),c.usbInterface,settings.hostname,c.usbAddress],{stdio:['ignore','pipe','ignore']});mdns=child;child.stdout.on('data',b=>{try{const a=JSON.parse(b.toString().trim());mdnsState={status:a.state===2?'published':'starting',hostname:a.hostname};}catch{}});child.on('error',()=>{mdnsState={status:'unavailable'};});child.on('close',()=>{if(mdns===child){mdnsState={status:'unavailable'};if(!closing){clearTimeout(mdnsRetry);mdnsRetry=setTimeout(publish,10000);mdnsRetry.unref();}}});}
 if(c.publishMdns!==false&&!isExit)publish();
 let wifiBootTimer;async function restoreWifi(){try{if(!jobs.current&&wifi?.profiles.length){const owned=await wifi.owned();if(wifi.profiles.some(p=>!owned.has(p.id)))await wifi.sync();}}catch{}finally{if(!closing){wifiBootTimer=setTimeout(restoreWifi,15000);wifiBootTimer.unref();}}}void restoreWifi();
 async function applyVpn(p){exact(p,['address','port','serverName','sni','profile']);need(isIPv4(p.address)&&Number.isInteger(p.port)&&p.port>=1&&p.port<=65535,'vpn_endpoint');for(const n of [p.serverName,p.sni])need(typeof n==='string'&&/^[a-zA-Z0-9.-]{1,253}$/.test(n),'tls_name');const raw=vpn(),old=packetConfig(raw);need(raw.role==='client'&&packetControls,'packet_client_config_required');const packet={...old,address:p.address,port:p.port,server_name:p.serverName,sni:p.sni};if(p.profile)packet.tls_profile_path=selected(p.profile);else delete packet.tls_profile_path;
 // Combo SNI selects the branch on exit. Changing it requires migrating the
 // shared listener and relay identities, outside a client settings transaction.
 if(raw.transport==='combo-tls')need(p.sni.toLowerCase()===raw.transparent.public_name.toLowerCase(),'combo_name_requires_exit_migration',409);
 const next=raw.transport==='combo-tls'?{...raw,boring:packet}:packet;const file=c.state+'/candidate.json';atomic(file,next);await run(c.engine,['--check-config',file],{timeout:15000});
 // A settings operation must not silently leave the independent guard allowing
 // the old exit while switching the route/DNS owner to a new endpoint.
 need(packet.address===old.address&&packet.port===old.port,'endpoint_change_requires_owner_migration',409);
 let result;try{result=await transaction.apply(next,{...settings,profile:p.profile??null});}finally{settings=readJson(settingsFile,{hostname:'mpn',profile:null});}
 return{...result,applied:!!c.nativeManaged&&result.restarted,requiresNativeMigration:!c.nativeManaged,requiresStart:!!c.nativeManaged&&!result.restarted};}
 async function dispatch(route,p={}){
 if(!['/status','/settings','/logs','/observer','/observer/pcap','/clients'].includes(route)){
  need(!jobs.current,'operation_in_progress',409);
  need(!transaction.load(),'vpn_transaction_recovery_required',409);
 }
 if(route.startsWith('/clients'))need(clients,'clients_not_configured',409);
 if(isExit&&['/hostname','/vpn/settings','/guard','/wifi/scan','/wifi/save','/wifi/connect','/wifi/delete','/probe','/observer/start','/observer/stop','/observer/pcap','/profile/import'].includes(route))need(false,'client_only_operation',409);
 if(!isExit&&!packetControls&&['/vpn/settings','/profile/import','/probe','/observer/start'].includes(route))need(false,'transport_control_not_supported',409);
 switch(route){
 case '/status':{const [v,g,w]=await Promise.all([unit(c.vpnUnit).catch(()=>({ActiveState:'unknown'})),guard().catch(()=>({active:null})),(wifi?wifi.status():Promise.resolve({wpa_state:'not_applicable'})).catch(()=>({wpa_state:'unavailable'}))]);return{metrics:metrics.sample(),certificates:certificateStatus(vpn()),vpn:v,network:c.networkUnit?await unit(c.networkUnit).catch(()=>({ActiveState:'unknown'})):null,guard:g,wifi:w,captive:readPortalState(path.dirname(c.socket)+'/captive.json'),mdns:mdnsState,jobs:jobs.history,vpnSettingsRecovery:{...recovery,pending:!!transaction.load()},capabilities:{nativeManaged:!!c.nativeManaged,networkOwner:!!c.networkUnit,role:isExit?'exit':'client',clients:!!clients,wifi:isExit?false:'wpa_supplicant-owned-profiles',guardToggle:!isExit,hostnameChange:!isExit,observer:packetControls,profileImport:packetControls,vpnSettings:packetControls,probes:packetControls?['exit','dns','internet']:[],routingRules:false,dnsUpstreamConfig:false,transports:[initialVpn.transport??'boring-tls']}};}
 case '/settings':{const raw=vpn(),v=raw.transport==='combo-tls'?raw.boring:raw;return{hostname:settings.hostname,adminUrl:'http://'+settings.hostname+'.local/',vpn:{role:isExit?'exit':'client',address:v.address,port:v.port,serverName:v.server_name,sni:v.sni,profile:settings.profile??(v.tls_profile_path?path.basename(v.tls_profile_path):null),dns:v.dns===true,transport:raw.transport??'boring-tls',nativeManaged:!!c.nativeManaged},dns:{mode:isExit?'exit':'tunnel',upstreams:isExit?'Private .mpn resolver is opt-in; host DNS unchanged':'native fixed upstreams; editing not supported by engine',integrationManaged:!!c.networkUnit},profiles:isExit?[]:profiles(),wifi:wifi?wifi.list():[]};}
 case '/clients':exact(p,[]);return publicClientList(await clients.list());
 case '/clients/add':exact(p,['name']);return jobs.start('client-add',async()=>publicClientList(await clients.add(p.name)));
 case '/clients/rename':exact(p,['name','newName']);return jobs.start('client-rename',async()=>publicClientList(await clients.rename(p.name,p.newName)));
 case '/clients/rotate':case '/clients/revoke':{exact(p,['name','confirm']);need(p.confirm===true,'client_action_confirmation_required',409);const action=route.split('/').at(-1);return jobs.start('client-'+action,async()=>publicClientList(await clients[action](p.name)));}
 case '/clients/export':exact(p,['name']);return clients.export(p.name);
 case '/hostname':exact(p,['hostname']);settings.hostname=hostname(p.hostname);atomic(settingsFile,settings);if(c.publishMdns!==false)publish();return{hostname:settings.hostname,adminUrl:'http://'+settings.hostname+'.local/',fallbackUrl:'http://'+c.usbAddress+'/'};
 case '/vpn/settings':return jobs.start('vpn-settings',()=>applyVpn(p));
 case '/vpn/action':exact(p,['action']);need(['start','stop','restart'].includes(p.action),'vpn_action');return jobs.start('vpn-'+p.action,()=>lifecycle(p.action));
 case '/guard':exact(p,['enabled','confirmDirect']);need(typeof p.enabled==='boolean','guard_enabled');need(p.enabled||p.confirmDirect===true,'direct_egress_confirmation_required',409);return jobs.start('guard',async()=>{const active=(await unit(c.vpnUnit)).ActiveState==='active';await lifecycle('stop');await run(process.execPath,[fileURLToPath(new URL('./usb-mdns.mjs',import.meta.url)),'down']);try{if(p.enabled)await run('/usr/bin/systemctl',['restart',c.guardUnit],{timeout:30000});else await run(c.guardScript,['down'],{timeout:30000});}finally{await run(process.execPath,[fileURLToPath(new URL('./usb-mdns.mjs',import.meta.url)),'up']);}if(p.enabled&&active)await lifecycle('start');return{...(await guard()),vpnStopped:!p.enabled};});
 case '/wifi/scan':exact(p,[]);return jobs.start('wifi-scan',()=>wifi.scan());
 case '/wifi/save':return jobs.start('wifi-save',async()=>{wifi.save(p);await wifi.sync();return wifi.list();});
 case '/wifi/connect':exact(p,['id']);return jobs.start('wifi-connect',()=>wifi.connect(p.id));
 case '/wifi/delete':exact(p,['id']);return jobs.start('wifi-delete',()=>wifi.remove(p.id));
 case '/logs':{exact(p,['service']);need(['vpn','network','guard','admin'].includes(p.service),'log_service');need(!isExit||p.service!=='guard','client_only_operation',409);need(p.service!=='network'||c.networkUnit,'network_owner_not_configured',409);const service=p.service==='vpn'?c.vpnUnit:p.service==='network'?c.networkUnit:p.service==='guard'?c.guardUnit:'meshpn-admin-broker.service';const data=(await run('/usr/bin/journalctl',['--no-pager','-u',service,'-n','120','-o','json'],{limit:512*1024})).out;return{lines:data.split('\n').filter(Boolean).flatMap(l=>{try{const x=JSON.parse(l),s=String(x.MESSAGE??'');if(/password|secret|authorization|bearer|private.key|psk|BEGIN .*KEY|--shared-hmac/i.test(s))return['[sensitive log line omitted]'];return[s.slice(0,1024)];}catch{return[];}})};}
 case '/probe':exact(p,['kind']);need(['exit','dns','internet'].includes(p.kind),'probe_kind');return jobs.start('probe-'+p.kind,async()=>{const began=performance.now(),v=packetConfig(vpn());if(p.kind==='exit'){await run('/bin/ping',['-n','-c','2','-W','2',v.address],{timeout:6000});return{status:'passed',milliseconds:Math.round(performance.now()-began),scope:'ICMP exit only, not VPN health'};}if(p.kind==='dns'){const out=(await run('/usr/bin/dig',['@127.0.0.1','example.com','A','+time=2','+tries=1','+short'],{timeout:4000})).out;need(out.split('\n').some(isIPv4),'dns_answer_missing');return{status:'passed',milliseconds:Math.round(performance.now()-began),scope:'current local DNS path, not a leak test'};}const out=(await run('/usr/bin/curl',['-q','-4','-fsS','--noproxy','*','--interface',v.tun,'--connect-timeout','3','--max-time','6','--max-filesize','4096','https://1.1.1.1/cdn-cgi/trace'],{timeout:8000})).out;const ip=/^ip=([0-9.]+)$/m.exec(out)?.[1];need(isIPv4(ip),'probe_response');return{status:'passed',observedExitIp:ip,milliseconds:Math.round(performance.now()-began),scope:'HTTPS bound to configured TUN; no direct fallback'};});
 case '/observer/start':{exact(p,['seconds']);const v=packetConfig(vpn()),profile=v.tls_profile_path?readJson(v.tls_profile_path):null;return observer.start({destination:v.address,port:v.port,profile,profileSni:vpn().transport==='combo-tls'?v.sni??v.server_name:null,seconds:p.seconds});}
 case '/observer/stop':exact(p,[]);return observer.stop();
 case '/observer/pcap':exact(p,[]);need(!observer.child&&observer.result?.pcapAvailable,'capture_not_ready',409);return{base64:fs.readFileSync(c.state+'/observer.pcap').toString('base64')};
 case '/observer':return observer.result??{status:'idle'};
 case '/profile/import':return jobs.start('profile-import',async()=>{exact(p,['profile']);need(p.profile?.kind==='clean-vpn-native-tls-profile'&&id(p.profile.id)&&JSON.stringify(p.profile).length<=16384,'profile_document');need(profiles().length<256,'profile_limit');const name=p.profile.id+'.json',file=path.join(c.profiles,name);need(!fs.existsSync(file),'profile_exists',409);const candidate=c.state+'/profile-candidate.json';atomic(candidate,p.profile);const raw=vpn(),packet={...packetConfig(raw),tls_profile_path:candidate},config=raw.transport==='combo-tls'?{...raw,boring:packet}:packet;const configFile=c.state+'/profile-check.json';atomic(configFile,config);await run(c.engine,['--check-config',configFile],{timeout:15000});atomic(file,p.profile,0o644);return{saved:true,id:name,activated:false};});
 default:throw Object.assign(Error('not_found'),{status:404});
 }}
 const server=http.createServer(async(req,res)=>{try{need(req.method==='POST','method',405);const p=await body(req,65536);send(res,200,await dispatch(req.url,p));}catch(e){send(res,e.status??500,{error:safeError(e)});}});server.requestTimeout=15000;server.headersTimeout=5000;server.maxConnections=16;server.on('clientError',(_,s)=>s.destroy());
 return{server,dispatch,close:()=>{closing=true;clearTimeout(mdnsRetry);clearTimeout(wifiBootTimer);mdns?.kill('SIGTERM');observer.stop();server.close();},config:c};
}
async function main(){need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');need(process.argv.length===3,'config_argument');const c=readJson(process.argv[2]),s=fs.lstatSync(process.argv[2]);need(s.uid===0&&!(s.mode&0o022)&&s.isFile()&&!s.isSymbolicLink(),'private_broker_config');const b=await createBroker(c);need(!fs.existsSync(c.socket),'broker_socket_exists');b.server.listen(c.socket,()=>fs.chmodSync(c.socket,0o660));for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{b.close();});}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(safeError(e));process.exitCode=1;});
