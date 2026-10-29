#!/usr/bin/env node
// Namespace-local supervisor. No Docker socket, host filesystem or arbitrary
// command API. It owns exactly one configured engine child and its guard.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {need,exact,readJson,atomic,body,send,safeError} from '../admin/lib/common.mjs';
import {Jobs} from '../admin/lib/command.mjs';
import {Metrics} from '../admin/lib/metrics.mjs';
import {VpnSettingsTransaction} from '../admin/lib/vpn-settings-transaction.mjs';
import {publicClientList} from '../admin/lib/clients.mjs';
import {NativeClientManager,clientName} from './lib/native-client-manager.mjs';

export async function boundedCommand(file,args,{timeout=15000}={}) {
 return await new Promise((resolve,reject)=>{
  const child=spawn(file,args,{env:process.env,stdio:['ignore','pipe','pipe']});let out='',bytes=0,failed=false;
  const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');},timeout);
  child.on('error',()=>{failed=true;});
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{bytes+=b.length;if(bytes>256*1024){failed=true;child.kill('SIGKILL');}else if(stream===child.stdout)out+=b;});
  child.on('close',code=>{clearTimeout(timer);if(failed||code!==0)reject(Error('container_command_failed'));else resolve({out,code});});
 });
}

export class ContainerEngine {
 constructor({config,engine,runtime,health,state='/run/clean-vpn'}, {run=boundedCommand,start=spawn}={}) {
  Object.assign(this,{config,engine,runtime,health,state,run,spawn:start});this.child=null;this.desired=false;this.closing=false;this.lines=[];this.engineState='stopped';this.restarts=[];this.reloadEvents=[];this.reloadSequence=0;
 }
 log(text){for(const line of String(text).split('\n').filter(Boolean)){this.lines.push(/password|secret|authorization|bearer|private.key|psk|BEGIN .*KEY/i.test(line)?'[sensitive log omitted]':line.slice(0,1024));}this.lines=this.lines.slice(-120);}
 async prepare(){await this.run(process.execPath,[this.runtime,this.config]);}
 async start(){
  need(!this.child,'engine_already_running',409);this.desired=true;clearTimeout(this.retry);
  await this.prepare();this.engineState='starting';
  const child=this.spawn(this.engine,['--config',this.state+'/engine.json','--service'],{env:process.env,stdio:['ignore','pipe','pipe']});this.child=child;let buffer='';
  child.stdout.on('data',b=>{buffer+=b.toString();if(buffer.length>16384){buffer='';this.log('engine_output_limit');child.kill('SIGTERM');return;}let i;while((i=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,i);buffer=buffer.slice(i+1);this.log(line);try{const event=JSON.parse(line);if(event.event==='state'&&typeof event.state==='string')this.engineState=event.state;if(event.event==='peer_reload'){this.reloadEvents.push({sequence:++this.reloadSequence,...event});this.reloadEvents=this.reloadEvents.slice(-32);}}catch{}}});
  child.stderr.on('data',b=>this.log(b));child.on('error',()=>this.log('engine_spawn_failed'));
  child.once('close',()=>{if(this.child!==child)return;this.child=null;this.engineState=this.desired?'failed':'stopped';if(this.desired&&!this.closing){const now=Date.now();this.restarts=this.restarts.filter(t=>now-t<60000);if(this.restarts.length<5){this.restarts.push(now);this.retry=setTimeout(()=>{this.start().catch(()=>{this.engineState='failed';this.log('engine_restart_failed');});},2000);}else this.log('engine_restart_limit');}});
  await this.ready();
 }
 async ready(){const until=performance.now()+15000;do{if(this.child&&['idle','idle_wait','listening','ready'].includes(this.engineState))return;if(!this.child)throw Error('engine_start_failed');await delay(50);}while(performance.now()<until);throw Error('engine_start_timeout');}
 async stop(){this.desired=false;clearTimeout(this.retry);const child=this.child;if(!child)return;await new Promise(resolve=>{const timer=setTimeout(()=>child.kill('SIGKILL'),10000);child.once('close',()=>{clearTimeout(timer);resolve();});child.kill('SIGTERM');});}
 async restart(){await this.stop();await this.start();}
 async reload(sha256){const child=this.child;need(child,'client_service_not_active',409);const before=this.reloadSequence;await this.prepare();need(this.child===child,'client_engine_changed',409);child.kill('SIGHUP');const deadline=performance.now()+8000;do{const event=this.reloadEvents.find(e=>e.sequence>before&&e.config_sha256===sha256);if(event){need(event.status==='applied','client_reload_rejected',409);return;}need(this.child===child,'client_engine_changed',409);await delay(50);}while(performance.now()<deadline);throw Error('client_reload_ack_timeout');}
 status(){return{ActiveState:this.child?'active':this.desired?'failed':'inactive',SubState:this.engineState,MainPID:this.child?.pid??0};}
 async close(){this.closing=true;await this.stop();}
}

export async function createContainerBroker(c,{engine=new ContainerEngine(c),run=boundedCommand}={}) {
 for(const key of ['config','engine','runtime','stateDirectory','socket'])need(typeof c[key]==='string'&&path.isAbsolute(c[key]),'container_broker_path');
 fs.mkdirSync(c.stateDirectory,{recursive:true,mode:0o700});const settingsFile=c.stateDirectory+'/settings.json';
 let settings=readJson(settingsFile,{hostname:'mpn',profile:null,desired:true});const jobs=new Jobs(),metrics=new Metrics();
 const vpn=()=>readJson(c.config),packet=v=>v.transport==='combo-tls'?v.boring:v;
 const role=packet(vpn()).role;need(['client','exit'].includes(role),'container_role');
 const profileDirectory=path.dirname(c.config);
 const profiles=()=>fs.readdirSync(profileDirectory).filter(n=>/^[a-zA-Z0-9_.-]+\.json$/.test(n)).flatMap(n=>{try{const p=readJson(path.join(profileDirectory,n));return p.kind==='clean-vpn-native-tls-profile'?[{id:n,name:p.id,scenario:p.scenario,browserEquivalent:false}]:[];}catch{return[];}}).slice(0,256);
 const service={validate:async()=>{},running:async()=>!!engine.child,guard:()=>engine.prepare(),stop:()=>engine.stop(),start:()=>engine.start(),restart:()=>engine.restart(),ready:async()=>{await engine.ready();await run(process.execPath,[c.health]);}};
 const transaction=new VpnSettingsTransaction({state:c.stateDirectory,config:c.config,settings:settingsFile,unit:'container-engine',managed:true},service);
 const recovery=await transaction.recover();settings=readJson(settingsFile,settings);
 let initializingClients=true;
 const clients=c.clientsDirectory?new NativeClientManager({directory:c.clientsDirectory,validateConfig:async file=>{await run(c.engine,['--check-config',file]);},beforeMutation:async()=>{const caps=JSON.parse((await run(c.engine,['--capabilities'])).out);need(caps.peer_reload,'client_engine_reload_unsupported',409);need(!!engine.child,'client_service_not_active',409);},applyConfig:async({configPath,sha256})=>{need(configPath===c.config,'clients_exit_binding',409);if(initializingClients){await engine.prepare();return;}await engine.reload(sha256);},initializeRelay:async config=>{const file=c.stateDirectory+'/relay-init.json';atomic(file,config);try{await run(c.engine,['--init-transparent-replay',file]);}finally{fs.unlinkSync(file);}}}):null;
 if(clients){need(role==='exit'&&clients.load().configPath===c.config,'clients_exit_binding',409);await clients.recover();}
 initializingClients=false;
 const capabilities={containerManaged:true,nativeManaged:true,networkOwner:true,wifi:false,guardToggle:false,hostnameChange:false,observer:false,clients:!!clients,profileImport:role==='client',vpnSettings:role==='client',transports:['boring-tls','combo-tls'],role};
 async function dispatch(route,p={}) {
  if(!['/status','/settings','/logs','/observer'].includes(route)){need(!jobs.current,'operation_in_progress',409);need(!transaction.load(),'vpn_transaction_recovery_required',409);}
  switch(route){
   case '/status':return{metrics:metrics.sample(),vpn:engine.status(),network:{ActiveState:fs.existsSync(engine.state+'/network.json')?'active':'unknown'},guard:{active:fs.existsSync(engine.state+'/network.json')?true:null,summary:'Namespace guard retained while engine stopped; no host guard control'},wifi:{wpa_state:'unsupported'},captive:{active:false},mdns:{status:'unsupported'},jobs:jobs.history,vpnSettingsRecovery:{...recovery,pending:!!transaction.load()},capabilities};
   case '/settings':{const v=vpn(),p=packet(v);return{hostname:settings.hostname,adminUrl:'http://127.0.0.1:'+(c.webPort??8080)+'/',vpn:{role,address:p.address,port:p.port,serverName:p.server_name,sni:p.sni,profile:settings.profile??(p.tls_profile_path?path.basename(p.tls_profile_path):null),dns:p.dns===true,transport:v.transport??'boring-tls',nativeManaged:true,containerManaged:true},dns:{mode:role==='client'?'tunnel':'exit',upstreams:'native fixed upstreams; host DNS unchanged',integrationManaged:false},profiles:profiles(),wifi:[],capabilities};}
   case '/vpn/action':exact(p,['action']);need(['start','stop','restart'].includes(p.action),'vpn_action');return jobs.start('vpn-'+p.action,async()=>{settings={...settings,desired:p.action!=='stop'};atomic(settingsFile,settings);if(p.action==='start'&&engine.child)return engine.status();await engine[p.action]();return engine.status();});
   case '/logs':exact(p,['service']);need(['vpn','admin','network'].includes(p.service),'log_service');return{lines:engine.lines.slice()};
   case '/clients':exact(p,[]);need(clients,'clients_not_configured',409);return publicClientList(await clients.list());
   case '/clients/export':exact(p,['name']);need(clients&&clientName(p.name),'client_name');return clients.export(p.name);
   case '/clients/add':case '/clients/rename':case '/clients/revoke':case '/clients/rotate':{
    exact(p,route==='/clients/rename'?['name','newName']:['name']);need(clients&&clientName(p.name)&&(route!=='/clients/rename'||clientName(p.newName)),'client_name');const action=route.slice('/clients/'.length);return jobs.start('clients-'+action,async()=>publicClientList(await clients[action](p.name,...(action==='rename'?[p.newName]:[]))));
   }
   case '/vpn/settings':return jobs.start('vpn-settings',async()=>{
    exact(p,['address','port','serverName','sni','profile']);need(role==='client','client_settings_only',409);const old=vpn(),v=packet(old);
    need(p.address===v.address&&p.port===v.port,'endpoint_change_requires_container_recreate',409);
    for(const name of [p.serverName,p.sni])need(typeof name==='string'&&/^[a-zA-Z0-9.-]{1,253}$/.test(name),'tls_name');
    const next=structuredClone(old),n=packet(next);n.server_name=p.serverName;n.sni=p.sni;
    if(p.profile){need(profiles().some(x=>x.id===p.profile),'profile_not_found',404);n.tls_profile_path=path.join(profileDirectory,p.profile);}else delete n.tls_profile_path;
    const candidate=c.stateDirectory+'/candidate.json';atomic(candidate,next);await run(c.engine,['--check-config',candidate]);
    try{return await transaction.apply(next,{...settings,profile:p.profile??null});}finally{settings=readJson(settingsFile,settings);}
   });
   case '/profile/import':return jobs.start('profile-import',async()=>{
    exact(p,['profile']);need(role==='client','client_settings_only',409);need(p.profile?.kind==='clean-vpn-native-tls-profile'&&/^[a-zA-Z0-9_-]{1,64}$/.test(p.profile.id)&&JSON.stringify(p.profile).length<=16384,'profile_document');
    need(profiles().length<256,'profile_limit');const name=p.profile.id+'.json',dest=path.join(profileDirectory,name);need(!fs.existsSync(dest),'profile_exists',409);
    const candidate=c.stateDirectory+'/profile.json';atomic(candidate,p.profile);const next=vpn();packet(next).tls_profile_path=candidate;const check=c.stateDirectory+'/profile-check.json';atomic(check,next);await run(c.engine,['--check-config',check]);atomic(dest,p.profile);return{saved:true,id:name,activated:false};
   });
   case '/probe':exact(p,['kind']);need(p.kind==='dns'&&role==='client','container_probe_not_supported',501);return jobs.start('probe-dns',async()=>{await run(process.execPath,[c.health]);return{status:'passed',scope:'native container runtime health, not general leak test'};});
   case '/observer':return{status:'unsupported',reason:'container_observer_requires_separate_capture_namespace'};
   default:throw Object.assign(Error('container_operation_not_supported'),{status:501});
  }
 }
 const server=http.createServer(async(req,res)=>{try{need(req.method==='POST','method',405);send(res,200,await dispatch(req.url,await body(req,65536)));}catch(e){send(res,e.status??500,{error:safeError(e)});}});
 server.requestTimeout=15000;server.headersTimeout=5000;server.maxConnections=16;server.on('clientError',(_,socket)=>socket.destroy());
 return{server,dispatch,engine,async start(){if(settings.desired!==false&&!engine.child)await engine.start();},async close(){server.close();await engine.close();}};
}

async function main(){
 need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');need(process.argv.length===3,'config_argument');
 need(/^net:\[\d+\]$/.test(process.env.CVPN_PARENT_NETNS??'')&&fs.readlinkSync('/proc/self/ns/net')!==process.env.CVPN_PARENT_NETNS,'isolated_container_namespace_required');
 const config=process.argv[2];need(config==='/config/engine.json','container_fixed_config');
 const c={config,engine:'/usr/local/bin/clean-vpn-engine',runtime:'/opt/clean-vpn/scripts/clean-vpn-native-runtime.mjs',health:'/opt/clean-vpn/scripts/clean-vpn-native-runtime-health.mjs',stateDirectory:'/config/admin-state',socket:'/run/meshpn-admin/broker.sock'};
 if(process.env.CVPN_CLIENTS_DIRECTORY){need(process.env.CVPN_CLIENTS_DIRECTORY==='/config/clients','container_fixed_clients_directory');c.clientsDirectory='/config/clients';}
 const gid=Number(process.env.MPN_ADMIN_GID??1000);need(Number.isInteger(gid)&&gid>=1&&gid<=65535,'admin_gid');
 const dir=path.dirname(c.socket);fs.mkdirSync(dir,{recursive:true,mode:0o750});const st=fs.lstatSync(dir);need(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===0,'broker_socket_directory');fs.chownSync(dir,0,gid);fs.chmodSync(dir,0o750);
 if(fs.existsSync(c.socket)){need(fs.lstatSync(c.socket).isSocket(),'broker_socket_type');const active=await new Promise(resolve=>{const s=net.connect(c.socket);s.setTimeout(1000);s.once('connect',()=>{s.destroy();resolve(true);});s.once('timeout',()=>{s.destroy();resolve(true);});s.once('error',e=>resolve(e.code!=='ECONNREFUSED'));});need(!active,'broker_already_running');fs.unlinkSync(c.socket);}
 const b=await createContainerBroker(c);try{await b.start();}catch(error){await b.close();throw error;}b.server.listen(c.socket,()=>{fs.chownSync(c.socket,0,gid);fs.chmodSync(c.socket,0o660);});
 for(const sig of ['SIGTERM','SIGINT'])process.once(sig,()=>{void b.close().then(()=>{try{fs.unlinkSync(c.socket);}catch{};process.exit(0);});});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(safeError(e));process.exitCode=1;});
