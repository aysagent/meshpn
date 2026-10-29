// Exit identities and offline enrollment. No payload, host routes or CA rotation.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {isIPv4} from 'node:net';
const uid=()=>process.getuid();
const fail=(ok,code)=>assert.ok(ok,code);
export const clientName=n=>typeof n==='string'&&/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(n);
const ip=n=>typeof n==='string'&&/^10\.99\.0\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(n);
const sha=b=>createHash('sha256').update(b).digest('hex');
const encode=v=>Buffer.from(JSON.stringify(v,null,2)+'\n');
const exists=p=>{try{fs.lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
function boundedRead(fd,limit){const b=Buffer.alloc(limit+1);let n=0,k;while(n<b.length&&(k=fs.readSync(fd,b,n,b.length-n,null))>0)n+=k;fail(n<=limit,'client_file_limit');return b.subarray(0,n);}
function trustedPath(p,{directory=false}={}){
 fail(path.isAbsolute(p)&&path.normalize(p)===p,'client_path_absolute');
 for(let q=directory?p:path.dirname(p);;q=path.dirname(q)){
  const s=fs.lstatSync(q);fail(s.isDirectory()&&!s.isSymbolicLink()&&[0,uid()].includes(s.uid)&&(!(s.mode&0o022)||(s.mode&0o1000)),'client_untrusted_parent');
  if(q==='/')break;
 }
}
export function readClientPrivate(p,limit=262144){
 trustedPath(p);const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const s=fs.fstatSync(fd);fail(s.isFile()&&s.uid===uid()&&s.nlink===1&&!(s.mode&0o077)&&s.size<=limit,'client_private_file');return boundedRead(fd,limit);}finally{fs.closeSync(fd);}
}
function readPublic(p,limit=32768){trustedPath(p);const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const s=fs.fstatSync(fd);fail(s.isFile()&&s.size<=limit&&[0,uid()].includes(s.uid)&&!(s.mode&0o022),'client_public_file');return boundedRead(fd,limit);}finally{fs.closeSync(fd);}}
function syncDir(dir){const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function fresh(p,b){trustedPath(p);const fd=fs.openSync(p,'wx',0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDir(path.dirname(p));}
function atomic(p,b){const tmp=p+'.'+randomBytes(12).toString('hex');fresh(tmp,b);try{fs.renameSync(tmp,p);syncDir(path.dirname(p));}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}}
function packet(c){return c.transport==='combo-tls'?c.boring:c;}
function validateRegistry(r){
 fail(r?.version===1&&Number.isSafeInteger(r.revision)&&r.revision>=0&&typeof r.configPath==='string'&&/^[a-f0-9]{64}$/.test(r.configSha256),'client_registry');
 fail(Array.isArray(r.clients)&&r.clients.length<=253,'client_registry_limit');const names=new Set(),ips=new Set();
 for(const c of r.clients){fail(clientName(c.name)&&ip(c.ipv4)&&typeof c.revoked==='boolean'&&path.isAbsolute(c.secret_path),'client_registry_entry');fail(!names.has(c.name)&&!ips.has(c.ipv4),'client_registry_duplicate');names.add(c.name);ips.add(c.ipv4);if(c.relay)fail(clientName(c.relay.id)&&path.isAbsolute(c.relay.secret_path),'client_registry_relay');}
 fail(r.clients.filter(c=>!c.revoked).length<=32,'client_active_limit');return r;
}
export class NativeClientManager {
 constructor({directory,validateConfig,applyConfig,initializeRelay,beforeMutation}={}){fail(typeof directory==='string'&&path.isAbsolute(directory),'client_directory');this.directory=directory;this.registryPath=directory+'/registry.json';this.journalPath=directory+'/transaction.json';this.validateConfig=validateConfig;this.applyConfig=applyConfig;this.initializeRelay=initializeRelay;this.beforeMutation=beforeMutation;}
 async locked(fn,{pending=false}={}){
  trustedPath(this.directory,{directory:true});const st=fs.lstatSync(this.directory);fail(st.uid===uid()&&!(st.mode&0o077),'client_directory_private');
  // flock lives on the inherited open-file description: the parent retains it
  // after the short helper exits, and kernel releases it on crash/SIGKILL.
  const lock=fs.openSync(this.directory+'/lock',fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK,0o600);
  try{const s=fs.fstatSync(lock);fail(s.isFile()&&s.uid===uid()&&s.nlink===1&&!(s.mode&0o077),'client_lock_file');
   try{if(process.platform==='linux')execFileSync('flock',['-n','3'],{stdio:['ignore','pipe','pipe',lock],timeout:5000});
    else execFileSync('python3',['-c','import fcntl; fcntl.flock(3,fcntl.LOCK_EX|fcntl.LOCK_NB)'],{stdio:['ignore','pipe','pipe',lock],timeout:5000});
   }catch{throw Error('client_manager_locked');}
   if(!pending)fail(!exists(this.journalPath),'client_recovery_required');return await fn();
  }finally{fs.closeSync(lock);}
 }
 load(){return validateRegistry(JSON.parse(readClientPrivate(this.registryPath)));}
 config(r){const b=readClientPrivate(r.configPath,16384);fail(sha(b)===r.configSha256,'client_config_changed_externally');return JSON.parse(b);}
 async init({configPath,endpoint,serverName,caPath,profilePath,relayMap,management}={}){
  trustedPath(this.directory);fs.mkdirSync(this.directory,{mode:0o700});
  return this.locked(async()=>{
   fail(typeof this.validateConfig==='function','client_validator_required');
   const raw=readClientPrivate(configPath,16384),c=JSON.parse(raw),p=packet(c);fail(p.role==='exit'&&(!c.transport||c.transport==='boring-tls'||c.transport==='combo-tls'),'client_exit_required');
   fail(typeof endpoint==='string'&&isIPv4(endpoint),'client_endpoint');
   fail(typeof serverName==='string'&&/^[a-zA-Z0-9.-]{1,253}$/.test(serverName),'client_server_name');readPublic(caPath);if(profilePath)JSON.parse(readPublic(profilePath,16384));
   await this.validateConfig(configPath);
   const peers=p.peers??[{ipv4:p.peer_ipv4??'10.99.0.2',secret_path:p.secret_path}];
   if(c.transport==='combo-tls'){
    fail(Array.isArray(c.transparent.peers)&&c.transparent.peers.length===peers.length,'client_combo_named_peers_required');
    fail(relayMap&&typeof relayMap==='object'&&!Array.isArray(relayMap)&&Object.keys(relayMap).length===peers.length&&new Set(Object.values(relayMap)).size===peers.length&&peers.every(p=>c.transparent.peers.some(x=>x.id===relayMap[p.ipv4])),'client_combo_identity_map_required');
   }
   const clients=peers.map(peer=>({name:'client-'+peer.ipv4.split('.').at(-1),ipv4:peer.ipv4,secret_path:peer.secret_path,revoked:false,...(c.transport==='combo-tls'?{relay:{...c.transparent.peers.find(x=>x.id===relayMap[peer.ipv4])}}:{})}));
   for(const peer of clients){fail(readClientPrivate(peer.secret_path,32).length===32,'client_key_length');if(peer.relay)fail(readClientPrivate(peer.relay.secret_path,32).length===32,'client_key_length');}
   if(management)fail(path.isAbsolute(management.engine)&&(!management.unit||/^[a-zA-Z0-9_-]+\.service$/.test(management.unit)),'client_management');
   const r=validateRegistry({version:1,revision:0,configPath,configSha256:sha(raw),endpoint,serverName,caPath,profilePath:profilePath??null,...(management?{management}:{}),clients});fs.mkdirSync(this.directory+'/keys',{mode:0o700});fresh(this.registryPath,encode(r));return this.public(r);
  });
 }
 public(r){return{version:1,revision:r.revision,zone:'mpn',clients:r.clients.map(c=>({name:c.name,hostname:c.name+'.mpn',ipv4:c.ipv4,revoked:c.revoked,connectionState:'unknown'}))};}
 async list(){return this.locked(async()=>{const r=this.load();this.config(r);return this.public(r);});}
 newKey(){const p=this.directory+'/keys/'+randomBytes(16).toString('hex')+'.psk';fresh(p,randomBytes(32));return p;}
 async mutate(change){return this.locked(async()=>{
  const old=this.load(),config=this.config(old),next=structuredClone(old),beforeConfig=readClientPrivate(old.configPath,16384),beforeRegistry=readClientPrivate(this.registryPath);
  if(this.beforeMutation)await this.beforeMutation({configPath:old.configPath});
  await change(next,config);next.revision++;validateRegistry(next);const p=packet(config),active=next.clients.filter(c=>!c.revoked);
  p.peers=active.map(c=>({ipv4:c.ipv4,secret_path:c.secret_path}));delete p.peer_ipv4;delete p.secret_path;
  if(config.transport==='combo-tls')config.transparent.peers=active.map(c=>({...c.relay}));
  const afterConfig=encode(config);fail(afterConfig.length<=16384,'client_config_size');next.configSha256=sha(afterConfig);const afterRegistry=encode(next);
  const candidate=this.directory+'/candidate-'+randomBytes(8).toString('hex')+'.json';fresh(candidate,afterConfig);
  try{fail(typeof this.validateConfig==='function','client_validator_required');await this.validateConfig(candidate);}finally{fs.unlinkSync(candidate);}
  fail(sha(readClientPrivate(old.configPath,16384))===sha(beforeConfig)&&sha(readClientPrivate(this.registryPath))===sha(beforeRegistry),'client_config_changed_externally');
  // Write-ahead exact images: recovery never overwrites an unrelated edit.
  const j={version:1,configPath:old.configPath,beforeConfig:beforeConfig.toString('base64'),afterConfig:afterConfig.toString('base64'),beforeRegistry:beforeRegistry.toString('base64'),afterRegistry:afterRegistry.toString('base64')};fresh(this.journalPath,encode(j));
  try{atomic(old.configPath,afterConfig);atomic(this.registryPath,afterRegistry);if(this.applyConfig)await this.applyConfig({configPath:old.configPath,sha256:next.configSha256,revision:next.revision});}
  catch(error){try{await this.rollback(j);}catch{throw Error('client_recovery_required');}throw error;}
  // Removing the marker publishes the committed registry to DNS readers.
  // A following directory-fsync error cannot justify an unmarked rollback.
  try{fs.unlinkSync(this.journalPath);syncDir(this.directory);}catch{throw Error('client_commit_durability_uncertain');}
  return{...this.public(next),applied:!!this.applyConfig,requiresReload:!this.applyConfig};
 });}
 async rollback(j){
  fail(j.version===1&&typeof j.configPath==='string','client_journal');const before=Buffer.from(j.beforeConfig,'base64'),after=Buffer.from(j.afterConfig,'base64'),br=Buffer.from(j.beforeRegistry,'base64'),ar=Buffer.from(j.afterRegistry,'base64');
  const previous=validateRegistry(JSON.parse(br)),future=validateRegistry(JSON.parse(ar));fail(previous.configPath===j.configPath&&future.configPath===j.configPath&&previous.configSha256===sha(before)&&future.configSha256===sha(after),'client_journal_integrity');
  if(this.beforeMutation)await this.beforeMutation({configPath:j.configPath});
  const now=readClientPrivate(j.configPath,16384),registry=readClientPrivate(this.registryPath);fail([sha(before),sha(after)].includes(sha(now))&&[sha(br),sha(ar)].includes(sha(registry)),'client_recovery_conflict');
  atomic(j.configPath,before);atomic(this.registryPath,br);if(this.applyConfig)await this.applyConfig({configPath:j.configPath,sha256:sha(before),revision:previous.revision,rollback:true});fs.unlinkSync(this.journalPath);syncDir(this.directory);
 }
 async recover(){return this.locked(async()=>{if(!exists(this.journalPath))return{recovered:false};await this.rollback(JSON.parse(readClientPrivate(this.journalPath,1048576)));return{recovered:true};},{pending:true});}
 async add(name){fail(clientName(name),'client_name');return this.mutate(async(r,c)=>{
  fail(!r.clients.some(x=>x.name===name),'client_name_exists');fail(r.clients.filter(x=>!x.revoked).length<32,'client_active_limit');const used=new Set(r.clients.map(x=>x.ipv4));let address;for(let i=2;i<=254;i++)if(!used.has('10.99.0.'+i)){address='10.99.0.'+i;break;}fail(address,'client_pool_exhausted');
  const peer={name,ipv4:address,secret_path:this.newKey(),revoked:false};if(c.transport==='combo-tls'){fail(this.initializeRelay,'client_replay_initializer_required');peer.relay={id:'peer-'+randomBytes(12).toString('hex'),secret_path:this.newKey()};await this.initializeRelay({...c.transparent,peers:[peer.relay]});}r.clients.push(peer);
 });}
 async revoke(name){return this.mutate(r=>{const p=r.clients.find(x=>x.name===name);fail(p,'client_not_found');p.revoked=true;});}
 async rename(name,newName){fail(clientName(newName),'client_name');return this.mutate(r=>{const p=r.clients.find(x=>x.name===name);fail(p,'client_not_found');fail(!r.clients.some(x=>x.name===newName&&x!==p),'client_name_exists');p.name=newName;});}
 async rotate(name){return this.mutate(async(r,c)=>{const p=r.clients.find(x=>x.name===name&&!x.revoked);fail(p,'client_not_found');p.secret_path=this.newKey();if(p.relay){fail(this.initializeRelay,'client_replay_initializer_required');p.relay={id:'peer-'+randomBytes(12).toString('hex'),secret_path:this.newKey()};await this.initializeRelay({...c.transparent,peers:[p.relay]});}});}
 async export(name){return this.locked(async()=>{
  const r=this.load(),c=this.config(r),p=r.clients.find(x=>x.name===name&&!x.revoked);fail(p,'client_not_found');const server=packet(c);
  const files={'psk':readClientPrivate(p.secret_path,32).toString('base64'),'ca.pem':readPublic(r.caPath).toString('base64')};
  const client={version:1,role:'client',tun:'cvpn0',address:r.endpoint,port:server.port,server_name:r.serverName,ca:'@bundle/ca.pem',secret_path:'@bundle/psk',peer_ipv4:p.ipv4,dns:true,http_version:'auto'};
  if(r.profilePath){files['profile.json']=readPublic(r.profilePath,16384).toString('base64');client.tls_profile_path='@bundle/profile.json';}
  let config=client;if(p.relay){files['relay.psk']=readClientPrivate(p.relay.secret_path,32).toString('base64');client.sni=c.transparent.public_name;config={version:1,role:'client',transport:'combo-tls',boring:client,transparent:{version:1,role:'client',transport:'transparent-tls',public_name:c.transparent.public_name,secret_path:'@bundle/relay.psk',listen:{ipv4:'0.0.0.0',port:10443},exit:{ipv4:r.endpoint,port:server.port},limits:c.transparent.limits,destination_policy:c.transparent.destination_policy}};}
  return{version:1,kind:'clean-vpn-client-enrollment',name:p.name,hostname:p.name+'.mpn',ipv4:p.ipv4,config,files};
 });}
}
export async function importClientBundle(bundle,directory,{validateConfig}={}){
 fail(bundle?.version===1&&bundle.kind==='clean-vpn-client-enrollment'&&clientName(bundle.name)&&ip(bundle.ipv4),'client_bundle');
 fail(typeof validateConfig==='function','client_validator_required');trustedPath(directory);fail(bundle.files&&Object.keys(bundle.files).length<=4&&Object.keys(bundle.files).every(n=>['psk','relay.psk','ca.pem','profile.json'].includes(n)),'client_bundle_files');
 const files={};for(const[n,b]of Object.entries(bundle.files)){fail(typeof b==='string'&&b.length<=65536&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b),'client_bundle_encoding');files[n]=Buffer.from(b,'base64');if(n.endsWith('psk'))fail(files[n].length===32,'client_key_length');}
 fail(files.psk&&files['ca.pem'],'client_bundle_required');
 const c=structuredClone(bundle.config),p=packet(c);fail(p.role==='client'&&p.peer_ipv4===bundle.ipv4,'client_bundle_role');if(c.transport)fail(c.transport==='combo-tls'&&c.role==='client'&&c.transparent?.role==='client','client_bundle_transport');
 // Only known credential fields may reference bundle paths. Never accept a host path.
 const rewrite=(o,k,n)=>{fail(o[k]==='@bundle/'+n&&files[n],'client_bundle_path');o[k]=directory+'/'+n;};rewrite(p,'secret_path','psk');rewrite(p,'ca','ca.pem');if(p.tls_profile_path)rewrite(p,'tls_profile_path','profile.json');if(c.transport==='combo-tls')rewrite(c.transparent,'secret_path','relay.psk');
 fs.mkdirSync(directory,{mode:0o700});for(const[n,b]of Object.entries(files))fresh(directory+'/'+n,b);fresh(directory+'/engine.json',encode(c));await validateConfig(directory+'/engine.json');return{directory,configPath:directory+'/engine.json',name:bundle.name,ipv4:bundle.ipv4,activated:false};
}
export const writeClientPrivate=fresh;
