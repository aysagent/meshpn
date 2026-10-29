// Opt-in address bootstrap for a fresh isolated runtime, never the host owner.
// Failure leaves the bootstrap guard in place; interrupted setup requires a
// recreated namespace. No stale-address fallback or live route replacement.
import fs from 'node:fs';
import {createHash,randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {isIPv4} from 'node:net';
import {restoreTable,runtimePacketConfig} from './native-runtime-plan.mjs';
const digest=s=>createHash('sha256').update(s).digest('hex');
const exists=p=>{try{fs.lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
function privateRead(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const s=fs.fstatSync(fd);assert.ok(s.isFile()&&s.uid===0&&s.nlink===1&&!(s.mode&0o077)&&s.size<=32768,'assignment_private_file');const b=Buffer.alloc(32769);let n=0,k;while(n<b.length&&(k=fs.readSync(fd,b,n,b.length-n,null))>0)n+=k;assert.ok(n<=32768,'assignment_file_limit');return b.subarray(0,n).toString();}finally{fs.closeSync(fd);}}
function persist(file,value,{exclusive=false}={}){const temporary=file+'.'+randomBytes(8).toString('hex');const fd=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}try{if(exclusive){fs.linkSync(temporary,file);fs.unlinkSync(temporary);}else fs.renameSync(temporary,file);const d=fs.openSync(file.slice(0,file.lastIndexOf('/')),'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}finally{if(exists(temporary))fs.unlinkSync(temporary);}}
const canonical=s=>s.replace(/ -m (tcp|udp)(?= |$)/g,'').replace(/--ctstate ([A-Z,]+)/g,(_,s)=>'--ctstate '+s.split(',').sort().join(',')).trim();
export function addressBootstrapTables({endpoint,port,uplink}){
 assert.match(uplink,/^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/);assert.ok(isIPv4(endpoint)&&!/^(0|127|10\.99\.0)\./.test(endpoint)&&Number(endpoint.split('.')[0])<224);assert.notEqual(uplink,'lo');assert.ok(Number.isInteger(port)&&port>=1&&port<=65535);
 const make=(family,rules)=>({family,name:'filter',entries:['INPUT','OUTPUT','FORWARD'].map(hook=>({hook,chain:'CVPN_A_'+hook,rules:[...(rules[hook]??[]),'-j DROP']}))});
 return[
  make(6,{INPUT:['-i lo -j ACCEPT'],OUTPUT:['-o lo -j ACCEPT']}),
  make(4,{INPUT:['-i lo -j ACCEPT',`-s ${endpoint}/32 -i ${uplink} -p tcp --sport ${port} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT`],OUTPUT:['-o lo -j ACCEPT',`-d ${endpoint}/32 -o ${uplink} -p tcp --dport ${port} -j ACCEPT`]}),
 ];
}
export function auditAddressBootstrap(tables,saved,{runtimeReady=false}={}){
 for(const t of tables){const lines=saved[t.family].split('\n').map(canonical);for(const e of t.entries){
  assert.deepEqual(lines.filter(l=>l.startsWith('-A '+e.chain+' ')),e.rules.map(r=>canonical('-A '+e.chain+' '+r)),'assignment_guard_changed');
  const jump='-A '+e.hook+' -j '+e.chain;assert.equal(lines.filter(l=>l.endsWith('-j '+e.chain)).length,1,'assignment_guard_jump_changed');
  const hooks=lines.filter(l=>l.startsWith('-A '+e.hook+' '));
  if(runtimeReady){assert.equal(hooks[0],'-A '+e.hook+' -j CVPN_R_'+e.hook,'assignment_runtime_guard_not_first');assert.equal(hooks[1],jump,'assignment_bootstrap_guard_order');}
  else assert.equal(hooks[0],jump,'assignment_guard_not_first');
 }}
}
export function parseAddressDiscovery(text){
 assert.ok(typeof text==='string'&&Buffer.byteLength(text)<=1024,'assignment_discovery_output');
 const value=JSON.parse(text);assert.deepEqual(Object.keys(value).sort(),['assignment','event','ipv4','status','version']);
 assert.equal(value.version,1);assert.equal(value.event,'address_discovery');assert.equal(value.status,'verified');assert.equal(value.assignment,'v1');
 assert.match(value.ipv4,/^10\.99\.0\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/,'assignment_ipv4');return value.ipv4;
}
export function prepareRuntimeAddress({config,sourceText,source,state,namespace,engine,plan,backend,enabled}, {run,read=privateRead,write=persist,present=exists}={}){
 const packet=runtimePacketConfig(config),file=state+'/assignment.json';
 if(packet.address_assignment===undefined){assert.ok(!enabled&&!present(file),'assignment_opt_in_mismatch');return{config,sourceText,complete:()=>{}};}
 assert.ok(enabled,'assignment_explicit_runtime_opt_in_required');assert.equal(packet.role,'client');assert.equal(packet.address_assignment,'v1');assert.equal(packet.peer_ipv4,undefined,'assignment_source_must_omit_fixed_ipv4');
 const tables=addressBootstrapTables(plan),command=(family,op)=>`${family===6?'ip6tables':'iptables'}-${backend}-${op}`;
 const saved=()=>Object.fromEntries(tables.map(t=>[t.family,run(command(t.family,'save'),['-t','filter'])]));
 const sourceSha256=digest(sourceText);let previous=null;
 assert.equal(digest(read(source)),sourceSha256,'assignment_source_changed_during_discovery');
 if(present(file)){
  previous=JSON.parse(read(file));assert.deepEqual(Object.keys(previous).sort(),['ipv4','namespace','phase','sourceSha256','version']);
  assert.equal(previous.version,1);assert.equal(previous.namespace,namespace,'assignment_namespace_changed');assert.equal(previous.sourceSha256,sourceSha256,'assignment_source_changed_recreate_required');assert.equal(previous.phase,'complete','assignment_interrupted_recreate_required');
  const network=JSON.parse(read(state+'/network.json'));assert.equal(network.namespace,namespace);assert.equal(network.phase,'ready','assignment_network_not_ready');
  auditAddressBootstrap(tables,saved(),{runtimeReady:true});
 }else{
  assert.ok(!present(state+'/network.json'),'assignment_existing_network_refused');
  assert.ok(Object.values(saved()).every(s=>!s.includes('CVPN_A_')&&!s.includes('CVPN_R_')),'assignment_foreign_guard_refused');
  write(file,{version:1,namespace,sourceSha256,phase:'preparing',ipv4:null},{exclusive:true});
  for(const t of tables)run(command(t.family,'restore'),['--wait','5','--noflush'],restoreTable(t));
  auditAddressBootstrap(tables,saved());
 }
 // Always reconfirm authority before restart, but never change an existing
 // namespace's address. The full TLS session repeats a separate purpose proof.
 let output;try{output=run(engine,['--discover-address',source]);}catch{throw Error('assignment_discovery_failed');}
 const ipv4=parseAddressDiscovery(output);assert.equal(digest(read(source)),sourceSha256,'assignment_source_changed_during_discovery');
 if(previous)assert.equal(ipv4,previous.ipv4,'assignment_changed_recreate_required');
 const effective=structuredClone(config);runtimePacketConfig(effective).peer_ipv4=ipv4;
 if(!previous)write(file,{version:1,namespace,sourceSha256,phase:'verified',ipv4});
 return{config:effective,sourceText:JSON.stringify(effective)+'\n',complete:()=>write(file,{version:1,namespace,sourceSha256,phase:'complete',ipv4})};
}
