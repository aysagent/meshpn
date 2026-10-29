import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareRuntimeAddress,parseAddressDiscovery,addressBootstrapTables,auditAddressBootstrap} from './lib/native-runtime-address.mjs';
const config={version:1,role:'client',tun:'cvpn0',address:'192.0.2.1',port:3443,dns:true,address_assignment:'v1'};
const offer=ipv4=>JSON.stringify({version:1,event:'address_discovery',status:'verified',assignment:'v1',ipv4});
function fixture(){
 const options={config:structuredClone(config),sourceText:JSON.stringify(config),source:'/config/engine.json',state:'/run/clean-vpn',namespace:'net:[123]',engine:'/engine',plan:{endpoint:'192.0.2.1',port:3443,uplink:'eth0'},backend:'nft',enabled:true};
 const files=new Map([[options.source,options.sourceText]]),tables={4:'*filter\nCOMMIT\n',6:'*filter\nCOMMIT\n'},calls=[];let reply=offer('10.99.0.17'),failAt;
 const io={present:p=>files.has(p),read:p=>{assert.ok(files.has(p));return files.get(p);},write:(p,v,{exclusive=false}={})=>{if(exclusive)assert.ok(!files.has(p));files.set(p,JSON.stringify(v));},run:(cmd,args,body)=>{
  calls.push([cmd,args]);if(failAt===cmd)throw Error('cut');if(cmd==='/engine'){auditAddressBootstrap(addressBootstrapTables(options.plan),tables,{runtimeReady:files.has('/run/clean-vpn/network.json')});return reply;}
  const family=cmd.startsWith('ip6')?6:4;if(cmd.endsWith('save'))return tables[family];
  assert.ok(cmd.endsWith('restore'));tables[family]=body.replaceAll(/^-I (\w+) 1 /gm,'-A $1 ');return'';
 }};
 return{options,files,tables,calls,io,reply:v=>reply=v,fail:v=>failAt=v,run:()=>prepareRuntimeAddress(options,io),ready:()=>{files.set('/run/clean-vpn/network.json',JSON.stringify({namespace:options.namespace,phase:'ready'}));for(const family of [4,6])for(const hook of ['INPUT','OUTPUT','FORWARD'])tables[family]=tables[family].replace('-A '+hook+' -j CVPN_A_',`-A ${hook} -j CVPN_R_${hook}\n-A ${hook} -j CVPN_A_`);}};
}
test('discovery output is exact, bounded and cannot supply routes or caller-selected subnets',()=>{
 assert.equal(parseAddressDiscovery(offer('10.99.0.17')),'10.99.0.17');
 for(const ip of ['10.99.0.1','10.99.0.255','10.99.0.017','192.0.2.1','10.99.0.2/32'])assert.throws(()=>parseAddressDiscovery(offer(ip)));
 for(const text of [offer('10.99.0.2')+'\n{}',offer('10.99.0.2').replace('verified','failed'),'x'.repeat(1025),JSON.stringify({...JSON.parse(offer('10.99.0.2')),gateway:'192.0.2.1'})])assert.throws(()=>parseAddressDiscovery(text));
});
test('fresh discovery installs both guards before network request and returns private effective config',()=>{
 const f=fixture(),result=f.run();assert.equal(result.config.peer_ipv4,'10.99.0.17');assert.equal(f.options.config.peer_ipv4,undefined);assert.equal(f.files.get(f.options.source),f.options.sourceText);
 assert.equal(JSON.parse(f.files.get('/run/clean-vpn/assignment.json')).phase,'verified');result.complete();assert.equal(JSON.parse(f.files.get('/run/clean-vpn/assignment.json')).phase,'complete');
 const rules=Object.values(f.tables).join('\n');assert.ok(!rules.includes('--dport 53'));assert.match(rules,/-d 192\.0\.2\.1\/32 -o eth0 -p tcp --dport 3443/);assert.match(rules,/-A CVPN_A_FORWARD -j DROP/);
});
test('same assignment restarts under both audited guards; reassignment requires namespace recreation',()=>{
 const f=fixture();f.run().complete();f.ready();assert.equal(f.run().config.peer_ipv4,'10.99.0.17');f.reply(offer('10.99.0.18'));assert.throws(()=>f.run(),/assignment_changed_recreate_required/);assert.equal(JSON.parse(f.files.get('/run/clean-vpn/assignment.json')).ipv4,'10.99.0.17');
});
test('crash during guard installation or after discovery never resumes an incomplete namespace',()=>{
 for(const point of ['iptables-nft-restore','/engine',null]){const f=fixture();f.fail(point);if(point)assert.throws(()=>f.run());else f.run();f.fail(null);assert.throws(()=>f.run(),/assignment_interrupted_recreate_required/);}
});
test('source changes, foreign guard, and replaced namespace are refused without adopting stale state',()=>{
 const f=fixture();f.files.set(f.options.source,f.options.sourceText+' ');assert.throws(()=>f.run(),/assignment_source_changed_during_discovery/);
 const g=fixture();g.tables[4]+=':CVPN_A_INPUT - [0:0]\n';assert.throws(()=>g.run(),/assignment_foreign_guard_refused/);assert.equal(g.files.has('/run/clean-vpn/assignment.json'),false);
 const h=fixture();h.run().complete();h.ready();h.options.namespace='net:[456]';assert.throws(()=>h.run(),/assignment_namespace_changed/);
});
test('fixed configurations never perform discovery and explicit opt-in cannot silently fall back',()=>{
 const f=fixture();delete f.options.config.address_assignment;f.options.enabled=false;const r=f.run();assert.deepEqual(r.config,f.options.config);assert.deepEqual(f.calls,[]);
 f.options.enabled=true;assert.throws(()=>f.run(),/assignment_opt_in_mismatch/);
 const g=fixture();g.options.enabled=false;assert.throws(()=>g.run(),/assignment_explicit_runtime_opt_in_required/);
 const h=fixture();h.options.config.peer_ipv4='10.99.0.2';assert.throws(()=>h.run(),/assignment_source_must_omit_fixed_ipv4/);
});
