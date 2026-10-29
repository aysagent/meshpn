import test from 'node:test';
import assert from 'node:assert/strict';
import {nativeNetworkPlan} from './lib/native-network-profile.mjs';
import {runtimePlan} from './lib/native-runtime-plan.mjs';
import {nativeSitePlan} from './lib/native-site-plan.mjs';
import {nativeExitHostPlan} from './lib/native-exit-host-plan.mjs';
import {nativeExitHostRules} from './lib/native-exit-host-network.mjs';
import {planNativeClients} from './lib/native-client-bundles.mjs';
import {parseRuntimeConfig} from './clean-vpn-native-runtime-config.mjs';
const profile={version:1,role:'exit',tun:'cvpn0',tun_address:'10.99.0.1/24',mtu:1400,uplink:'eth0',endpoint:'192.0.2.1',port:3443,lan:null};
const packet={version:1,role:'exit',tun:'cvpn0',address:'192.0.2.1',port:3443};
const combo=boring=>({version:1,transport:'combo-tls',role:'exit',boring,transparent:{version:1,transport:'transparent-tls',role:'exit',public_name:'relay.example',listen:{ipv4:packet.address,port:3443},destination_policy:{mode:'public-https',deny_ipv4:[]},replay_directory:'/replay'}});
test('dedicated and runtime plans open private DNS only on exit TUN, including combo output rewrite',()=>{
 for(const enabled of [false,true])for(const combined of [false,true]){
  const p={...profile,private_peer_dns:enabled,...(combined?{transport:'combo-tls',listen_port:3443,deny_ipv4:[]}:{})};
  const rules=nativeNetworkPlan(p).ipv4.split('\n').filter(l=>l.includes('1055'));assert.equal(rules.length,enabled?4:0);
  const engine={...packet,private_peer_dns:enabled},r=runtimePlan(combined?combo(engine):engine).tables.flatMap(t=>t.entries.flatMap(e=>e.rules)).filter(l=>l.includes('1055'));assert.equal(r.length,enabled?4:0);
  for(const line of [...rules,...r]){assert.match(line,/(?:-i|-o) cvpn0/);assert.match(line,/10\.99\.0\.1\/32/);assert.ok(!line.includes('eth0'));if(line.includes('--sport'))assert.match(line,/--ctdir REPLY/);}
 }
 assert.throws(()=>nativeNetworkPlan({...profile,role:'client',private_peer_dns:false}));
 assert.throws(()=>runtimePlan({...packet,role:'client',private_peer_dns:false,dns:true}));
 assert.throws(()=>nativeNetworkPlan({...profile,private_peer_dns:'yes'}));
});
test('site requires matching engine/network opt-in and supported native capability',()=>{
 const args={name:'dns',target:'/opt/dns',site:{link_unit:'links.service',profile:{...profile,private_peer_dns:true}},engine:{...packet,private_peer_dns:true},capability:{private_peer_dns:{exit_opt_in:true}}};
 assert.ok(nativeSitePlan(args));assert.throws(()=>nativeSitePlan({...args,capability:{}}),/capability/);
 assert.throws(()=>nativeSitePlan({...args,engine:packet}),/owner_mismatch/);
 assert.throws(()=>nativeSitePlan({...args,site:{...args.site,profile}}),/owner_mismatch/);
});
test('scoped host owner derives flagged rules from exit config; no global policy or public listener exception',()=>{
 const args={name:'dns',target:'/opt/dns',profile:{version:1,uplink:'eth0'},engine:{...packet,tun:'cvexit0',private_peer_dns:true}};
 const plan=nativeExitHostPlan(args),config=JSON.parse(plan.files.get('network.json'));
 assert.equal(config.private_peer_dns,true);const rules=nativeExitHostRules(config,'a'.repeat(24));assert.equal(rules.length,7);
 assert.equal(rules.filter(r=>r.chain==='INPUT').length,2);for(const r of rules.filter(r=>r.chain==='INPUT'))assert.ok(r.spec.includes('cvexit0')&&!r.spec.includes('eth0'));
 assert.equal(nativeExitHostRules({...config,private_peer_dns:false},'b'.repeat(24)).length,3);
});
test('offline manifest passes DNS opt-in only to exit packet and its network owner',()=>{
 const source={version:1,transport:'boring-tls',endpoint:'192.0.2.1',port:3443,server_name:'vpn.example',cert:'/private/cert',key:'/private/key',ca:'/private/ca',deploy_root:'/opt/vpn',private_peer_dns:true,exit:{uplink:'eth0',link_unit:'links.service'},clients:[{name:'laptop',ipv4:'10.99.0.2',uplink:'eth0',link_unit:'links.service'}]};
 for(const transport of ['boring-tls','combo-tls']){const input={...source,transport,...(transport==='combo-tls'?{public_name:'relay.example',clients:[{...source.clients[0],lan:{interface:'usb0',subnet:'192.168.7.0/24'}}]}:{})},p=planNativeClients(input);assert.equal((p.exit.config.boring??p.exit.config).private_peer_dns,true);assert.equal(p.exit.site.profile.private_peer_dns,true);assert.ok(!('private_peer_dns' in(p.clients[0].config.boring??p.clients[0].config)));}
 const o=parseRuntimeConfig(['create','--mode=standalone','--directory=/tmp/dns-new','--endpoint=192.0.2.1','--exit-address=192.0.2.1','--server-name=vpn.example','--private-peer-dns']);assert.equal(o.privatePeerDns,true);
});
