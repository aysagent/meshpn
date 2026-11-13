import test from 'node:test';
import assert from 'node:assert/strict';
import {validateNativeHostConfig,validateNativeTailscalePolicy,nativeHostNatPlan} from './lib/native-host-network.mjs';
import {nativeHostPlan} from './lib/native-host-plan.mjs';
const base=[{priority:0,src:'all',table:'255'},{priority:32766,src:'all',table:'254'},{priority:32767,src:'all',table:'253'}];
const ts=[{priority:5210,src:'all',fwmark:'0x80000',fwmask:'0xff0000',table:'254'},
 {priority:5230,src:'all',fwmark:'0x80000',fwmask:'0xff0000',table:'253'},
 {priority:5250,src:'all',fwmark:'0x80000',fwmask:'0xff0000',action:'7'},
 {priority:5270,src:'all',table:'52'}];
const rules=[...base,...ts].sort((a,b)=>a.priority-b.priority);
const prefs={NetfilterMode:0,CorpDNS:false,RouteAll:false,ExitNodeID:'',ExitNodeIP:'',AdvertiseRoutes:null};
const route={table:'52',dst:'100.92.1.2',dev:'tailscale0',scope:'link',flags:[]};
test('tailnet coexistence admits exact routing and host-only preferences',()=>{
 validateNativeTailscalePolicy(rules,[route],prefs);
 validateNativeTailscalePolicy(base,[],prefs); // stopped / starting daemon
 validateNativeTailscalePolicy(rules,[],prefs); // unauthenticated daemon
 const dns=['1.1.1.1','8.8.8.8'].map((dst,i)=>({priority:10996+i,src:'10.99.0.37',dst,table:'19998'}));
 validateNativeTailscalePolicy([...rules,...dns].sort((a,b)=>a.priority-b.priority),[route],prefs,{active:true,peer:'10.99.0.37'});
 assert.throws(()=>validateNativeTailscalePolicy([...rules,...dns].sort((a,b)=>a.priority-b.priority),[],prefs,{active:true}));
});
test('exit routes, DNS takeover and foreign rule variants stay refused',()=>{
 for(const patch of [{NetfilterMode:2},{CorpDNS:true},{RouteAll:true},{ExitNodeIP:'100.64.0.1'},{ExitNodeID:'x'},{AdvertiseRoutes:['0.0.0.0/0']},{AppConnector:{Advertise:true}}])
  assert.throws(()=>validateNativeTailscalePolicy(rules,[],{...prefs,...patch}));
 for(const changed of [rules.slice(1),[...rules,ts[0]],rules.map(r=>r.priority===5270?{...r,table:'99'}:r),rules.map(r=>r.priority===5210?{...r,fwmark:'0x0'}:r)])
  assert.throws(()=>validateNativeTailscalePolicy(changed,[],prefs));
 for(const patch of [{dst:'default'},{dst:'0.0.0.0/1'},{dst:'100.64.0.0/9'},{dst:'100.128.0.1'},{dst:'1.1.1.1'},{dst:'192.168.8.0/24'},{dev:'wlan0'},{gateway:'192.168.1.1'},{type:'local'},{nexthops:[]},{encap:{}}])
  assert.throws(()=>validateNativeTailscalePolicy(rules,[{...route,...patch}],prefs));
});
test('overlay grants only host OUTPUT; USB/overlay forwarding never gains ACCEPT',()=>{
 const c={version:1,exit_ip:'84.201.14.124',engine_unit:'native-client.service',network_unit:'native-client-network.service',guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh',tailscale:true};
 validateNativeHostConfig(c);
 for(const tailscale of [false,'true',{},null])assert.throws(()=>validateNativeHostConfig({...c,tailscale}));
 const rules=nativeHostNatPlan('a'.repeat(24),'10.99.0.2',undefined,c).filter(r=>r.table==='filter');
 assert.equal(rules.length,5);
 assert.deepEqual(rules.filter(r=>r.spec.at(-1)==='ACCEPT').map(r=>r.chain),['OUTPUT']);
 assert.ok(rules[0].spec.includes('0x80000/0xff0000')&&rules[0].spec.includes('10.99.0.2/32')&&rules[0].spec.includes('REJECT'));
 assert.ok(rules[1].spec.includes('tailscale0')&&rules[1].spec.includes('100.64.0.0/10'));
 assert.ok(rules.filter(r=>r.chain==='FORWARD').every(r=>r.spec.at(-1)==='DROP'));
});
test('host installer carries explicit tailnet opt-in into persistent network configuration',()=>{
 const plan=nativeHostPlan({name:'test',target:'/opt/clean-vpn-native/test',profile:{version:1,guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh',tailscale:true},
  engine:{role:'client',transport:'boring-tls',tun:'tun0',dns:true,address:'84.201.14.124'},capability:{dns_socket_mark:'0x43564e'}});
 assert.equal(JSON.parse(plan.files.get('network.json')).tailscale,true);
});
