import test from 'node:test';
import assert from 'node:assert/strict';
import {validateNativeHostConfig,nativeHostNatPlan,nativeHostNetwork} from './lib/native-host-network.mjs';
import {nativeHostUnit} from './lib/native-host-unit.mjs';
const profile={version:1,exit_ip:'154.62.226.216',engine_unit:'native-daily.service',network_unit:'native-daily-network.service',guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'};
test('fixed host profile rejects ambiguous dependencies and executable injection',()=>{
  assert.deepEqual(validateNativeHostConfig(profile),profile);
  for(const c of [{...profile,extra:true},{...profile,version:2},{...profile,exit_ip:'127.0.0.1'},
    {...profile,guard_unit:profile.engine_unit},{...profile,engine_unit:'a;reboot.service'},
    {...profile,guard_script:'/tmp/guard.sh'},{...profile,guard_script:'/usr/local/bin/../evil'}])assert.throws(()=>validateNativeHostConfig(c));
});
test('network owner has independent cleanup and no legacy activation',()=>{
  const unit=nativeHostUnit({script:'/opt/clean-vpn-native/daily/control/clean-vpn-native-host-network.mjs',config:'/opt/clean-vpn-native/daily/network.json',profile});
  assert.match(unit,/ExecStopPost=.* recover --config=/);assert.match(unit,/BindsTo=clean-vpn-killswitch.service/);
  assert.match(unit,/KillMode=mixed/);assert.doesNotMatch(unit,/clean-vpn\.service|flush|CAP_SYS_TIME|network-online/);
  assert.throws(()=>nativeHostUnit({script:'/x/../y',config:'/config',profile}));
  const nvm=nativeHostUnit({script:'/opt/owner.mjs',config:'/opt/config.json',profile,node:'/root/.nvm/versions/node/v24.13.0/bin/node'});
  assert.match(nvm,/ExecStopPost=\/root\/\.nvm\/versions\/node\/v24.13.0\/bin\/node /);
  assert.match(nvm,/ProtectHome=read-only/);
});
test('translation is restricted to USB peer IPv4 and TUN, with bounded MSS',()=>{
  const plan=nativeHostNatPlan('a'.repeat(24));assert.equal(plan.length,3);
  assert.ok(plan.every(o=>!['filter','INPUT','OUTPUT'].includes(o.table)));
  assert.equal(plan[2].table,'nat');assert.deepEqual(plan[2].spec.slice(-4),['-j','SNAT','--to-source','10.99.0.2']);
  assert.ok(plan.slice(0,2).every(o=>o.spec.at(-1)==='1360'));assert.throws(()=>nativeHostNatPlan('bad'));
});

test('host peer identity is bounded to the native pool and controls USB SNAT',()=>{
  for(const peer_ipv4 of ['10.99.0.2','10.99.0.37','10.99.0.254']){
    assert.equal(validateNativeHostConfig({...profile,peer_ipv4}).peer_ipv4,peer_ipv4);
    assert.equal(nativeHostNatPlan('a'.repeat(24),peer_ipv4)[2].spec.at(-1),peer_ipv4);
  }
  for(const peer_ipv4 of ['10.99.0.0','10.99.0.1','10.99.0.255','10.100.0.2','::1','10.99.0.02',null]){
    assert.throws(()=>validateNativeHostConfig({...profile,peer_ipv4}));
    assert.throws(()=>nativeHostNatPlan('a'.repeat(24),peer_ipv4));
  }
});

test('non-default peer refuses a stale guard before any network operation',()=>{
  for(const answer of ['{}','{"native_peer_dns":false}','old helper usage']){
    const calls=[];
    const owner=nativeHostNetwork({...profile,peer_ipv4:'10.99.0.37'},{run:(file,args)=>{calls.push([file,args]);return answer;}});
    assert.throws(()=>owner.preflight());
    assert.deepEqual(calls,[[profile.guard_script,['capabilities']]]);
  }
});

test('incoming grant is one exit source and TCP port; peer interface and replies stay constrained',()=>{
  const incoming_tcp={source_ipv4:'10.99.0.1',port:9443};
  validateNativeHostConfig({...profile,incoming_tcp});
  for(const patch of [{source_ipv4:'0.0.0.0/0'},{source_ipv4:'10.99.0.37'},{port:22},{port:1053},{port:65536},{port:'9443'},{extra:true}])
    assert.throws(()=>validateNativeHostConfig({...profile,incoming_tcp:{...incoming_tcp,...patch}}));
  const plan=nativeHostNatPlan('a'.repeat(24),'10.99.0.37',incoming_tcp);
  assert.equal(plan.length,7);assert.ok(plan.slice(3).every(o=>o.table==='filter'&&o.chain==='INPUT'));
  assert.ok(plan[5].spec.includes('10.99.0.37/32'));assert.ok(plan[5].spec.includes('10.99.0.1/32'));
  assert.equal(plan[3].spec.at(-1),'DROP');assert.equal(plan[4].spec.at(-1),'DROP');
  assert.throws(()=>validateNativeHostConfig({...profile,incoming_tcp,combo_redirect:{interface:'usb0',subnet:'192.168.7.0/24',endpoint:profile.exit_ip,listen_port:9443,deny_ipv4:[]}}),/native_incoming_relay_port_conflict/);
});
