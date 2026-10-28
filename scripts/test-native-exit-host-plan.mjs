import test from 'node:test';
import assert from 'node:assert/strict';
import {nativeExitHostPlan} from './lib/native-exit-host-plan.mjs';
import {nativeServiceUnit} from './lib/native-service-unit.mjs';
const input={name:'exit',target:'/opt/clean-vpn-native/exit',profile:{version:1,uplink:'eth0'},engine:{role:'exit',address:'192.0.2.1',port:443,tun:'cvexit0'}};
test('scoped exit uses its own disabled network activation and NVM Node',()=>{
  const p=nativeExitHostPlan({...input,node:'/root/.nvm/versions/node/v24/bin/node'});
  assert.equal(p.activation,'native-exit-network.service');assert.deepEqual(p.dependencies,[]);
  const body=p.units.get(p.network);assert.match(body,/ExecStopPost=.* recover/);assert.match(body,/KillMode=mixed/);
  assert.match(body,/ExecStart=\/root\/\.nvm/);assert.doesNotMatch(body,/network-online|ip_forward|iptables-restore/);
});
test('one scoped protection dependency is exit-only and explicit',()=>{
  const base={binary:'/opt/engine',config:'/opt/config.json',networkUnit:'owner.service',guardUnit:'owner.service'};
  assert.throws(()=>nativeServiceUnit(base),/distinct_dependencies/);
  assert.throws(()=>nativeServiceUnit({...base,role:'client',scopedExit:true}),/scoped_exit_only/);
  assert.throws(()=>nativeServiceUnit({...base,role:'exit',transport:'combo-tls',scopedExit:true}),/scoped_exit_only/);
  assert.match(nativeServiceUnit({...base,role:'exit',scopedExit:true}),/BindsTo=owner.service\n/);
});
test('exit host profile rejects client, relay and unbounded TUN names',()=>{
  for(const engine of [{...input.engine,role:'client'},{...input.engine,transport:'transparent-tls'},{...input.engine,tun:'eth0'}])assert.throws(()=>nativeExitHostPlan({...input,engine}));
  assert.throws(()=>nativeExitHostPlan({...input,profile:{...input.profile,forwarding:true}}));
});
