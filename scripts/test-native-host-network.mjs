import test from 'node:test';
import assert from 'node:assert/strict';
import {validateNativeHostConfig,nativeHostNatPlan} from './lib/native-host-network.mjs';
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
  assert.match(unit,/KillMode=control-group/);assert.doesNotMatch(unit,/clean-vpn\.service|flush|CAP_SYS_TIME/);
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
