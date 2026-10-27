import test from 'node:test';
import assert from 'node:assert/strict';
import {nativeServiceUnit} from './lib/native-service-unit.mjs';
import {nativeClockRecoveryUnit} from './lib/native-clock-unit.mjs';
const engine={binary:'/opt/cvpn/engine',config:'/etc/cvpn/client.json',networkUnit:'cvpn-network.service',guardUnit:'cvpn-guard.service',role:'client',clockRecoveryUnit:'cvpn-clock.service'};
const recovery={consumerUnit:'cvpn-client.service',script:'/opt/cvpn/clock.py',config:'/etc/cvpn/clock.json',stateDirectory:'/var/lib/cvpn-clock'};
test('only specific native exit codes hand off; time privilege stays out of engine',()=>{
  const a=nativeServiceUnit(engine),b=nativeClockRecoveryUnit(recovery);
  assert.match(a,/OnFailure=cvpn-clock.service\n/);assert.match(a,/--service --clock-recovery\n/);
  assert.match(a,/RestartPreventExitStatus=75 76 77\n/);assert.doesNotMatch(a,/CAP_SYS_TIME|ExecStartPre=.*clock/);
  assert.match(b,/Before=cvpn-client.service\n/);assert.match(b,/ recover --config=/);
  assert.match(b,/CapabilityBoundingSet=CAP_SYS_TIME\n/);assert.match(b,/Restart=no\n/);
  assert.doesNotMatch(b,/WantedBy|ExecStartPre|CAP_NET_ADMIN|CAP_NET_RAW/);
});
test('explicit client opt-in and safe unit/path names are required',()=>{
  for(const change of [{role:'exit'},{role:undefined},{transport:'combo-tls'},{transport:'transparent-tls'},
    {clockRecoveryUnit:engine.guardUnit},{clockRecoveryUnit:'foo.service\nExecStart=id'}])assert.throws(()=>nativeServiceUnit({...engine,...change}));
  for(const field of ['script','config','stateDirectory'])for(const value of ['/a b','/a%p','/a/../b','/a\nExecStart=id'])assert.throws(()=>nativeClockRecoveryUnit({...recovery,[field]:value}));
  assert.throws(()=>nativeClockRecoveryUnit({...recovery,consumerUnit:'bad@.service'}));
  assert.throws(()=>nativeClockRecoveryUnit({...recovery,namespace:'a/b'}));
  assert.match(nativeClockRecoveryUnit({...recovery,namespace:'client'}),/NetworkNamespacePath=\/run\/netns\/client/);
});
