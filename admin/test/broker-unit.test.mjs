import test from 'node:test';
import assert from 'node:assert/strict';
import {brokerWritablePaths,upgradeBrokerUnit,verifyLegacyBrokerBinding} from '../lib/broker-unit.mjs';
const binding={state:'/var/lib/meshpn-admin-broker',bundle:'/opt/clean-vpn-native/combo-daily'};
const baseline='# meshpn-admin-owned-v1\n[Unit]\nAfter=network.target avahi-daemon.service\n[Service]\nProtectSystem=strict\nReadWritePaths=/var/lib/meshpn-admin-broker /run/meshpn-admin -/run/clean-vpn-killswitch -/run/xtables.lock\nCapabilityBoundingSet=CAP_NET_ADMIN\n';
test('update binds protected broker to current combo bundle, including legacy base unit',()=>{
 const upgraded=upgradeBrokerUnit(baseline,binding);
 assert.match(upgraded,/ProtectSystem=strict/);assert.match(upgraded,/ReadWritePaths=.* \/opt\/clean-vpn-native\/combo-daily /);
 assert.equal(upgradeBrokerUnit(upgraded,binding),upgraded);
 const previous=upgradeBrokerUnit(baseline,{...binding,bundle:'/opt/clean-vpn-native/daily'});
 assert.equal(upgradeBrokerUnit(previous,binding),upgraded);
 assert.equal(upgraded.split('\n').filter(l=>l.startsWith('ReadWritePaths=')).length,1);
});
test('foreign writable paths, additional directives and edited legacy dropins are refused',()=>{
 for(const text of [baseline.replace('ReadWritePaths=','ReadWritePaths=/etc '),baseline+'ReadWritePaths=/\n',baseline.replace('# meshpn-admin-owned-v1','# local')])assert.throws(()=>upgradeBrokerUnit(text,binding));
 const legacy='# clean-vpn-daily-native-binding\n[Service]\nReadWritePaths=/opt/clean-vpn-native/daily\n';
 verifyLegacyBrokerBinding(legacy);
 for(const text of [legacy+'ReadWritePaths=/\n',legacy.replace('/daily','/../../etc'),legacy+'# edited\n'])assert.throws(()=>verifyLegacyBrokerBinding(text));
 for(const bundle of ['/','/etc','/opt/clean-vpn-native/../etc','/opt/clean-vpn-native/daily other'])assert.throws(()=>brokerWritablePaths({...binding,bundle}));
});
