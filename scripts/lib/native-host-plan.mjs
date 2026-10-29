import assert from 'node:assert/strict';
import {nativeHostUnit} from './native-host-unit.mjs';
import {validateNativeHostConfig} from './native-host-network.mjs';
export const nativeHostSources=['clean-vpn-native-host-network.mjs','clean-vpn-native-tun.py',
  'lib/native-host-network.mjs','lib/native-host-store.mjs','lib/vpn-host-routes.mjs',
  'lib/dns-tunnel-journal.mjs','lib/dns-tunnel-plan.mjs','lib/dns-tunnel-command.mjs','lib/dns-tunnel-conntrack.mjs',
  'lib/dns-tunnel-forwarder.mjs','lib/dns-tunnel-stub.mjs','lib/lab-dns-wire.mjs',
  'lib/transparent-tls-destination.mjs','lib/transparent-tls-io.mjs','lib/tls-clienthello-ja3.mjs'];
export function nativeHostPlan({name,target,profile,engine,capability,node='/usr/bin/node'}){
  assert.deepEqual(Object.keys(profile).sort(),['guard_script','guard_unit','version']);assert.equal(profile.version,1);
  assert.equal(engine.role,'client');assert.ok(engine.transport===undefined||engine.transport==='boring-tls');
  assert.equal(engine.tun,'tun0');assert.equal(engine.dns,true);
  assert.equal(capability.dns_socket_mark,'0x43564e');
  const network=`native-${name}-network.service`,unit=`native-${name}.service`;
  const config=validateNativeHostConfig({version:1,exit_ip:engine.address,engine_unit:unit,network_unit:network,guard_unit:profile.guard_unit,guard_script:profile.guard_script,...('peer_ipv4' in engine ? {peer_ipv4:engine.peer_ipv4} : {})});
  return {network,guard:profile.guard_unit,dependencies:[profile.guard_unit],activation:network,
    files:new Map([['network.json',JSON.stringify(config)+'\n']]),
    units:new Map([[network,nativeHostUnit({node,script:target+'/control/clean-vpn-native-host-network.mjs',config:target+'/network.json',profile:config})]])};
}
