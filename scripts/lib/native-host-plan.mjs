import assert from 'node:assert/strict';
import {validateNativeComboRedirectConfig} from './native-combo-redirect-plan.mjs';
import {nativeHostUnit} from './native-host-unit.mjs';
import {validateNativeHostConfig} from './native-host-network.mjs';
export const nativeHostSources=['clean-vpn-native-host-network.mjs','clean-vpn-native-tun.py',
  'lib/native-host-network.mjs','lib/native-host-store.mjs','lib/vpn-host-routes.mjs',
  'lib/dns-tunnel-journal.mjs','lib/dns-tunnel-plan.mjs','lib/dns-tunnel-command.mjs','lib/dns-tunnel-conntrack.mjs',
  'lib/dns-tunnel-forwarder.mjs','lib/dns-tunnel-stub.mjs','lib/lab-dns-wire.mjs',
  'lib/transparent-tls-destination.mjs','lib/transparent-tls-io.mjs','lib/tls-clienthello-ja3.mjs','lib/native-combo-redirect-journal.mjs',
  'lib/native-combo-redirect-plan.mjs','lib/native-transparent-network.mjs'];
export function nativeHostPlan({name,target,profile,engine,capability,node='/usr/bin/node'}){
  assert.deepEqual(Object.keys(profile).sort(),['guard_script','guard_unit','version',...('incoming_tcp' in profile?['incoming_tcp']:[])].sort());assert.equal(profile.version,1);
  assert.equal(engine.role,'client');
  let combo_redirect;
  if(engine.transport==='combo-tls'){
    const relay=engine.transparent,packet=engine.boring;
    assert.equal(capability.experimental_transports?.['combo-tls']?.site_provisioning,true);
    assert.equal(packet.role,'client');assert.equal(relay.role,'client');assert.equal(relay.transport,'transparent-tls');
    assert.equal(relay.listen.ipv4,'0.0.0.0');assert.deepEqual(relay.exit,{ipv4:packet.address,port:packet.port});
    assert.equal(relay.destinations,undefined);assert.equal(relay.destination_policy.mode,'public-https');
    combo_redirect=validateNativeComboRedirectConfig({interface:'usb0',subnet:'192.168.7.0/24',endpoint:packet.address,listen_port:relay.listen.port,deny_ipv4:relay.destination_policy.deny_ipv4});
    engine=packet;
  }
  assert.ok(engine.transport===undefined||engine.transport==='boring-tls');
  assert.equal(engine.tun,'tun0');assert.equal(engine.dns,true);
  if(profile.incoming_tcp){assert.equal(engine.connection_mode,'persistent','native_incoming_requires_persistent');assert.ok(capability.connection_modes?.includes('persistent'));if(combo_redirect)assert.notEqual(profile.incoming_tcp.port,combo_redirect.listen_port,'native_incoming_relay_port_conflict');}
  assert.equal(capability.dns_socket_mark,'0x43564e');
  const network=`native-${name}-network.service`,unit=`native-${name}.service`;
  const config=validateNativeHostConfig({version:1,exit_ip:engine.address,engine_unit:unit,network_unit:network,guard_unit:profile.guard_unit,guard_script:profile.guard_script,...('peer_ipv4' in engine ? {peer_ipv4:engine.peer_ipv4} : {}),...(combo_redirect?{combo_redirect}:{}),...('incoming_tcp' in profile?{incoming_tcp:profile.incoming_tcp}:{})});
  return {network,guard:profile.guard_unit,dependencies:[profile.guard_unit],activation:network,
    files:new Map([['network.json',JSON.stringify(config)+'\n']]),
    units:new Map([[network,nativeHostUnit({node,script:target+'/control/clean-vpn-native-host-network.mjs',config:target+'/network.json',profile:config})]])};
}
