import assert from 'node:assert/strict';
import path from 'node:path';
import {validateNativeExitHost} from './native-exit-host-network.mjs';
export const nativeExitHostSources=['clean-vpn-native-exit-host.mjs','clean-vpn-native-tun.py','lib/native-exit-host-network.mjs','lib/native-host-store.mjs'];
export function nativeExitHostPlan({name,target,profile,engine,node='/usr/bin/node'}){
  assert.deepEqual(Object.keys(profile).sort(),['uplink','version']);assert.equal(profile.version,1);
  assert.equal(engine.role,'exit');
  if(engine.transport==='combo-tls'){
    const relay=engine.transparent,packet=engine.boring;
    assert.equal(packet.role,'exit');assert.equal(relay.role,'exit');assert.equal(relay.transport,'transparent-tls');
    assert.deepEqual(relay.listen,{ipv4:packet.address,port:packet.port});
    assert.equal(relay.destinations,undefined);assert.equal(relay.destination_policy.mode,'public-https');
    engine=packet;
  }
  assert.ok(engine.transport===undefined||engine.transport==='boring-tls');
  for(const p of [target,node]){assert.match(p,/^\/[\w./-]+$/);assert.equal(path.normalize(p),p);}
  const network=`native-${name}-network.service`,unit=`native-${name}.service`;
  const config=validateNativeExitHost({version:1,endpoint:engine.address,port:engine.port,uplink:profile.uplink,tun:engine.tun,engine_unit:unit,network_unit:network,...('private_peer_dns' in engine?{private_peer_dns:engine.private_peer_dns}:{})});
  const body=`[Unit]
Description=clean-vpn scoped exit network owner
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${node} ${target}/control/clean-vpn-native-exit-host.mjs run --config=${target}/network.json
ExecStopPost=${node} ${target}/control/clean-vpn-native-exit-host.mjs recover --config=${target}/network.json
Restart=on-failure
RestartSec=10
TimeoutStopSec=180
KillMode=mixed
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
TasksMax=48
MemoryMax=192M

[Install]
WantedBy=multi-user.target
`;
  return {network,guard:network,dependencies:[],activation:network,scopedExit:true,sources:nativeExitHostSources,
    files:new Map([['network.json',JSON.stringify(config)+'\n']]),units:new Map([[network,body]])};
}
