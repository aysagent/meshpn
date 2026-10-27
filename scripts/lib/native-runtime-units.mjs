// Render only. Existing isolated namespaces and their lifetime remain external.
import assert from 'node:assert/strict';
import path from 'node:path';
const safePath = p => { assert.ok(typeof p==='string'&&/^\/[a-zA-Z0-9_./-]+$/.test(p)&&path.normalize(p)===p&&p!=='/');return p; };
function base({ namespace, parent, scripts, node }) {
  assert.match(namespace,/^[a-zA-Z][a-zA-Z0-9_-]{0,40}$/);assert.match(parent,/^net:\[\d+\]$/);
  safePath(scripts);safePath(node);
  return `NetworkNamespacePath=/run/netns/${namespace}
Environment=CVPN_PARENT_NETNS=${parent}
Environment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
TasksMax=96
MemoryMax=256M
KillMode=control-group
TimeoutStartSec=45
TimeoutStopSec=30
`;
}
export function runtimeGatewayUnit(o) {
  safePath(o.config);assert.ok(Number.isInteger(o.seconds)&&o.seconds>=10&&o.seconds<=900);
  return `[Unit]
Description=Bounded clean-vpn selected ingress trial (isolated namespace)

[Service]
Type=exec
${base(o)}ExecStart=${o.node} ${o.scripts}/clean-vpn-native-gateway.mjs apply --config=${o.config} --seconds=${o.seconds}
ExecStopPost=${o.node} ${o.scripts}/clean-vpn-native-gateway.mjs recover
Restart=no
RuntimeMaxSec=${o.seconds+30}
`;
}
export function runtimeEngineUnit(o) {
  safePath(o.config);safePath(o.engine);assert.match(o.instance,/^[a-zA-Z0-9_-]{1,40}$/);
  if(o.lanSubnet)assert.match(o.lanSubnet,/^192\.168\.\d+\.\d+\/(?:1[6-9]|2[0-9]|30)$/);
  return `[Unit]
Description=clean-vpn native boring-tls (isolated namespace)
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
${base(o)}Environment=CVPN_ENGINE=${o.engine}
Environment=CVPN_CONTROL_DIRECTORY=${o.scripts}
Environment=CVPN_STATE_DIRECTORY=/run/clean-vpn-${o.instance}
${o.lanSubnet?`Environment=CVPN_UPLINK=auto CVPN_LAN_INTERFACE=auto CVPN_LAN_SUBNET=${o.lanSubnet}\n`:''}\
ExecStart=/bin/sh ${o.scripts}/containers/native-runtime-entrypoint.sh ${o.config}
Restart=on-failure
RestartSec=2
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
`;
}
