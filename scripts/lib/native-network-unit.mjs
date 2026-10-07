import assert from 'node:assert/strict';
import path from 'node:path';
export function nativeNetworkUnit({ script, config, linkUnit }) {
  for (const p of [script, config]) { assert.match(p, /^\/[\w./-]+$/); assert.equal(path.normalize(p), p); }
  assert.match(linkUnit, /^[a-z][a-z0-9-]{0,63}\.service$/);
  return `[Unit]
Description=clean-vpn dedicated native network profile
Requires=${linkUnit}
After=${linkUnit}
BindsTo=${linkUnit}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/node ${script} --apply --config=${config}
TimeoutStartSec=120
TimeoutStopSec=10
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
TasksMax=32
MemoryMax=192M
`;
}
