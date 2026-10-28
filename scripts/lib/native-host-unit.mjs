import assert from 'node:assert/strict';
import path from 'node:path';
import {validateNativeHostConfig} from './native-host-network.mjs';
export function nativeHostUnit({script,config,profile,node='/usr/bin/node'}){
  const c=validateNativeHostConfig(profile);
  for(const p of [script,config,node]){assert.match(p,/^\/[\w./-]+$/);assert.equal(path.normalize(p),p);}
  return `[Unit]
Description=clean-vpn native Radxa network owner
Requires=${c.guard_unit}
After=${c.guard_unit} network.target
BindsTo=${c.guard_unit}
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${node} ${script} run --config=${config}
ExecStopPost=${node} ${script} recover --config=${config}
Restart=on-failure
RestartSec=10
TimeoutStopSec=180
# Let a synchronous journal command finish before the main process handles
# SIGTERM. Remaining children are still killed after main exit or stop timeout.
KillMode=mixed
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run /proc/sys/net/ipv4/conf/all/rp_filter
ProtectHome=read-only
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
TasksMax=48
MemoryMax=192M

[Install]
WantedBy=multi-user.target
`;
}
