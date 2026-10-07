import path from 'node:path';
import { validateNativeRouteConfig } from './native-route-service.mjs';
export function nativeRouteServiceUnit({ config, script, profile, provisionUnit }) {
  validateNativeRouteConfig(profile);
  for (const p of [config, script]) if (typeof p !== 'string' || !/^\/[\w./-]+$/.test(p) || path.normalize(p) !== p) throw Error('unsafe_path');
  if (!/^[a-z][a-z0-9-]{0,63}\.service$/.test(provisionUnit) ||
    [profile.engine_unit, profile.guard_unit, profile.route_unit].includes(provisionUnit)) throw Error('unsafe_dependency');
  return `[Unit]
Description=clean-vpn native route control (no packet IO)
Requires=${provisionUnit} ${profile.guard_unit}
After=${provisionUnit} ${profile.guard_unit}
BindsTo=${provisionUnit} ${profile.guard_unit}

[Service]
Type=simple
ExecStart=/usr/bin/node ${script} --config=${config}
StandardInput=null
Restart=no
TimeoutStopSec=30
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
TasksMax=32
LimitNOFILE=128
MemoryMax=192M
`;
}
