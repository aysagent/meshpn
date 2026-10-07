// Pure renderer: no host writes, network mutations, enable/start or secrets.
import path from 'node:path';
export function nativeServiceUnit({ binary, config, networkUnit, guardUnit }) {
  for (const p of [binary, config]) {
    if (typeof p !== 'string' || !/^\/[a-zA-Z0-9_./-]+$/.test(p) || path.normalize(p) !== p || p === '/')
      throw Error('native_service_absolute_safe_path_required');
  }
  for (const name of [networkUnit, guardUnit]) {
    if (typeof name !== 'string' || !/^[a-zA-Z0-9_-]+\.service$/.test(name))
      throw Error('native_service_protection_dependency_required');
  }
  if (networkUnit === guardUnit) throw Error('native_service_distinct_dependencies_required');
  return `[Unit]
Description=clean-vpn native data plane
Requires=${networkUnit} ${guardUnit}
After=${networkUnit} ${guardUnit}
BindsTo=${networkUnit} ${guardUnit}
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=notify
NotifyAccess=main
ExecStartPre=${binary} --check-config ${config}
ExecStart=${binary} --config ${config} --service
StandardInput=null
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=2
TimeoutStartSec=45
TimeoutStopSec=10
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
LimitNOFILE=512
TasksMax=96
MemoryMax=256M

[Install]
WantedBy=multi-user.target
`;
}
