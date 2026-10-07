// Pure renderer: no host writes, network mutations, enable/start or secrets.
import path from 'node:path';
export function nativeServiceUnit({ binary, config, networkUnit, guardUnit, transport = 'boring-tls', replayDirectory }) {
  if (!['boring-tls', 'transparent-tls', 'combo-tls'].includes(transport)) throw Error('native_service_transport');
  if (replayDirectory !== undefined && transport === 'boring-tls') throw Error('native_service_replay_transport');
  for (const p of [binary, config, ...(replayDirectory === undefined ? [] : [replayDirectory])]) {
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
${replayDirectory === undefined ? '' : `ReadWritePaths=${replayDirectory}\n`}ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
CapabilityBoundingSet=${transport === 'transparent-tls' ? 'CAP_NET_BIND_SERVICE' : 'CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE'}
DevicePolicy=closed
${transport === 'transparent-tls' ? '' : 'DeviceAllow=/dev/net/tun rw\n'}LimitNOFILE=512
TasksMax=96
MemoryMax=256M

[Install]
WantedBy=multi-user.target
`;
}
