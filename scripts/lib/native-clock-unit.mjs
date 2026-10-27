// Pure renderers. No provisioning, enable/start, credentials or host changes.
import path from 'node:path';
export function clockUnitName(value){
  if(typeof value!=='string'||!/^[a-z][a-z0-9-]{0,63}\.service$/.test(value))throw Error('clock_unit_name');
  return value;
}
export function clockPath(value){
  if(typeof value!=='string'||!/^\/[a-zA-Z0-9_./-]+$/.test(value)||path.normalize(value)!==value||value==='/')throw Error('clock_absolute_path');
  return value;
}
export function nativeClockRecoveryUnit({consumerUnit,script,config,stateDirectory,namespace}){
  clockUnitName(consumerUnit);[script,config,stateDirectory].forEach(clockPath);
  if(namespace!==undefined&&!/^[a-z][a-z0-9_-]{0,40}$/.test(namespace))throw Error('clock_namespace');
  return `[Unit]
Description=Conditional clean-vpn clock recovery
Before=${consumerUnit}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${script} recover --config=${config}
${namespace?`NetworkNamespacePath=/run/netns/${namespace}\n`:''}TimeoutStartSec=30
Restart=no
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${stateDirectory}
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET
CapabilityBoundingSet=CAP_SYS_TIME
DevicePolicy=closed
TasksMax=16
MemoryMax=96M
StandardOutput=journal
StandardError=journal
`;
}
