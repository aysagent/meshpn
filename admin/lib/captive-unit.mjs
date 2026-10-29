export const captiveUnitName='meshpn-admin-captive.service';
export function captiveUnit(){return `# meshpn-admin-owned-v1
[Unit]
Description=MeshPN offline USB Wi-Fi setup portal
BindsTo=meshpn-admin-broker.service
After=meshpn-admin-broker.service clean-vpn-usb-rescue-address.service
Wants=clean-vpn-usb-rescue-address.service
[Service]
Type=simple
User=root
Group=meshpn-admin
RuntimeDirectory=meshpn-admin-captive
RuntimeDirectoryMode=0700
ExecStart=/opt/meshpn-admin/node /opt/meshpn-admin/admin/usb-captive.mjs run /etc/meshpn-admin/broker.json
ExecStopPost=/opt/meshpn-admin/node /opt/meshpn-admin/admin/usb-captive.mjs down
Restart=on-failure
RestartSec=5
TimeoutStopSec=40
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
ReadWritePaths=/run/meshpn-admin /run/meshpn-admin-captive -/run/xtables.lock
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
TasksMax=32
MemoryMax=96M
[Install]
WantedBy=multi-user.target meshpn-admin-broker.service
`;}
