import {managementAccess} from './management-access.mjs';
export const managementMdnsTag='meshpn-admin-management-mdns-v1';
export function managementMdnsRule(iface,address){
 managementAccess({interface:iface,subnet:address+'/32'});
 return ['-s',address+'/32','-d','224.0.0.251/32','-o',iface,'-p','udp','-m','udp','--sport','5353','--dport','5353','-m','comment','--comment',managementMdnsTag,'-j','ACCEPT'];
}
export function parseManagementMdnsRule(line){
 const m=/^-A OUTPUT -s ([0-9.]+)\/32 -d 224\.0\.0\.251\/32 -o ([a-zA-Z0-9_]{1,15}) -p udp -m udp --sport 5353 --dport 5353 -m comment --comment meshpn-admin-management-mdns-v1 -j ACCEPT$/.exec(line);
 if(!m)return null;
 try{const rule=managementMdnsRule(m[2],m[1]);return '-A OUTPUT '+rule.join(' ')===line?rule:null;}catch{return null;}
}
export const managementMdnsUnit=`# meshpn-admin-management-mdns-owned-v1
[Unit]
Description=Scoped MeshPN management name publication
Wants=avahi-daemon.service
After=avahi-daemon.service clean-vpn-killswitch.service
[Service]
Type=simple
ExecStart=/opt/meshpn-admin/node /opt/meshpn-admin/admin/management-mdns.mjs up
ExecStopPost=/opt/meshpn-admin/node /opt/meshpn-admin/admin/management-mdns.mjs down
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
ReadWritePaths=-/run/xtables.lock
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
UMask=0077
TasksMax=16
MemoryMax=96M
[Install]
WantedBy=multi-user.target
`;
