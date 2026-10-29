#!/usr/bin/env node
// Fresh, explicit USB-only install. Existing deployments require a reviewed
// update rather than silently replacing files or importing foreign ownership.
import fs from 'node:fs';import {createHash} from 'node:crypto';import path from 'node:path';import {fileURLToPath} from 'node:url';import {execFileSync} from 'node:child_process';
import {need,atomic,readJson} from './lib/common.mjs';
import {nativeAdminBinding} from './lib/native-binding.mjs';
import {captiveUnit,captiveUnitName} from './lib/captive-unit.mjs';
import {usbAdminSocketUnit,upgradeUsbAdminSocket} from './lib/socket-unit.mjs';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),base='/opt/meshpn-admin',etc='/etc/meshpn-admin';
const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']}).trim();
need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');
const action=process.argv[2],nameArg=process.argv[3];
need(['--plan','--apply','--remove','--container','--standalone','--update'].includes(action)&&process.argv.length<=4,'use_plan_apply_remove');
need(nameArg===undefined||(['--plan','--apply'].includes(action)&&/^--native-name=[a-z][a-z0-9-]{0,31}$/.test(nameArg)),'native_name_argument');
const nativeName=nameArg?.slice(14);
const captivePath='/etc/systemd/system/'+captiveUnitName;
function captivePreflight(){
 for(const f of ['conntrack','iptables','ip','wpa_cli'])need(fs.existsSync('/usr/sbin/'+f),'captive_tool_missing_'+f);
 if(fs.existsSync(captivePath))need(fs.readFileSync(captivePath,'utf8')===captiveUnit(),'captive_unit_changed');
 else{for(const port of [1054,18080])need(!run('/usr/bin/ss',['-H','-lnt','sport','=',':'+port]),'portal_port_busy');need(!run('/usr/bin/ss',['-H','-lnu','sport','=',':1054']),'portal_dns_port_busy');}
}
const guardPath='/usr/local/bin/clean-vpn-killswitch.sh';
const digest=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function updateGuard(){
 const wanted=root+'/scripts/autostart/killswitch.sh',before=etc+'/guard.before';
 if(digest(guardPath)===digest(wanted))return;
 // Only the exact audited Radxa baseline is accepted on first install.
 const owned=readJson(etc+'/guard-installed.json',null);
 need(digest(guardPath)===(owned?.sha256??'287357800e81d115020ec91cd13e87ba615748daea8489b61b4c5e6bfbbc089b'),'guard_script_changed');
 if(!fs.existsSync(before))fs.copyFileSync(guardPath,before,fs.constants.COPYFILE_EXCL);
 atomic(guardPath,fs.readFileSync(wanted,'utf8'),0o755);atomic(etc+'/guard-installed.json',{sha256:digest(wanted)});
}
if(process.argv[2]==='--update'){
 need(readJson(etc+'/manifest.json').kind==='meshpn-admin-owned-install','install_manifest');
 captivePreflight();
 const socketPath='/etc/systemd/system/meshpn-admin.socket';
 const socketText=upgradeUsbAdminSocket(fs.readFileSync(socketPath,'utf8'));
 const socketEnabled=run('/usr/bin/systemctl',['show','meshpn-admin.socket','-p','UnitFileState','--value']);
 if(fs.existsSync(captivePath))run('/usr/bin/systemctl',['stop',captiveUnitName]);
 for(const u of['meshpn-admin.socket','meshpn-admin-web.service','meshpn-admin-broker.service'])run('/usr/bin/systemctl',['stop',u]);
 if(['enabled','enabled-runtime'].includes(socketEnabled))run('/usr/bin/systemctl',['disable','meshpn-admin.socket']);
 atomic(socketPath,socketText,0o644);
 updateGuard();
 const unitPath='/etc/systemd/system/meshpn-admin-broker.service',unitText=fs.readFileSync(unitPath,'utf8');need(unitText.startsWith('# meshpn-admin-owned-v1\n'),'unit_changed');atomic(unitPath,unitText.replace('After=network.target avahi-daemon.service\n','After=network.target avahi-daemon.service clean-vpn-killswitch.service\n'),0o644);run('/usr/bin/systemctl',['daemon-reload']);
 for(const dir of['admin','scripts/lib'])fs.cpSync(path.join(root,dir),path.join(base,dir),{recursive:true,filter:p=>!p.includes('/test/')&&!p.endsWith('/WORK.md')});
 fs.copyFileSync(root+'/scripts/clean-vpn-pcap-fingerprints.mjs',base+'/scripts/clean-vpn-pcap-fingerprints.mjs');
 const manifest=readJson(etc+'/manifest.json');atomic(etc+'/manifest.json',{...manifest,sourceCommit:run('git',['-C',root,'rev-parse','HEAD']),updatedAt:new Date().toISOString()});
 if(['enabled','enabled-runtime'].includes(socketEnabled))run('/usr/bin/systemctl',['enable',...(socketEnabled==='enabled-runtime'?['--runtime']:[]),'meshpn-admin.socket']);
 atomic(captivePath,captiveUnit(),0o644);run('/usr/bin/systemctl',['daemon-reload']);
 run('/usr/bin/systemctl',['start','meshpn-admin-broker.service','meshpn-admin.socket']);run('/usr/bin/systemctl',['enable','--now',captiveUnitName]);console.log('ADMIN_UPDATED');process.exit(0);
}
if(['--container','--standalone','--update'].includes(process.argv[2])){
 const manifest=readJson(etc+'/manifest.json');need(manifest.kind==='meshpn-admin-owned-install','install_manifest');
 const dir='/etc/systemd/system/meshpn-admin-web.service.d',file=dir+'/container.conf';
 run('/usr/bin/systemctl',['stop','meshpn-admin-web.service']);
 if(process.argv[2]==='--container'){need(!fs.existsSync(file),'mode_collision');fs.mkdirSync(dir,{recursive:true});atomic(file,'# meshpn-admin-owned-container-v1\n[Service]\nExecStart=\nExecStart='+base+'/node '+base+'/admin/socket-proxy.mjs\n',0o644);}
 else if(fs.existsSync(file)){need(fs.readFileSync(file,'utf8').startsWith('# meshpn-admin-owned-container-v1\n'),'mode_changed');fs.unlinkSync(file);}
 run('/usr/bin/systemctl',['daemon-reload']);console.log('ADMIN_MODE='+process.argv[2].slice(2));process.exit(0);
}
const units=[captiveUnitName,'meshpn-admin-broker.service','meshpn-admin-web.service','meshpn-admin.socket'];
if(process.argv[2]==='--remove'){
 const manifest=readJson(etc+'/manifest.json');need(manifest.kind==='meshpn-admin-owned-install','install_manifest');
 if(fs.existsSync(captivePath)){need(fs.readFileSync(captivePath,'utf8')===captiveUnit(),'captive_unit_changed');run('/usr/bin/systemctl',['disable','--now',captiveUnitName]);}
 for(const u of ['meshpn-admin.socket','meshpn-admin-web.service','meshpn-admin-broker.service'])run('/usr/bin/systemctl',['stop',u]);
 run('/usr/bin/systemctl',['disable','meshpn-admin.socket','meshpn-admin-broker.service']);
 for(const u of units){const p='/etc/systemd/system/'+u;if(u===captiveUnitName&&!fs.existsSync(p))continue;need(fs.readFileSync(p,'utf8').startsWith('# meshpn-admin-owned-v1\n'),'unit_changed');fs.unlinkSync(p);}
 if(fs.existsSync(etc+'/guard-installed.json')){need(digest(guardPath)===readJson(etc+'/guard-installed.json').sha256,'guard_script_changed');atomic(guardPath,fs.readFileSync(etc+'/guard.before','utf8'),0o755);}
 run('/usr/bin/systemctl',['daemon-reload']);console.log('ADMIN_REMOVED_SERVICES; settings/account/source retained for inspection');process.exit(0);
}
const node=process.execPath;
need(nativeName,'native_name_required');
const binding=nativeAdminBinding(nativeName),{config:vpn,...native}=binding;
const plan={kind:'meshpn-admin-install',bind:'192.168.7.1:80',capture:'192.168.7.1:8443',interface:'usb0',name:'mpn.local',vpnUnit:native.vpnUnit,networkUnit:native.networkUnit,nativeManaged:true,units,defaultPassword:'admin',changedHostNetworking:true,networkChangeScope:'USB-only mDNS OUTPUT exception plus offline captive DNS/HTTP DNAT and dedicated-port INPUT rules',captive:'offline USB only; no HTTPS interception; conntrack cleanup',dnsMigration:false,rootWeb:false};
if(action==='--plan'){console.log(JSON.stringify(plan,null,2));process.exit(0);}
captivePreflight();
for(const p of [base,etc,...units.map(u=>'/etc/systemd/system/'+u)])need(!fs.existsSync(p),'installation_collision');
need(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd','systemd_required');
const links=JSON.parse(run('/usr/sbin/ip',['-j','address','show','usb0']));need(links.length===1&&links[0].addr_info.some(a=>a.local==='192.168.7.1'&&a.prefixlen===24),'usb_address_not_ready');
const guard=run('/usr/local/bin/clean-vpn-killswitch.sh',['status']);need(guard.includes('IPv4: cvks4:')&&guard.includes('IPv6: cvks4:'),'guard_not_ready');
for(const port of [80,8443,1054,18080])need(!run('/usr/bin/ss',['-H','-lnt','sport','=',':'+port]),'admin_port_busy');
need(!run('/usr/bin/ss',['-H','-lnu','sport','=',':1054']),'portal_dns_port_busy');
run('/usr/bin/python3',['-c','import dbus; dbus.SystemBus().get_object("org.freedesktop.Avahi","/")']);
need(digest(guardPath)===digest(root+'/scripts/autostart/killswitch.sh'),'guard_update_required_before_admin');
// Account collision must be detected before touching any install destination.
try{run('/usr/bin/id',['meshpn-admin']);throw Error('account_collision');}catch(e){if(e.message==='account_collision')throw e;}
run('/usr/sbin/useradd',['--system','--user-group','--home-dir','/var/lib/meshpn-admin-web','--shell','/usr/sbin/nologin','meshpn-admin']);
fs.mkdirSync(base,{mode:0o755});fs.mkdirSync(etc,{mode:0o755});
for(const dir of ['admin','scripts/lib'])fs.cpSync(path.join(root,dir),path.join(base,dir),{recursive:true,filter:p=>!p.includes('/test/')&&!p.endsWith('/WORK.md')});
for(const file of ['scripts/clean-vpn-pcap-fingerprints.mjs'])fs.copyFileSync(path.join(root,file),path.join(base,file));
fs.copyFileSync(node,base+'/node');fs.chmodSync(base+'/node',0o755);
const state='/var/lib/meshpn-admin-broker';fs.mkdirSync(state,{mode:0o700});fs.mkdirSync(state+'/profiles',{mode:0o755});
fs.copyFileSync(root+'/fixtures/native-tls-profiles/chromium-156-bounded-cold.json',state+'/profiles/chromium-156-bounded-cold.json');
if(vpn.tls_profile_path)fs.copyFileSync(vpn.tls_profile_path,state+'/profiles/'+path.basename(vpn.tls_profile_path));
const web={version:1,address:'192.168.7.1',subnet:'192.168.7.0/24',port:80,capturePort:8443,hostname:'mpn',state:'/var/lib/meshpn-admin-web',brokerSocket:'/run/meshpn-admin/broker.sock'};
const broker={version:1,usbAddress:web.address,usbInterface:'usb0',wifiInterface:'wlan0',...native,state,profiles:state+'/profiles',socket:web.brokerSocket};
atomic(etc+'/web.json',web,0o644);atomic(etc+'/web-container.json',{...web,address:'127.0.0.1',subnet:'127.0.0.0/8',port:8080,capturePort:18443,publicAddress:web.address,publicPort:80,publicCapturePort:8443,loopbackProxy:true,container:true},0o644);atomic(etc+'/broker.json',broker);atomic(etc+'/manifest.json',{...plan,kind:'meshpn-admin-owned-install',sourceCommit:run('git',['-C',root,'rev-parse','HEAD'])});
const common='NoNewPrivileges=yes\nProtectSystem=strict\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nUMask=0077\n';
const bodies={
 'meshpn-admin-broker.service':`[Unit]\nDescription=MeshPN restricted system broker\nAfter=network.target avahi-daemon.service clean-vpn-killswitch.service\nWants=avahi-daemon.service\n[Service]\nType=simple\nUser=root\nGroup=meshpn-admin\nRuntimeDirectory=meshpn-admin\nRuntimeDirectoryMode=0750\nStateDirectory=meshpn-admin-broker\nStateDirectoryMode=0700\nExecStartPre=${base}/node ${base}/admin/usb-mdns.mjs up\nExecStopPost=${base}/node ${base}/admin/usb-mdns.mjs down\nExecStart=${base}/node ${base}/admin/broker.mjs ${etc}/broker.json\nRestart=on-failure\nRestartSec=3\n${common}ProtectHome=read-only\nReadWritePaths=${state} ${native.bundle} /run/meshpn-admin -/run/clean-vpn-killswitch -/run/xtables.lock\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH\nTasksMax=48\nMemoryMax=192M\n[Install]\nWantedBy=multi-user.target\n`,
 'meshpn-admin-web.service':`[Unit]\nDescription=MeshPN USB administration\nRequires=meshpn-admin-broker.service\nAfter=meshpn-admin-broker.service\n[Service]\nType=simple\nUser=meshpn-admin\nGroup=meshpn-admin\nStateDirectory=meshpn-admin-web\nStateDirectoryMode=0700\nExecStart=${base}/node ${base}/admin/server.mjs ${etc}/web.json\nRestart=on-failure\nRestartSec=2\n${common}ProtectHome=yes\nReadWritePaths=/var/lib/meshpn-admin-web\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET\nTasksMax=32\nMemoryMax=192M\n`,
 'meshpn-admin.socket':usbAdminSocketUnit()};
atomic(captivePath,captiveUnit(),0o644);
for(const[u,s]of Object.entries(bodies))atomic('/etc/systemd/system/'+u,'# meshpn-admin-owned-v1\n'+s,0o644);
run('/usr/bin/systemctl',['daemon-reload']);
try{run('/usr/bin/systemctl',['enable','--now','meshpn-admin-broker.service','meshpn-admin.socket',captiveUnitName]);}catch(e){for(const u of units)try{run('/usr/bin/systemctl',['stop',u]);}catch{}throw Error('admin_start_failed_services_stopped');}
console.log(JSON.stringify({...plan,status:'installed',nativeVpnReplaced:false}));
