#!/usr/bin/env node
// Opt-in private LAN access for an existing standalone admin installation.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {managementAccess,publishManagementFile as publish} from './lib/management-access.mjs';
import {managementMdnsUnit} from './lib/management-mdns.mjs';
import {need,readJson,atomic} from './lib/common.mjs';

const root=path.dirname(fileURLToPath(import.meta.url)),etc='/etc/meshpn-admin',base='/opt/meshpn-admin';
const unit='meshpn-admin-management.service',unitPath='/etc/systemd/system/'+unit;
const dropinDir='/etc/systemd/system/meshpn-admin-web.service.d',dropin=dropinDir+'/management.conf';
const legacyDropin='# meshpn-admin-management-owned-v1\n[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n';
const lowPortDropin=legacyDropin+'CapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n';
const mdnsUnit='meshpn-admin-management-mdns.service',mdnsPath='/etc/systemd/system/'+mdnsUnit;
const unitText=`# meshpn-admin-management-owned-v1
[Unit]
Description=Start MeshPN administration with opt-in private LAN access
Requires=meshpn-admin.socket
After=meshpn-admin.socket
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl start meshpn-admin-web.service
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
`;
const run=(...args)=>execFileSync('/usr/bin/systemctl',args,{encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']});
const [action,...args]=process.argv.slice(2),options={};let apply=false;
need(['enable','disable'].includes(action),'use_enable_or_disable');
for(const arg of args){if(arg==='--apply'){need(!apply,'duplicate_apply');apply=true;continue;}if(arg==='--mdns'){need(!options.mdns,'duplicate_mdns');options.mdns=true;continue;}const m=/^--(interface|subnet|port|capture-port)=(.+)$/.exec(arg);need(m&&!Object.hasOwn(options,m[1]),'management_argument');options[m[1]]=m[2];}
need(action==='enable'||Object.keys(options).length===0,'disable_arguments');
const access=action==='enable'?managementAccess({interface:options.interface,subnet:options.subnet,...(options.port?{port:Number(options.port)}:{}),...(options['capture-port']?{capturePort:Number(options['capture-port'])}:{}),...(options.mdns?{mdns:true}:{})}):null;
const dropinText=access?.port===80?lowPortDropin:legacyDropin;
const plan={kind:'meshpn-admin-management',action,access,changedVpn:false,firewallScope:access?.mdns?'one scoped IPv4 mDNS OUTPUT exception':'no new exception; remove previous management mDNS if present',changedMacNetwork:false};
if(!apply){console.log(JSON.stringify({...plan,mode:'plan'},null,2));process.exit(0);}
need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');
need(readJson(etc+'/manifest.json').kind==='meshpn-admin-owned-install','install_manifest');
need(!fs.existsSync('/etc/systemd/system/meshpn-admin-web.service.d/container.conf'),'management_standalone_required');
const file=etc+'/web.json',before=readJson(file);
const group=execFileSync('/usr/bin/getent',['group','meshpn-admin'],{encoding:'utf8'}).trim().split(':');
need(group[0]==='meshpn-admin'&&/^\d+$/.test(group[2]),'management_web_group');const webGid=Number(group[2]);
need(!before.container&&!before.loopbackProxy&&!before.lab,'management_standalone_required');
if(fs.existsSync(unitPath))need(fs.readFileSync(unitPath,'utf8')===unitText,'management_unit_changed');
if(fs.existsSync(dropin))need([legacyDropin,lowPortDropin].includes(fs.readFileSync(dropin,'utf8')),'management_dropin_changed');
if(fs.existsSync(mdnsPath))need(fs.readFileSync(mdnsPath,'utf8')===managementMdnsUnit,'management_mdns_unit_changed');
if(access?.mdns){const capabilities=JSON.parse(execFileSync('/usr/local/bin/clean-vpn-killswitch.sh',['capabilities'],{encoding:'utf8'}));need(capabilities.management_mdns===true,'management_mdns_guard_update_required');need(fs.existsSync(base+'/admin/mdns-helper'),'management_mdns_helper_required');const helper=JSON.parse(execFileSync(base+'/admin/mdns-helper',['--capabilities'],{encoding:'utf8'}));need(helper.dual_stack_transport===true,'management_mdns_helper_update_required');}
const code=['server.mjs','lib/management-access.mjs','management-mdns.mjs','lib/management-mdns.mjs'];
const files=[file,unitPath,dropin,mdnsPath,...code.map(relative=>base+'/admin/'+relative)];
const snapshots=files.map(p=>({path:p,exists:fs.existsSync(p),...(fs.existsSync(p)?{text:fs.readFileSync(p,'utf8'),mode:fs.statSync(p).mode&0o777,uid:fs.statSync(p).uid,gid:fs.statSync(p).gid}:{})}));
const backup=fs.mkdtempSync(etc+'/management-backup-');fs.chmodSync(backup,0o700);atomic(backup+'/before.json',snapshots);
let wasEnabled=false;try{wasEnabled=run('is-enabled',unit).trim()==='enabled';}catch{}
let mdnsWasEnabled=false;try{mdnsWasEnabled=run('is-enabled',mdnsUnit).trim()==='enabled';}catch{}
try{
 if(fs.existsSync(mdnsPath))run('disable','--now',mdnsUnit);
 const next={...before};if(access)next.managementAccess=access;else delete next.managementAccess;
 if(access){
  for(const relative of code)publish(base+'/admin/'+relative,fs.readFileSync(root+'/'+relative,'utf8'));
  publish(unitPath,unitText);
  fs.mkdirSync(dropinDir,{recursive:true,mode:0o755});fs.chmodSync(dropinDir,0o755);publish(dropin,dropinText);
 }else{if(fs.existsSync(unitPath)){run('disable','--now',unit);fs.unlinkSync(unitPath);}if(fs.existsSync(dropin))fs.unlinkSync(dropin);}
 if(access?.mdns)publish(mdnsPath,managementMdnsUnit);else if(fs.existsSync(mdnsPath))fs.unlinkSync(mdnsPath);
 publish(file,next,0o640);fs.chownSync(file,0,webGid);run('daemon-reload');
 if(access)run('enable',unit);
 run('restart','meshpn-admin-web.service');
 if(access)run('start',unit);
 if(access?.mdns)run('enable','--now',mdnsUnit);
 console.log(JSON.stringify({...plan,mode:'applied',backup,activation:'listeners follow eligible IPv4 addresses; inspect journal for bind failures'},null,2));
}catch(e){
 try{if(fs.existsSync(mdnsPath))run('disable','--now',mdnsUnit);if(!wasEnabled&&fs.existsSync(unitPath))run('disable','--now',unit);for(const s of snapshots){if(s.exists){publish(s.path,s.text,s.mode);fs.chownSync(s.path,s.uid,s.gid);}else if(fs.existsSync(s.path))fs.unlinkSync(s.path);}run('daemon-reload');if(wasEnabled)run('enable',unit);run('restart','meshpn-admin-web.service');if(wasEnabled)run('start',unit);if(mdnsWasEnabled)run('enable','--now',mdnsUnit);}catch{console.error('management_rollback_failed: '+backup);}
 throw e;
}
