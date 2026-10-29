// Separate localhost-only exit administration; never rewrites the USB install.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {NativeClientManager,readClientPrivate} from '../../scripts/lib/native-client-manager.mjs';
import {need,atomic} from './common.mjs';
const safe=p=>typeof p==='string'&&/^\/[a-zA-Z0-9_./-]+$/.test(p)&&path.normalize(p)===p;
const absent=p=>{try{fs.lstatSync(p);return false;}catch(e){if(e.code==='ENOENT')return true;throw e;}};
function ownedFile(p){const s=fs.lstatSync(p);need(s.isFile()&&s.uid===0&&s.nlink===1&&!(s.mode&0o022),'exit_admin_unit_ownership');return fs.readFileSync(p);}
function trustedParents(p){for(let d=path.dirname(p);;d=path.dirname(d)){const s=fs.lstatSync(d);need(s.isDirectory()&&s.uid===0&&!(s.mode&0o022),'exit_admin_parent_ownership');if(d==='/')break;}}
export function exitAdminPlan({name='main',directory='/var/lib/clean-vpn/clients',port=18880,capturePort=18843},registry,config={}){
 need(/^[a-z][a-z0-9-]{0,19}$/.test(name),'exit_admin_name');need(safe(directory)&&safe(registry.configPath)&&safe(registry.management?.engine),'exit_admin_paths');
 need(directory!=='/'&&path.dirname(registry.configPath)!=='/','exit_admin_write_scope');
 need(/^[a-zA-Z0-9_-]+\.service$/.test(registry.management?.unit),'exit_admin_unit');
 for(const p of [port,capturePort])need(Number.isInteger(p)&&p>=1024&&p<=65535&&!([1053,1054,1055,2222].includes(p)),'exit_admin_port');need(port!==capturePort,'exit_admin_port');
 const label='meshpn-exit-'+name,base='/opt/'+label,etc='/etc/'+label,state='/var/lib/'+label,account='cvweb-'+name,socket='/run/'+label+'/broker.sock';
 const replay=config.transport==='combo-tls'?config.transparent?.replay_directory:null;if(replay)need(safe(replay)&&replay!=='/','exit_admin_replay_path');
 const writable=[state+'/broker',directory,path.dirname(registry.configPath),'/run/'+label,...(replay?[replay]:[])].join(' ');
 const broker={version:1,usbAddress:'127.0.0.1',usbInterface:'lo',publishMdns:false,state:state+'/broker',profiles:state+'/broker/profiles',socket,engine:registry.management.engine,vpnUnit:registry.management.unit,vpnConfig:registry.configPath,nativeManaged:true,clientsDirectory:directory};
 const web={version:1,address:'127.0.0.1',subnet:'127.0.0.0/8',port,capturePort,state:state+'/web',brokerSocket:socket,loopbackProxy:true,container:true};
 const common='NoNewPrivileges=yes\nProtectSystem=strict\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\nUMask=0077\n';
 const brokerUnit=label+'-broker.service',webUnit=label+'-web.service';
 const units={
  [brokerUnit]:`# meshpn-exit-admin-v1\n[Unit]\nDescription=MeshPN restricted exit administration broker\nAfter=network.target\n[Service]\nType=simple\nUser=root\nGroup=${account}\nRuntimeDirectory=${label}\nRuntimeDirectoryMode=0750\nExecStart=${base}/node ${base}/admin/broker.mjs ${etc}/broker.json\nRestart=on-failure\nRestartSec=2\n${common}ProtectHome=read-only\nReadWritePaths=${writable}\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET\nTasksMax=48\nMemoryMax=192M\n[Install]\nWantedBy=multi-user.target\n`,
  [webUnit]:`# meshpn-exit-admin-v1\n[Unit]\nDescription=MeshPN localhost exit administration\nRequires=${brokerUnit}\nAfter=${brokerUnit}\n[Service]\nType=simple\nUser=${account}\nGroup=${account}\nExecStart=${base}/node ${base}/admin/server.mjs ${etc}/web.json\nRestart=on-failure\nRestartSec=2\n${common}ProtectHome=yes\nReadWritePaths=${state}/web\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET\nTasksMax=32\nMemoryMax=192M\n[Install]\nWantedBy=multi-user.target\n`,
 };
 return{kind:'meshpn-exit-admin-plan',version:1,name,label,base,etc,state,account,directory,brokerUnit,webUnit,units,broker,web,url:`http://127.0.0.1:${port}/`,networkSettingsChanged:false};
}
export async function inspectExitAdmin(options){const m=new NativeClientManager({directory:options.directory??'/var/lib/clean-vpn/clients'});await m.list();const r=m.load(),c=JSON.parse(readClientPrivate(r.configPath));need(c.role==='exit','exit_admin_exit_required');return exitAdminPlan(options,r,c);}
const hash=s=>createHash('sha256').update(s).digest('hex');
export async function installExitAdmin(options,{root,node,run}){
 need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');const plan=await inspectExitAdmin(options);
 need(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd','systemd_required');
 for(const p of [plan.base,plan.etc,plan.state,...Object.keys(plan.units).map(u=>'/etc/systemd/system/'+u)]){trustedParents(p);need(absent(p),'exit_admin_install_collision');}
 try{await run('id',[plan.account]);throw Error('exit_admin_account_collision');}catch(e){if(e.message==='exit_admin_account_collision')throw e;need(e.code===1,'exit_admin_account_check');}
 for(const port of [plan.web.port,plan.web.capturePort])need(!(await run('ss',['-H','-lnt','sport','=',':'+port])).trim(),'exit_admin_port_busy');
 const capabilities=JSON.parse(await run(plan.broker.engine,['--capabilities']));need(capabilities.peer_reload,'client_engine_reload_unsupported');await run(plan.broker.engine,['--check-config',plan.broker.vpnConfig]);
 await run('useradd',['--system','--user-group','--home-dir',plan.state+'/web','--shell','/usr/sbin/nologin',plan.account]);
 const created=[];
 try{
  for(const d of [plan.base,plan.etc,plan.state])fs.mkdirSync(d,{mode:0o755});
  fs.mkdirSync(plan.state+'/broker',{mode:0o700});fs.mkdirSync(plan.state+'/broker/profiles',{mode:0o700});fs.mkdirSync(plan.state+'/web',{mode:0o700});
  const uid=Number((await run('id',['-u',plan.account])).trim()),gid=Number((await run('id',['-g',plan.account])).trim());fs.chownSync(plan.state+'/web',uid,gid);
  for(const dir of ['admin','scripts/lib'])fs.cpSync(root+'/'+dir,plan.base+'/'+dir,{recursive:true,filter:p=>!p.includes('/test/')});
  fs.copyFileSync(root+'/scripts/clean-vpn-pcap-fingerprints.mjs',plan.base+'/scripts/clean-vpn-pcap-fingerprints.mjs');fs.copyFileSync(node,plan.base+'/node');fs.chmodSync(plan.base+'/node',0o755);
  atomic(plan.etc+'/broker.json',plan.broker);atomic(plan.etc+'/web.json',plan.web,0o644);
  for(const[u,b]of Object.entries(plan.units)){const p='/etc/systemd/system/'+u;fs.writeFileSync(p,b,{flag:'wx',mode:0o644});created.push(u);}
  atomic(plan.etc+'/manifest.json',{kind:'meshpn-exit-admin-install',version:1,name:plan.name,base:plan.base,state:plan.state,units:Object.fromEntries(Object.entries(plan.units).map(([u,b])=>[u,hash(b)]))});
  await run('systemctl',['daemon-reload']);await run('systemctl',['enable','--now',plan.brokerUnit,plan.webUnit]);
  return{status:'installed',url:plan.url,defaultPassword:'admin',vpnRestarted:false,systemDnsChanged:false,manifest:plan.etc+'/manifest.json'};
 }catch(error){
  for(const u of created.reverse()){try{await run('systemctl',['disable','--now',u]);}catch{}const p='/etc/systemd/system/'+u;if(fs.readFileSync(p,'utf8')===plan.units[u])fs.unlinkSync(p);}
  try{await run('systemctl',['daemon-reload']);}catch{}throw error;
 }
}
export async function removeExitAdmin({name='main'},{run}){
 need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');need(/^[a-z][a-z0-9-]{0,19}$/.test(name),'exit_admin_name');const etc='/etc/meshpn-exit-'+name,m=JSON.parse(readClientPrivate(etc+'/manifest.json'));
 need(m.kind==='meshpn-exit-admin-install'&&m.version===1&&m.name===name,'exit_admin_manifest');const expected=['meshpn-exit-'+name+'-web.service','meshpn-exit-'+name+'-broker.service'];
 need(Object.keys(m.units).sort().join()===expected.slice().sort().join(),'exit_admin_manifest_units');
 for(const u of expected){const p='/etc/systemd/system/'+u;trustedParents(p);need(hash(ownedFile(p))===m.units[u],'exit_admin_unit_changed');}
 for(const u of expected)await run('systemctl',['disable','--now',u]);for(const u of expected)fs.unlinkSync('/etc/systemd/system/'+u);await run('systemctl',['daemon-reload']);
 return{status:'removed-services',retained:'account, source, settings and credentials for inspection; VPN and client registry unchanged'};
}
