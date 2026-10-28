#!/usr/bin/env node
// Opt-in binary updates for a fresh, named boring-tls installation. No network
// mutation and no legacy adoption. Inputs are trusted administrator binaries.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {NativeBinaryUpdate,binaryDigest,readOwned,writeDurable,syncDir} from './lib/native-binary-update.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:file==='/usr/bin/systemd-run'?240000:90000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const ctl=(...args)=>run('/usr/bin/systemctl',args);
const props=unit=>Object.fromEntries(ctl('show',unit,'-p','ActiveState,MainPID,Type,StatusText,FragmentPath,DropInPaths').split('\n').map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));
const safePath=p=>typeof p==='string'&&/^\/[a-zA-Z0-9_./-]+$/.test(p)&&path.normalize(p)===p;
export function recoveryUnit({name,bundle,node}) {
  return `[Unit]\nDescription=clean-vpn binary recovery ${name}\nBefore=native-${name}.service\nAfter=local-fs.target\nRequiresMountsFor=${bundle}\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=${node} ${bundle}/update-control/clean-vpn-native-update.mjs --recover-boot ${name}\nTimeoutStartSec=30\nUMask=0077\n`;
}
async function main(args) {
  if(args.length===1&&args[0]==='--help') {
    console.log('Usage: --enroll NAME | --apply NAME /absolute/trusted-engine SHA256 | --recover NAME | --status NAME\nFresh named boring-tls install only. Enroll while stopped; never enables VPN. Apply uses a bounded transient systemd unit with independent recovery. Cold-boot recovery precedes engine. No config/key/network update.');return;
  }
  const [action,name,binary,expected,...extra]=args;
  need(process.platform==='linux'&&process.getuid()===0,'update_linux_root');
  need(/^[a-z][a-z0-9-]{0,31}$/.test(name??'')&&extra.length===0,'update_name');
  need(['--enroll','--apply','--worker','--recover','--recover-boot','--status'].includes(action),'update_action');
  need(['--apply','--worker'].includes(action)?safePath(binary)&&/^[a-f0-9]{64}$/.test(expected??''):binary===undefined,'update_arguments');
  need(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd','update_systemd');
  const bundle='/opt/clean-vpn-native/'+name, unit='native-'+name+'.service';
  const manifest=JSON.parse(readOwned(bundle+'/installed.json'));
  need(manifest.schema===1&&manifest.name===name&&manifest.unit===unit&&manifest.transport==='boring-tls'&&
    manifest.mutableDirectories.length===0&&manifest.networkUnit&&manifest.guardUnit,'update_named_external_boring_install');
  const json=x=>JSON.stringify(x,null,2)+'\n';
  if(action==='--enroll') {
    const state=props(unit);need(['inactive','failed'].includes(state.ActiveState)&&state.MainPID==='0','update_enroll_stopped');
    need(state.FragmentPath==='/etc/systemd/system/'+unit,'update_unit_path');
    for(const f of manifest.files){need(/^[a-zA-Z0-9_.-]+$/.test(f.name),'update_manifest_path');
      const p=bundle+'/'+f.name;need(binaryDigest(readOwned(p,64*1024*1024))===f.sha256&&(fs.lstatSync(p).mode&0o777)===f.mode,'update_install_changed');}
    need(binaryDigest(readOwned(state.FragmentPath))===manifest.files.find(f=>f.name==='service.unit')?.sha256,'update_unit_changed');
    const recUnit='native-'+name+'-binary-recovery.service', recPath='/etc/systemd/system/'+recUnit;
    const dropDir='/etc/systemd/system/'+unit+'.d', drop=dropDir+'/80-binary-recovery.conf';
    need(!fs.existsSync(recPath)&&!fs.existsSync(drop)&&!fs.existsSync(bundle+'/binary-updates')&&
      !fs.existsSync(bundle+'/update-control'),'update_already_enrolled');
    const control=bundle+'/update-control';fs.mkdirSync(control,{mode:0o700});fs.mkdirSync(control+'/lib',{mode:0o700});
    writeDurable(control+'/clean-vpn-native-update.mjs',fs.readFileSync(fileURLToPath(import.meta.url)));
    writeDurable(control+'/lib/native-binary-update.mjs',fs.readFileSync(fileURLToPath(new URL('./lib/native-binary-update.mjs',import.meta.url))));
    const node=fs.realpathSync(process.execPath);need(safePath(node),'update_node_path');
    writeDurable(recPath,recoveryUnit({name,bundle,node}),0o644);
    if(!fs.existsSync(dropDir)){fs.mkdirSync(dropDir,{mode:0o755});syncDir(path.dirname(dropDir));}
    writeDurable(drop,`[Unit]\nRequires=${recUnit}\nAfter=${recUnit}\n`,0o644);
    // Partial enrollment fails closed: recovery is required but its binding
    // is absent until all owned files and the service identity are recorded.
    ctl('daemon-reload');
    const installed=props(unit);
    const files=[bundle+'/installed.json',...manifest.files.filter(f=>f.name!=='engine').map(f=>bundle+'/'+f.name),
      ...Object.keys(manifest.dependencies).map(n=>'/etc/systemd/system/'+n),state.FragmentPath,
      ...installed.DropInPaths.split(' ').filter(Boolean),recPath,control+'/clean-vpn-native-update.mjs',control+'/lib/native-binary-update.mjs'];
    for(const [dep,sha]of Object.entries(manifest.dependencies))need(binaryDigest(readOwned('/etc/systemd/system/'+dep))===sha,'update_dependency_changed');
    const sha=NativeBinaryUpdate.initialize(bundle,[...new Set(files)]);
    writeDurable(bundle+'/binary-updates/service.json',json({fragment:installed.FragmentPath,dropins:installed.DropInPaths,node}));
    const binding=JSON.parse(readOwned(bundle+'/binary-updates/binding.json'));
    binding.protectedFiles.push(bundle+'/binary-updates/service.json');
    writeDurable(bundle+'/binary-updates/binding.json',json(binding));
    console.log(json({status:'enrolled-stopped',sha256:sha,unit}));return;
  }
  const serviceIdentity=JSON.parse(readOwned(bundle+'/binary-updates/service.json'));
  const state=props(unit);need(state.FragmentPath===serviceIdentity.fragment&&state.DropInPaths===serviceIdentity.dropins&&state.Type==='notify','update_service_changed');
  const service={
    running:async()=>{const s=props(unit);if(action==='--recover-boot')return s.MainPID!=='0';
      need(['active','inactive','failed'].includes(s.ActiveState),'update_service_transition');return s.ActiveState==='active';},
    stop:async()=>{ctl('stop',unit);need(props(unit).MainPID==='0','update_stop_failed');},
    start:async()=>{ctl('reset-failed',unit);ctl('start',unit);},
    guard:async()=>{for(const dep of [manifest.guardUnit,manifest.networkUnit])need(props(dep).ActiveState==='active','update_dependency_inactive');},
    validate:async candidate=>{const c=JSON.parse(run(candidate,['--capabilities']));need(c.engine==='clean-vpn-native-m1'&&c.packet_ipc===false&&c.service_mode===true,'update_capabilities');run(candidate,['--check-config',bundle+'/config.json']);},
    ready:async()=>{const s=props(unit);need(s.ActiveState==='active'&&Number(s.MainPID)>0&&['ready','idle_wait','listening'].includes(s.StatusText),'update_not_ready');
      need(binaryDigest(fs.readFileSync('/proc/'+s.MainPID+'/exe'))===binaryDigest(readOwned(bundle+'/engine',64*1024*1024)),'update_running_binary');await service.guard();}
  };
  if(action==='--apply') {
    // Verify input before creating the worker. Worker verifies again; source
    // path is never executed before its bytes match the administrator's hash.
    need(binaryDigest(readOwned(binary,64*1024*1024))===expected,'release_candidate_digest');
    const script=bundle+'/update-control/clean-vpn-native-update.mjs', node=serviceIdentity.node;
    run('/usr/bin/systemd-run',['--quiet','--wait','--collect','--unit=native-'+name+'-binary-update',
      '--property=Type=exec','--property=RuntimeMaxSec=180','--property=TimeoutStopSec=15',
      '--property=UMask=0077','--property=KillMode=control-group','--property=MemoryMax=256M','--property=TasksMax=32',
      '--property=ExecStopPost='+node+' '+script+' --recover '+name,
      node,script,'--worker',name,binary,expected]);
    console.log(json({status:'worker-finished',...JSON.parse(readOwned(bundle+'/binary-updates/last-result.json'))}));return;
  }
  if(action==='--status') {const update=new NativeBinaryUpdate(bundle,service);
    console.log(json({sha256:update.current(),pending:!!update.pending(),unit,service:state.ActiveState}));return;}
  // flock belongs to the enclosing process; no stale PID lock after SIGKILL.
  // Internal invocation is passed via a private inherited environment value.
  const lock=bundle+'/binary-updates/operation.lock';
  if(process.env.CVPN_BINARY_UPDATE_LOCK!==bundle) {
    readOwned(lock,0,true); // reject an existing symlink/foreign/writable lock
    execFileSync('/usr/bin/flock',['-n','-E','73',lock,serviceIdentity.node,fileURLToPath(import.meta.url),...args],
      {stdio:'inherit',timeout:210000,env:{...process.env,CVPN_BINARY_UPDATE_LOCK:bundle}});return;
  }
  const update=new NativeBinaryUpdate(bundle,service);
  const result=action==='--worker'?await update.apply(binary,expected):await update.recover({boot:action==='--recover-boot'});
  if(result.status!=='none')writeDurable(bundle+'/binary-updates/last-result.json',json(result));
  console.log(json(result));
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===path.resolve(process.argv[1]))main(process.argv.slice(2)).catch(e=>{
  console.error(JSON.stringify({status:'failed',error:/^[a-z0-9_]+$/.test(e.message)?e.message:'update_operation_failed'}));process.exitCode=1;
});
