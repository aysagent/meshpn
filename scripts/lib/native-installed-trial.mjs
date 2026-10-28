// Temporary installed service fixture using the existing Radxa network owner.
// Does not enable units or adopt/overwrite a previous installation.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {installNative} from './native-install.mjs';
import {fileURLToPath} from 'node:url';
export const installedTrialName='radxa-lifecycle-pilot';
const name=installedTrialName,bundle='/opt/clean-vpn-native/'+name;
const unit='native-'+name+'.service',network='native-'+name+'-network.service',clock='native-'+name+'-clock.service';
const root=fileURLToPath(new URL('../../',import.meta.url));
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:180000,maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}).trim();
const ctl=(...a)=>run('/usr/bin/systemctl',a);
const need=(ok,c)=>{if(!ok)throw Error(c);};
export function prepareInstalledTrial({binary,config,clockProfile,log}) {
  need(ctl('show','clean-vpn-native-trial.service','-p','ActiveState','--value')==='active','installed_trial_owner_inactive');
  need(!fs.existsSync(bundle),'installed_trial_collision');
  const names=[unit,network,clock,'native-'+name+'-binary-recovery.service','native-'+name+'-binary-update.service'];
  for(const u of names)need(ctl('show',u,'-p','LoadState','--value')==='not-found'&&!fs.existsSync('/etc/systemd/system/'+u+'.d'),'installed_trial_unit_collision');
  const files=new Map(),put=(p,b)=>{fs.writeFileSync(p,b,{flag:'wx',mode:0o644});files.set(p,Buffer.from(b));};
  const cleanup=()=>{
    for(const u of [names[4],clock,unit,names[3],network])try{ctl('stop',u);}catch{}
    for(const u of names)need(ctl('show',u,'-p','MainPID','--value')==='0','installed_trial_process_alive');
    for(const[p,b]of files)need(fs.readFileSync(p).equals(b),'installed_trial_file_changed');
    // The entire bundle was exclusively created here; never adopt a prior one.
    for(const p of files.keys())fs.unlinkSync(p);
    if(fs.existsSync('/etc/systemd/system/'+unit+'.d'))fs.rmdirSync('/etc/systemd/system/'+unit+'.d');
    fs.rmSync(bundle,{recursive:true,force:true});ctl('daemon-reload');
    for(const u of names)try{ctl('reset-failed',u);}catch{}
  };
  try {
    put('/etc/systemd/system/'+network,`# clean-vpn-owned-installed-trial\n[Unit]\nRequires=clean-vpn-native-trial.service\nAfter=clean-vpn-native-trial.service\nBindsTo=clean-vpn-native-trial.service\nPartOf=clean-vpn-native-trial.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/systemctl is-active clean-vpn-native-trial.service\n`);
    installNative({name,binary,config,networkUnit:network,guardUnit:'clean-vpn-killswitch.service',clockProfile,apply:true});
    for(const u of [unit,clock])for(const p of ['/etc/systemd/system/'+u,'/etc/systemd/system/.'+u+'.prepared'])files.set(p,fs.readFileSync(p));
    const drop='/etc/systemd/system/'+unit+'.d';fs.mkdirSync(drop,{mode:0o755});
    put(drop+'/50-trial.conf',`[Unit]\nPartOf=clean-vpn-native-trial.service\n[Service]\nExecStartPre=\nStandardOutput=append:${log}\nStandardError=null\n`);
    ctl('daemon-reload');
    run(process.execPath,[root+'scripts/clean-vpn-native-update.mjs','--enroll',name]);
    for(const p of [drop+'/80-binary-recovery.conf','/etc/systemd/system/'+names[3]])files.set(p,fs.readFileSync(p));
    return {unit,recovery:clock,cleanup,bundle};
  } catch(e) {
    // Preserve incomplete publication for inspection. Never remove unknown files.
    // No engine has started yet and the outer trial owns route rollback.
    try{ctl('stop',network);}catch{}
    throw e;
  }
}
