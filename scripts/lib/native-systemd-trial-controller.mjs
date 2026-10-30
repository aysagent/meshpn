// Temporary systemd engine adapter for the existing Radxa route/DNS owner.
// No packet IPC. Does not replace/enable any installed unit or modify clocks.
import {validNativeDiagnostics} from './native-engine-diagnostics.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {EventEmitter} from 'node:events';
import {execFileSync} from 'node:child_process';
import {nativeServiceUnit} from './native-service-unit.mjs';
import {nativeClockRecoveryUnit} from './native-clock-unit.mjs';
import {prepareInstalledTrial} from './native-installed-trial.mjs';
import {validAddressDiagnostic} from './native-address-diagnostic.mjs';
const UNIT='clean-vpn-native-clock-trial-engine.service',RECOVERY='clean-vpn-native-clock-trial-recovery.service';
const require=(ok,code)=>{if(!ok)throw Error(code);};
const run=(...args)=>execFileSync('/usr/bin/systemctl',args,{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','pipe']}).trim();
export class NativeSystemdTrialController extends EventEmitter{
 constructor({binary,config,clockConfig,installedProfile}){super();this.closed=false;this.stopping=false;this.offset=0;this.pending='';this.lastState=null;this.failedAt=null;
  require(process.platform==='linux'&&process.getuid()===0,'clock_trial_linux_root');
  for(const p of [binary,config,installedProfile??clockConfig])require(/^\/[a-zA-Z0-9_./-]+$/.test(p)&&path.normalize(p)===p,'clock_trial_path');
  let c;
  if(!installedProfile){
  const st=fs.lstatSync(clockConfig);require(st.isFile()&&!st.isSymbolicLink()&&st.uid===0&&(st.mode&0o077)===0&&st.size<8192,'clock_trial_config_permissions');
  c=JSON.parse(fs.readFileSync(clockConfig));require(c.consumer_unit===UNIT&&c.host==='154.62.226.216'&&c.port===22,'clock_trial_consumer');
  }
  require(run('show','clean-vpn-native-trial.service','-p','ActiveState','--value')==='active','clock_trial_owner_inactive');
  const root=path.dirname(path.dirname(binary));const script=path.resolve(root,'../../scripts/clean-vpn-native-clock.py');require(fs.existsSync(script),'clock_helper_missing');
  // Validate separately: ExecStartPre shares StandardOutput with the engine,
  // but its config report is not a runtime status event.
  execFileSync(binary,['--check-config',config],{timeout:15000,stdio:['ignore','pipe','pipe'],maxBuffer:65536});
  for(const u of [UNIT,RECOVERY])require(!fs.existsSync('/run/systemd/system/'+u),'clock_trial_unit_collision');
  this.dir=fs.mkdtempSync('/run/clean-vpn-systemd-trial-');fs.chmodSync(this.dir,0o700);this.log=this.dir+'/events';fs.writeFileSync(this.log,'',{mode:0o600});
  if(installedProfile){
    const installed=prepareInstalledTrial({binary,config,clockProfile:installedProfile,log:this.log});
    this.unit=installed.unit;this.recovery=installed.recovery;this.cleanupInstalled=installed.cleanup;this.files=new Map();
  }else{
  this.unit=UNIT;this.recovery=RECOVERY;
  const marker='# clean-vpn-owned-clock-trial\n';
  const consumer=marker+nativeServiceUnit({binary,config,networkUnit:'clean-vpn-native-trial.service',guardUnit:'clean-vpn-killswitch.service',role:'client',clockRecoveryUnit:RECOVERY}).replace(`ExecStartPre=${binary} --check-config ${config}\n`,'').replace('StandardOutput=journal','StandardOutput=append:'+this.log).replace('StandardError=journal','StandardError=null').replace('ProtectHome=yes','ProtectHome=read-only');
  const recovery=marker+nativeClockRecoveryUnit({consumerUnit:UNIT,script,config:clockConfig,stateDirectory:c.state_dir}).replace('[Unit]\n','[Unit]\nPartOf=clean-vpn-native-trial.service\nAfter=clean-vpn-native-trial.service\n').replace('ProtectHome=yes','ProtectHome=read-only');
  this.files=new Map([['/run/systemd/system/'+UNIT,consumer],['/run/systemd/system/'+RECOVERY,recovery]]);
  }
  for(const p of this.files.keys())require(!fs.existsSync(p),'clock_trial_unit_collision');
  try{for(const[p,s]of this.files)fs.writeFileSync(p,s,{flag:'wx',mode:0o644});run('daemon-reload');run('--no-block','start',this.unit);}catch(e){this.cleanupInstalled?.();for(const[p,s]of this.files)if(fs.existsSync(p)&&fs.readFileSync(p,'utf8')===s)fs.unlinkSync(p);run('daemon-reload');fs.unlinkSync(this.log);fs.rmdirSync(this.dir);throw e;}
  this.timer=setInterval(()=>this.poll(),200);this.started=performance.now();
 }
 poll(){if(this.closed||this.stopping)return;try{
  const st=fs.statSync(this.log);require(st.size<=256*1024&&st.size>=this.offset,'clock_trial_output_limit');if(st.size>this.offset){const fd=fs.openSync(this.log,'r'),b=Buffer.alloc(st.size-this.offset);try{fs.readSync(fd,b,0,b.length,this.offset);}finally{fs.closeSync(fd);}this.offset=st.size;this.pending+=b;for(;;){const i=this.pending.indexOf('\n');if(i<0)break;const line=this.pending.slice(0,i);this.pending=this.pending.slice(i+1);const event=JSON.parse(line);if(validNativeDiagnostics(event)){this.emit('diagnostic',event);continue;}if(validAddressDiagnostic(event)){this.emit('diagnostic',event);continue;}require(event.version===1&&['state','status'].includes(event.event)&&/^[a-z0-9_]{1,64}$/.test(event.state)&&['generation','tx_packets','rx_packets','dropped_packets'].every(k=>Number.isSafeInteger(event[k])&&event[k]>=0),'clock_trial_event');this.lastState=event;this.emit('status',event);}}
  const state=run('show',this.unit,'-p','ActiveState','--value');if(state==='failed'||state==='inactive'){this.failedAt??=performance.now();require(performance.now()-this.failedAt<(this.cleanupInstalled?210000:45000),'clock_trial_recovery_failed');}else this.failedAt=null;
 }catch{this.emit('fault',{reason:'clock_trial_service_failed'});this.stop();}}
 status(){if(this.lastState)this.emit('status',this.lastState);}
 uplink(ready){if(this.stopping||this.closed)return;try{run('--no-block',ready?'start':'stop',this.unit);}catch{this.emit('fault',{reason:'clock_trial_uplink'});this.stop();}}
 stop(){if(this.closed||this.stopping)return;this.stopping=true;clearInterval(this.timer);let code=0;try{run('stop',this.recovery);run('stop',this.unit);this.cleanupInstalled?.();for(const[p,s]of this.files){require(fs.readFileSync(p,'utf8')===s,'clock_trial_unit_changed');fs.unlinkSync(p);}run('daemon-reload');fs.unlinkSync(this.log);fs.rmdirSync(this.dir);}catch{code=1;}this.closed=true;queueMicrotask(()=>this.emit('exit',{code,signal:null,incompleteStatus:!!this.pending}));}
}
