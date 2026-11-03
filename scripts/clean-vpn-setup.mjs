#!/usr/bin/env node
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {setupOptions,NativeSetup,usage} from './lib/native-setup.mjs';
let lock;
try{
 const [action,...args]=process.argv.slice(2),o=setupOptions(action,args);
 if(o.help)console.log(usage);
 else{
  if(!o.plan&&o.action!=='check'){
   if(process.platform!=='linux'||process.getuid()!==0)throw Error('linux_root_required');
   lock=fs.openSync('/run/clean-vpn-install.lock',fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_NOFOLLOW,0o600);
   const s=fs.fstatSync(lock);if(!s.isFile()||s.uid!==0||s.nlink!==1||(s.mode&0o777)!==0o600)throw Error('unsafe_install_lock');
   execFileSync('flock',['-n','3'],{stdio:['ignore','pipe','pipe',lock],timeout:3000});
  }
  console.log(JSON.stringify(await new NativeSetup(o).execute(),null,2));
 }
}catch(e){console.error(JSON.stringify({status:'failed',phase:e.setupPhase,code:/^[a-z0-9_]+$/.test(e.message)?e.message:e.code??'setup_failed',note:'Run uninstall.sh with the same role/name to undo owned changes before retrying. Credentials are retained; foreign or modified files are refused.'}));process.exitCode=1;}
finally{if(lock!==undefined)fs.closeSync(lock);}
