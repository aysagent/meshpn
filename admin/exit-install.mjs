#!/usr/bin/env node
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {inspectExitAdmin,installExitAdmin,removeExitAdmin} from './lib/exit-install.mjs';
import {need,safeError} from './lib/common.mjs';
const exec=promisify(execFile),run=async(c,a)=>{const r=await exec(c,a,{timeout:30000,maxBuffer:1048576});return r.stdout;};
async function main(){const[action,...args]=process.argv.slice(2),options={};need(['--plan','--apply','--remove'].includes(action),'exit_admin_action');for(const arg of args){const m=arg.match(/^--(name|directory|port|capture-port)=(.+)$/);need(m&&!Object.hasOwn(options,m[1]),'exit_admin_option');options[m[1]]=m[2];}if(options.port)options.port=Number(options.port);if(options['capture-port']){options.capturePort=Number(options['capture-port']);delete options['capture-port'];}if(action==='--remove')return removeExitAdmin(options,{run});if(action==='--plan')return inspectExitAdmin(options);return installExitAdmin(options,{root:fileURLToPath(new URL('../',import.meta.url)).replace(/\/$/,''),node:process.execPath,run});}
main().then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error('EXIT_ADMIN=failed: '+safeError(e));process.exitCode=1;});
