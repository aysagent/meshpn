import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {need} from './common.mjs';
export async function command(file,args,{input,timeout=10000,limit=256*1024,allowFailure=false,captureError=false}={}){
 return await new Promise((resolve,reject)=>{const child=spawn(file,args,{env:{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL:'C'},stdio:['pipe','pipe','pipe']});let out=[],err=[],n=0,failed=false;const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');},timeout);for(const[stream,keep]of[[child.stdout,true],[child.stderr,false]])stream.on('data',b=>{n+=b.length;if(n>limit){failed=true;child.kill('SIGKILL');}else if(keep)out.push(b);else if(captureError)err.push(b);});child.on('error',()=>{failed=true;});child.stdin.on('error',()=>{});child.stdin.end(input);child.once('close',code=>{clearTimeout(timer);if(failed||(!allowFailure&&code!==0))reject(Error(failed?'command_timeout_or_limit':'command_failed'));else resolve({code,out:Buffer.concat(out).toString('utf8'),...(captureError?{err:Buffer.concat(err).toString('utf8')}:{})});});});
}
export class Jobs{
 constructor(){this.current=null;this.history=[];}
 start(kind,fn){
  need(!this.current,'operation_in_progress',409);
  const began=performance.now();let ended;
  const job={id:randomUUID(),kind,status:'running',phase:'queued',started:new Date().toISOString()};
  Object.defineProperty(job,'elapsedMs',{enumerable:true,get:()=>Math.max(0,Math.round((ended??performance.now())-began))});
  const phases=new Set(['validating','checking-guard','starting-network','stopping-network','starting-engine','restarting-engine','waiting-tunnel','enabling-guard','disabling-guard','restoring-usb-access','applying-settings']);
  const phase=value=>{need(job.status==='running'&&phases.has(value),'operation_phase');job.phase=value;};
  this.current=job;this.history.unshift(job);this.history.length=Math.min(this.history.length,16);
  Promise.resolve().then(()=>{phase('validating');return fn({phase});}).then(result=>{job.status='passed';job.phase='completed';job.result=result;},e=>{job.status='failed';job.phase='failed';job.error=/^[a-z0-9_]{1,100}$/.test(e.message)?e.message:'operation_failed';}).finally(()=>{ended=performance.now();job.finished=new Date().toISOString();this.current=null;});
  return{...job};
 }
}
