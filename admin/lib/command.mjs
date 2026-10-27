import {spawn} from 'node:child_process';
import {need} from './common.mjs';
export async function command(file,args,{input,timeout=10000,limit=256*1024,allowFailure=false}={}){
 return await new Promise((resolve,reject)=>{const child=spawn(file,args,{env:{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL:'C'},stdio:['pipe','pipe','pipe']});let out=[],n=0,failed=false;const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');},timeout);for(const[stream,keep]of[[child.stdout,true],[child.stderr,false]])stream.on('data',b=>{n+=b.length;if(n>limit){failed=true;child.kill('SIGKILL');}else if(keep)out.push(b);});child.on('error',()=>{failed=true;});child.stdin.on('error',()=>{});child.stdin.end(input);child.once('close',code=>{clearTimeout(timer);if(failed||(!allowFailure&&code!==0))reject(Error(failed?'command_timeout_or_limit':'command_failed'));else resolve({code,out:Buffer.concat(out).toString('utf8')});});});
}
export class Jobs{
 constructor(){this.current=null;this.history=[];}
 start(kind,fn){need(!this.current,'operation_in_progress',409);const job={id:Date.now().toString(36),kind,status:'running',started:new Date().toISOString()};this.current=job;this.history.unshift(job);this.history.length=Math.min(this.history.length,16);Promise.resolve().then(fn).then(result=>{job.status='passed';job.result=result;},e=>{job.status='failed';job.error=/^[a-z0-9_]{1,100}$/.test(e.message)?e.message:'operation_failed';}).finally(()=>{job.finished=new Date().toISOString();this.current=null;});return{...job};}
}
