#!/usr/bin/env node
// Authenticated clock recovery. No TLS bypass; same bounded wire protocol and
// persistent attempt/floor files as the original helper.
import fs from 'node:fs';
import path from 'node:path';
import {isIPv4} from 'node:net';
import {randomBytes,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const need=(v,c)=>{if(!v)throw Error(c);};
const MIN=1767225600,MAX=4102444800;
const failures={'75':'tls_verify_not_yet_valid','76':'tls_verify_expired','77':'auth_clock_skew'};
const eligible=new Set(Object.values(failures));
const run=(f,a,o={})=>execFileSync(f,a,{encoding:'utf8',timeout:3000,maxBuffer:65536,env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL:'C'},stdio:['ignore','pipe','ignore'],...o}).trim();
export function strictFlatJson(data){
 const text=data.toString(),value=JSON.parse(text);need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.values(value).every(v=>v===null||typeof v!=='object'),'invalid_json_object');
 const seen=new Set();for(let i=0;i<text.length;i++){if(text[i]!==String.fromCharCode(34))continue;const begin=i++;while(i<text.length){if(text[i]===String.fromCharCode(92)){i+=2;continue;}if(text[i]===String.fromCharCode(34))break;i++;}let next=i+1;while(/\s/.test(text[next]??'')&&next<text.length)next++;if(text[next]===':'){const key=JSON.parse(text.slice(begin,i+1));need(!seen.has(key),'duplicate_json_key');seen.add(key);}}
 return value;
}
export function trusted(p){
 need(typeof p==='string'&&/^\/[\w./-]+$/.test(p)&&path.normalize(p)===p&&p!=='/','unsafe_path');
 for(let d=path.dirname(p);;d=path.dirname(d)){const s=fs.lstatSync(d);need(s.isDirectory()&&!s.isSymbolicLink()&&[0,process.getuid()].includes(s.uid)&&(!(s.mode&0o022)||(s.mode&0o1000)),'unsafe_ancestor');if(d==='/')break;}
 return p;
}
export function readPrivate(p,limit=4096,privateFile=true){
 trusted(p);const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const s=fs.fstatSync(fd);need(s.isFile()&&s.nlink===1&&s.uid===process.getuid()&&!(s.mode&(privateFile?0o077:0o022))&&s.size>0&&s.size<=limit,'unsafe_file');const b=fs.readFileSync(fd);need(b.length===s.size,'changed_file');return b;}finally{fs.closeSync(fd);}
}
export function clockConfig(c){
 need(c&&JSON.stringify(Object.keys(c).filter(k=>k!=='update_directory').sort())===JSON.stringify(['version','host','port','user','identity','known_hosts','state_dir','consumer_unit'].sort()),'invalid_config_fields');
 need(c.version===1&&isIPv4(c.host)&&c.host!=='0.0.0.0'&&Number(c.host.split('.')[0])<224,'invalid_host');
 need(Number.isInteger(c.port)&&c.port>0&&c.port<=65535&&/^[a-z][a-z0-9_-]{0,31}$/.test(c.user)&&/^[a-z][a-z0-9-]{0,63}\.service$/.test(c.consumer_unit),'invalid_config');
 for(const k of ['identity','known_hosts','state_dir',...(c.update_directory?['update_directory']:[])])trusted(c[k]);return c;
}
export function hostPin(b){const a=b.toString('ascii').trim().split(/\s+/);need(a.length===3&&a[0]==='clean-vpn-clock'&&a[1]==='ssh-ed25519'&&/^[A-Za-z0-9+/]+={0,2}$/.test(a[2]),'single_pinned_host_required');const raw=Buffer.from(a[2],'base64');need(raw.length===51&&raw.subarray(0,19).toString('hex')==='0000000b7373682d6564323535313900000020','invalid_ed25519_pin');return createHash('sha256').update(raw).digest('hex');}
export function sshArgs(c){return ['-F','/dev/null','-4','-T','-p',String(c.port),'-i',c.identity,...Object.entries({BatchMode:'yes',IdentitiesOnly:'yes',IdentityAgent:'none',StrictHostKeyChecking:'yes',HostKeyAlgorithms:'ssh-ed25519',HostKeyAlias:'clean-vpn-clock',UserKnownHostsFile:c.known_hosts,GlobalKnownHostsFile:'/dev/null',KnownHostsCommand:'none',UpdateHostKeys:'no',VerifyHostKeyDNS:'no',ControlMaster:'no',ControlPath:'none',ProxyCommand:'none',ProxyJump:'none',ForwardAgent:'no',ForwardX11:'no',ClearAllForwardings:'yes',PermitLocalCommand:'no',PasswordAuthentication:'no',KbdInteractiveAuthentication:'no',ConnectTimeout:'3',ConnectionAttempts:'1',ServerAliveInterval:'1',ServerAliveCountMax:'2'}).flatMap(([k,v])=>['-o',k+'='+v]),c.user+'@'+c.host,'clean-vpn-clock-v1'];}
export function validateResponse(data,nonce,elapsed,before,after,floor=0){
 need(elapsed>=0&&elapsed<=5,'clock_round_trip_exceeded');need(Math.abs(after-before-elapsed)<=1.5,'local_clock_changed_during_probe');need(Buffer.byteLength(data)<=512,'clock_response_too_large');
 const r=strictFlatJson(data);need(JSON.stringify(Object.keys(r).sort())===JSON.stringify(['version','nonce','unix_seconds','synchronized'].sort()),'invalid_clock_response');
 need(r.version===1&&r.nonce===nonce&&/^[a-f0-9]{64}$/.test(nonce),'clock_nonce_or_version_mismatch');need(r.synchronized===true,'exit_clock_not_synchronized');need(Number.isInteger(r.unix_seconds)&&r.unix_seconds>=MIN&&r.unix_seconds<MAX,'invalid_remote_epoch');need(r.unix_seconds+5>=floor,'remote_time_older_than_trusted_floor');
 return {remoteUnixSeconds:r.unix_seconds,roundTripMs:Math.round(elapsed*1000),uncertaintySeconds:elapsed+1,offsetSeconds:Math.round((r.unix_seconds-after)*1000)/1000,needsCorrection:Math.abs(r.unix_seconds-after)>elapsed+2};
}
function floorRead(c){
 try{const s=fs.lstatSync(c.state_dir);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700,'unsafe_state_directory');}catch(e){if(e.code==='ENOENT')return 0;throw e;}
 let r;try{r=strictFlatJson(readPrivate(c.state_dir+'/last-good.json'));}catch(e){if(e.code==='ENOENT')return 0;throw e;}
 need(Object.keys(r).sort().join(',')==='unix_seconds,version'&&r.version===1&&Number.isInteger(r.unix_seconds)&&r.unix_seconds>=MIN&&r.unix_seconds<MAX,'invalid_clock_floor');return r.unix_seconds;
}
function save(c,name,value){
 fs.mkdirSync(c.state_dir,{mode:0o700,recursive:true});floorRead(c);
 const temp=c.state_dir+'/clock-'+randomBytes(12).toString('hex');const fd=fs.openSync(temp,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,c.state_dir+'/'+name);const d=fs.openSync(c.state_dir,'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
}
export function claimAttempt(c,failure,boot){
 need(eligible.has(failure),'clock_failure_required');const valid=b=>typeof b==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(b);need(valid(boot),'invalid_boot_id');
 let old;try{old=strictFlatJson(readPrivate(c.state_dir+'/attempt.json'));}catch(e){if(e.code!=='ENOENT')throw e;}
 if(old){need(Object.keys(old).sort().join(',')==='boot_id,failure,version'&&old.version===1&&valid(old.boot_id)&&eligible.has(old.failure),'invalid_attempt_state');need(old.boot_id!==boot,'clock_attempt_already_consumed');}
 save(c,'attempt.json',{version:1,boot_id:boot,failure});
}
export function probe(c){
 readPrivate(c.identity,16384);need(!fs.existsSync(c.identity+'-cert.pub'),'ssh_certificate_not_allowed');const pin=hostPin(readPrivate(c.known_hosts,4096,false)),floor=floorRead(c),nonce=randomBytes(32).toString('hex');const before=Date.now()/1000,start=performance.now();
 let data;try{data=run('/usr/bin/ssh',sshArgs(c),{input:nonce+'\n',stdio:['pipe','pipe','ignore'],timeout:5000,killSignal:'SIGKILL',maxBuffer:512});}catch{throw Error(performance.now()-start>=5000?'clock_round_trip_exceeded':'authenticated_clock_query_failed');}
 return {...validateResponse(data,nonce,(performance.now()-start)/1000,before,Date.now()/1000,floor),hostPinSha256:pin,trustedFloor:floor};
}
function state(c){return Object.fromEntries(run('/usr/bin/systemctl',['show',c.consumer_unit,...['MainPID','ActiveState','SubState','Job','Result','ExecMainCode','ExecMainStatus','InvocationID'].flatMap(k=>['-p',k])]).split('\n').map(x=>{const i=x.indexOf('=');return[x.slice(0,i),x.slice(i+1)];}));}
function failed(c){const s=state(c);if(s.MainPID!=='0'||s.ActiveState!=='failed'||s.SubState!=='failed'||s.Job!==''||s.Result!=='exit-code'||s.ExecMainCode!=='1'||!failures[s.ExecMainStatus])return null;need(/^[a-f0-9]{32}$/.test(s.InvocationID),'invalid_invocation_id');return [failures[s.ExecMainStatus],s.InvocationID];}
function stopped(c){const s=state(c);need(s.MainPID==='0'&&['inactive','failed'].includes(s.ActiveState)&&['dead','failed'].includes(s.SubState)&&s.Job==='','consumer_still_running');}
function lock(p,create=true){trusted(p);const fd=fs.openSync(p,fs.constants.O_RDWR|(create?fs.constants.O_CREAT:0)|fs.constants.O_NOFOLLOW,0o600);try{const s=fs.fstatSync(fd);need(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&0o777)===0o600,'unsafe_lock');execFileSync('flock',['-n','3'],{stdio:['ignore','pipe','pipe',fd],timeout:3000});return fd;}catch(e){fs.closeSync(fd);throw e;}}
export async function clockMain(args){
 const [mode,...opts]=args;need(['serve','probe','apply','recover'].includes(mode),'clock_mode');const o={};for(let i=0;i<opts.length;i++){const m=/^--(config|failure)(?:=(.+))?$/.exec(opts[i]);need(m&&!Object.hasOwn(o,m[1]),'clock_arguments');o[m[1]]=m[2]??opts[++i];}
 if(mode==='serve'){
  need(!opts.length&&process.env.SSH_ORIGINAL_COMMAND==='clean-vpn-clock-v1','forced_command_required');
  const nonce=await new Promise((resolve,reject)=>{let b='';const timer=setTimeout(()=>{process.stdin.destroy();reject(Error('invalid_nonce'));},3000);process.stdin.setEncoding('ascii');process.stdin.on('data',s=>{b+=s;if(b.length>65){clearTimeout(timer);process.stdin.destroy();reject(Error('invalid_nonce'));}else if(b.endsWith('\n')){clearTimeout(timer);process.stdin.pause();resolve(b);}});process.stdin.on('end',()=>{clearTimeout(timer);reject(Error('invalid_nonce'));});});
  need(/^[a-f0-9]{64}\n$/.test(nonce),'invalid_nonce');need(run('/usr/bin/busctl',['get-property','org.freedesktop.timedate1','/org/freedesktop/timedate1','org.freedesktop.timedate1','NTPSynchronized'])==='b true','exit_clock_not_synchronized');const now=Math.floor(Date.now()/1000);need(now>=MIN&&now<MAX,'invalid_exit_epoch');return {version:1,nonce:nonce.trim(),unix_seconds:now,synchronized:true};
 }
 need(o.config&&(mode==='apply'?eligible.has(o.failure):o.failure===undefined),'clock_arguments');const c=clockConfig(strictFlatJson(readPrivate(o.config)));
 if(mode==='probe')return {kind:'clean-vpn-authenticated-clock',status:'passed',mode,...probe(c),systemClockChanged:false};
 need(process.platform==='linux'&&process.getuid()===0&&fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd','linux_root_systemd_required');const locks=[];
 try{
  if(c.update_directory&&fs.existsSync(c.update_directory)){const s=fs.lstatSync(c.update_directory);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0&&(s.mode&0o777)===0o700,'unsafe_update_directory');locks.push(lock(c.update_directory+'/operation.lock',false));need(!fs.existsSync(c.update_directory+'/transaction.json'),'binary_update_recovery_required');}
  const invocation=mode==='recover'?failed(c):null;
  if(mode==='recover'&&!invocation)return {kind:'clean-vpn-authenticated-clock',status:'skipped',mode,code:'not_a_native_time_failure',systemClockChanged:false};
  fs.mkdirSync(c.state_dir,{mode:0o700,recursive:true});floorRead(c);locks.push(lock(c.state_dir+'/lock'));
  const check=()=>{stopped(c);if(invocation)need(JSON.stringify(failed(c))===JSON.stringify(invocation),'consumer_failure_changed');};check();
  const failure=invocation?.[0]??o.failure;claimAttempt(c,failure,fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim());const r=probe(c),received=performance.now(),wall=Date.now()/1000;check();const elapsed=(performance.now()-received)/1000;need(elapsed<=4,'clock_response_stale');need(Math.abs(Date.now()/1000-wall-elapsed)<=1.5,'local_clock_changed_before_apply');
  if(r.needsCorrection)run('/usr/bin/date',['--utc','--set=@'+(r.remoteUnixSeconds+Math.floor(elapsed))]);
  save(c,'last-good.json',{version:1,unix_seconds:Math.max(r.trustedFloor,r.remoteUnixSeconds)});
  let restartQueued=false;if(invocation){check();if(r.needsCorrection){run('/usr/bin/systemctl',['--no-block','start',c.consumer_unit]);restartQueued=true;}}
  return {kind:'clean-vpn-authenticated-clock',status:'passed',mode,...r,failure,systemClockChanged:r.needsCorrection,...(invocation?{restartQueued}:{})};
 }finally{for(const fd of locks.reverse())fs.closeSync(fd);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)clockMain(process.argv.slice(2)).then(r=>console.log(JSON.stringify(r))).catch(e=>{console.error(JSON.stringify({kind:'clean-vpn-authenticated-clock',status:'refused',code:/^[a-z_]{1,100}$/.test(e.message)?e.message:'clock_operation_failed'}));process.exitCode=1;});
