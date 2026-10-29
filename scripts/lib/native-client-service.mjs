import fs from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {writeClientPrivate} from './native-client-manager.mjs';
const exec=promisify(execFile);
export function nativeClientService({engine,unit,directory,run=async(cmd,args)=>{const r=await exec(cmd,args,{timeout:15000,maxBuffer:1048576});return r.stdout;}}){
 assert.ok(typeof engine==='string'&&engine.startsWith('/'),'client_engine_absolute');
 if(unit)assert.match(unit,/^[a-zA-Z0-9_-]+\.service$/,'client_service_unit');
 const identity=async configPath=>{
  const state=Object.fromEntries((await run('systemctl',['show',unit,'-p','MainPID','-p','ActiveState','-p','InvocationID'])).trim().split('\n').map(l=>l.split('=')));
  assert.equal(state.ActiveState,'active','client_service_not_active');assert.match(state.MainPID,/^[1-9][0-9]*$/);
  const argv=fs.readFileSync('/proc/'+state.MainPID+'/cmdline','utf8').split('\0'),i=argv.indexOf('--config');
  assert.ok(i>=0&&argv[i+1]===configPath&&argv[0]&&fs.realpathSync(argv[0])===fs.realpathSync(engine),'client_service_identity');
  assert.match(state.InvocationID,/^[a-f0-9]{32}$/,'client_service_invocation');
  // The running instance must announce the API, not just a possibly replaced
  // on-disk binary. No /proc/PID/exe or CAP_SYS_PTRACE is needed by the broker.
  const evidence=await run('journalctl',['-u',unit,'_SYSTEMD_INVOCATION_ID='+state.InvocationID,'_PID='+state.MainPID,'--grep="event":"peer_reload_ready"','-n','1','-o','json','--no-pager']);
  let ready=false;for(const line of evidence.trim().split('\n'))try{const r=JSON.parse(line),e=JSON.parse(r.MESSAGE);if(r._PID===state.MainPID&&e.version===1&&e.event==='peer_reload_ready'&&/^[a-f0-9]{64}$/.test(e.config_sha256))ready=true;}catch{}
  assert.ok(ready,'client_running_engine_reload_unconfirmed');
  return state.MainPID;
 };
 const preflight=async()=>{if(unit){const c=JSON.parse(await run(engine,['--capabilities']));assert.ok(c.peer_reload,'client_engine_reload_unsupported');}};
 return{
  validateConfig:async file=>{await run(engine,['--check-config',file]);},
  initializeRelay:async config=>{
   assert.ok(directory&&directory.startsWith('/'),'client_replay_preparation_required');const file=directory+'/relay-init-'+randomBytes(8).toString('hex')+'.json';
   writeClientPrivate(file,Buffer.from(JSON.stringify(config)));try{await run(engine,['--init-transparent-replay',file]);}finally{fs.unlinkSync(file);}
  },
  preflight,
  beforeMutation:unit?async({configPath})=>{await preflight();await identity(configPath);}:undefined,
  applyConfig:unit?async({configPath,sha256})=>{
   const pid=await identity(configPath);
   const cursor=(await run('journalctl',['-u',unit,'-n','0','--show-cursor','--no-pager'])).match(/-- cursor: (.+)/)?.[1];assert.ok(cursor,'client_journal_cursor');
   await run('systemctl',['kill','--kill-whom=main','--signal=HUP',unit]);
   const deadline=performance.now()+8000;
   do{const lines=(await run('journalctl',['-u',unit,'--after-cursor',cursor,'-o','json','--no-pager','-n','100'])).trim().split('\n');
    for(const line of lines){let event,record;try{record=JSON.parse(line);event=JSON.parse(record.MESSAGE);}catch{continue;}if(event.event==='peer_reload'&&event.config_sha256===sha256&&record._PID===pid){assert.equal(event.status,'applied','client_reload_rejected');assert.equal(await identity(configPath),pid,'client_service_restarted_during_reload');return;}}
    await delay(100);
   }while(performance.now()<deadline);
   throw Error('client_reload_ack_timeout');
  }:undefined,
 };
}
